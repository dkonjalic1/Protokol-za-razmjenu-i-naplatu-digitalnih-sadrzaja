#define BOOST_TEST_MODULE DigitalContentProtocol_test
#include <boost/test/included/unit_test.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>
#include <array>
#include <cctype>
#include <cstdio>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
  #include <sys/types.h>
  #include <sys/wait.h>
  #include <unistd.h>
#endif

#include "json/json.h"

namespace asio = boost::asio;
using asio::ip::tcp;
using asio::ip::udp;
namespace ssl = asio::ssl;
using json = nlohmann::json;

static constexpr size_t kMaxJsonFrame = 1024 * 1024;
static constexpr uint16_t kMcastPort  = 30000;

// ------------------------- env helpers -------------------------
static const char* env_or(const char* k, const char* defv) {
    const char* v = std::getenv(k);
    return (v && *v) ? v : defv;
}

static bool env_bool(const char* k, bool defv) {
    const char* v = std::getenv(k);
    if (!v || !*v) return defv;
    std::string s(v);
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return (s == "1" || s == "true" || s == "yes" || s == "on");
}

static std::string uniq() {
    return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
}

static bool file_exists(const std::string& p) {
    std::ifstream f(p.c_str(), std::ios::binary);
    return (bool)f;
}

// ------------------------- framing helpers -------------------------
static void write_u32_be(std::array<unsigned char,4>& out, uint32_t v) {
    out[0] = static_cast<unsigned char>((v >> 24) & 0xFF);
    out[1] = static_cast<unsigned char>((v >> 16) & 0xFF);
    out[2] = static_cast<unsigned char>((v >>  8) & 0xFF);
    out[3] = static_cast<unsigned char>( v        & 0xFF);
}

static uint32_t read_u32_be(const std::array<unsigned char,4>& in) {
    return (static_cast<uint32_t>(in[0]) << 24)
         | (static_cast<uint32_t>(in[1]) << 16)
         | (static_cast<uint32_t>(in[2]) <<  8)
         | (static_cast<uint32_t>(in[3]));
}

// ------------------------- TLS framed test client -------------------------
class TlsFrameClient {
public:
    TlsFrameClient(const std::string& host, int port)
        : host_(host), port_(std::to_string(port)), ctx_(ssl::context::tls_client), stream_(io_, ctx_) {}

    void connect() {
        ctx_.set_options(
            ssl::context::default_workarounds |
            ssl::context::no_sslv2 |
            ssl::context::no_sslv3 |
            ssl::context::no_tlsv1 |
            ssl::context::no_tlsv1_1
        );

        // Demo: trust self-signed server-cert.pem.
        const std::string cert = env_or("SERVER_CERT", "server-cert.pem");
        ctx_.load_verify_file(cert);
        stream_.set_verify_mode(ssl::verify_peer);

        SSL_CTX_set_min_proto_version(ctx_.native_handle(), TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx_.native_handle(), TLS1_3_VERSION);

        // PQC / hybrid preferences (non-fatal if provider missing)
        (void)SSL_CTX_set1_groups_list(ctx_.native_handle(), "X25519MLKEM768");
        (void)SSL_CTX_set1_sigalgs_list(ctx_.native_handle(), "ML-DSA-44");

        tcp::resolver resolver(io_);
        auto eps = resolver.resolve(host_, port_);
        asio::connect(stream_.lowest_layer(), eps);
        stream_.handshake(ssl::stream_base::client);
    }

    void close() {
        boost::system::error_code ec;
        stream_.lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
        stream_.lowest_layer().close(ec);
    }

    json request(const std::string& cmd, const json& payload = json::object()) {
        json msg;
        msg["cmd"] = cmd;
        msg["payload"] = payload;

        const std::string body = msg.dump();
        if (body.size() > kMaxJsonFrame) throw std::runtime_error("request too large");

        std::array<unsigned char,4> len{};
        write_u32_be(len, static_cast<uint32_t>(body.size()));
        asio::write(stream_, asio::buffer(len));
        asio::write(stream_, asio::buffer(body));

        return read_frame();
    }

    json upload_preview_bytes(const std::string& content_id, const std::vector<unsigned char>& bytes) {
        json hdr;
        hdr["cmd"] = "UPLOAD_PREVIEW_BYTES";
        hdr["payload"] = { {"content_id", content_id}, {"size", (int64_t)bytes.size()} };

        const std::string body = hdr.dump();
        std::array<unsigned char,4> len{};
        write_u32_be(len, static_cast<uint32_t>(body.size()));

        asio::write(stream_, asio::buffer(len));
        asio::write(stream_, asio::buffer(body));
        if (!bytes.empty()) asio::write(stream_, asio::buffer(bytes));

        return read_frame();
    }

private:
    json read_frame() {
        std::array<unsigned char,4> rlen{};
        asio::read(stream_, asio::buffer(rlen));
        const uint32_t n = read_u32_be(rlen);
        if (n == 0 || n > kMaxJsonFrame) throw std::runtime_error("invalid response length");

        std::vector<unsigned char> buf(n);
        asio::read(stream_, asio::buffer(buf));
        std::string s(reinterpret_cast<const char*>(buf.data()), buf.size());
        return json::parse(s);
    }

private:
    std::string host_;
    std::string port_;
    asio::io_context io_;
    ssl::context ctx_;
    ssl::stream<tcp::socket> stream_;
};

// ------------------------- UDP collector (unicast + multicast) -------------------------
class UdpCollector {
public:
    // If bind_port==0 => bind to ephemeral port.
    explicit UdpCollector(uint16_t bind_port = 0)
        : sock_(io_) {
        udp::endpoint ep(udp::v4(), bind_port);
        sock_.open(ep.protocol());
        sock_.set_option(asio::socket_base::reuse_address(true));
        sock_.bind(ep);
        start_receive();
        th_ = std::thread([this]{ io_.run(); });
    }

    // Join multicast group and bind to port (usually kMcastPort).
    static std::unique_ptr<UdpCollector> multicast(const asio::ip::address_v4& group, uint16_t port) {
        auto c = std::unique_ptr<UdpCollector>(new UdpCollector(/*bind_port=*/port, /*already_bound=*/true));
        boost::system::error_code ec;
        // Join on default interface.
        c->sock_.set_option(asio::ip::multicast::join_group(group), ec);
        if (ec) {
            // Try explicit "any" interface.
            c->sock_.set_option(asio::ip::multicast::join_group(group, asio::ip::address_v4::any()), ec);
        }
        if (ec) {
            throw std::runtime_error(std::string("join_group failed: ") + ec.message());
        }
        return c;
    }

    ~UdpCollector() {
        stop();
    }

    uint16_t local_port() const {
        boost::system::error_code ec;
        auto ep = sock_.local_endpoint(ec);
        if (ec) return 0;
        return ep.port();
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (stopped_) return;
            stopped_ = true;
        }
        boost::system::error_code ec;
        sock_.close(ec);
        io_.stop();
        if (th_.joinable()) th_.join();
    }

    bool wait_for_contains(const std::string& needle, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lk(mu_);
        return cv_.wait_for(lk, timeout, [&]{
            for (const auto& m : msgs_) {
                if (m.find(needle) != std::string::npos) return true;
            }
            return false;
        });
    }

    std::vector<std::string> snapshot() const {
        std::lock_guard<std::mutex> lk(mu_);
        return msgs_;
    }

private:
    // Internal ctor to bind to an explicit port for multicast.
    UdpCollector(uint16_t bind_port, bool already_bound)
        : sock_(io_) {
        (void)already_bound;
        udp::endpoint ep(udp::v4(), bind_port);
        sock_.open(ep.protocol());
        sock_.set_option(asio::socket_base::reuse_address(true));
        sock_.bind(ep);
        start_receive();
        th_ = std::thread([this]{ io_.run(); });
    }

    void start_receive() {
        sock_.async_receive_from(
            asio::buffer(buf_), remote_,
            [this](const boost::system::error_code& ec, std::size_t n) {
                if (!ec) {
                    std::string s(buf_.data(), buf_.data() + n);
                    {
                        std::lock_guard<std::mutex> lk(mu_);
                        msgs_.push_back(std::move(s));
                    }
                    cv_.notify_all();
                }
                // Continue unless we're stopping.
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    if (stopped_) return;
                }
                start_receive();
            }
        );
    }

private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    asio::io_context io_;
    udp::socket sock_;
    udp::endpoint remote_;
    std::array<char, 2048> buf_{};
    std::vector<std::string> msgs_;
    std::thread th_;
    bool stopped_ = false;
};

// ------------------------- server process fixture -------------------------
static std::string g_host;
static int g_port = 0;
static bool g_server_spawned = false;
static bool g_server_ready = false;
static std::string g_db_path;
#if defined(__unix__) || defined(__APPLE__)
static pid_t g_server_pid = -1;
#endif

static int pick_free_port() {
    asio::io_context io;
    tcp::acceptor a(io, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    return (int)a.local_endpoint().port();
}

static void wait_server_ready_or_throw(const std::string& host, int port) {
    // Try a few times to establish TLS and PING.
    for (int i = 0; i < 60; ++i) {
        try {
            TlsFrameClient c(host, port);
            c.connect();
            auto r = c.request("PING", json::object());
            c.close();
            if (r.value("ok", false) && r.value("cmd", "") == "PONG") return;
        } catch (...) {
            // ignore
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    throw std::runtime_error("Server did not become ready (TLS+PING failed). Check cert/key and server logs.");
}

static void kill_server_best_effort() {
#if defined(__unix__) || defined(__APPLE__)
    if (g_server_pid <= 0) return;
    ::kill(g_server_pid, SIGTERM);

    // Wait a bit, then SIGKILL if needed.
    for (int i = 0; i < 40; ++i) {
        int status = 0;
        pid_t r = ::waitpid(g_server_pid, &status, WNOHANG);
        if (r == g_server_pid) { g_server_pid = -1; return; }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    ::kill(g_server_pid, SIGKILL);
    int status = 0;
    (void)::waitpid(g_server_pid, &status, 0);
    g_server_pid = -1;
#endif
}

struct ServerFixture {
    ServerFixture() {
        g_host = env_or("HOST", "127.0.0.1");
        const int env_port = std::atoi(env_or("PORT", "0"));
        g_port = (env_port > 0) ? env_port : pick_free_port();

        const bool spawn = env_bool("SPAWN_SERVER", true);
        const std::string server_bin = env_or("SERVER_BIN", "./server");

        // Preconditions: if spawning, we need server binary + TLS files.
        if (spawn) {
            if (!file_exists(server_bin)) {
                throw std::runtime_error("SERVER_BIN not found: " + server_bin + " (build server first or set SPAWN_SERVER=0)");
            }
            if (!file_exists("server-cert.pem") || !file_exists("server-key.pem")) {
                throw std::runtime_error("Missing TLS files in current directory: server-cert.pem and/or server-key.pem");
            }
            g_db_path = std::string("dc_test_") + uniq() + ".db";

#if defined(__unix__) || defined(__APPLE__)
            g_server_pid = ::fork();
            if (g_server_pid < 0) {
                throw std::runtime_error("fork() failed");
            }
            if (g_server_pid == 0) {
                // Child: exec server
                std::string port_s = std::to_string(g_port);
                ::execl(server_bin.c_str(), server_bin.c_str(), g_host.c_str(), port_s.c_str(), g_db_path.c_str(), (char*)nullptr);
                std::perror("execl");
                std::_Exit(127);
            }
            g_server_spawned = true;
#else
            throw std::runtime_error("SPAWN_SERVER=1 requires POSIX (fork/exec). Run with SPAWN_SERVER=0 on this platform.");
#endif
        }

        // Whether spawned or external, require that it answers PING.
        wait_server_ready_or_throw(g_host, g_port);
        g_server_ready = true;
    }

    ~ServerFixture() {
        if (g_server_spawned) {
            kill_server_best_effort();
        }
        // cleanup db file
        if (!g_db_path.empty()) {
            // std::remove(g_db_path.c_str()); // leave it present for inspection
        }
    }
};

BOOST_GLOBAL_FIXTURE(ServerFixture);

// ------------------------- protocol helpers -------------------------
struct TestUser {
    std::string uri;
    std::string password;
    std::string role; // PUBLISHER/SUBSCRIBER
};

static TestUser make_user(const std::string& role) {
    TestUser u;
    u.role = role;
    u.uri = (role == "PUBLISHER" ? "pub+" : "sub+") + uniq() + "@example.com";
    u.password = "Aa1aaaaa"; // meets policy: >=8, upper, lower, digit
    return u;
}

static json register_user(TlsFrameClient& c, const TestUser& u) {
    json p;
    p["uri"] = u.uri;
    p["first_name"] = (u.role == "PUBLISHER" ? "Pub" : "Sub");
    p["last_name"] = "Tester";
    p["dob"] = "1990-01-01";
    p["password"] = u.password;
    p["role"] = u.role;
    return c.request("REGISTER_USER", p);
}

static json login(TlsFrameClient& c, const TestUser& u, int udp_port = 0) {
    json p;
    p["uri"] = u.uri;
    p["password"] = u.password;
    if (udp_port > 0) p["udp_port"] = udp_port;
    return c.request("LOGIN", p);
}

static void require_ok(const json& r) {
    BOOST_REQUIRE_MESSAGE(r.value("ok", false), r.dump());
}

static void require_not_ok(const json& r) {
    BOOST_REQUIRE_MESSAGE(!r.value("ok", true), r.dump());
}

// ------------------------- tests -------------------------

BOOST_AUTO_TEST_CASE(ping_pong) {
    BOOST_REQUIRE_MESSAGE(g_server_ready, "Server not ready");

    TlsFrameClient c(g_host, g_port);
    c.connect();
    auto r = c.request("PING", json::object());
    c.close();

    require_ok(r);
    BOOST_CHECK_EQUAL(r.value("cmd", ""), "PONG");
    BOOST_CHECK(r.contains("payload"));
}

BOOST_AUTO_TEST_CASE(register_missing_fields_fails) {
    TlsFrameClient c(g_host, g_port);
    c.connect();

    json p;
    p["uri"] = "x+" + uniq() + "@example.com";
    // missing required fields: first_name, last_name, dob, password, role
    auto r = c.request("REGISTER_USER", p);
    c.close();

    require_not_ok(r);
    BOOST_CHECK_EQUAL(r.value("cmd", ""), "REGISTER_RESULT");
    BOOST_CHECK(r.contains("err"));
}

BOOST_AUTO_TEST_CASE(register_and_login_publisher_and_subscriber) {
    TestUser pub = make_user("PUBLISHER");
    TestUser sub = make_user("SUBSCRIBER");

    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        auto r1 = register_user(c, pub);
        require_ok(r1);
        auto r2 = register_user(c, sub);
        require_ok(r2);
        c.close();
    }

    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        auto lp = login(c, pub);
        require_ok(lp);
        BOOST_CHECK_EQUAL(lp["payload"].value("role", ""), "PUBLISHER");
        c.close();
    }

    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        auto ls = login(c, sub);
        require_ok(ls);
        BOOST_CHECK_EQUAL(ls["payload"].value("role", ""), "SUBSCRIBER");
        c.close();
    }
}

BOOST_AUTO_TEST_CASE(publisher_only_commands_forbidden_for_subscriber) {
    TestUser pub = make_user("PUBLISHER");
    TestUser sub = make_user("SUBSCRIBER");

    // Register both
    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        require_ok(register_user(c, pub));
        require_ok(register_user(c, sub));
        c.close();
    }

    // Login subscriber and try publish
    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        require_ok(login(c, sub));

        json p = {
            {"title", "Should fail"},
            {"description", "nope"},
            {"type", "text"},
            {"category", "test"},
            {"price_fenings", 123},
            {"status", "ACTIVE"},
            {"min_age", 0}
        };
        auto r = c.request("PUBLISH_CONTENT", p);
        require_not_ok(r);
        BOOST_CHECK_EQUAL(r.value("cmd", ""), "PUBLISH_RESULT");
        BOOST_CHECK(r.dump().find("Publisher only") != std::string::npos);
        c.close();
    }
}

BOOST_AUTO_TEST_CASE(end_to_end_purchase_rate_moderate_and_unicast_notification) {
    TestUser pub = make_user("PUBLISHER");
    TestUser sub = make_user("SUBSCRIBER");

    // Register both
    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        require_ok(register_user(c, pub));
        require_ok(register_user(c, sub));
        c.close();
    }

    // Subscriber UDP receiver (unicast FEEDBACK_STATUS)
    auto uni = std::make_unique<UdpCollector>(0);
    const int sub_udp_port = (int)uni->local_port();

    std::string content_id;
    int feedback_id = 0;

    // Publisher: login + publish + upload preview
    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        require_ok(login(c, pub));

        json pubp = {
            {"title", "Test content " + uniq()},
            {"description", "desc"},
            {"type", "text"},
            {"category", "educational"},
            {"price_fenings", 2300},
            {"status", "ACTIVE"},
            {"min_age", 0}
        };
        auto pr = c.request("PUBLISH_CONTENT", pubp);
        require_ok(pr);
        content_id = pr["payload"].value("content_id", "");
        BOOST_REQUIRE_MESSAGE(!content_id.empty(), pr.dump());

        std::vector<unsigned char> bytes = {'H','e','l','l','o',' ','P','r','e','v','i','e','w'};
        auto ur = c.upload_preview_bytes(content_id, bytes);
        require_ok(ur);
        BOOST_CHECK_EQUAL(ur.value("cmd", ""), "UPLOAD_PREVIEW_RESULT");
        BOOST_CHECK_EQUAL((int)ur["payload"].value("bytes", 0), (int)bytes.size());

        c.close();
    }

    // Subscriber: login with udp_port + list + purchase + rate (comment -> PENDING)
    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        require_ok(login(c, sub, sub_udp_port));

        // List content (should include our category)
        auto lr = c.request("LIST_CONTENT", json{{"category", "educational"}});
        require_ok(lr);
        BOOST_CHECK_EQUAL(lr.value("cmd", ""), "CONTENT_LIST");

        // Purchase
        auto pur = c.request("PURCHASE_CONTENT", json{{"content_id", content_id}});
        require_ok(pur);
        BOOST_CHECK_EQUAL(pur.value("cmd", ""), "PURCHASE_RESULT");

        // Rate with comment => PENDING
        auto rr = c.request("RATE", json{{"content_id", content_id}, {"rating", 5}, {"comment", "Nice!"}});
        require_ok(rr);
        BOOST_CHECK_EQUAL(rr.value("cmd", ""), "RATE_RESULT");
        feedback_id = rr["payload"].value("feedback_id", 0);
        BOOST_REQUIRE(feedback_id > 0);
        BOOST_CHECK_EQUAL(rr["payload"].value("comment_status", ""), "PENDING");

        c.close();
    }

    // Publisher: login + list pending + moderate APPROVE
    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        require_ok(login(c, pub));

        auto pend = c.request("LIST_PENDING_FEEDBACK", json{{"content_id", content_id}});
        require_ok(pend);
        BOOST_CHECK_EQUAL(pend.value("cmd", ""), "PENDING_LIST");
        std::string pend_dump = pend.dump();
        BOOST_CHECK_MESSAGE(pend_dump.find(std::to_string(feedback_id)) != std::string::npos, pend_dump);

        auto mod = c.request("MODERATE", json{{"feedback_id", feedback_id}, {"action", "APPROVE"}, {"note", "ok"}});
        require_ok(mod);
        BOOST_CHECK_EQUAL(mod.value("cmd", ""), "MODERATE_RESULT");
        BOOST_CHECK_EQUAL(mod["payload"].value("new_status", ""), "APPROVED");

        c.close();
    }

    // Subscriber should receive unicast FEEDBACK_STATUS
    // (message is a JSON string sent over UDP)
    const std::string needle1 = "\"type\":\"FEEDBACK_STATUS\"";
    BOOST_CHECK_MESSAGE(uni->wait_for_contains(needle1, std::chrono::milliseconds(3000)),
                        "Did not receive FEEDBACK_STATUS UDP notification");

    // Ensure feedback_id appears in any received packet.
    const std::string needle2 = "\"feedback_id\":" + std::to_string(feedback_id);
    BOOST_CHECK_MESSAGE(uni->wait_for_contains(needle2, std::chrono::milliseconds(1)),
                        "FEEDBACK_STATUS received, but feedback_id not found in payload");
}

BOOST_AUTO_TEST_CASE(subscribe_and_receive_multicast_new_content) {
    TestUser pub = make_user("PUBLISHER");
    TestUser sub = make_user("SUBSCRIBER");

    // Register both
    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        require_ok(register_user(c, pub));
        require_ok(register_user(c, sub));
        c.close();
    }

    int publisher_id = 0;
    asio::ip::address_v4 group;

    // Publisher login: we need publisher_id for group mapping; easiest is LIST_PUBLISHERS after registration.
    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        // no need to login to list publishers
        auto pl = c.request("LIST_PUBLISHERS", json::object());
        require_ok(pl);
        BOOST_CHECK_EQUAL(pl.value("cmd", ""), "PUBLISHER_LIST");

        // Find our publisher by URI
        bool found = false;
        for (const auto& it : pl["payload"]["publishers"]) {
            if (it.value("publisher_uri", "") == pub.uri) {
                publisher_id = it.value("publisher_id", 0);
                group = asio::ip::make_address_v4(it.value("mcast_group", "239.255.1.1"));
                found = true;
                break;
            }
        }
        BOOST_REQUIRE_MESSAGE(found, pl.dump());
        BOOST_REQUIRE(publisher_id > 0);
        c.close();
    }

    // Subscriber subscribes (not required for multicast delivery, but matches intended flow)
    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        require_ok(login(c, sub));
        auto sr = c.request("SUBSCRIBE_PUBLISHER", json{{"publisher_id", publisher_id}, {"months", 1}});
        require_ok(sr);
        BOOST_CHECK_EQUAL(sr.value("cmd", ""), "SUBSCRIPTION_RESULT");
        BOOST_CHECK_EQUAL(sr["payload"].value("mcast_port", 0), (int)kMcastPort);
        c.close();
    }

    // Multicast receiver joins group
    auto mc = UdpCollector::multicast(group, kMcastPort);

    // Publisher publishes new content; multicast should arrive
    std::string cid;
    {
        TlsFrameClient c(g_host, g_port);
        c.connect();
        require_ok(login(c, pub));
        auto pr = c.request("PUBLISH_CONTENT", json{
            {"title", "MC content " + uniq()},
            {"description", "desc"},
            {"type", "text"},
            {"category", "mc"},
            {"price_fenings", 100},
            {"status", "ACTIVE"},
            {"min_age", 0}
        });
        require_ok(pr);
        cid = pr["payload"].value("content_id", "");
        c.close();
    }

    const std::string ntype = "\"type\":\"NEW_CONTENT\"";
    BOOST_CHECK_MESSAGE(mc->wait_for_contains(ntype, std::chrono::milliseconds(3000)),
                        "Did not receive NEW_CONTENT multicast notification");

    const std::string ncid = "\"content_id\":\"" + cid + "\"";
    BOOST_CHECK_MESSAGE(mc->wait_for_contains(ncid, std::chrono::milliseconds(1)),
                        "NEW_CONTENT received, but published content_id not found in packet");
}
