#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>
#include "json/json.h"

namespace asio = boost::asio;
using asio::ip::tcp;
using asio::ip::udp;
using json = nlohmann::json;

static constexpr uint16_t kMcastPort = 30000;
static constexpr size_t kMaxJsonFrame = 1024 * 1024;

static std::string trim(const std::string& s)
{
    size_t a = 0;
    while (a < s.size() && std::isspace((unsigned char)s[a])) a++;
    size_t b = s.size();
    while (b > a && std::isspace((unsigned char)s[b-1])) b--;
    return s.substr(a, b-a);
}

static std::string prompt_line(const std::string& p)
{
    std::cout << p << std::flush;
    std::string s;
    std::getline(std::cin, s);
    return trim(s);
}

static bool parse_int64(const std::string& s, int64_t& out)
{
    try {
        size_t idx = 0;
        long long v = std::stoll(s, &idx, 10);
        if (idx != s.size()) return false;
        out = (int64_t)v;
        return true;
    } catch (...) { return false; }
}

static bool parse_int(const std::string& s, int& out)
{
    int64_t v=0;
    if (!parse_int64(s, v)) return false;
    if (v < std::numeric_limits<int>::min() || v > std::numeric_limits<int>::max()) return false;
    out = (int)v;
    return true;
}

static std::string bam_fmt(int64_t fenings)
{
    // 1 BAM = 100 fenings
    int64_t abs = fenings >= 0 ? fenings : -fenings;
    int64_t whole = abs / 100;
    int64_t frac = abs % 100;
    std::ostringstream oss;
    if (fenings < 0) oss << "-";
    oss << whole << "." << std::setw(2) << std::setfill('0') << frac << " BAM";
    return oss.str();
}

// ------------------- Length-prefixed JSON framing -------------------

static void write_u32_be(std::array<unsigned char,4>& out, uint32_t v)
{
    out[0] = static_cast<unsigned char>((v >> 24) & 0xFF);
    out[1] = static_cast<unsigned char>((v >> 16) & 0xFF);
    out[2] = static_cast<unsigned char>((v >> 8) & 0xFF);
    out[3] = static_cast<unsigned char>(v & 0xFF);
}

static uint32_t read_u32_be(const std::array<unsigned char,4>& in)
{
    return (static_cast<uint32_t>(in[0]) << 24)
         | (static_cast<uint32_t>(in[1]) << 16)
         | (static_cast<uint32_t>(in[2]) << 8)
         | (static_cast<uint32_t>(in[3]));
}

class TlsClient {
public:
    TlsClient(const std::string& host, const std::string& port)
        : host_(host), port_(port), ctx_(asio::ssl::context::tls_client), stream_(io_, ctx_)
    {}

    void connect()
    {
        ctx_.set_options(
            asio::ssl::context::default_workarounds |
            asio::ssl::context::no_sslv2 |
            asio::ssl::context::no_sslv3 |
            asio::ssl::context::no_tlsv1 |
            asio::ssl::context::no_tlsv1_1
        );

        ctx_.load_verify_file("server-cert.pem");
        stream_.set_verify_mode(asio::ssl::verify_peer);

        SSL_CTX_set_min_proto_version(ctx_.native_handle(), TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx_.native_handle(), TLS1_3_VERSION);

        if (SSL_CTX_set1_groups_list(ctx_.native_handle(), "X25519MLKEM768") != 1) {
            std::cerr << "[client][WARN] SSL_CTX_set1_groups_list failed (PQC provider missing?)" << std::endl;
        }
        if (SSL_CTX_set1_sigalgs_list(ctx_.native_handle(), "ML-DSA-44") != 1) {
            std::cerr << "[client][WARN] SSL_CTX_set1_sigalgs_list failed (PQC provider missing?)" << std::endl;
        }

        tcp::resolver resolver(io_);
        auto endpoints = resolver.resolve(host_, port_);

        asio::connect(stream_.lowest_layer(), endpoints);
        stream_.handshake(asio::ssl::stream_base::client);
    }

    void close()
    {
        boost::system::error_code ec;
        stream_.lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
        stream_.lowest_layer().close(ec);
    }

    json request(const std::string& cmd, const json& payload)
    {
        json msg;
        msg["cmd"] = cmd;
        msg["payload"] = payload;

        std::string body = msg.dump();
        if (body.size() > kMaxJsonFrame) throw std::runtime_error("request too large");

        std::array<unsigned char,4> len;
        write_u32_be(len, (uint32_t)body.size());

        asio::write(stream_, asio::buffer(len));
        asio::write(stream_, asio::buffer(body));

        // read response
        std::array<unsigned char,4> rlen{};
        asio::read(stream_, asio::buffer(rlen));
        uint32_t n = read_u32_be(rlen);
        if (n == 0 || n > kMaxJsonFrame) throw std::runtime_error("invalid response length");

        std::vector<unsigned char> buf(n);
        asio::read(stream_, asio::buffer(buf));
        std::string s(reinterpret_cast<const char*>(buf.data()), buf.size());
        return json::parse(s);
    }

    // Byte-stream demo: upload preview bytes after content is created.
    // json upload_preview_bytes(const std::string& content_id, const std::vector<unsigned char>& bytes)
    // {
    //     json hdr;
    //     hdr["cmd"] = "UPLOAD_PREVIEW_BYTES";
    //     hdr["payload"] = {{"content_id", content_id}, {"size", (int64_t)bytes.size()}};

    //     std::string body = hdr.dump();
    //     std::array<unsigned char,4> len;
    //     write_u32_be(len, (uint32_t)body.size());

    //     asio::write(stream_, asio::buffer(len));
    //     asio::write(stream_, asio::buffer(body));
    //     asio::write(stream_, asio::buffer(bytes));

    //     // response is normal JSON frame
    //     std::array<unsigned char,4> rlen{};
    //     asio::read(stream_, asio::buffer(rlen));
    //     uint32_t n = read_u32_be(rlen);
    //     if (n == 0 || n > kMaxJsonFrame) throw std::runtime_error("invalid response length");

    //     std::vector<unsigned char> buf(n);
    //     asio::read(stream_, asio::buffer(buf));
    //     std::string s(reinterpret_cast<const char*>(buf.data()), buf.size());
    //     return json::parse(s);
    // }

private:
    std::string host_, port_;
    asio::io_context io_;
    asio::ssl::context ctx_;
    asio::ssl::stream<tcp::socket> stream_;
};

// ------------------- UDP notification receiver -------------------

class UdpNotifications {
public:
    UdpNotifications()
        : unicast_sock_(io_), mcast_sock_(io_)
    {}

    void start(uint16_t unicast_port = 0)
    {
        boost::system::error_code ec;

        // Unicast socket (unique per client)
        udp::endpoint unicast_ep(udp::v4(), unicast_port);
        unicast_sock_.open(udp::v4(), ec);
        if (ec) throw std::runtime_error("unicast_sock open: " + ec.message());
        unicast_sock_.bind(unicast_ep, ec);
        if (ec) throw std::runtime_error("unicast_sock bind: " + ec.message());
        unicast_port_ = unicast_sock_.local_endpoint().port();

        // Multicast socket (shared port)
        udp::endpoint mcast_ep(udp::v4(), kMcastPort);
        mcast_sock_.open(udp::v4(), ec);
        if (ec) throw std::runtime_error("mcast_sock open: " + ec.message());
        mcast_sock_.set_option(asio::socket_base::reuse_address(true), ec);
        mcast_sock_.bind(mcast_ep, ec);
        if (ec) throw std::runtime_error("mcast_sock bind: " + ec.message());

        do_recv_unicast();
        do_recv_mcast();

        th_ = std::thread([this](){ io_.run(); });
    }

    void stop()
    {
        boost::system::error_code ec;
        unicast_sock_.close(ec);
        mcast_sock_.close(ec);
        io_.stop();
        if (th_.joinable()) th_.join();
    }

    uint16_t unicast_port() const { return unicast_port_; }

    void join_publisher_group(const std::string& group_ip)
    {
        boost::system::error_code ec;
        auto addr = asio::ip::make_address_v4(group_ip, ec);
        if (ec) {
            std::cerr << "[client][udp][WARN] bad multicast address: " << group_ip << std::endl;
            return;
        }

        // mcast_sock_.set_option(asio::ip::multicast::join_group(addr), ec);
        mcast_sock_.set_option(asio::ip::multicast::join_group(addr, asio::ip::address_v4::any()), ec);

        if (ec) {
            std::cerr << "[client][udp][WARN] join_group failed: " << ec.message() << std::endl;
        } else {
            std::lock_guard<std::mutex> lk(mu_);
            joined_groups_.insert(group_ip);
        }
    }

    bool is_joined(const std::string& group_ip)
    {
        std::lock_guard<std::mutex> lk(mu_);
        return joined_groups_.count(group_ip) != 0;
    }

private:
    void print_notif(const std::string& prefix, const std::string& s)
    {
        try {
            auto j = json::parse(s);
            std::lock_guard<std::mutex> lk(out_mu_);
            std::cout << "\n[" << prefix << "] " << j.dump() << "\n> " << std::flush;
        } catch (...) {
            std::lock_guard<std::mutex> lk(out_mu_);
            std::cout << "\n[" << prefix << "] " << s << "\n> " << std::flush;
        }
    }

    void do_recv_unicast()
    {
        unicast_sock_.async_receive_from(
            asio::buffer(unicast_buf_), unicast_from_,
            [this](boost::system::error_code ec, std::size_t n)
            {
                if (!ec && n > 0) {
                    print_notif("notification-unicast", std::string(unicast_buf_.data(), n));
                }
                if (!ec) do_recv_unicast();
            });
    }

    void do_recv_mcast()
    {
        mcast_sock_.async_receive_from(
            asio::buffer(mcast_buf_), mcast_from_,
            [this](boost::system::error_code ec, std::size_t n)
            {
                if (!ec && n > 0) {
                    print_notif("notification-mcast", std::string(mcast_buf_.data(), n));
                }
                if (!ec) do_recv_mcast();
            });
    }

private:
    asio::io_context io_;
    udp::socket unicast_sock_;
    udp::socket mcast_sock_;
    udp::endpoint unicast_from_;
    udp::endpoint mcast_from_;
    std::array<char, 4096> unicast_buf_{};
    std::array<char, 4096> mcast_buf_{};
    uint16_t unicast_port_ = 0;

    std::thread th_;
    std::mutex out_mu_;

    std::mutex mu_;
    std::unordered_set<std::string> joined_groups_;
};

// ------------------- Client FSM -------------------

enum class ConnState { DISCONNECTED, TLS_OK_UNAUTH, AUTHED };
enum class UIState { MAIN_MENU, REGISTER_FLOW, LOGIN_FLOW, AUTH_MENU_SUB, AUTH_MENU_PUB, EXIT };

static void print_json_result(const json& r)
{
    bool ok = r.value("ok", false);
    if (ok) {
        std::cout << "[OK] " << r.value("payload", json::object()).dump() << std::endl;
    } else {
        auto err = r.value("err", json::object());
        std::cout << "[FAIL] " << err.value("code","") << ": " << err.value("message","") << std::endl;
    }
}

static void show_content_items(const json& items)
{
    if (!items.is_array() || items.empty()) {
        std::cout << "No content items." << std::endl;
        return;
    }
    std::cout << "Content list (" << items.size() << "):" << std::endl;
    for (auto& it : items) {
        std::cout << "- " << it.value("content_id","")
                  << " | " << it.value("title","")
                  << " | " << it.value("type","")
                  << " | " << it.value("category","")
                  << " | " << bam_fmt(it.value("price_fenings",(int64_t)0))
                  << " | " << it.value("status","")
                  << " | pub=" << it.value("publisher_uri","")
                  << " (" << it.value("publisher_id",0) << ")"
                  << std::endl;
    }
}

static void show_publishers(const json& pubs)
{
    if (!pubs.is_array() || pubs.empty()) {
        std::cout << "No publishers registered." << std::endl;
        return;
    }
    std::cout << "Publishers (" << pubs.size() << "):" << std::endl;
    for (auto& p : pubs) {
        std::cout << "- " << p.value("publisher_id",0)
                  << " | " << p.value("publisher_uri","")
                  << " | monthly=" << bam_fmt(p.value("monthly_fee_fenings",(int64_t)0))
                  << " | mcast=" << p.value("mcast_group","") << ":" << p.value("mcast_port",0)
                  << std::endl;
    }
}

int main(int argc, char** argv)
{
    try {
        std::string host = "127.0.0.1";
        std::string port = "1111";
        if (argc >= 2) host = argv[1];
        if (argc >= 3) port = argv[2];

        std::cout << "Server: " << host << ":" << port << std::endl;

        UdpNotifications udp_notifs;
        udp_notifs.start(0);
        std::cout << "UDP unicast listening on port " << udp_notifs.unicast_port() << std::endl;
        std::cout << "UDP multicast listening on port " << kMcastPort << " (reuse_address enabled)" << std::endl;

        TlsClient client(host, port);
        client.connect();
        std::cout << "TLS connected (TLS1.3 + PQC configured)" << std::endl;

        ConnState conn = ConnState::TLS_OK_UNAUTH;
        UIState ui = UIState::MAIN_MENU;

        int user_id = 0;
        std::string role;
        std::string uri;
        std::string token;

        auto ensure_subscriber_mcast_groups = [&]() {
            if (role != "SUBSCRIBER") return;
            auto r = client.request("LIST_SUBSCRIPTIONS", json::object());
            if (!r.value("ok", false)) return;
            auto subs = r["payload"].value("subscriptions", json::array());
            for (auto& s : subs) {
                std::string grp = s.value("mcast_group","");
                if (!grp.empty() && !udp_notifs.is_joined(grp)) udp_notifs.join_publisher_group(grp);
            }
        };

        while (ui != UIState::EXIT)
        {
            if (ui == UIState::MAIN_MENU)
            {
                std::cout << "\n=== Main Menu (unauthenticated) ===\n"
                          << "1) Register\n"
                          << "2) Login\n"
                          << "3) Browse content (ACTIVE)\n"
                          << "0) Exit\n";
                std::string ch = prompt_line("> ");
                if (ch == "1") ui = UIState::REGISTER_FLOW;
                else if (ch == "2") ui = UIState::LOGIN_FLOW;
                else if (ch == "3") {
                    json payload;
                    payload["status"] = "ACTIVE";
                    auto r = client.request("LIST_CONTENT", payload);
                    if (r.value("ok", false)) show_content_items(r["payload"]["items"]);
                    else print_json_result(r);
                }
                else if (ch == "0") ui = UIState::EXIT;
            }
            else if (ui == UIState::REGISTER_FLOW)
            {
                std::cout << "\n=== Register User ===\n";
                std::string r_uri = prompt_line("URI (email): ");
                std::string first = prompt_line("First name: ");
                std::string last = prompt_line("Last name: ");
                std::string dob = prompt_line("Date of birth (YYYY-MM-DD): ");
                std::string pw = prompt_line("Password (min 8, upper+lower+digit): ");
                std::cout << "Role:\n  1) SUBSCRIBER\n  2) PUBLISHER\n";
                std::string r = prompt_line("Choose: ");
                std::string r_role = (r == "2") ? "PUBLISHER" : "SUBSCRIBER";

                auto resp = client.request("REGISTER_USER", {
                    {"uri", r_uri},
                    {"first_name", first},
                    {"last_name", last},
                    {"dob", dob},
                    {"password", pw},
                    {"role", r_role}
                });

                print_json_result(resp);
                ui = UIState::MAIN_MENU;
            }
            else if (ui == UIState::LOGIN_FLOW)
            {
                std::cout << "\n=== Login ===\n";
                std::string l_uri = prompt_line("URI: ");
                std::string pw = prompt_line("Password: ");

                auto resp = client.request("LOGIN", {
                    {"uri", l_uri},
                    {"password", pw},
                    {"udp_port", (int)udp_notifs.unicast_port()}
                });
                if (resp.value("ok", false)) {
                    conn = ConnState::AUTHED;
                    user_id = resp["payload"].value("user_id", 0);
                    role = resp["payload"].value("role", "");
                    uri = resp["payload"].value("uri", "");
                    token = resp["payload"].value("token", "");
                    std::cout << "[OK] Logged in as " << uri << " (" << role << "), user_id=" << user_id << std::endl;

                    if (role == "SUBSCRIBER") {
                        ensure_subscriber_mcast_groups();
                        ui = UIState::AUTH_MENU_SUB;
                    } else {
                        ui = UIState::AUTH_MENU_PUB;
                    }
                } else {
                    print_json_result(resp);
                    ui = UIState::MAIN_MENU;
                }
            }
            else if (ui == UIState::AUTH_MENU_SUB)
            {
                std::cout << "\n=== Subscriber Menu (" << uri << ") ===\n"
                          << "1) Browse content\n"
                          << "2) List publishers\n"
                          << "3) Subscribe to a publisher\n"
                          << "4) List my subscriptions\n"
                          << "5) Purchase content\n"
                          << "6) Rate content + optional comment\n"
                          << "7) View approved comments for a content\n"
                          << "9) Logout\n"
                          << "0) Exit\n";
                std::string ch = prompt_line("> ");

                if (ch == "1") {
                    std::string cat = prompt_line("Optional category (empty=all): ");
                    std::string type = prompt_line("Optional type (text/video/audio/interactive, empty=all): ");
                    json payload;
                    if (!cat.empty()) payload["category"] = cat;
                    if (!type.empty()) payload["type"] = type;
                    payload["status"] = "ACTIVE";
                    auto r = client.request("LIST_CONTENT", payload);
                    if (r.value("ok", false)) show_content_items(r["payload"]["items"]);
                    else print_json_result(r);
                }
                else if (ch == "2") {
                    auto r = client.request("LIST_PUBLISHERS", json::object());
                    if (r.value("ok", false)) show_publishers(r["payload"]["publishers"]);
                    else print_json_result(r);
                }
                else if (ch == "3") {
                    // show publishers first
                    auto r = client.request("LIST_PUBLISHERS", json::object());
                    if (r.value("ok", false)) show_publishers(r["payload"]["publishers"]);
                    else { print_json_result(r); continue; }

                    std::string sid = prompt_line("publisher_id to subscribe: ");
                    int publisher_id=0; if (!parse_int(sid, publisher_id) || publisher_id<=0) { std::cout<<"Invalid publisher_id\n"; continue; }
                    std::string sm = prompt_line("months (1..24): ");
                    int months=1; if (!parse_int(sm, months)) { std::cout<<"Invalid months\n"; continue; }

                    auto resp = client.request("SUBSCRIBE_PUBLISHER", {{"publisher_id", publisher_id}, {"months", months}});
                    if (resp.value("ok", false)) {
                        auto pl = resp["payload"];
                        std::cout << "[OK] Subscribed. Charged " << bam_fmt(pl.value("charged_fenings",(int64_t)0)) << std::endl;
                        std::string grp = pl.value("mcast_group","");
                        if (!grp.empty()) udp_notifs.join_publisher_group(grp);
                    } else print_json_result(resp);
                }
                else if (ch == "4") {
                    auto r = client.request("LIST_SUBSCRIPTIONS", json::object());
                    if (!r.value("ok", false)) { print_json_result(r); continue; }
                    auto subs = r["payload"].value("subscriptions", json::array());
                    if (subs.empty()) std::cout << "No subscriptions.\n";
                    for (auto& s : subs) {
                        std::cout << "- sub_id=" << s.value("sub_id",0)
                                  << " pub=" << s.value("publisher_uri","")
                                  << " (" << s.value("publisher_id",0) << ")"
                                  << " monthly=" << bam_fmt(s.value("monthly_fee_fenings",(int64_t)0))
                                  << " end_ts=" << s.value("end_ts",(int64_t)0)
                                  << " mcast=" << s.value("mcast_group","") << ":" << s.value("mcast_port",0)
                                  << std::endl;
                        std::string grp = s.value("mcast_group","");
                        if (!grp.empty() && !udp_notifs.is_joined(grp)) udp_notifs.join_publisher_group(grp);
                    }
                }
                else if (ch == "5") {
                    // show content first
                    auto r = client.request("LIST_CONTENT", {{"status","ACTIVE"}});
                    if (r.value("ok", false)) show_content_items(r["payload"]["items"]);
                    else { print_json_result(r); continue; }

                    std::string cid = prompt_line("content_id to purchase: ");
                    auto resp = client.request("PURCHASE_CONTENT", {{"content_id", cid}});
                    if (resp.value("ok", false)) {
                        auto pl = resp["payload"];
                        std::cout << "[OK] Purchased. Charged " << bam_fmt(pl.value("charged_fenings",(int64_t)0)) << std::endl;
                    } else print_json_result(resp);
                }
                else if (ch == "6") {
                    auto r = client.request("LIST_CONTENT", {{"status","ACTIVE"}});
                    if (r.value("ok", false)) show_content_items(r["payload"]["items"]);
                    else { print_json_result(r); continue; }

                    std::string cid = prompt_line("content_id to rate: ");
                    std::string rs = prompt_line("rating (1..5): ");
                    int rating=0; if (!parse_int(rs, rating)) { std::cout<<"Invalid rating\n"; continue; }
                    std::string cmt = prompt_line("comment (optional, empty=no comment): ");

                    auto resp = client.request("RATE", {{"content_id", cid}, {"rating", rating}, {"comment", cmt}});
                    print_json_result(resp);
                    if (resp.value("ok", false)) {
                        std::cout << "Note: comments are PENDING until publisher moderates them.\n";
                    }
                }
                else if (ch == "7") {
                    std::string cid = prompt_line("content_id: ");
                    auto resp = client.request("LIST_COMMENTS", {{"content_id", cid}});
                    if (!resp.value("ok", false)) { print_json_result(resp); continue; }
                    auto comments = resp["payload"].value("comments", json::array());
                    if (comments.empty()) std::cout << "No approved comments.\n";
                    for (auto& c : comments) {
                        std::cout << "- [" << c.value("rating",0) << "/5] "
                                  << c.value("subscriber_uri","") << ": "
                                  << c.value("comment","") << " (id=" << c.value("feedback_id",0) << ")\n";
                    }
                }
                else if (ch == "9") {
                    auto r = client.request("LOGOUT", json::object());
                    print_json_result(r);
                    conn = ConnState::TLS_OK_UNAUTH;
                    user_id = 0; role.clear(); uri.clear(); token.clear();
                    ui = UIState::MAIN_MENU;
                }
                else if (ch == "0") {
                    ui = UIState::EXIT;
                }
            }
            else if (ui == UIState::AUTH_MENU_PUB)
            {
                std::cout << "\n=== Publisher Menu (" << uri << ") ===\n"
                          << "1) Publish new content (metadata)\n"
                         // << "2) Upload preview bytes (byte-stream demo)\n"
                          << "3) Update content price/status\n"
                          << "4) Set my monthly subscription fee\n"
                          << "5) View my content list (filtered by me)\n"
                          << "6) List pending comments for moderation\n"
                          << "7) Moderate (approve/reject/hide/delete)\n"
                          << "9) Logout\n"
                          << "0) Exit\n";
                std::string ch = prompt_line("> ");

                if (ch == "1") {
                    std::cout << "Allowed types: text, video, audio, interactive\n";
                    std::cout << "Allowed status: ACTIVE, DRAFT, ARCHIVED\n";
                    std::string title = prompt_line("title: ");
                    std::string desc = prompt_line("description: ");
                    std::string type = prompt_line("type: ");
                    std::string cat = prompt_line("category: ");
                    std::string price = prompt_line("price (in fenings, e.g. 250 = 2.50 BAM): ");
                    int64_t pf=0; if (!parse_int64(price, pf) || pf < 0) { std::cout << "Invalid price\n"; continue; }
                    std::string status = prompt_line("status: ");
                    std::string mins = prompt_line("min_age (0 if none): ");
                    int min_age=0; parse_int(mins, min_age);

                    auto resp = client.request("PUBLISH_CONTENT", {
                        {"title", title},
                        {"description", desc},
                        {"type", type},
                        {"category", cat},
                        {"price_fenings", pf},
                        {"status", status},
                        {"min_age", min_age}
                    });
                    print_json_result(resp);
                    if (resp.value("ok", false)) {
                        std::cout << "Async multicast notification NEW_CONTENT was sent by the server.\n";
                    }
                }
                // else if (ch == "2") {
                //     std::string cid = prompt_line("content_id: ");
                //     std::string txt = prompt_line("preview text (<=64KB). It will be uploaded as raw bytes: ");
                //     std::vector<unsigned char> bytes(txt.begin(), txt.end());
                //     auto resp = client.upload_preview_bytes(cid, bytes);
                //     print_json_result(resp);
                // }
                else if (ch == "3") {
                    auto r = client.request("LIST_CONTENT", {{"publisher_id", user_id}});
                    if (r.value("ok", false)) show_content_items(r["payload"]["items"]);
                    else { print_json_result(r); continue; }

                    std::string cid = prompt_line("content_id to update: ");
                    std::string np = prompt_line("new price fenings (empty=keep): ");
                    std::string ns = prompt_line("new status (ACTIVE/DRAFT/ARCHIVED, empty=keep): ");

                    json payload;
                    payload["content_id"] = cid;
                    if (!np.empty()) {
                        int64_t v=0; if (!parse_int64(np, v) || v < 0) { std::cout<<"Invalid price\n"; continue; }
                        payload["price_fenings"] = v;
                    }
                    if (!ns.empty()) payload["status"] = ns;

                    auto resp = client.request("UPDATE_CONTENT", payload);
                    print_json_result(resp);
                }
                else if (ch == "4") {
                    std::string fee = prompt_line("New monthly fee (fenings): ");
                    int64_t v=0; if (!parse_int64(fee, v) || v < 0) { std::cout<<"Invalid fee\n"; continue; }
                    auto resp = client.request("SET_PUBLISHER_MONTHLY_FEE", {{"monthly_fee_fenings", v}});
                    print_json_result(resp);
                }
                else if (ch == "5") {
                    auto r = client.request("LIST_CONTENT", {{"publisher_id", user_id}});
                    if (r.value("ok", false)) show_content_items(r["payload"]["items"]);
                    else print_json_result(r);
                }
                else if (ch == "6") {
                    auto resp = client.request("LIST_PENDING_FEEDBACK", json::object());
                    if (!resp.value("ok", false)) { print_json_result(resp); continue; }
                    auto items = resp["payload"].value("pending", json::array());
                    if (items.empty()) std::cout << "No pending feedback.\n";
                    for (auto& it : items) {
                        std::cout << "- feedback_id=" << it.value("feedback_id",0)
                                  << " content=" << it.value("content_id","")
                                  << " from=" << it.value("subscriber_uri","")
                                  << " rating=" << it.value("rating",0)
                                  << " comment=\"" << it.value("comment","") << "\"\n";
                    }
                }
                else if (ch == "7") {
                    auto resp = client.request("LIST_PENDING_FEEDBACK", json::object());
                    if (!resp.value("ok", false)) { print_json_result(resp); continue; }
                    auto items = resp["payload"].value("pending", json::array());
                    if (items.empty()) { std::cout << "No pending feedback.\n"; continue; }
                    for (auto& it : items) {
                        std::cout << "- feedback_id=" << it.value("feedback_id",0)
                                  << " content=" << it.value("content_id","")
                                  << " from=" << it.value("subscriber_uri","")
                                  << " rating=" << it.value("rating",0)
                                  << " comment=\"" << it.value("comment","") << "\"\n";
                    }

                    std::string fid_s = prompt_line("feedback_id to moderate: ");
                    int fid=0; if (!parse_int(fid_s, fid) || fid<=0) { std::cout<<"Invalid feedback_id\n"; continue; }
                    std::cout << "Actions: APPROVE, REJECT, HIDE, DELETE\n";
                    std::string action = prompt_line("action: ");
                    std::string note = prompt_line("optional note (sent to subscriber on approve/reject): ");

                    auto r2 = client.request("MODERATE", {{"feedback_id", fid}, {"action", action}, {"note", note}});
                    print_json_result(r2);
                    if (r2.value("ok", false)) {
                        std::cout << "Async unicast notification FEEDBACK_STATUS was sent by the server (if subscriber is online).\n";
                    }
                }
                else if (ch == "9") {
                    auto r = client.request("LOGOUT", json::object());
                    print_json_result(r);
                    conn = ConnState::TLS_OK_UNAUTH;
                    user_id = 0; role.clear(); uri.clear(); token.clear();
                    ui = UIState::MAIN_MENU;
                }
                else if (ch == "0") {
                    ui = UIState::EXIT;
                }
            }
        }

        try { client.close(); } catch (...) {}
        udp_notifs.stop();
        std::cout << "Bye.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[client][FATAL] " << e.what() << std::endl;
        return 1;
    }
}