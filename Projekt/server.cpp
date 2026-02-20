#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <sqlite3.h>
#include <vector>
#include "json/json.h"
#include "sqlite3/sqlite3_wrapper.h"

namespace asio = boost::asio;
using asio::ip::tcp;
using asio::ip::udp;
using json = nlohmann::json;
namespace sqlite = sqlite3_wrapper;

static constexpr int kDefaultPort = 1111;
static constexpr uint16_t kMcastPort = 30000;     // shared port for multicast NEW_CONTENT
static constexpr size_t kMaxJsonFrame = 1024 * 1024; // 1MB
static constexpr size_t kMaxPreviewBytes = 64 * 1024; // 64KB (byte-stream demo) //not used

static std::string now_timestamp()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

static int64_t now_unix()
{
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

static std::string hex_encode(const std::vector<unsigned char>& bytes)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char b : bytes)
    {
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

static std::string random_hex(size_t nbytes)
{
    std::vector<unsigned char> buf(nbytes);
    if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return hex_encode(buf);
}

static std::string sha256_hex(const std::string& in)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    if (EVP_DigestUpdate(ctx, in.data(), in.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }
    if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    EVP_MD_CTX_free(ctx);

    std::vector<unsigned char> v(md, md + md_len);
    return hex_encode(v);
}

static bool password_ok(const std::string& pw, std::string& why)
{
    if (pw.size() < 8) { why = "Password too short (min 8)"; return false; }
    bool has_upper=false, has_lower=false, has_digit=false;
    for (unsigned char c : pw)
    {
        if (std::isupper(c)) has_upper = true;
        else if (std::islower(c)) has_lower = true;
        else if (std::isdigit(c)) has_digit = true;
    }
    if (!has_upper || !has_lower || !has_digit) {
        why = "Password must contain uppercase, lowercase, and a digit";
        return false;
    }
    return true;
}

static bool valid_iso_date(const std::string& s)
{
    static const std::regex re(R"(^\d{4}-\d{2}-\d{2}$)");
    if (!std::regex_match(s, re)) return false;
    int y=0,m=0,d=0;
    try {
        y = std::stoi(s.substr(0,4));
        m = std::stoi(s.substr(5,2));
        d = std::stoi(s.substr(8,2));
    } catch (...) { return false; }
    if (y < 1900 || y > 2100) return false;
    if (m < 1 || m > 12) return false;
    if (d < 1 || d > 31) return false;
    return true;
}

static int compute_age_years(const std::string& dob_iso)
{
    int by = std::stoi(dob_iso.substr(0,4));
    int bm = std::stoi(dob_iso.substr(5,2));
    int bd = std::stoi(dob_iso.substr(8,2));

    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    int y = tm.tm_year + 1900;
    int m = tm.tm_mon + 1;
    int d = tm.tm_mday;

    int age = y - by;
    if (m < bm || (m == bm && d < bd)) age--;
    return age;
}

static uint32_t fnv1a_32(const std::string& s)
{
    uint32_t h = 2166136261u;
    for (unsigned char c : s) {
        h ^= c;
        h *= 16777619u;
    }
    return h;
}

static asio::ip::address_v4 multicast_group_for_publisher(int publisher_id)
{
    // 239.255.X.Y
    // Stable mapping so subscribers can "know" which group to join after subscribing.
    uint32_t h = fnv1a_32(std::to_string(publisher_id));
    uint8_t x = static_cast<uint8_t>((h >> 8) & 0xFF);
    uint8_t y = static_cast<uint8_t>(h & 0xFF);
    if (x == 0) x = 1;
    if (y == 0) y = 1;
    return asio::ip::address_v4({239, 255, x, y});
}

// ------------------- Length-prefixed JSON framing (data-stream over TCP) -------------------

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

// ------------------- Database -------------------

struct UserRow {
    int user_id = 0;
    std::string uri;
    std::string first_name;
    std::string last_name;
    std::string dob;
    std::string pass_store; // "salt$hash"
    std::string role;       // PUBLISHER/SUBSCRIBER
    int64_t monthly_fee_fenings = 0; // publisher's monthly fee
};

struct ContentRow {
    std::string content_id;
    int publisher_id = 0;
    std::string title;
    std::string description;
    std::string type;
    std::string category;
    int64_t price_fenings = 0;
    std::string status;
    int min_age = 0;
};

class Database {
public:
    explicit Database(std::string path) : path_(std::move(path)) {}

    void init()
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        db.execute("PRAGMA journal_mode=WAL;");
        db.execute("PRAGMA foreign_keys=ON;");

        db.execute(R"(
            CREATE TABLE IF NOT EXISTS users(
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                uri TEXT NOT NULL UNIQUE,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                dob TEXT NOT NULL,
                pass_store TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('PUBLISHER','SUBSCRIBER')),
                monthly_fee_fenings INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
        )");

        db.execute(R"(
            CREATE TABLE IF NOT EXISTS content(
                content_id TEXT PRIMARY KEY,
                publisher_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('text','video','audio','interactive')),
                category TEXT NOT NULL,
                price_fenings INTEGER NOT NULL,
                currency TEXT NOT NULL DEFAULT 'BAM',
                status TEXT NOT NULL CHECK(status IN ('ACTIVE','DRAFT','ARCHIVED')),
                min_age INTEGER NOT NULL DEFAULT 0,
                preview BLOB,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
        )");

        db.execute(R"(
            CREATE TABLE IF NOT EXISTS purchases(
                purchase_id INTEGER PRIMARY KEY AUTOINCREMENT,
                subscriber_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                content_id TEXT NOT NULL REFERENCES content(content_id) ON DELETE CASCADE,
                price_fenings INTEGER NOT NULL,
                currency TEXT NOT NULL DEFAULT 'BAM',
                created_at INTEGER NOT NULL,
                UNIQUE(subscriber_id, content_id)
            );
        )");

        db.execute(R"(
            CREATE TABLE IF NOT EXISTS subscriptions(
                sub_id INTEGER PRIMARY KEY AUTOINCREMENT,
                subscriber_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                publisher_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                start_ts INTEGER NOT NULL,
                end_ts INTEGER NOT NULL,
                monthly_fee_fenings INTEGER NOT NULL,
                currency TEXT NOT NULL DEFAULT 'BAM',
                created_at INTEGER NOT NULL
            );
        )");

        db.execute(R"(
            CREATE TABLE IF NOT EXISTS feedback(
                feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
                content_id TEXT NOT NULL REFERENCES content(content_id) ON DELETE CASCADE,
                subscriber_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
                comment TEXT,
                comment_status TEXT NOT NULL CHECK(comment_status IN ('PENDING','APPROVED','REJECTED','HIDDEN')),
                created_at INTEGER NOT NULL,
                moderated_at INTEGER,
                moderator_id INTEGER REFERENCES users(user_id),
                moderator_note TEXT
            );
        )");

        db.execute(R"(
            CREATE TABLE IF NOT EXISTS transactions(
                tx_id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL CHECK(kind IN ('PURCHASE','SUBSCRIPTION')),
                subscriber_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                publisher_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
                content_id TEXT REFERENCES content(content_id) ON DELETE CASCADE,
                amount_fenings INTEGER NOT NULL,
                currency TEXT NOT NULL DEFAULT 'BAM',
                created_at INTEGER NOT NULL
            );
        )");
    }

    bool user_exists_uri(const std::string& uri)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        auto st = db.prepare("SELECT user_id FROM users WHERE uri=?");
        st.execute(uri);
        int uid=0;
        if (st.fetch(uid)) return true;
        return false;
    }

    int create_user(const std::string& uri, const std::string& first, const std::string& last,
                    const std::string& dob, const std::string& pass_store, const std::string& role)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        db.begin();
        auto st = db.prepare(R"(
            INSERT INTO users(uri, first_name, last_name, dob, pass_store, role, monthly_fee_fenings, created_at)
            VALUES(?,?,?,?,?,?,?,?)
        )");
        int64_t monthly_fee = 0;
        if (role == "PUBLISHER") monthly_fee = 1000; // 10.00 BAM default monthly fee
        st.execute(uri, first, last, dob, pass_store, role, monthly_fee, now_unix());
        auto idst = db.prepare("SELECT last_insert_rowid()");
        idst.execute();
        int id=0;
        idst.fetch(id);
        db.commit();
        return id;
    }

    std::optional<UserRow> find_user_by_uri(const std::string& uri)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        auto st = db.prepare(R"(
            SELECT user_id, uri, first_name, last_name, dob, pass_store, role, monthly_fee_fenings
            FROM users WHERE uri=?
        )");
        st.execute(uri);
        UserRow u;
        if (st.fetch(u.user_id, u.uri, u.first_name, u.last_name, u.dob, u.pass_store, u.role, u.monthly_fee_fenings))
            return u;
        return std::nullopt;
    }

    std::optional<UserRow> find_user_by_id(int user_id)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        auto st = db.prepare(R"(
            SELECT user_id, uri, first_name, last_name, dob, pass_store, role, monthly_fee_fenings
            FROM users WHERE user_id=?
        )");
        st.execute(user_id);
        UserRow u;
        if (st.fetch(u.user_id, u.uri, u.first_name, u.last_name, u.dob, u.pass_store, u.role, u.monthly_fee_fenings))
            return u;
        return std::nullopt;
    }

    std::vector<UserRow> list_publishers()
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        auto st = db.prepare(R"(
            SELECT user_id, uri, first_name, last_name, dob, pass_store, role, monthly_fee_fenings
            FROM users WHERE role='PUBLISHER' ORDER BY user_id ASC
        )");
        st.execute();
        std::vector<UserRow> out;
        while (true) {
            UserRow u;
            if (!st.fetch(u.user_id, u.uri, u.first_name, u.last_name, u.dob, u.pass_store, u.role, u.monthly_fee_fenings))
                break;
            out.push_back(std::move(u));
        }
        return out;
    }

    bool set_publisher_monthly_fee(int publisher_id, int64_t fee_fenings)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        auto st = db.prepare("UPDATE users SET monthly_fee_fenings=? WHERE user_id=? AND role='PUBLISHER'");
        st.execute(fee_fenings, publisher_id);
        auto u = find_user_by_id(publisher_id);
        return u.has_value() && u->role=="PUBLISHER" && u->monthly_fee_fenings==fee_fenings;
    }

    std::string create_content(int publisher_id, const ContentRow& c)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        db.begin();
        auto st = db.prepare(R"(
            INSERT INTO content(content_id, publisher_id, title, description, type, category, price_fenings, status, min_age, created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
        )");
        st.execute(c.content_id, publisher_id, c.title, c.description, c.type, c.category,
                   c.price_fenings, c.status, c.min_age, now_unix(), now_unix());
        db.commit();
        return c.content_id;
    }

    bool set_content_preview(const std::string& content_id, const std::vector<unsigned char>& bytes)
    {
        if (bytes.size() > kMaxPreviewBytes) return false;
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        sqlite3* raw = db.native_handle();
        const char* sql = "UPDATE content SET preview=?, updated_at=? WHERE content_id=?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v3(raw, sql, -1, SQLITE_PREPARE_PERSISTENT, &stmt, nullptr) != SQLITE_OK)
            throw sqlite::exception(raw);
        auto finalize = [&](){ if (stmt) sqlite3_finalize(stmt); };
        if (sqlite3_bind_blob(stmt, 1, bytes.data(), (int)bytes.size(), SQLITE_TRANSIENT) != SQLITE_OK) { finalize(); throw sqlite::exception(stmt); }
        if (sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now_unix()) != SQLITE_OK) { finalize(); throw sqlite::exception(stmt); }
        if (sqlite3_bind_text(stmt, 3, content_id.c_str(), (int)content_id.size(), SQLITE_TRANSIENT) != SQLITE_OK) { finalize(); throw sqlite::exception(stmt); }
        int rc = sqlite3_step(stmt);
        finalize();
        return rc == SQLITE_DONE;
    }

    std::optional<ContentRow> get_content(const std::string& content_id)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        auto st = db.prepare(R"(
            SELECT content_id, publisher_id, title, description, type, category, price_fenings, status, min_age
            FROM content WHERE content_id=?
        )");
        st.execute(content_id);
        ContentRow c;
        if (st.fetch(c.content_id, c.publisher_id, c.title, c.description, c.type, c.category, c.price_fenings, c.status, c.min_age))
            return c;
        return std::nullopt;
    }

    bool update_content(int publisher_id, const std::string& content_id,
                        const std::optional<int64_t>& new_price,
                        const std::optional<std::string>& new_status)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        auto st0 = db.prepare("SELECT publisher_id FROM content WHERE content_id=?");
        st0.execute(content_id);
        int owner=0;
        if (!st0.fetch(owner) || owner != publisher_id) return false;

        if (!new_price && !new_status) return true;

        std::string sql = "UPDATE content SET updated_at=?";
        if (new_price) sql += ", price_fenings=?";
        if (new_status) sql += ", status=?";
        sql += " WHERE content_id=?";

        sqlite::statement st(db.native_handle(), sql);
        if (new_price && new_status) {
            st.execute(now_unix(), *new_price, *new_status, content_id);
        } else if (new_price) {
            st.execute(now_unix(), *new_price, content_id);
        } else {
            st.execute(now_unix(), *new_status, content_id);
        }
        return true;
    }

    std::vector<json> list_content(const json& filters)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);

        std::string sql = R"(
            SELECT c.content_id, c.title, c.description, c.type, c.category, c.price_fenings, c.status, c.min_age,
                   c.publisher_id, u.uri
            FROM content c JOIN users u ON c.publisher_id=u.user_id
            WHERE 1=1
        )";
        std::vector<std::string> where;
        std::vector<json> binds;

        auto add_bind = [&](const char* key, const std::string& col){
            if (filters.contains(key) && !filters[key].is_null()) {
                where.push_back(col + "=?");
                binds.push_back(filters[key]);
            }
        };
        auto add_bind_i = [&](const char* key, const std::string& col){
            if (filters.contains(key) && !filters[key].is_null()) {
                where.push_back(col + "=?");
                binds.push_back(filters[key]);
            }
        };

        add_bind("category", "c.category");
        add_bind("type", "c.type");
        add_bind("status", "c.status");
        add_bind_i("publisher_id", "c.publisher_id");

        for (auto& w : where) sql += " AND " + w;
        sql += " ORDER BY c.created_at DESC;";

        sqlite3_stmt* stmt=nullptr;
        sqlite3* raw=db.native_handle();
        if (sqlite3_prepare_v3(raw, sql.c_str(), -1, SQLITE_PREPARE_PERSISTENT, &stmt, nullptr) != SQLITE_OK)
            throw sqlite::exception(raw);
        auto finalize=[&](){ if(stmt) sqlite3_finalize(stmt); };

        int idx=1;
        for (auto& b : binds)
        {
            if (b.is_number_integer()) {
                if (sqlite3_bind_int64(stmt, idx, (sqlite3_int64)b.get<int64_t>()) != SQLITE_OK) { finalize(); throw sqlite::exception(stmt); }
            } else {
                std::string s = b.get<std::string>();
                if (sqlite3_bind_text(stmt, idx, s.c_str(), (int)s.size(), SQLITE_TRANSIENT) != SQLITE_OK) { finalize(); throw sqlite::exception(stmt); }
            }
            idx++;
        }

        std::vector<json> out;
        while (true)
        {
            int rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) { finalize(); throw sqlite::exception(stmt); }

            json it;
            it["content_id"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt,0));
            it["title"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt,1));
            it["description"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt,2));
            it["type"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt,3));
            it["category"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt,4));
            it["price_fenings"] = (int64_t)sqlite3_column_int64(stmt,5);
            it["currency"] = "BAM";
            it["status"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt,6));
            it["min_age"] = sqlite3_column_int(stmt,7);
            it["publisher_id"] = sqlite3_column_int(stmt,8);
            it["publisher_uri"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt,9));
            out.push_back(std::move(it));
        }
        finalize();
        return out;
    }

    bool has_access(int subscriber_id, const std::string& content_id)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);

        // Purchase?
        {
            auto st = db.prepare("SELECT purchase_id FROM purchases WHERE subscriber_id=? AND content_id=?");
            st.execute(subscriber_id, content_id);
            int pid=0;
            if (st.fetch(pid)) return true;
        }

        // Subscription?
        auto c = get_content(content_id);
        if (!c) return false;

        auto st = db.prepare(R"(
            SELECT sub_id FROM subscriptions
            WHERE subscriber_id=? AND publisher_id=? AND start_ts<=? AND end_ts>=?
            ORDER BY end_ts DESC LIMIT 1
        )");
        int64_t t = now_unix();
        st.execute(subscriber_id, c->publisher_id, t, t);
        int sid=0;
        if (st.fetch(sid)) return true;
        return false;
    }

    bool purchase(int subscriber_id, const std::string& content_id, int64_t& charged_fenings, std::string& why)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);

        auto c = get_content(content_id);
        if (!c) { why = "Unknown content_id"; return false; }
        if (c->status != "ACTIVE") { why = "Content not ACTIVE"; return false; }

        // already purchased?
        {
            auto st = db.prepare("SELECT purchase_id FROM purchases WHERE subscriber_id=? AND content_id=?");
            st.execute(subscriber_id, content_id);
            int pid=0;
            if (st.fetch(pid)) { why = "Already purchased"; return false; }
        }

        // Age restriction check
        {
            auto st = db.prepare("SELECT dob FROM users WHERE user_id=?");
            st.execute(subscriber_id);
            std::string dob;
            if (!st.fetch(dob)) { why = "Subscriber not found"; return false; }
            int age = compute_age_years(dob);
            if (age < c->min_age) { why = "AGE_RESTRICTED (min_age=" + std::to_string(c->min_age) + ")"; return false; }
        }
        charged_fenings = c->price_fenings;

        db.begin();
        auto st1 = db.prepare(R"(
            INSERT INTO purchases(subscriber_id, content_id, price_fenings, created_at)
            VALUES(?,?,?,?)
        )");
        st1.execute(subscriber_id, content_id, charged_fenings, now_unix());

        auto st2 = db.prepare(R"(
            INSERT INTO transactions(kind, subscriber_id, publisher_id, content_id, amount_fenings, created_at)
            VALUES('PURCHASE',?,?,?,?,?)
        )");
        st2.execute(subscriber_id, c->publisher_id, content_id, charged_fenings, now_unix());
        db.commit();
        return true;
    }

    bool subscribe(int subscriber_id, int publisher_id, int months, int64_t& charged_fenings, std::string& why,
                   int64_t& start_ts, int64_t& end_ts, int64_t& monthly_fee_fenings)
    {
        if (months < 1 || months > 24) { why = "months must be 1..24"; return false; }

        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);

        // publisher exists?
        auto pu = find_user_by_id(publisher_id);
        if (!pu || pu->role != "PUBLISHER") { why = "publisher_id invalid"; return false; }

        monthly_fee_fenings = pu->monthly_fee_fenings;
        charged_fenings = monthly_fee_fenings * (int64_t)months;

        start_ts = now_unix();
        end_ts = start_ts + (int64_t)months * 30LL * 24LL * 3600LL; // month=30d

        db.begin();
        auto st1 = db.prepare(R"(
            INSERT INTO subscriptions(subscriber_id, publisher_id, start_ts, end_ts, monthly_fee_fenings, created_at)
            VALUES(?,?,?,?,?,?)
        )");
        st1.execute(subscriber_id, publisher_id, start_ts, end_ts, monthly_fee_fenings, now_unix());

        auto st2 = db.prepare(R"(
            INSERT INTO transactions(kind, subscriber_id, publisher_id, content_id, amount_fenings, created_at)
            VALUES('SUBSCRIPTION',?,?,?,?,?)
        )");
        st2.execute(subscriber_id, publisher_id, nullptr, charged_fenings, now_unix());
        db.commit();
        return true;
    }

    std::vector<json> list_subscriptions(int subscriber_id)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);

        auto st = db.prepare(R"(
            SELECT s.sub_id, s.publisher_id, u.uri, s.start_ts, s.end_ts, s.monthly_fee_fenings
            FROM subscriptions s JOIN users u ON s.publisher_id=u.user_id
            WHERE s.subscriber_id=?
            ORDER BY s.end_ts DESC
        )");
        st.execute(subscriber_id);

        std::vector<json> out;
        while (true) {
            int sub_id=0, pub_id=0;
            std::string pub_uri;
            int64_t st_ts=0, en_ts=0, fee=0;
            if (!st.fetch(sub_id, pub_id, pub_uri, st_ts, en_ts, fee)) break;
            json j;
            j["sub_id"] = sub_id;
            j["publisher_id"] = pub_id;
            j["publisher_uri"] = pub_uri;
            j["start_ts"] = st_ts;
            j["end_ts"] = en_ts;
            j["monthly_fee_fenings"] = fee;
            j["currency"] = "BAM";
            auto grp = multicast_group_for_publisher(pub_id).to_string();
            j["mcast_group"] = grp;
            j["mcast_port"] = kMcastPort;
            out.push_back(std::move(j));
        }
        return out;
    }

    bool rate(int subscriber_id, const std::string& content_id, int rating, const std::string& comment,
              int& feedback_id, std::string& comment_status, std::string& why)
    {
        if (rating < 1 || rating > 5) { why = "rating must be 1..5"; return false; }

        // access check (also verifies existence)
        if (!has_access(subscriber_id, content_id)) { why = "No access (purchase or active subscription required)"; return false; }

        // Age restriction check
        {
            auto c = get_content(content_id);
            auto u = find_user_by_id(subscriber_id);
            if (!c || !u) { why = "Unknown content or subscriber"; return false; }
            int age = compute_age_years(u->dob);
            if (age < c->min_age) { why = "AGE_RESTRICTED (min_age=" + std::to_string(c->min_age) + ")"; return false; }
        }

        comment_status = "APPROVED";
        if (!comment.empty()) comment_status = "PENDING";

        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        db.begin();

        auto st = db.prepare(R"(
            INSERT INTO feedback(content_id, subscriber_id, rating, comment, comment_status, created_at)
            VALUES(?,?,?,?,?,?)
        )");
        if (comment.empty()) {
            st.execute(content_id, subscriber_id, rating, nullptr, comment_status, now_unix());
        } else {
            st.execute(content_id, subscriber_id, rating, comment, comment_status, now_unix());
        }

        auto idst = db.prepare("SELECT last_insert_rowid()");
        idst.execute();
        idst.fetch(feedback_id);

        db.commit();
        return true;
    }

    
    void rating_meta(const std::string& content_id, double& avg_out, int& cnt_out)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        auto st = db.prepare("SELECT AVG(rating), COUNT(*) FROM feedback WHERE content_id=?");
        st.execute(content_id);
        double avg = 0.0;
        int cnt = 0;
        st.fetch(avg, cnt);
        avg_out = avg;
        cnt_out = cnt;
    }

    std::vector<json> list_comments(const std::string& content_id)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);

        // avg rating
        double avg = 0.0;
        int cnt = 0;
        {
            auto st = db.prepare("SELECT AVG(rating), COUNT(*) FROM feedback WHERE content_id=?");
            st.execute(content_id);
            st.fetch(avg, cnt);
        }

        auto st = db.prepare(R"(
            SELECT f.feedback_id, u.uri, f.rating, f.comment, f.comment_status, f.created_at
            FROM feedback f JOIN users u ON f.subscriber_id=u.user_id
            WHERE f.content_id=? AND f.comment_status='APPROVED'
            ORDER BY f.created_at DESC
        )");
        st.execute(content_id);

        std::vector<json> out;
        while (true) {
            int fid=0;
            std::string uri;
            int rating=0;
            std::string comment;
            std::string status;
            int64_t created=0;
            if (!st.fetch(fid, uri, rating, comment, status, created)) break;
            json j;
            j["feedback_id"] = fid;
            j["subscriber_uri"] = uri;
            j["rating"] = rating;
            j["comment"] = comment;
            j["created_at"] = created;
            out.push_back(std::move(j));
        }

        json meta;
        meta["avg_rating"] = avg;
        meta["count"] = cnt;

        (void)meta;

        return out;
    }

    std::vector<json> list_pending_feedback(int publisher_id, const std::optional<std::string>& content_id_filter)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);

        std::string sql = R"(
            SELECT f.feedback_id, f.content_id, u.uri, f.rating, f.comment, f.created_at
            FROM feedback f
            JOIN content c ON f.content_id=c.content_id
            JOIN users u ON f.subscriber_id=u.user_id
            WHERE c.publisher_id=? AND f.comment_status='PENDING'
        )";
        if (content_id_filter) sql += " AND f.content_id=?";
        sql += " ORDER BY f.created_at ASC;";

        sqlite3_stmt* stmt=nullptr;
        sqlite3* raw=db.native_handle();
        if (sqlite3_prepare_v3(raw, sql.c_str(), -1, SQLITE_PREPARE_PERSISTENT, &stmt, nullptr) != SQLITE_OK)
            throw sqlite::exception(raw);
        auto finalize=[&](){ if(stmt) sqlite3_finalize(stmt); };

        int idx=1;
        sqlite3_bind_int(stmt, idx++, publisher_id);
        if (content_id_filter) {
            sqlite3_bind_text(stmt, idx++, content_id_filter->c_str(), (int)content_id_filter->size(), SQLITE_TRANSIENT);
        }

        std::vector<json> out;
        while (true) {
            int rc=sqlite3_step(stmt);
            if (rc==SQLITE_DONE) break;
            if (rc!=SQLITE_ROW) { finalize(); throw sqlite::exception(stmt); }
            json j;
            j["feedback_id"] = sqlite3_column_int(stmt,0);
            j["content_id"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt,1));
            j["subscriber_uri"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt,2));
            j["rating"] = sqlite3_column_int(stmt,3);
            const unsigned char* cmt = sqlite3_column_text(stmt,4);
            j["comment"] = cmt ? reinterpret_cast<const char*>(cmt) : "";
            j["created_at"] = (int64_t)sqlite3_column_int64(stmt,5);
            out.push_back(std::move(j));
        }
        finalize();
        return out;
    }

    struct FeedbackOwner {
        int publisher_id = 0;
        int subscriber_id = 0;
        std::string content_id;
        std::string comment_status;
    };

    std::optional<FeedbackOwner> get_feedback_owner(int feedback_id)
    {
        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        auto st = db.prepare(R"(
            SELECT c.publisher_id, f.subscriber_id, f.content_id, f.comment_status
            FROM feedback f JOIN content c ON f.content_id=c.content_id
            WHERE f.feedback_id=?
        )");
        st.execute(feedback_id);
        FeedbackOwner fo;
        if (st.fetch(fo.publisher_id, fo.subscriber_id, fo.content_id, fo.comment_status))
            return fo;
        return std::nullopt;
    }

    bool moderate(int publisher_id, int feedback_id, const std::string& action, const std::string& note,
                  int& subscriber_id_out, std::string& content_id_out, std::string& new_status_out, std::string& why)
    {
        auto fo = get_feedback_owner(feedback_id);
        if (!fo) { why = "feedback_id not found"; return false; }
        if (fo->publisher_id != publisher_id) { why = "Not owner of content"; return false; }

        std::string new_status;
        bool delete_row = false;

        if (action == "APPROVE") new_status = "APPROVED";
        else if (action == "REJECT") new_status = "REJECTED";
        else if (action == "HIDE") new_status = "HIDDEN";
        else if (action == "DELETE") delete_row = true;
        else { why = "Invalid action"; return false; }

        std::lock_guard<std::recursive_mutex> lk(mu_);
        sqlite::db db(path_);
        db.begin();
        if (delete_row) {
            auto st = db.prepare("DELETE FROM feedback WHERE feedback_id=?");
            st.execute(feedback_id);
            new_status = "DELETED";
        } else {
            auto st = db.prepare(R"(
                UPDATE feedback SET comment_status=?, moderated_at=?, moderator_id=?, moderator_note=?
                WHERE feedback_id=?
            )");
            if (note.empty()) st.execute(new_status, now_unix(), publisher_id, nullptr, feedback_id);
            else st.execute(new_status, now_unix(), publisher_id, note, feedback_id);
        }
        db.commit();

        subscriber_id_out = fo->subscriber_id;
        content_id_out = fo->content_id;
        new_status_out = new_status;
        return true;
    }

private:
    std::string path_;
    std::recursive_mutex mu_;
};

// ------------------- Server core -------------------

struct UdpPresence {
    asio::ip::address ip;
    uint16_t port = 0;
    int64_t last_seen = 0;
};

class Server;

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(asio::ssl::stream<tcp::socket> stream, std::shared_ptr<Server> server)
        : stream_(std::move(stream)),
          server_(std::move(server)),
          strand_(asio::make_strand(stream_.get_executor()))
    {}

    void start();

private:
    enum class ConnState { NEW, TLS_OK_UNAUTH, AUTHED, CLOSED };
    enum class OpState {
        WAIT_CMD,
        HANDLE_REGISTER,
        HANDLE_LOGIN,
        HANDLE_LIST_CONTENT,
        HANDLE_LIST_PUBLISHERS,
        HANDLE_PUBLISH,
        HANDLE_UPLOAD_PREVIEW,
        HANDLE_UPDATE_CONTENT,
        HANDLE_PURCHASE,
        HANDLE_SUBSCRIBE,
        HANDLE_LIST_SUBS,
        HANDLE_RATE,
        HANDLE_LIST_COMMENTS,
        HANDLE_LIST_PENDING,
        HANDLE_MODERATE,
        HANDLE_SET_MONTHLY_FEE,
        HANDLE_PING,
        HANDLE_LOGOUT
    };

    std::string peer_tag() const
    {
        boost::system::error_code ec;
        auto ep = stream_.lowest_layer().remote_endpoint(ec);
        if (ec) return "[unknown]";
        std::ostringstream oss;
        oss << ep.address().to_string() << ":" << ep.port();
        if (!auth_uri_.empty()) oss << " uri=" << auth_uri_;
        return oss.str();
    }

    void log(const std::string& what) const
    {
        std::cout << "[server][" << now_timestamp() << "][" << peer_tag() << "] " << what << std::endl;
    }

    void fail(const std::string& what, const boost::system::error_code& ec)
    {
        std::cerr << "[server][" << now_timestamp() << "][" << peer_tag() << "][ERR] "
                  << what << ": " << ec.message() << std::endl;
        close();
    }

    void close()
    {
        if (conn_state_ == ConnState::CLOSED) return;
        conn_state_ = ConnState::CLOSED;
        boost::system::error_code ec;
        stream_.lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
        stream_.lowest_layer().close(ec);
    }

    void do_handshake();
    void read_frame_len();
    void read_frame_body(uint32_t len);
    void dispatch_json(const json& j);

    // byte-stream demo: read preview bytes after header
    void read_preview_bytes(const json& header, size_t nbytes);

    void send_json(const json& j);

private:
    asio::ssl::stream<tcp::socket> stream_;
    std::shared_ptr<Server> server_;
    asio::strand<asio::any_io_executor> strand_;

    ConnState conn_state_ = ConnState::NEW;
    OpState op_state_ = OpState::WAIT_CMD;

    std::array<unsigned char,4> len_buf_{};
    std::vector<unsigned char> body_buf_;

    // auth
    int auth_user_id_ = 0;
    std::string auth_uri_;
    std::string auth_role_;
    std::string session_token_;
};

class Server : public std::enable_shared_from_this<Server> {
public:
    Server(asio::io_context& io, const asio::ip::address& bind_addr, int port, std::string db_path)
        : io_(io),
          acceptor_(io, tcp::endpoint(bind_addr, (uint16_t)port)),
          tls_ctx_(asio::ssl::context::tls_server),
          udp_sock_(io, udp::endpoint(udp::v4(), 0)),
          db_(std::move(db_path))
    {
        configure_tls();
        db_.init();
    }

    void start()
    {
        std::cout << "[server][" << now_timestamp() << "] Listening on "
                  << acceptor_.local_endpoint().address().to_string()
                  << ":" << acceptor_.local_endpoint().port()
                  << " (TLS1.3 + PQC configured)" << std::endl;
        do_accept();
    }

    asio::ssl::context& tls_ctx() { return tls_ctx_; }
    Database& db() { return db_; }

    void set_presence(int user_id, const asio::ip::address& ip, uint16_t udp_port)
    {
        std::lock_guard<std::recursive_mutex> lk(pres_mu_);
        pres_[user_id] = UdpPresence{ip, udp_port, now_unix()};
    }

    std::optional<UdpPresence> get_presence(int user_id)
    {
        std::lock_guard<std::recursive_mutex> lk(pres_mu_);
        auto it = pres_.find(user_id);
        if (it == pres_.end()) return std::nullopt;
        return it->second;
    }

    void send_unicast_notification(int user_id, const json& notif)
    {
        auto p = get_presence(user_id);
        if (!p || p->port == 0) return;

        std::string s = notif.dump();
        udp::endpoint ep(p->ip, p->port);
        boost::system::error_code ec;
        udp_sock_.send_to(asio::buffer(s), ep, 0, ec);
        if (ec) {
            std::cerr << "[server][" << now_timestamp() << "][udp-unicast][ERR] "
                      << ec.message() << std::endl;
        }
    }

    void send_multicast_new_content(int publisher_id, const json& notif)
    {
        auto group = multicast_group_for_publisher(publisher_id);
        udp::endpoint ep(group, kMcastPort);

        // local loopback
        boost::system::error_code ec;
        udp_sock_.set_option(asio::ip::multicast::enable_loopback(true), ec);

        std::string s = notif.dump();
        udp_sock_.send_to(asio::buffer(s), ep, 0, ec);
        if (ec) {
            std::cerr << "[server][" << now_timestamp() << "][udp-mcast][ERR] "
                      << ec.message() << std::endl;
        }
    }

private:
    void configure_tls()
    {
        SSL_CTX* native = tls_ctx_.native_handle();

        BIO* bio_key = BIO_new_file("server-key.pem", "r");
        if (!bio_key) throw std::runtime_error("Cannot open server-key.pem");
        EVP_PKEY* key = PEM_read_bio_PrivateKey(bio_key, nullptr, nullptr, nullptr);
        BIO_free(bio_key);
        if (!key) throw std::runtime_error("PEM_read_bio_PrivateKey failed");

        BIO* bio_cert = BIO_new_file("server-cert.pem", "r");
        if (!bio_cert) { EVP_PKEY_free(key); throw std::runtime_error("Cannot open server-cert.pem"); }
        X509* cert = PEM_read_bio_X509(bio_cert, nullptr, nullptr, nullptr);
        BIO_free(bio_cert);
        if (!cert) { EVP_PKEY_free(key); throw std::runtime_error("PEM_read_bio_X509 failed"); }

        if (SSL_CTX_use_certificate(native, cert) != 1) {
            X509_free(cert); EVP_PKEY_free(key);
            throw std::runtime_error("SSL_CTX_use_certificate failed");
        }
        if (SSL_CTX_use_PrivateKey(native, key) != 1) {
            X509_free(cert); EVP_PKEY_free(key);
            throw std::runtime_error("SSL_CTX_use_PrivateKey failed");
        }

        // PQC / hybrid
        if (SSL_CTX_set1_groups_list(native, "X25519MLKEM768") != 1) {
            std::cerr << "[server][" << now_timestamp() << "][WARN] SSL_CTX_set1_groups_list failed (PQC provider missing?)" << std::endl;
        }
        if (SSL_CTX_set1_sigalgs_list(native, "ML-DSA-44") != 1) {
            std::cerr << "[server][" << now_timestamp() << "][WARN] SSL_CTX_set1_sigalgs_list failed (PQC provider missing?)" << std::endl;
        }

        SSL_CTX_set_min_proto_version(native, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(native, TLS1_3_VERSION);

        X509_free(cert);
        EVP_PKEY_free(key);

        tls_ctx_.set_options(
            asio::ssl::context::default_workarounds |
            asio::ssl::context::no_sslv2 |
            asio::ssl::context::no_sslv3 |
            asio::ssl::context::single_dh_use
        );
    }

    void do_accept()
    {
        auto self = shared_from_this();
        acceptor_.async_accept(
            [this, self](boost::system::error_code ec, tcp::socket sock)
            {
                if (!ec)
                {
                    auto remote = sock.remote_endpoint();
                    std::cout << "[server][" << now_timestamp() << "] New TCP connection from "
                              << remote.address().to_string() << ":" << remote.port() << std::endl;

                    auto sess = std::make_shared<Session>(asio::ssl::stream<tcp::socket>(std::move(sock), tls_ctx_), self);
                    sess->start();
                }
                do_accept();
            });
    }

private:
    asio::io_context& io_;
    tcp::acceptor acceptor_;
    asio::ssl::context tls_ctx_;
    udp::socket udp_sock_;

    Database db_;

    std::recursive_mutex pres_mu_;
    std::unordered_map<int, UdpPresence> pres_;
};

// ------------------- Session implementation -------------------

void Session::start()
{
    do_handshake();
}

void Session::do_handshake()
{
    auto self = shared_from_this();
    log("TLS handshake start");
    stream_.async_handshake(asio::ssl::stream_base::server,
        asio::bind_executor(strand_, [this, self](const boost::system::error_code& ec)
        {
            if (ec) { fail("TLS handshake failed", ec); return; }
            conn_state_ = ConnState::TLS_OK_UNAUTH;
            log("TLS handshake OK -> state=TLS_OK_UNAUTH");
            read_frame_len();
        }));
}

void Session::read_frame_len()
{
    auto self = shared_from_this();
    asio::async_read(stream_, asio::buffer(len_buf_),
        asio::bind_executor(strand_, [this, self](const boost::system::error_code& ec, std::size_t)
        {
            if (ec) { fail("read length", ec); return; }
            uint32_t len = read_u32_be(len_buf_);
            if (len == 0 || len > kMaxJsonFrame) {
                boost::system::error_code e2 = asio::error::invalid_argument;
                fail("invalid frame length", e2);
                return;
            }
            read_frame_body(len);
        }));
}

void Session::read_frame_body(uint32_t len)
{
    body_buf_.assign(len, 0);
    auto self = shared_from_this();
    asio::async_read(stream_, asio::buffer(body_buf_),
        asio::bind_executor(strand_, [this, self](const boost::system::error_code& ec, std::size_t)
        {
            if (ec) { fail("read body", ec); return; }
            try {
                std::string s(reinterpret_cast<const char*>(body_buf_.data()), body_buf_.size());
                auto j = json::parse(s);
                dispatch_json(j);
            } catch (const std::exception& e) {
                boost::system::error_code e2 = asio::error::invalid_argument;
                fail(std::string("JSON parse error: ") + e.what(), e2);
                return;
            }
        }));
}

void Session::read_preview_bytes(const json& header, size_t nbytes)
{
    if (nbytes == 0 || nbytes > kMaxPreviewBytes) {
        json r;
        r["cmd"] = "UPLOAD_PREVIEW_RESULT";
        r["ok"] = false;
        r["err"] = {{"code","INVALID_SIZE"}, {"message","preview size must be 1..65536"}};
        send_json(r);
        return;
    }

    auto self = shared_from_this();
    auto bytes = std::make_shared<std::vector<unsigned char>>(nbytes);

    asio::async_read(stream_, asio::buffer(*bytes),
        asio::bind_executor(strand_, [this, self, header, bytes](const boost::system::error_code& ec, std::size_t)
        {
            if (ec) { fail("read preview bytes", ec); return; }

            // handle upload
            json r;
            r["cmd"] = "UPLOAD_PREVIEW_RESULT";
            try {
                if (conn_state_ != ConnState::AUTHED || auth_role_ != "PUBLISHER") {
                    r["ok"] = false;
                    r["err"] = {{"code","FORBIDDEN"}, {"message","Publisher only"}};
                } else {
                    std::string content_id = header.value("content_id", "");
                    if (content_id.empty()) {
                        r["ok"] = false;
                        r["err"] = {{"code","BAD_REQUEST"}, {"message","content_id required"}};
                    } else {
                        // verify ownership
                        auto c = server_->db().get_content(content_id);
                        if (!c || c->publisher_id != auth_user_id_) {
                            r["ok"] = false;
                            r["err"] = {{"code","FORBIDDEN"}, {"message","Not owner or unknown content"}};
                        } else {
                            bool ok = server_->db().set_content_preview(content_id, *bytes);
                            r["ok"] = ok;
                            if (ok) r["payload"] = {{"content_id", content_id}, {"bytes", (int64_t)bytes->size()}};
                            else r["err"] = {{"code","FAIL"}, {"message","DB update failed"}};
                        }
                    }
                }
            } catch (const std::exception& e) {
                r["ok"] = false;
                r["err"] = {{"code","EXCEPTION"}, {"message", e.what()}};
            }
            send_json(r);
        }));
}

static bool is_allowed_enum(const std::string& v, const std::set<std::string>& allowed)
{
    return allowed.find(v) != allowed.end();
}

void Session::dispatch_json(const json& j)
{
    // FSM: WAIT_CMD -> HANDLE_<CMD> -> WAIT_CMD
    std::string cmd = j.value("cmd", "");
    json payload = j.value("payload", json::object());

    auto result_cmd_for = [](const std::string& c) -> std::string {
        if (c == "PING") return "PONG";
        if (c == "REGISTER_USER") return "REGISTER_RESULT";
        if (c == "LOGIN") return "LOGIN_RESULT";
        if (c == "LOGOUT") return "LOGOUT_RESULT";
        if (c == "LIST_PUBLISHERS") return "PUBLISHER_LIST";
        if (c == "SET_PUBLISHER_MONTHLY_FEE") return "SET_MONTHLY_FEE_RESULT";
        if (c == "LIST_CONTENT") return "CONTENT_LIST";
        if (c == "PUBLISH_CONTENT") return "PUBLISH_RESULT";
        if (c == "UPLOAD_PREVIEW_BYTES") return "UPLOAD_PREVIEW_RESULT";
        if (c == "UPDATE_CONTENT") return "UPDATE_RESULT";
        if (c == "PURCHASE_CONTENT") return "PURCHASE_RESULT";
        if (c == "SUBSCRIBE_PUBLISHER") return "SUBSCRIPTION_RESULT";
        if (c == "LIST_SUBSCRIPTIONS") return "SUBSCRIPTIONS_LIST";
        if (c == "RATE") return "RATE_RESULT";
        if (c == "LIST_COMMENTS") return "COMMENTS_LIST";
        if (c == "LIST_PENDING_FEEDBACK") return "PENDING_LIST";
        if (c == "MODERATE") return "MODERATE_RESULT";
        return "ERROR";
    };

    log(std::string("RX cmd=") + cmd + " state=" +
        (conn_state_==ConnState::TLS_OK_UNAUTH ? "TLS_OK_UNAUTH" : conn_state_==ConnState::AUTHED ? "AUTHED" : "NEW"));

    if (cmd == "UPLOAD_PREVIEW_BYTES") {
        op_state_ = OpState::HANDLE_UPLOAD_PREVIEW;
        size_t nbytes = (size_t)payload.value("size", 0);
        // We already consumed JSON header frame; now read raw bytes.
        read_preview_bytes(payload, nbytes);
        return; // continue after response
    }

    json resp;
    resp["cmd"] = result_cmd_for(cmd);
    resp["ok"] = false;

    try {
        if (cmd == "PING") {
            op_state_ = OpState::HANDLE_PING;
            resp["ok"] = true;
            resp["payload"] = {{"pong", true}, {"ts", now_unix()}};
        }
        else if (cmd == "REGISTER_USER") {
            op_state_ = OpState::HANDLE_REGISTER;
            std::string uri = payload.value("uri", "");
            std::string first = payload.value("first_name", "");
            std::string last = payload.value("last_name", "");
            std::string dob = payload.value("dob", "");
            std::string pw = payload.value("password", "");
            std::string role = payload.value("role", "");

            if (uri.empty() || first.empty() || last.empty() || dob.empty() || pw.empty() || role.empty()) {
                resp["err"] = {{"code","BAD_REQUEST"}, {"message","Missing required fields"}};
            } else if (!valid_iso_date(dob)) {
                resp["err"] = {{"code","BAD_REQUEST"}, {"message","dob must be YYYY-MM-DD"}};
            } else if (!(role=="PUBLISHER" || role=="SUBSCRIBER")) {
                resp["err"] = {{"code","BAD_REQUEST"}, {"message","role must be PUBLISHER or SUBSCRIBER"}};
            } else {
                std::string why;
                if (!password_ok(pw, why)) {
                    resp["err"] = {{"code","BAD_PASSWORD"}, {"message", why}};
                } else if (server_->db().user_exists_uri(uri)) {
                    resp["err"] = {{"code","URI_EXISTS"}, {"message","Account with that URI already exists"}};
                } else {
                    std::string salt = random_hex(16);
                    std::string hash = sha256_hex(salt + ":" + pw);
                    std::string pass_store = salt + "$" + hash;
                    int id = server_->db().create_user(uri, first, last, dob, pass_store, role);
                    resp["ok"] = true;
                    resp["payload"] = {{"user_id", id}};
                }
            }
        }
        else if (cmd == "LOGIN") {
            op_state_ = OpState::HANDLE_LOGIN;
            std::string uri = payload.value("uri", "");
            std::string pw = payload.value("password", "");
            int udp_port = payload.value("udp_port", 0);

            if (uri.empty() || pw.empty()) {
                resp["err"] = {{"code","BAD_REQUEST"}, {"message","uri and password required"}};
            } else {
                auto u = server_->db().find_user_by_uri(uri);
                if (!u) {
                    resp["err"] = {{"code","NO_SUCH_USER"}, {"message","Unknown URI"}};
                } else {
                    // verify pass
                    auto pos = u->pass_store.find('$');
                    if (pos == std::string::npos) {
                        resp["err"] = {{"code","SERVER_ERROR"}, {"message","Bad pass_store"}};
                    } else {
                        std::string salt = u->pass_store.substr(0, pos);
                        std::string hash = u->pass_store.substr(pos+1);
                        std::string got = sha256_hex(salt + ":" + pw);
                        if (got != hash) {
                            resp["err"] = {{"code","AUTH_FAIL"}, {"message","Invalid credentials"}};
                        } else {
                            conn_state_ = ConnState::AUTHED;
                            auth_user_id_ = u->user_id;
                            auth_uri_ = u->uri;
                            auth_role_ = u->role;
                            session_token_ = random_hex(16);

                            // Presence for UDP unicast notifications
                            boost::system::error_code ec;
                            auto ip = stream_.lowest_layer().remote_endpoint(ec).address();
                            if (!ec && udp_port > 0 && udp_port < 65536) {
                                server_->set_presence(auth_user_id_, ip, (uint16_t)udp_port);
                            }

                            resp["ok"] = true;
                            resp["payload"] = {
                                {"token", session_token_},
                                {"user_id", auth_user_id_},
                                {"uri", auth_uri_},
                                {"role", auth_role_},
                                {"udp_seen", (udp_port>0)}
                            };
                        }
                    }
                }
            }
        }
        else if (cmd == "LOGOUT") {
            op_state_ = OpState::HANDLE_LOGOUT;
            conn_state_ = ConnState::TLS_OK_UNAUTH;
            auth_user_id_ = 0;
            auth_uri_.clear();
            auth_role_.clear();
            session_token_.clear();
            resp["ok"] = true;
        }
        else if (cmd == "LIST_PUBLISHERS") {
            op_state_ = OpState::HANDLE_LIST_PUBLISHERS;
            auto pubs = server_->db().list_publishers();
            json arr = json::array();
            for (auto& p : pubs) {
                arr.push_back({
                    {"publisher_id", p.user_id},
                    {"publisher_uri", p.uri},
                    {"monthly_fee_fenings", p.monthly_fee_fenings},
                    {"currency", "BAM"},
                    {"mcast_group", multicast_group_for_publisher(p.user_id).to_string()},
                    {"mcast_port", kMcastPort}
                });
            }
            resp["ok"] = true;
            resp["payload"] = {{"publishers", arr}};
        }
        else if (cmd == "SET_PUBLISHER_MONTHLY_FEE") {
            op_state_ = OpState::HANDLE_SET_MONTHLY_FEE;
            if (conn_state_ != ConnState::AUTHED || auth_role_ != "PUBLISHER") {
                resp["err"] = {{"code","FORBIDDEN"}, {"message","Publisher only"}};
            } else {
                int64_t fee = payload.value("monthly_fee_fenings", (int64_t)-1);
                if (fee < 0) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","monthly_fee_fenings must be >=0"}};
                } else {
                    bool ok = server_->db().set_publisher_monthly_fee(auth_user_id_, fee);
                    resp["ok"] = ok;
                    if (ok) resp["payload"] = {{"monthly_fee_fenings", fee}, {"currency","BAM"}};
                    else resp["err"] = {{"code","FAIL"}, {"message","Could not update fee"}};
                }
            }
        }
        else if (cmd == "LIST_CONTENT") {
            op_state_ = OpState::HANDLE_LIST_CONTENT;
            // validate enums
            static const std::set<std::string> allowed_type = {"text","video","audio","interactive"};
            static const std::set<std::string> allowed_status = {"ACTIVE","DRAFT","ARCHIVED"};

            json filters = json::object();
            if (payload.contains("category") && payload["category"].is_string()) {
                std::string cat = payload["category"].get<std::string>();
                if (!cat.empty()) filters["category"] = cat;
            }
            if (payload.contains("type") && payload["type"].is_string()) {
                std::string t = payload["type"].get<std::string>();
                if (!t.empty() && !is_allowed_enum(t, allowed_type)) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","Invalid type"}};
                    send_json(resp); op_state_=OpState::WAIT_CMD; read_frame_len(); return;
                }
                if (!t.empty()) filters["type"] = t;
            }
            if (payload.contains("status") && payload["status"].is_string()) {
                std::string st = payload["status"].get<std::string>();
                if (!st.empty() && !is_allowed_enum(st, allowed_status)) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","Invalid status"}};
                    send_json(resp); op_state_=OpState::WAIT_CMD; read_frame_len(); return;
                }
                if (!st.empty()) filters["status"] = st;
            }
            if (payload.contains("publisher_id") && payload["publisher_id"].is_number_integer()) {
                filters["publisher_id"] = payload["publisher_id"].get<int>();
            }

            if (!filters.contains("status")) {
                // Default browsing shows only ACTIVE
                if (conn_state_ != ConnState::AUTHED || auth_role_ != "PUBLISHER") {
                    filters["status"] = "ACTIVE";
                }
            }
            auto items = server_->db().list_content(filters);
            resp["ok"] = true;
            resp["payload"] = {{"items", items}};
        }
        else if (cmd == "PUBLISH_CONTENT") {
            op_state_ = OpState::HANDLE_PUBLISH;
            if (conn_state_ != ConnState::AUTHED || auth_role_ != "PUBLISHER") {
                resp["err"] = {{"code","FORBIDDEN"}, {"message","Publisher only"}};
            } else {
                ContentRow c;
                c.content_id = "cnt_" + random_hex(12);
                c.title = payload.value("title", "");
                c.description = payload.value("description", "");
                c.type = payload.value("type", "");
                c.category = payload.value("category", "");
                c.price_fenings = payload.value("price_fenings", (int64_t)-1);
                c.status = payload.value("status", "");
                c.min_age = payload.value("min_age", 0);

                static const std::set<std::string> allowed_type = {"text","video","audio","interactive"};
                static const std::set<std::string> allowed_status = {"ACTIVE","DRAFT","ARCHIVED"};

                if (c.title.empty() || c.description.empty() || c.type.empty() || c.category.empty() || c.status.empty()) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","Missing fields"}};
                } else if (c.price_fenings < 0) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","price_fenings must be >=0"}};
                } else if (!is_allowed_enum(c.type, allowed_type)) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","Invalid type"}};
                } else if (!is_allowed_enum(c.status, allowed_status)) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","Invalid status"}};
                } else if (c.min_age < 0 || c.min_age > 120) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","min_age invalid"}};
                } else {
                    server_->db().create_content(auth_user_id_, c);
                    resp["ok"] = true;
                    resp["payload"] = {{"content_id", c.content_id}};

                    // async multicast notification 
                    json n;
                    n["type"] = "NEW_CONTENT";
                    n["publisher_id"] = auth_user_id_;
                    n["publisher_uri"] = auth_uri_;
                    n["content_id"] = c.content_id;
                    n["title"] = c.title;
                    n["category"] = c.category;
                    n["price_fenings"] = c.price_fenings;
                    n["currency"] = "BAM";
                    n["mcast_group"] = multicast_group_for_publisher(auth_user_id_).to_string();
                    n["mcast_port"] = kMcastPort;
                    n["ts"] = now_unix();
                    server_->send_multicast_new_content(auth_user_id_, n);
                }
            }
        }
        else if (cmd == "UPDATE_CONTENT") {
            op_state_ = OpState::HANDLE_UPDATE_CONTENT;
            if (conn_state_ != ConnState::AUTHED || auth_role_ != "PUBLISHER") {
                resp["err"] = {{"code","FORBIDDEN"}, {"message","Publisher only"}};
            } else {
                std::string content_id = payload.value("content_id", "");
                if (content_id.empty()) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","content_id required"}};
                } else {
                    std::optional<int64_t> new_price;
                    std::optional<std::string> new_status;

                    if (payload.contains("price_fenings") && payload["price_fenings"].is_number_integer()) {
                        int64_t p = payload["price_fenings"].get<int64_t>();
                        if (p < 0) { resp["err"] = {{"code","BAD_REQUEST"}, {"message","price_fenings must be >=0"}}; send_json(resp); op_state_=OpState::WAIT_CMD; read_frame_len(); return; }
                        new_price = p;
                    }
                    if (payload.contains("status") && payload["status"].is_string()) {
                        std::string st = payload["status"].get<std::string>();
                        static const std::set<std::string> allowed_status = {"ACTIVE","DRAFT","ARCHIVED"};
                        if (!is_allowed_enum(st, allowed_status)) { resp["err"]={{"code","BAD_REQUEST"},{"message","Invalid status"}}; send_json(resp); op_state_=OpState::WAIT_CMD; read_frame_len(); return; }
                        new_status = st;
                    }

                    bool ok = server_->db().update_content(auth_user_id_, content_id, new_price, new_status);
                    resp["ok"] = ok;
                    if (!ok) resp["err"] = {{"code","FAIL"}, {"message","Not owner or content not found"}};
                    else resp["payload"] = {{"content_id", content_id}};
                }
            }
        }
        else if (cmd == "PURCHASE_CONTENT") {
            op_state_ = OpState::HANDLE_PURCHASE;
            if (conn_state_ != ConnState::AUTHED || auth_role_ != "SUBSCRIBER") {
                resp["err"] = {{"code","FORBIDDEN"}, {"message","Subscriber only"}};
            } else {
                std::string content_id = payload.value("content_id", "");
                if (content_id.empty()) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","content_id required"}};
                } else {
                    int64_t charged=0;
                    std::string why;
                    bool ok = server_->db().purchase(auth_user_id_, content_id, charged, why);
                    resp["ok"] = ok;
                    if (ok) resp["payload"] = {{"content_id", content_id}, {"charged_fenings", charged}, {"currency","BAM"}};
                    else resp["err"] = {{"code","FAIL"}, {"message", why}};
                }
            }
        }
        else if (cmd == "SUBSCRIBE_PUBLISHER") {
            op_state_ = OpState::HANDLE_SUBSCRIBE;
            if (conn_state_ != ConnState::AUTHED || auth_role_ != "SUBSCRIBER") {
                resp["err"] = {{"code","FORBIDDEN"}, {"message","Subscriber only"}};
            } else {
                int publisher_id = payload.value("publisher_id", 0);
                int months = payload.value("months", 1);
                if (publisher_id <= 0) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","publisher_id required"}};
                } else {
                    int64_t charged=0,start_ts=0,end_ts=0,fee=0;
                    std::string why;
                    bool ok = server_->db().subscribe(auth_user_id_, publisher_id, months, charged, why, start_ts, end_ts, fee);
                    resp["ok"] = ok;
                    if (ok) {
                        resp["payload"] = {
                            {"publisher_id", publisher_id},
                            {"months", months},
                            {"charged_fenings", charged},
                            {"currency", "BAM"},
                            {"start_ts", start_ts},
                            {"end_ts", end_ts},
                            {"monthly_fee_fenings", fee},
                            {"mcast_group", multicast_group_for_publisher(publisher_id).to_string()},
                            {"mcast_port", kMcastPort}
                        };
                    } else {
                        resp["err"] = {{"code","FAIL"}, {"message", why}};
                    }
                }
            }
        }
        else if (cmd == "LIST_SUBSCRIPTIONS") {
            op_state_ = OpState::HANDLE_LIST_SUBS;
            if (conn_state_ != ConnState::AUTHED || auth_role_ != "SUBSCRIBER") {
                resp["err"] = {{"code","FORBIDDEN"}, {"message","Subscriber only"}};
            } else {
                auto subs = server_->db().list_subscriptions(auth_user_id_);
                resp["ok"] = true;
                resp["payload"] = {{"subscriptions", subs}};
            }
        }
        else if (cmd == "RATE") {
            op_state_ = OpState::HANDLE_RATE;
            if (conn_state_ != ConnState::AUTHED || auth_role_ != "SUBSCRIBER") {
                resp["err"] = {{"code","FORBIDDEN"}, {"message","Subscriber only"}};
            } else {
                std::string content_id = payload.value("content_id", "");
                int rating = payload.value("rating", 0);
                std::string comment = payload.value("comment", "");

                if (content_id.empty()) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","content_id required"}};
                } else {
                    int fid=0;
                    std::string status, why;
                    bool ok = server_->db().rate(auth_user_id_, content_id, rating, comment, fid, status, why);
                    resp["ok"] = ok;
                    if (ok) resp["payload"] = {{"feedback_id", fid}, {"comment_status", status}};
                    else resp["err"] = {{"code","FAIL"}, {"message", why}};
                }
            }
        }
        else if (cmd == "LIST_COMMENTS") {
            op_state_ = OpState::HANDLE_LIST_COMMENTS;
            std::string content_id = payload.value("content_id", "");
            if (content_id.empty()) {
                resp["err"] = {{"code","BAD_REQUEST"}, {"message","content_id required"}};
            } else {
                auto c = server_->db().get_content(content_id);
                if (!c) {
                    resp["err"] = {{"code","FAIL"}, {"message","Unknown content"}};
                } else {
                    double avg = 0.0;
                    int cnt = 0;
                    server_->db().rating_meta(content_id, avg, cnt);
                    auto comments = server_->db().list_comments(content_id);
                    resp["ok"] = true;
                    resp["payload"] = {{"content_id", content_id}, {"comments", comments}, {"avg_rating", avg}, {"rating_count", cnt}};
                }
            }
        }
        else if (cmd == "LIST_PENDING_FEEDBACK") {
            op_state_ = OpState::HANDLE_LIST_PENDING;
            if (conn_state_ != ConnState::AUTHED || auth_role_ != "PUBLISHER") {
                resp["err"] = {{"code","FORBIDDEN"}, {"message","Publisher only"}};
            } else {
                std::optional<std::string> cid;
                if (payload.contains("content_id") && payload["content_id"].is_string()) {
                    std::string s = payload["content_id"].get<std::string>();
                    if (!s.empty()) cid = s;
                }
                auto items = server_->db().list_pending_feedback(auth_user_id_, cid);
                resp["ok"] = true;
                resp["payload"] = {{"pending", items}};
            }
        }
        else if (cmd == "MODERATE") {
            op_state_ = OpState::HANDLE_MODERATE;
            if (conn_state_ != ConnState::AUTHED || auth_role_ != "PUBLISHER") {
                resp["err"] = {{"code","FORBIDDEN"}, {"message","Publisher only"}};
            } else {
                int feedback_id = payload.value("feedback_id", 0);
                std::string action = payload.value("action", "");
                std::string note = payload.value("note", "");
                if (feedback_id <= 0 || action.empty()) {
                    resp["err"] = {{"code","BAD_REQUEST"}, {"message","feedback_id and action required"}};
                } else {
                    int subscriber_id = 0;
                    std::string content_id;
                    std::string new_status;
                    std::string why;
                    bool ok = server_->db().moderate(auth_user_id_, feedback_id, action, note, subscriber_id, content_id, new_status, why);
                    resp["ok"] = ok;
                    if (ok) {
                        resp["payload"] = {{"feedback_id", feedback_id}, {"content_id", content_id}, {"new_status", new_status}};
                        // async unicast notification to subscriber
                        if (new_status == "APPROVED" || new_status == "REJECTED") {
                            json n;
                            n["type"] = "FEEDBACK_STATUS";
                            n["feedback_id"] = feedback_id;
                            n["content_id"] = content_id;
                            n["status"] = new_status;
                            if (!note.empty()) n["note"] = note;
                            n["ts"] = now_unix();
                            server_->send_unicast_notification(subscriber_id, n);
                        }
                    } else {
                        resp["err"] = {{"code","FAIL"}, {"message", why}};
                    }
                }
            }
        }
        else {
            resp["err"] = {{"code","UNKNOWN_CMD"}, {"message","Unknown cmd"}};
        }
    } catch (const std::exception& e) {
        resp["ok"] = false;
        resp["err"] = {{"code","EXCEPTION"}, {"message", e.what()}};
    }

    send_json(resp);
}

void Session::send_json(const json& j)
{
    std::string body;
    if (j.is_object() && j.contains("cmd")) {
        body = j.dump();
    } else {
        json jj = j;
        if (!jj.is_object()) jj = json::object();
        jj["cmd"] = jj.value("cmd", "ERROR");
        body = jj.dump();
    }
    if (body.size() > kMaxJsonFrame) {
        json e; e["cmd"]="ERROR"; e["ok"]=false; e["err"]={{"code","TOO_LARGE"},{"message","response too large"}};
        body = e.dump();
    }

    std::array<unsigned char,4> len;
    write_u32_be(len, (uint32_t)body.size());

    std::vector<asio::const_buffer> bufs;
    bufs.push_back(asio::buffer(len));
    bufs.push_back(asio::buffer(body));

    auto self = shared_from_this();
    asio::async_write(stream_, bufs,
        asio::bind_executor(strand_, [this, self](const boost::system::error_code& ec, std::size_t)
        {
            if (ec) { fail("write", ec); return; }
            op_state_ = OpState::WAIT_CMD;
            read_frame_len();
        }));
}

// ------------------- main -------------------

int main(int argc, char** argv)
{
    try {
        std::string bind_ip = "0.0.0.0";
        int port = kDefaultPort;
        std::string db_path = "content.db";

        if (argc >= 2) bind_ip = argv[1];
        if (argc >= 3) port = std::atoi(argv[2]);
        if (argc >= 4) db_path = argv[3];

        asio::io_context io;

        auto server = std::make_shared<Server>(io, asio::ip::make_address(bind_ip), port, db_path);
        server->start();

        io.run();
    } catch (const std::exception& e) {
        std::cerr << "[server][FATAL] " << e.what() << std::endl;
        return 1;
    }
    return 0;
}