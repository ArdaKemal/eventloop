#include "api.h"

#include "eventloop/file_io.h"
#include "eventloop/http/request.h"
#include "eventloop/http/response.h"
#include "eventloop/http/websocket_stream.h"
#include "eventloop/task.h"
#include "eventloop/task_composition.h"
#include "eventloop/ws/web_socket.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <optional>
#include <span>
#include <string_view>

using namespace eventloop;

namespace parley {

namespace {

constexpr std::size_t max_json_body = 64 * 1024;
constexpr std::size_t max_websocket_message = 64 * 1024;
constexpr std::size_t history_page = 50;
constexpr int password_iterations = 200000;

auto bytes(std::string_view text) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(text.data(), text.size()));
}

auto app_of(http::request& request) -> app&
{
    return *static_cast<app*>(request.route_context());
}

auto equal_ci(std::string_view a, std::string_view b) -> bool
{
    return std::ranges::equal(a, b, [](char x, char y) {
        return (x | 0x20) == (y | 0x20);
    });
}

auto trim(std::string_view text) -> std::string_view
{
    while (!text.empty() && text.front() == ' ') text.remove_prefix(1);
    while (!text.empty() && text.back() == ' ') text.remove_suffix(1);
    return text;
}

// HTTP/2 and HTTP/3 may split cookies into several fields.
auto session_token(const http::request& request) -> std::string_view
{
    for (const auto& field : request.headers()) {
        if (!equal_ci(field.name, "cookie")) continue;
        auto value = field.value;
        while (!value.empty()) {
            const auto end = value.find(';');
            const auto pair = trim(value.substr(0, end));
            if (pair.starts_with("parley=")) return pair.substr(7);
            if (end == std::string_view::npos) break;
            value.remove_prefix(end + 1);
        }
    }
    return {};
}

auto authenticate(app& application, const http::request& request) -> user*
{
    return application.data.session_user(session_token(request));
}

auto query_value(std::string_view query, std::string_view name) -> std::string_view
{
    while (!query.empty()) {
        const auto end = query.find('&');
        const auto pair = query.substr(0, end);
        if (pair.size() > name.size() && pair.starts_with(name) && pair[name.size()] == '=')
            return pair.substr(name.size() + 1);
        if (end == std::string_view::npos) break;
        query.remove_prefix(end + 1);
    }
    return {};
}

template<typename T>
auto to_number(std::string_view text) -> std::optional<T>
{
    T value {};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc {} || parsed.ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

auto percent_decode(std::string_view text) -> std::optional<std::string>
{
    std::string out;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '+') { out.push_back(' '); continue; }
        if (text[i] != '%') { out.push_back(text[i]); continue; }
        unsigned value = 0;
        if (i + 2 >= text.size()) return std::nullopt;
        const auto parsed = std::from_chars(text.data() + i + 1, text.data() + i + 3, value, 16);
        if (parsed.ec != std::errc {} || parsed.ptr != text.data() + i + 3) return std::nullopt;
        out.push_back(static_cast<char>(value));
        i += 2;
    }
    return out;
}

// Same-origin check for state-changing requests and WebSockets, on top of the
// SameSite=Strict session cookie.
auto same_origin(const http::request& request) -> bool
{
    const auto origin = request.header_value("origin");
    if (!origin) return true; // non-browser clients
    auto host = *origin;
    if (!host.starts_with("https://")) return false;
    host.remove_prefix(8);
    return equal_ci(host, request.authority());
}

struct header_list {
    std::array<http::header, 8> fields {};
    std::size_t size {0};

    auto add(std::string_view name, std::string_view value) -> header_list&
    {
        if (!value.empty()) fields[size++] = {name, value};
        return *this;
    }
    [[nodiscard]] auto view() const -> std::span<const http::header>
    {
        return std::span(fields).first(size);
    }
};

auto send_json(event_loop& loop, http::response& response, unsigned status, std::string body,
               std::string_view cookie = {}, std::string_view alt_svc = {}) -> task<void>
{
    (void)loop;
    header_list headers;
    headers.add("content-type", "application/json")
        .add("cache-control", "no-store")
        .add("set-cookie", cookie)
        .add("alt-svc", alt_svc);
    (void)co_await response.async_send(status, headers.view(), bytes(body));
}

auto send_error(event_loop& loop, http::response& response, unsigned status, std::string_view text)
    -> task<void>
{
    std::string body;
    json_writer(body).begin_object().field("error", text).end_object();
    co_await send_json(loop, response, status, std::move(body));
}

auto read_json(event_loop& loop, http::request& request) -> task<std::expected<json, std::error_code>>
{
    (void)loop;
    const auto invalid = std::unexpected(std::make_error_code(std::errc::invalid_argument));
    if (request.content_length().value_or(0) > max_json_body) co_return invalid;
    std::string body;
    for (;;) {
        const auto used = body.size();
        if (used >= max_json_body) co_return invalid;
        body.resize(std::min(max_json_body, used + 4096));
        const auto read = flatten_result(co_await request.async_read_body(
            std::as_writable_bytes(std::span(body.data() + used, body.size() - used))));
        if (!read) co_return std::unexpected(read.error());
        body.resize(used + *read);
        if (*read == 0) break;
    }
    auto parsed = json::parse(body);
    if (!parsed) co_return invalid;
    co_return std::move(*parsed);
}

auto session_cookie(std::string_view token) -> std::string
{
    std::string cookie = "parley=";
    cookie += token;
    cookie += token.empty() ? "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
                            : "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=31536000";
    return cookie;
}

// Passwords: PBKDF2-HMAC-SHA256, run on worker threads.

auto hex(const unsigned char* data, std::size_t size) -> std::string
{
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0xf]);
    }
    return out;
}

auto derive(std::string_view password, std::string_view salt, int iterations) -> std::string
{
    std::array<unsigned char, 32> key {};
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                          reinterpret_cast<const unsigned char*>(salt.data()),
                          static_cast<int>(salt.size()), iterations, EVP_sha256(),
                          static_cast<int>(key.size()), key.data()) != 1) return {};
    return hex(key.data(), key.size());
}

auto hash_password(std::string_view password) -> std::string
{
    const auto salt = random_hex(16);
    return "pbkdf2$" + std::to_string(password_iterations) + "$" + salt + "$" +
        derive(password, salt, password_iterations);
}

auto verify_password(std::string_view password, std::string_view stored) -> bool
{
    // pbkdf2$<iterations>$<salt>$<hash>
    std::array<std::string_view, 4> parts {};
    for (auto& part : parts) {
        const auto end = stored.find('$');
        part = stored.substr(0, end);
        stored = end == std::string_view::npos ? std::string_view {} : stored.substr(end + 1);
    }
    const auto iterations = to_number<int>(parts[1]);
    if (parts[0] != "pbkdf2" || !iterations || *iterations < 1) return false;
    const auto derived = derive(password, parts[2], *iterations);
    return derived.size() == parts[3].size() &&
        CRYPTO_memcmp(derived.data(), parts[3].data(), derived.size()) == 0;
}

// Realtime event encoding.

auto message_event(const store& data, const message& item) -> payload
{
    std::string text;
    json_writer out(text);
    out.begin_object().field("t", "message").key("message");
    data.write_message(out, item);
    out.end_object();
    return make_payload(std::move(text));
}

auto conversation_event(const store& data, const conversation& where) -> payload
{
    std::string text;
    json_writer out(text);
    out.begin_object().field("t", "conversation").key("conversation");
    data.write_conversation(out, where, 0);
    out.end_object();
    return make_payload(std::move(text));
}

auto user_event(app& application, const user& who) -> payload
{
    std::string text;
    json_writer out(text);
    out.begin_object().field("t", "user").key("user");
    application.data.write_user(out, who, application.clients.online(who.id));
    out.end_object();
    return make_payload(std::move(text));
}

// Commands arrive as WebSocket text messages or POST /api/command bodies.
// Returns an error message, or nothing on success.
auto run_command(app& application, user& me, const json& command) -> std::optional<std::string>
{
    auto& data = application.data;
    const auto type = command["t"].str();
    auto* where = data.find_conversation(static_cast<conversation_id>(command["conv"].integer()));
    if (!where || !where->find_member(me.id)) return "Unknown conversation";

    if (type == "send") {
        message item;
        item.conversation = where->id;
        item.sender = me.id;
        item.text = command["text"].str();
        item.media_id = command["media"].str();
        item.duration_ms = std::clamp<std::int64_t>(command["duration"].integer(), 0, 86400000);
        item.reply_to = static_cast<message_id>(std::max<std::int64_t>(0, command["reply_to"].integer()));
        item.client_id = command["client_id"].str();
        auto added = data.add_message(std::move(item));
        if (!added) return added.error();
        application.clients.send_members(*where, message_event(data, **added));
        return std::nullopt;
    }
    if (type == "delivered" || type == "read") {
        const auto upto = static_cast<message_id>(std::max<std::int64_t>(0, command["upto"].integer()));
        if (!data.writable()) return "Storage is busy; try again";
        if (data.mark(*where, me.id, upto, type == "read" ? upto : 0)) {
            const auto* entry = where->find_member(me.id);
            std::string text;
            json_writer(text).begin_object().field("t", "receipt").field("conv", where->id)
                .field("user", me.id).field("delivered", entry->delivered)
                .field("read", entry->read).end_object();
            application.clients.send_members(*where, make_payload(std::move(text)));
        }
        return std::nullopt;
    }
    if (type == "typing") {
        std::string text;
        json_writer(text).begin_object().field("t", "typing").field("conv", where->id)
            .field("user", me.id).field("recording", command["recording"].boolean()).end_object();
        application.clients.send_members(*where, make_payload(std::move(text)), me.id);
        return std::nullopt;
    }
    return "Unknown command";
}

// ---------------------------------------------------------------------------
// Accounts

auto register_account(event_loop& loop, http::request& request, http::response& response)
    -> task<void>
{
    auto& application = app_of(request);
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    const auto body = flatten_result(co_await read_json(loop, request));
    if (!body) co_return (void)co_await send_error(loop, response, 400, "Invalid request");
    std::string username((*body)["username"].str());
    std::ranges::transform(username, username.begin(), [](char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c;
    });
    std::string name(trim((*body)["name"].str()));
    std::string password((*body)["password"].str());
    if (password.size() < 8 || password.size() > 128)
        co_return (void)co_await send_error(loop, response, 400, "Password must be 8-128 characters");
    if (application.data.find_username(username))
        co_return (void)co_await send_error(loop, response, 409, "That username is taken");

    auto hashed = co_await run_blocking(loop, [password = std::move(password)]() noexcept {
        return hash_password(password);
    });
    if (!hashed || hashed->empty())
        co_return (void)co_await send_error(loop, response, 503, "Server is busy");
    auto created = application.data.add_user(username, name, std::move(*hashed));
    if (!created) co_return (void)co_await send_error(loop, response, 400, created.error());
    auto& me = **created;
    application.clients.send_everyone(user_event(application, me));

    const auto cookie = session_cookie(application.data.create_session(me.id));
    std::string out;
    json_writer writer(out);
    writer.begin_object().key("me");
    application.data.write_user(writer, me, false);
    writer.end_object();
    co_await send_json(loop, response, 201, std::move(out), cookie);
}

auto login(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    const auto body = flatten_result(co_await read_json(loop, request));
    if (!body) co_return (void)co_await send_error(loop, response, 400, "Invalid request");
    auto* who = application.data.find_username((*body)["username"].str());
    // Unknown users still pay for a hash so timing does not reveal them.
    std::string stored = who ? who->password
        : "pbkdf2$" + std::to_string(password_iterations) + "$00000000000000000000000000000000$";
    const auto user_id = who ? who->id : 0;
    auto verified = co_await run_blocking(loop,
        [password = std::string((*body)["password"].str()), stored = std::move(stored)]() noexcept {
            return verify_password(password, stored);
        });
    if (!verified) co_return (void)co_await send_error(loop, response, 503, "Server is busy");
    who = application.data.find_user(user_id);
    if (!*verified || !who)
        co_return (void)co_await send_error(loop, response, 401, "Wrong username or password");

    const auto cookie = session_cookie(application.data.create_session(who->id));
    std::string out;
    json_writer writer(out);
    writer.begin_object().key("me");
    application.data.write_user(writer, *who, application.clients.online(who->id));
    writer.end_object();
    co_await send_json(loop, response, 200, std::move(out), cookie);
}

auto logout(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    application.data.revoke_session(session_token(request));
    co_await send_json(loop, response, 200, "{}", session_cookie({}));
}

auto update_profile(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    auto* me = authenticate(application, request);
    if (!me) co_return (void)co_await send_error(loop, response, 401, "Sign in first");
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    const auto body = flatten_result(co_await read_json(loop, request));
    if (!body) co_return (void)co_await send_error(loop, response, 400, "Invalid request");
    me = authenticate(application, request);
    if (!me) co_return (void)co_await send_error(loop, response, 401, "Sign in first");
    const auto name = trim((*body)["name"].str(me->name));
    const auto about = (*body)["about"].str(me->about);
    if (name.empty() || name.size() > 64 || about.size() > 140)
        co_return (void)co_await send_error(loop, response, 400, "Name must be 1-64 and about at most 140 characters");
    if (!application.data.writable())
        co_return (void)co_await send_error(loop, response, 503, "Storage is busy; try again");
    application.data.update_profile(*me, name, about);
    application.clients.send_everyone(user_event(application, *me));
    co_await send_json(loop, response, 200, "{}");
}

// ---------------------------------------------------------------------------
// State and history

auto bootstrap(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    auto& data = application.data;
    auto* me = authenticate(application, request);
    if (!me) co_return (void)co_await send_error(loop, response, 401, "Sign in first");
    std::string out;
    json_writer writer(out);
    writer.begin_object().key("me");
    data.write_user(writer, *me, true);
    writer.key("users").begin_array();
    for (const auto& who : data.users()) data.write_user(writer, *who, application.clients.online(who->id));
    writer.end_array().key("conversations").begin_array();
    for (const auto id : data.conversations_of(me->id))
        data.write_conversation(writer, *data.find_conversation(id), me->id);
    writer.end_array().end_object();
    co_await send_json(loop, response, 200, std::move(out), {}, application.alt_svc);
}

auto history(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    auto* me = authenticate(application, request);
    if (!me) co_return (void)co_await send_error(loop, response, 401, "Sign in first");
    const auto id = to_number<conversation_id>(query_value(request.query(), "conv"));
    auto* where = id ? application.data.find_conversation(*id) : nullptr;
    if (!where || !where->find_member(me->id))
        co_return (void)co_await send_error(loop, response, 404, "Unknown conversation");
    const auto before = to_number<message_id>(query_value(request.query(), "before"))
        .value_or(std::numeric_limits<message_id>::max());

    const auto& messages = where->messages;
    const auto end = std::ranges::lower_bound(messages, before, {}, &message::id);
    const auto count = std::min<std::size_t>(history_page,
        static_cast<std::size_t>(end - messages.begin()));
    std::string out;
    json_writer writer(out);
    writer.begin_object().field("more", static_cast<std::size_t>(end - messages.begin()) > count)
        .key("messages").begin_array();
    for (auto item = end - static_cast<std::ptrdiff_t>(count); item != end; ++item)
        application.data.write_message(writer, *item);
    writer.end_array().end_object();
    co_await send_json(loop, response, 200, std::move(out));
}

auto open_conversation(event_loop& loop, http::request& request, http::response& response)
    -> task<void>
{
    auto& application = app_of(request);
    auto& data = application.data;
    if (!authenticate(application, request)) co_return (void)co_await send_error(loop, response, 401, "Sign in first");
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    const auto body = flatten_result(co_await read_json(loop, request));
    auto* me = authenticate(application, request);
    if (!body || !me) co_return (void)co_await send_error(loop, response, 400, "Invalid request");

    conversation* where = nullptr;
    bool created = false;
    if ((*body)["group"].boolean()) {
        std::vector<user_id> members;
        for (const auto& id : (*body)["members"].items())
            members.push_back(static_cast<user_id>(id.integer()));
        auto group = data.create_group(me->id, trim((*body)["title"].str()), std::move(members));
        if (!group) co_return (void)co_await send_error(loop, response, 400, group.error());
        where = *group;
        created = true;
    } else {
        auto direct = data.direct_conversation(me->id, static_cast<user_id>((*body)["user"].integer()));
        if (!direct) co_return (void)co_await send_error(loop, response, 400, direct.error());
        std::tie(where, created) = *direct;
    }
    if (created) application.clients.send_members(*where, conversation_event(data, *where));
    std::string out;
    json_writer writer(out);
    writer.begin_object().key("conversation");
    data.write_conversation(writer, *where, me->id);
    writer.end_object();
    co_await send_json(loop, response, created ? 201 : 200, std::move(out));
}

auto command(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    if (!authenticate(application, request)) co_return (void)co_await send_error(loop, response, 401, "Sign in first");
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    const auto body = flatten_result(co_await read_json(loop, request));
    auto* me = authenticate(application, request);
    if (!body || !me) co_return (void)co_await send_error(loop, response, 400, "Invalid request");
    if (const auto failed = run_command(application, *me, *body))
        co_return (void)co_await send_error(loop, response, 400, *failed);
    co_await send_json(loop, response, 200, "{}");
}

// ---------------------------------------------------------------------------
// Media

struct media_type {
    std::string_view mime;
    std::string_view kind;
};

// Types served inline. Anything else is stored as a downloadable document.
constexpr std::array<media_type, 13> inline_types {{
    {"image/jpeg", "image"}, {"image/png", "image"}, {"image/gif", "image"},
    {"image/webp", "image"}, {"audio/webm", "audio"}, {"audio/ogg", "audio"},
    {"audio/mpeg", "audio"}, {"audio/mp4", "audio"}, {"audio/aac", "audio"},
    {"audio/wav", "audio"}, {"audio/x-m4a", "audio"}, {"audio/mp3", "audio"},
    {"audio/x-wav", "audio"},
}};

auto classify(std::string_view content_type) -> media_type
{
    auto mime = trim(content_type.substr(0, content_type.find(';')));
    for (const auto& type : inline_types)
        if (equal_ci(type.mime, mime)) return type;
    const bool token = !mime.empty() && mime.size() <= 100 &&
        std::ranges::all_of(mime, [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                std::string_view("/.+-_").find(c) != std::string_view::npos;
        });
    return {token ? mime : "application/octet-stream", "file"};
}

auto upload(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    auto* me = authenticate(application, request);
    if (!me) co_return (void)co_await send_error(loop, response, 401, "Sign in first");
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    const auto owner = me->id;
    auto name = percent_decode(query_value(request.query(), "name"));
    if (!name || name->empty() || name->size() > 200 || !valid_utf8(*name) ||
        name->find_first_of("\r\n\"\\/") != std::string::npos)
        co_return (void)co_await send_error(loop, response, 400, "Invalid file name");
    if (request.content_length().value_or(0) > max_upload_bytes)
        co_return (void)co_await send_error(loop, response, 413, "Files are limited to 16 MiB");
    const auto type = classify(request.header_value("content-type").value_or(""));

    const auto id = random_hex(16);
    auto opened = co_await async_openat(loop, application.media_directory.get(), id,
                                        O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (!opened) co_return (void)co_await send_error(loop, response, 500, "Cannot store the file");
    // One buffer per upload; HTTP/2 and HTTP/3 deliver at most 16 KiB per read.
    constexpr std::size_t chunk = 64 * 1024;
    auto buffer = std::make_unique<std::byte[]>(chunk);
    std::uint64_t size = 0;
    bool failed = false;
    for (;;) {
        const auto read = flatten_result(co_await request.async_read_body({buffer.get(), chunk}));
        if (!read) { failed = true; break; }
        if (*read == 0) break;
        if (size + *read > max_upload_bytes) { failed = true; break; }
        std::size_t written = 0;
        while (written < *read) {
            const auto wrote = co_await async_write_at(loop, opened->get(),
                std::span<const std::byte>(buffer.get() + written, *read - written),
                static_cast<std::int64_t>(size + written));
            if (!wrote || *wrote == 0) { failed = true; break; }
            written += *wrote;
        }
        if (failed) break;
        size += *read;
    }
    opened->reset();
    if (failed || size == 0 || !application.data.writable()) {
        (void)::unlinkat(application.media_directory.get(), id.c_str(), 0);
        co_return (void)co_await send_error(loop, response, failed ? 400 : 503,
            size == 0 ? "The file is empty" : "Upload failed");
    }
    auto* stored = application.data.add_media({.id = id, .owner = owner, .kind = std::string(type.kind),
        .mime = std::string(type.mime), .name = std::move(*name), .size = size});
    std::string out;
    json_writer(out).begin_object().key("media").begin_object().field("id", stored->id)
        .field("kind", stored->kind).field("mime", stored->mime).field("name", stored->name)
        .field("size", stored->size).field("url", "/media/" + stored->id).end_object().end_object();
    co_await send_json(loop, response, 201, std::move(out));
}

struct byte_range {
    std::uint64_t first;
    std::uint64_t length;
};

// A single bytes range. Returns nothing to send the whole file; sets
// unsatisfiable for a valid range outside the file.
auto parse_range(std::string_view value, std::uint64_t size, bool& unsatisfiable)
    -> std::optional<byte_range>
{
    unsatisfiable = false;
    if (!value.starts_with("bytes=") || value.find(',') != std::string_view::npos) return std::nullopt;
    value.remove_prefix(6);
    const auto dash = value.find('-');
    if (dash == std::string_view::npos) return std::nullopt;
    const auto first = value.substr(0, dash);
    const auto last = value.substr(dash + 1);
    if (first.empty()) {
        const auto suffix = to_number<std::uint64_t>(last);
        if (!suffix) return std::nullopt;
        if (*suffix == 0 || size == 0) { unsatisfiable = true; return std::nullopt; }
        const auto length = std::min(*suffix, size);
        return byte_range {size - length, length};
    }
    const auto start = to_number<std::uint64_t>(first);
    if (!start) return std::nullopt;
    auto end = last.empty() ? std::optional<std::uint64_t>(size - 1) : to_number<std::uint64_t>(last);
    if (!end || *end < *start) return std::nullopt;
    if (*start >= size) { unsatisfiable = true; return std::nullopt; }
    *end = std::min(*end, size - 1);
    return byte_range {*start, *end - *start + 1};
}

auto content_disposition(const media& item) -> std::string
{
    std::string ascii;
    std::string encoded;
    constexpr char digits[] = "0123456789ABCDEF";
    for (const char c : item.name) {
        const auto byte = static_cast<unsigned char>(c);
        ascii.push_back(byte >= 0x20 && byte < 0x7f && c != '"' && c != '\\' ? c : '_');
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '.' || c == '-' || c == '_') {
            encoded.push_back(c);
        } else {
            encoded.push_back('%');
            encoded.push_back(digits[byte >> 4]);
            encoded.push_back(digits[byte & 0xf]);
        }
    }
    return (item.kind == "file" ? "attachment" : "inline") + std::string("; filename=\"") +
        ascii + "\"; filename*=UTF-8''" + encoded;
}

auto serve_media(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    auto* me = authenticate(application, request);
    if (!me) co_return (void)co_await send_error(loop, response, 401, "Sign in first");
    const auto id = request.path().substr(std::string_view("/media/").size());
    const auto* item = application.data.find_media(id);
    auto* where = item ? application.data.find_conversation(item->conversation) : nullptr;
    if (!item || (item->owner != me->id && !(where && where->find_member(me->id))))
        co_return (void)co_await send_error(loop, response, 404, "Not found");

    const auto size = item->size;
    const auto disposition = content_disposition(*item);
    const auto mime = item->mime;
    std::string length_text = std::to_string(size);
    std::string range_text;
    bool unsatisfiable = false;
    const auto range = parse_range(request.header_value("range").value_or(""), size, unsatisfiable);
    header_list headers;
    headers.add("content-type", mime)
        .add("content-disposition", disposition)
        .add("x-content-type-options", "nosniff")
        .add("content-security-policy", "default-src 'none'; sandbox")
        .add("cache-control", "private, max-age=31536000, immutable")
        .add("accept-ranges", "bytes");
    if (unsatisfiable) {
        range_text = "bytes */" + length_text;
        headers.add("content-range", range_text);
        co_return (void)co_await response.async_send(416, headers.view());
    }
    auto opened = co_await async_openat(loop, application.media_directory.get(), item->id, O_RDONLY, 0);
    if (!opened) co_return (void)co_await send_error(loop, response, 404, "Not found");
    if (range) {
        range_text = "bytes " + std::to_string(range->first) + "-" +
            std::to_string(range->first + range->length - 1) + "/" + length_text;
        headers.add("content-range", range_text);
        co_return (void)co_await response.async_send_file(206, headers.view(), std::move(*opened),
                                                         range->first, range->length);
    }
    (void)co_await response.async_send_file(200, headers.view(), std::move(*opened), 0, size);
}

// ---------------------------------------------------------------------------
// Realtime: WebSocket over HTTP/2 or HTTP/3 (Extended CONNECT), with
// server-sent events as the fallback for browsers that do not offer it.

struct websocket_session {
    websocket_session(event_loop& loop, user_id who,
                      http::websocket_stream& transport)
        : stream(transport), socket(loop, transport, max_websocket_message), connection(loop, who)
    {}

    http::websocket_stream& stream;
    ws::web_socket<http::websocket_stream> socket;
    client connection;
    bool reader_done {false};
    bool writer_done {false};
};

auto websocket_reader(event_loop& loop, app& application, websocket_session& session) -> task<void>
{
    (void)loop;
    for (;;) {
        auto message = flatten_result(co_await session.socket.async_receive());
        if (!message || message->type == ws::message_type::close) break;
        if (message->type != ws::message_type::text) continue;
        const auto text = std::string_view(reinterpret_cast<const char*>(message->payload.data()),
                                           message->payload.size());
        auto* me = application.data.find_user(session.connection.user);
        const auto parsed = json::parse(text);
        if (!me || !parsed) break;
        if (const auto failed = run_command(application, *me, *parsed)) {
            std::string reply;
            json_writer(reply).begin_object().field("t", "error")
                .field("client_id", (*parsed)["client_id"].str()).field("error", *failed).end_object();
            application.clients.send(session.connection, make_payload(std::move(reply)));
        }
    }
    session.reader_done = true;
    if (!session.writer_done) {
        session.connection.closing = true;
        session.connection.wake.notify();
        session.stream.close(); // aborts a pending write
    }
}

auto websocket_writer(event_loop& loop, websocket_session& session) -> task<void>
{
    auto& connection = session.connection;
    while (!connection.closing) {
        if (connection.queue.empty()) {
            if (!co_await connection.wake.async_wait()) break;
            continue;
        }
        const auto event = std::move(connection.queue.front());
        connection.queue.pop_front();
        for (;;) {
            const auto sent = flatten_result(co_await session.socket.async_send_text(
                {reinterpret_cast<const char8_t*>(event->data()), event->size()}));
            if (sent) break;
            // The reader may be flushing a Pong; try again after it.
            if (sent.error() == ws::errc::concurrent_operation && !connection.closing) {
                (void)co_await yield(loop);
                continue;
            }
            connection.closing = true;
            break;
        }
    }
    session.writer_done = true;
    if (!session.reader_done) session.stream.close(); // aborts the pending read
}

auto websocket(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    auto* me = authenticate(application, request);
    if (!me) co_return (void)co_await send_error(loop, response, 401, "Sign in first");
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    const auto who = me->id;
    auto accepted = flatten_result(co_await request.async_accept_websocket());
    if (!accepted) {
        const std::array<http::header, 1> version {{{"sec-websocket-version", "13"}}};
        co_return (void)co_await response.async_send(400, version);
    }
    auto session = std::make_unique<websocket_session>(loop, who, *accepted);
    if (!application.clients.attach(session->connection)) co_return; // destroying the stream resets it
    (void)co_await when_all(websocket_reader(loop, application, *session), websocket_writer(loop, *session));
    application.clients.detach(session->connection);
}

// Browsers without Extended CONNECT try an HTTP/1.1 upgrade here.
auto websocket_unavailable(event_loop& loop, http::request&, http::response& response) -> task<void>
{
    co_await send_error(loop, response, 426, "WebSockets need HTTP/2 or HTTP/3");
}

auto events(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    auto* me = authenticate(application, request);
    if (!me) co_return (void)co_await send_error(loop, response, 401, "Sign in first");
    if (request.method() == http::method_type::head)
        co_return (void)co_await send_json(loop, response, 200, {});
    auto connection = std::make_unique<client>(loop, me->id);
    if (!application.clients.attach(*connection))
        co_return (void)co_await send_error(loop, response, 503, "Too many connections");
    const std::array<http::header, 2> headers {{
        {"content-type", "text/event-stream"}, {"cache-control", "no-store"},
    }};
    bool open = static_cast<bool>(flatten_result(co_await response.async_start(200, headers)));
    std::string frame = ": connected\n\n";
    while (open && !connection->closing) {
        if (!frame.empty()) {
            open = static_cast<bool>(flatten_result(co_await response.async_write(bytes(frame))));
            frame.clear();
            continue;
        }
        if (connection->queue.empty()) {
            if (!co_await connection->wake.async_wait()) break;
            continue;
        }
        frame = "data: ";
        frame += *connection->queue.front();
        frame += "\n\n";
        connection->queue.pop_front();
    }
    application.clients.detach(*connection);
    if (open) (void)co_await response.async_finish();
}

auto add(http::router& routes, http::method_type method, std::string_view path, http::handler function,
         app& application) -> void
{
    if (!routes.add(method, path, function, &application))
        throw std::runtime_error("cannot register route " + std::string(path));
}

} // namespace

auto make_routes(app& application) -> std::shared_ptr<http::router>
{
    using enum http::method_type;
    auto routes = std::make_shared<http::router>();
    add(*routes, post, "/api/register", register_account, application);
    add(*routes, post, "/api/login", login, application);
    add(*routes, post, "/api/logout", logout, application);
    add(*routes, post, "/api/profile", update_profile, application);
    add(*routes, get, "/api/bootstrap", bootstrap, application);
    add(*routes, get, "/api/messages", history, application);
    add(*routes, post, "/api/conversations", open_conversation, application);
    add(*routes, post, "/api/command", command, application);
    add(*routes, post, "/api/upload", upload, application);
    add(*routes, connect, "/api/ws", websocket, application);
    add(*routes, get, "/api/ws", websocket_unavailable, application);
    add(*routes, get, "/api/events", events, application);
    if (!routes->add_prefix(get, "/media/", serve_media, &application))
        throw std::runtime_error("cannot register /media/");
    return routes;
}

} // namespace parley
