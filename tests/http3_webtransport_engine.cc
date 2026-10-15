// Private-header test for the WebTransport session engine (draft-16, server role).
// A real QUIC server and client run over loopback. The server plays server.cc's
// role: it accepts streams, parses CONNECT requests, and drives
// webtransport_connection directly. The client writes raw bytes: SETTINGS, CONNECT
// stream frames and capsules, WT stream headers, and datagrams.
#include "eventloop/event_loop.h"
#include "eventloop/http/webtransport.h"
#include "eventloop/quic.h"
#include "eventloop/task.h"
#include "eventloop/wakeup.h"

#include "http3/peer_streams.h"
#include "http3/request_stream.h"
#include "http3/webtransport_session.h"
#include "http3/webtransport_wire.h"
#include "quic/varint.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace {

using namespace eventloop;
using namespace std::chrono_literals;
using webtransport_connection = http::detail::webtransport_connection;
using admission = webtransport_connection::admission;
using session_t = http::webtransport_session;
using stream_t = http::webtransport_stream;
using http::webtransport_errc;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::fprintf(stderr, "WebTransport engine: %.*s\n", static_cast<int>(message.size()), message.data());
    std::abort();
}

auto write_pem(const std::filesystem::path& path, X509* certificate, EVP_PKEY* key) -> bool
{
    std::unique_ptr<BIO, decltype(&BIO_free)> bio {BIO_new(BIO_s_mem()), BIO_free};
    if (!bio) return false;
    const int written = certificate != nullptr
        ? PEM_write_bio_X509(bio.get(), certificate)
        : PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr);
    if (written != 1) return false;
    char* data = nullptr;
    const auto size = BIO_get_mem_data(bio.get(), &data);
    if (size <= 0) return false;
    std::FILE* file = std::fopen(path.string().c_str(), "wb");
    if (file == nullptr) return false;
    const bool all = std::fwrite(data, 1, static_cast<std::size_t>(size), file) == static_cast<std::size_t>(size);
    std::fclose(file);
    return all;
}

auto make_certificate(const std::filesystem::path& directory) -> bool
{
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key {
        EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1"), EVP_PKEY_free};
    std::unique_ptr<X509, decltype(&X509_free)> certificate {X509_new(), X509_free};
    if (!key || !certificate) return false;
    if (X509_set_version(certificate.get(), 2) != 1) return false;
    if (ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) != 1) return false;
    if (X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) == nullptr) return false;
    if (X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600) == nullptr) return false;
    if (X509_set_pubkey(certificate.get(), key.get()) != 1) return false;
    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name {X509_NAME_new(), X509_NAME_free};
    if (!name) return false;
    if (X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) != 1)
        return false;
    if (X509_set_subject_name(certificate.get(), name.get()) != 1) return false;
    if (X509_set_issuer_name(certificate.get(), name.get()) != 1) return false;
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> san {
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                            const_cast<char*>("DNS:localhost")), X509_EXTENSION_free};
    if (!san || X509_add_ext(certificate.get(), san.get(), -1) != 1) return false;
    if (X509_sign(certificate.get(), key.get(), EVP_sha256()) <= 0) return false;
    return write_pem(directory / "cert.pem", certificate.get(), nullptr) &&
        write_pem(directory / "key.pem", nullptr, key.get());
}

constexpr std::array<std::uint8_t, 4> protocol {'t', 'e', 's', 't'};
constexpr std::uint64_t h3_message_error = 0x10e;
constexpr std::uint64_t h3_request_rejected = 0x10b;
constexpr std::uint64_t h3_id_error = 0x108;
constexpr std::uint64_t wt_flow_error = 0x045d4487;
constexpr std::uint64_t wt_gone = 0x170d7b68;
constexpr std::uint64_t wt_rejected = 0x3994bd84;
constexpr std::array<std::byte, 5> response_head {std::byte {0x01}, std::byte {0x03}, std::byte {0x00},
                                                  std::byte {0x00}, std::byte {0xd9}};

// Helper tasks yield expected<T, task_result>; cancellation maps to T{}.
template<typename T>
auto settle(std::expected<T, task_result> result) -> T
{
    return result.value_or(T {});
}

// Fails the scenario with the condition text and ends the current coroutine.
#define WT_REQUIRE(scenario_ref, condition)                                    \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fail(scenario_ref, #condition, __LINE__);                                    \
            co_return;                                                         \
        }                                                                      \
    } while (false)

// ---- Byte builders ----

auto put_varint(std::vector<std::byte>& out, std::uint64_t value) -> void
{
    const auto size = quic::detail::varint_size(value);
    const auto start = out.size();
    out.resize(start + size);
    (void)quic::detail::encode_varint(value, std::span<std::byte>(out).subspan(start));
}

auto put_text(std::vector<std::byte>& out, std::string_view text) -> void
{
    for (const char c : text) out.push_back(static_cast<std::byte>(c));
}

// One HTTP/3 DATA frame carrying a single capsule (type, length, value).
auto capsule_frame(std::uint64_t type, const std::vector<std::byte>& value) -> std::vector<std::byte>
{
    std::vector<std::byte> capsule;
    put_varint(capsule, type);
    put_varint(capsule, value.size());
    capsule.insert(capsule.end(), value.begin(), value.end());
    std::vector<std::byte> frame;
    put_varint(frame, 0x00);
    put_varint(frame, capsule.size());
    frame.insert(frame.end(), capsule.begin(), capsule.end());
    return frame;
}

auto varint_bytes(std::uint64_t value) -> std::vector<std::byte>
{
    std::vector<std::byte> out;
    put_varint(out, value);
    return out;
}

auto close_capsule(std::uint32_t code, std::string_view reason) -> std::vector<std::byte>
{
    std::vector<std::byte> value;
    for (int shift = 24; shift >= 0; shift -= 8) value.push_back(static_cast<std::byte>((code >> shift) & 0xff));
    put_text(value, reason);
    return capsule_frame(http3::detail::wt_close_session_capsule, value);
}

// The CONNECT request head: an empty field section (the engine does not decode it).
auto connect_head() -> std::vector<std::byte>
{
    return {std::byte {0x01}, std::byte {0x02}, std::byte {0x00}, std::byte {0x00}};
}

// A WT stream header (signal or type, then session ID) followed by body text.
auto wt_stream_bytes(bool unidirectional, std::uint64_t session, std::string_view body)
    -> std::vector<std::byte>
{
    std::vector<std::byte> out;
    put_varint(out, unidirectional ? http3::detail::webtransport_uni_stream_type
                                   : http3::detail::webtransport_bidi_signal);
    put_varint(out, session);
    put_text(out, body);
    return out;
}

auto settings_frame(bool h3_datagram, bool wt_enabled, std::uint64_t data, std::uint64_t bidi,
                    std::uint64_t uni) -> std::vector<std::byte>
{
    std::vector<std::byte> payload;
    const auto setting = [&payload](std::uint64_t id, std::uint64_t value) {
        put_varint(payload, id);
        put_varint(payload, value);
    };
    setting(http3::detail::enable_connect_protocol_setting, 1);
    if (h3_datagram) setting(http3::detail::h3_datagram_setting, 1);
    if (wt_enabled) setting(http3::detail::wt_enabled_setting, 1);
    setting(http3::detail::wt_initial_max_data_setting, data);
    setting(http3::detail::wt_initial_max_streams_bidi_setting, bidi);
    setting(http3::detail::wt_initial_max_streams_uni_setting, uni);
    std::vector<std::byte> frame;
    put_varint(frame, 0x04);
    put_varint(frame, payload.size());
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

// Parses the WT bidirectional header at the start of bytes: signal, then session ID.
auto parse_bidi_header(std::span<const std::byte> bytes)
    -> std::optional<std::pair<std::size_t, std::uint64_t>>
{
    const auto type = quic::detail::decode_varint(bytes);
    if (!type || type->value != http3::detail::webtransport_bidi_signal) return std::nullopt;
    const auto id = quic::detail::decode_varint(bytes.subspan(type->encoded_size));
    if (!id) return std::nullopt;
    return std::pair {type->encoded_size + id->encoded_size, id->value};
}

// ---- Scenario state ----

struct client_setup {
    bool h3_datagram {true};
    bool wt_enabled {true};
    bool datagram_tp {true};
    bool reset_stream_at {true};
    std::uint64_t initial_data {1 << 20};
    std::uint64_t initial_bidi {16};
    std::uint64_t initial_uni {8};
};

auto flow_off_setup() -> client_setup
{
    client_setup setup;
    setup.initial_data = 0;
    setup.initial_bidi = 0;
    setup.initial_uni = 0;
    return setup;
}

// The CONNECT request's head and body, read by the server before admission.
struct request_reader {
    std::array<std::byte, 128> block {};
    http3::detail::request_frames frames {std::span<std::byte>(block)};
    std::array<std::byte, 512> buffer {};
    std::span<const std::byte> pending {};
};

struct server_side;
struct client_side;

struct scenario {
    const char* failure {nullptr};
    int failure_line {0};
    http::webtransport_options options {};
    client_setup setup {};
    std::size_t connects {1};
    admission expected {admission::accepted};
    bool server_done {false};
    bool client_done {false};
    std::unique_ptr<server_side> server;
    std::unique_ptr<client_side> client;
};

auto fail(scenario& s, const char* what, int line) -> void
{
    if (s.failure == nullptr) {
        s.failure = what;
        s.failure_line = line;
    }
}

struct server_side {
    server_side(event_loop& loop, quic_connection c, const http::webtransport_options& options,
                std::size_t connects)
        : connection(std::move(c)), wt(loop, options), request_ready(loop), connect_count(connects)
    {
    }

    quic_connection connection;
    http3::detail::peer_critical_streams critical;
    webtransport_connection wt;
    wakeup request_ready;
    std::size_t connect_count;
    std::vector<std::uint64_t> requests;
    std::vector<std::uint64_t> open_ids {0, 4, 8};
    std::unique_ptr<request_reader> connect;
};

struct client_side {
    explicit client_side(quic_connection c) : connection(std::move(c)) {}
    quic_connection connection;
    std::uint64_t control {0};
};

// Capsules seen on a CONNECT stream, with the stream's end state.
struct capsule_pump {
    std::array<std::byte, 128> block {};
    http3::detail::request_frames frames {std::span<std::byte>(block)};
    http3::detail::capsule_parser parser {true};
    std::array<std::byte, 512> buffer {};
    std::vector<std::uint64_t> types;
    std::vector<std::uint64_t> values;
    std::vector<std::uint32_t> codes;
    std::vector<std::string> reasons;
    bool fin {false};
    bool broken {false};
};

// ---- Server routing (server.cc's role) ----

auto request_open(void* context, std::uint64_t id) noexcept -> bool
{
    auto& sv = *static_cast<server_side*>(context);
    return std::find(sv.open_ids.begin(), sv.open_ids.end(), id) != sv.open_ids.end();
}

// Client bidirectional streams are CONNECT requests first, then WT streams. A WT
// stream's header is read a chunk at a time; the body prefix passed on is at most
// 16 bytes (the peer_bidirectional contract), and the engine reads the rest.
auto route_bidi(event_loop& loop, server_side& sv, std::uint64_t id) -> task<void>
{
    (void)loop;
    std::array<std::byte, 16> chunk {};
    std::vector<std::byte> head;
    for (;;) {
        auto received = flatten_result(co_await sv.connection.async_read(id, chunk));
        if (!received || *received == 0) co_return;
        head.insert(head.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(*received));
        const auto parsed = parse_bidi_header(head);
        if (!parsed) continue;
        sv.wt.peer_bidirectional(id, parsed->second, parsed->first,
                                 std::span<const std::byte>(head).subspan(parsed->first));
        co_return;
    }
}

// Client unidirectional streams: control (critical) or WT. A WT stream stops being read
// here; its header and up to 16 body bytes go to the engine.
auto route_uni(event_loop& loop, server_side& sv, std::uint64_t id) -> task<void>
{
    (void)loop;
    http3::detail::peer_uni_stream parser(true);
    std::array<std::byte, 16> chunk {};
    std::size_t header = 0;
    for (;;) {
        auto received = flatten_result(co_await sv.connection.async_read(id, chunk));
        if (!received || *received == 0) co_return;
        std::span<const std::byte> input(chunk.data(), *received);
        if (!parser.receive(input, sv.critical)) co_return;
        const auto consumed = parser.bytes_consumed();
        header += consumed;
        if (parser.stream_kind() == http3::detail::peer_uni_stream::kind::webtransport &&
            parser.session_id()) {
            sv.wt.peer_unidirectional(id, *parser.session_id(), header,
                                      std::span<const std::byte>(chunk).subspan(consumed, *received - consumed));
            co_return;
        }
    }
}

auto route_stream(event_loop& loop, server_side& sv, std::uint64_t id) -> task<void>
{
    if (id % 4 == 2) {
        co_await route_uni(loop, sv, id);
        co_return;
    }
    if (id / 4 < sv.connect_count) {
        sv.requests.push_back(id);
        sv.request_ready.notify();
        co_return;
    }
    co_await route_bidi(loop, sv, id);
}

auto router(event_loop& loop, server_side& sv) -> task<void>
{
    for (;;) {
        auto id = flatten_result(co_await sv.connection.async_accept_stream());
        if (!id) co_return;
        (void)loop.spawn(route_stream(loop, sv, *id));
    }
}

auto next_request([[maybe_unused]] event_loop& loop, server_side& sv) -> task<std::uint64_t>
{
    while (sv.requests.empty()) (void)co_await sv.request_ready.async_wait();
    const auto id = sv.requests.front();
    sv.requests.erase(sv.requests.begin());
    co_return id;
}

// Reads the CONNECT request head; the bytes after it stay pending for establish().
auto read_connect([[maybe_unused]] event_loop& loop, server_side& sv, std::uint64_t id) -> task<bool>
{
    sv.connect = std::make_unique<request_reader>();
    auto& reader = *sv.connect;
    for (;;) {
        auto received = flatten_result(co_await sv.connection.async_read(id, reader.buffer));
        if (!received || *received == 0) co_return false;
        std::span<const std::byte> input(reader.buffer.data(), *received);
        while (!input.empty()) {
            auto event = reader.frames.receive(input);
            if (!event) co_return false;
            if (*event == http3::detail::request_frames::event::header_block) {
                reader.frames.accept_connect();
                reader.pending = input;
                co_return true;
            }
            if (*event == http3::detail::request_frames::event::need_input) break;
        }
    }
}

// The route handler's half: admit, answer 2xx, establish. slot receives the reservation.
auto accept_connect([[maybe_unused]] event_loop& loop, server_side& sv, std::uint64_t id, std::optional<session_t>& out, std::uint32_t& slot)
    -> task<bool>
{
    if (!settle(co_await read_connect(loop, sv, id))) co_return false;
    const auto decision = (co_await sv.wt.admit(id, slot)).value_or(admission::cancelled);
    if (decision != admission::accepted) co_return false;
    auto written = flatten_result(co_await sv.connection.async_write(id, response_head, false));
    if (!written || *written != response_head.size()) co_return false;
    auto session = sv.wt.establish(slot, sv.connect->frames, sv.connect->pending, "chat");
    if (!session) co_return false;
    out.emplace(std::move(*session));
    co_return true;
}

// ---- Client helpers ----

auto write_all([[maybe_unused]] event_loop& loop, quic_connection& connection, std::uint64_t id, std::vector<std::byte> bytes, bool fin)
    -> task<bool>
{
    std::size_t written = 0;
    while (written < bytes.size()) {
        auto sent = flatten_result(co_await connection.async_write(
            id, std::span<const std::byte>(bytes).subspan(written), false));
        if (!sent) co_return false;
        written += *sent;
    }
    if (fin) {
        auto closed = flatten_result(co_await connection.async_write(id, {}, true));
        if (!closed) co_return false;
    }
    co_return true;
}

// Reads one chunk of a CONNECT stream and records the capsules in it. False at FIN or error.
auto pump([[maybe_unused]] event_loop& loop, quic_connection& connection, std::uint64_t id, capsule_pump& pumped) -> task<bool>
{
    auto received = flatten_result(co_await connection.async_read(id, pumped.buffer));
    if (!received) {
        pumped.broken = true;
        co_return false;
    }
    if (*received == 0) {
        pumped.fin = true;
        co_return false;
    }
    std::span<const std::byte> input(pumped.buffer.data(), *received);
    while (!input.empty()) {
        auto event = pumped.frames.receive(input);
        if (!event) {
            pumped.broken = true;
            co_return false;
        }
        if (*event == http3::detail::request_frames::event::header_block) {
            pumped.frames.accept_connect();
            continue;
        }
        if (*event != http3::detail::request_frames::event::data) continue;
        auto payload = pumped.frames.data();
        while (!payload.empty()) {
            auto capsule = pumped.parser.next(payload);
            if (!capsule) {
                pumped.broken = true;
                co_return false;
            }
            if (!*capsule) break;
            const auto& item = **capsule;
            if (const auto* close = std::get_if<http3::detail::wt_close_session>(&item)) {
                pumped.types.push_back(http3::detail::wt_close_session_capsule);
                pumped.values.push_back(0);
                pumped.codes.push_back(close->code);
                pumped.reasons.emplace_back(close->message);
            } else if (const auto* max = std::get_if<http3::detail::wt_max_data>(&item)) {
                pumped.types.push_back(http3::detail::wt_max_data_capsule);
                pumped.values.push_back(max->maximum);
                pumped.codes.push_back(0);
                pumped.reasons.emplace_back();
            } else if (const auto* blocked = std::get_if<http3::detail::wt_data_blocked>(&item)) {
                pumped.types.push_back(http3::detail::wt_data_blocked_capsule);
                pumped.values.push_back(blocked->maximum);
                pumped.codes.push_back(0);
                pumped.reasons.emplace_back();
            } else if (std::holds_alternative<http3::detail::wt_drain_session>(item)) {
                pumped.types.push_back(http3::detail::wt_drain_session_capsule);
                pumped.values.push_back(0);
                pumped.codes.push_back(0);
                pumped.reasons.emplace_back();
            }
        }
    }
    co_return true;
}

auto saw(const capsule_pump& pumped, std::uint64_t type) -> bool
{
    return std::find(pumped.types.begin(), pumped.types.end(), type) != pumped.types.end();
}

// Pumps until a capsule of the type has been recorded. False if the stream ends first.
auto pump_until([[maybe_unused]] event_loop& loop, quic_connection& connection, std::uint64_t id, capsule_pump& pumped, std::uint64_t type)
    -> task<bool>
{
    while (!saw(pumped, type)) {
        if (!settle(co_await pump(loop, connection, id, pumped))) co_return saw(pumped, type);
    }
    co_return true;
}

// Reads from a stream until at least count bytes arrived. False at FIN or error.
auto read_at_least([[maybe_unused]] event_loop& loop, quic_connection& connection, std::uint64_t id, std::size_t count,
                   std::vector<std::byte>& out) -> task<bool>
{
    std::array<std::byte, 256> buffer {};
    while (out.size() < count) {
        auto received = flatten_result(co_await connection.async_read(id, buffer));
        if (!received || *received == 0) co_return false;
        out.insert(out.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*received));
    }
    co_return true;
}

// Reads until FIN or error, returning the error (empty on FIN).
auto read_to_end([[maybe_unused]] event_loop& loop, quic_connection& connection, std::uint64_t id, std::vector<std::byte>& out)
    -> task<std::error_code>
{
    std::array<std::byte, 256> buffer {};
    for (;;) {
        auto received = flatten_result(co_await connection.async_read(id, buffer));
        if (!received) co_return received.error();
        if (*received == 0) co_return std::error_code {};
        out.insert(out.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*received));
    }
}

auto text_of(const std::vector<std::byte>& bytes) -> std::string
{
    std::string text;
    for (const auto b : bytes) text.push_back(static_cast<char>(b));
    return text;
}

auto bytes_of(std::string_view text) -> std::vector<std::byte>
{
    std::vector<std::byte> out;
    put_text(out, text);
    return out;
}

// Opens the control stream and sends SETTINGS as the setup describes.
auto send_settings([[maybe_unused]] event_loop& loop, quic_connection& connection, client_side& cs, const client_setup& setup) -> task<bool>
{
    auto opened = flatten_result(co_await connection.async_open_stream(quic_stream_direction::unidirectional));
    if (!opened) co_return false;
    cs.control = *opened;
    std::vector<std::byte> bytes;
    put_varint(bytes, http3::detail::control_stream_type);
    const auto settings = settings_frame(setup.h3_datagram, setup.wt_enabled, setup.initial_data,
                                         setup.initial_bidi, setup.initial_uni);
    bytes.insert(bytes.end(), settings.begin(), settings.end());
    co_return settle(co_await write_all(loop, connection, cs.control, std::move(bytes), false));
}

// Opens a CONNECT stream and writes its head followed by extra bytes.
auto open_connect([[maybe_unused]] event_loop& loop, quic_connection& connection, std::vector<std::byte> extra, std::uint64_t& id)
    -> task<bool>
{
    auto opened = flatten_result(co_await connection.async_open_stream(quic_stream_direction::bidirectional));
    if (!opened) co_return false;
    id = *opened;
    auto bytes = connect_head();
    bytes.insert(bytes.end(), extra.begin(), extra.end());
    co_return settle(co_await write_all(loop, connection, id, std::move(bytes), false));
}

// ---- Runner ----

using server_body = task<void> (*)(event_loop&, server_side&, scenario&);
using client_body = task<void> (*)(event_loop&, client_side&, scenario&);

// Accepts one connection, attaches the engine, runs the body, and shuts the engine down.
auto server_main(event_loop& loop, quic_endpoint& endpoint, scenario& s, server_body body) -> task<void>
{
    auto accepted = flatten_result(co_await endpoint.async_accept());
    if (!accepted) {
        fail(s, "server accept", __LINE__);
        s.server_done = true;
        co_return;
    }
    s.server = std::make_unique<server_side>(loop, std::move(*accepted), s.options, s.connects);
    auto& sv = *s.server;
    if (!sv.wt.attach(sv.connection, sv.critical, &request_open, &sv)) {
        fail(s, "attach", __LINE__);
    } else {
        (void)loop.spawn(router(loop, sv));
        co_await body(loop, sv, s);
    }
    co_await sv.wt.shutdown();
    s.server_done = true;
}

auto client_main(event_loop& loop, quic_endpoint& endpoint, ip_endpoint server, scenario& s,
                 client_body body) -> task<void>
{
    auto connected = flatten_result(co_await endpoint.async_connect(server, "localhost"));
    if (!connected) {
        fail(s, "client connect", __LINE__);
        s.client_done = true;
        co_return;
    }
    s.client = std::make_unique<client_side>(std::move(*connected));
    co_await body(loop, *s.client, s);
    s.client_done = true;
}

auto hold(event_loop& loop, scenario& s) -> task<void>
{
    for (int i = 0; i < 2000 && !s.failure && !(s.server_done && s.client_done); ++i)
        (void)co_await sleep_for(loop, 5ms);
}

auto watch(event_loop& loop, quic_endpoint& server, quic_endpoint& client, scenario& s) -> task<void>
{
    co_await hold(loop, s);
    co_await server.async_close();
    co_await client.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

auto transport_limits(bool datagrams, bool reset_at) -> quic_transport_limits
{
    quic_transport_limits limits;
    limits.max_datagram_frame_size = datagrams ? 1232 : 0;
    limits.reset_stream_at = reset_at;
    return limits;
}

auto run(const char* name, const std::filesystem::path& certificate, scenario config, server_body serve,
         client_body drive) -> bool
{
    event_loop loop;
    quic_server_options server_options;
    server_options.certificate_chain = certificate / "cert.pem";
    server_options.private_key = certificate / "key.pem";
    server_options.alpn = protocol;
    server_options.limits = transport_limits(true, true);
    quic_client_options client_options;
    client_options.alpn = protocol;
    client_options.trusted_ca = certificate / "cert.pem";
    client_options.limits = transport_limits(config.setup.datagram_tp, config.setup.reset_stream_at);
    quic_endpoint server(loop, ip_endpoint::loopback_v4(0), std::move(server_options));
    quic_endpoint client(loop, ip_endpoint::loopback_v4(0), std::move(client_options));
    scenario s;
    s.options = config.options;
    s.setup = config.setup;
    s.connects = config.connects;
    s.expected = config.expected;
    check(loop.spawn(server_main(loop, server, s, serve)) == task_spawn_result::accepted, "spawn server");
    check(loop.spawn(client_main(loop, client, server.local_endpoint(), s, drive)) ==
              task_spawn_result::accepted, "spawn client");
    check(loop.spawn(watch(loop, server, client, s)) == task_spawn_result::accepted, "spawn watch");
    (void)loop.run();
    if (s.failure != nullptr) {
        std::fprintf(stderr, "WebTransport engine %s: line %d: %s\n", name, s.failure_line, s.failure);
        return false;
    }
    if (!s.server_done || !s.client_done) {
        std::fprintf(stderr, "WebTransport engine %s: scenario did not finish\n", name);
        return false;
    }
    std::printf("WebTransport engine %s: ok\n", name);
    return true;
}

auto keep_open(event_loop& loop, scenario& s) -> task<void>
{
    while (!s.client_done && !s.failure) (void)co_await sleep_for(loop, 2ms);
}

// ---- Admission ----

auto admit_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    (void)loop;
    std::uint32_t slot = 0;
    const auto decision = (co_await sv.wt.admit(0, slot)).value_or(admission::cancelled);
    if (decision == admission::accepted) sv.wt.release(slot);
    WT_REQUIRE(s, decision == s.expected);
}

auto settings_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    (void)loop;
}

// The engine closes the connection when H3_DATAGRAM comes without a datagram TP.
auto settings_error_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    (void)loop;
    std::uint32_t slot = 0;
    const auto decision = (co_await sv.wt.admit(0, slot)).value_or(admission::cancelled);
    WT_REQUIRE(s, decision == admission::malformed);
}

auto settings_error_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    (void)loop;
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    auto accepted = flatten_result(co_await cs.connection.async_accept_stream());
    WT_REQUIRE(s, !accepted);
}

// A second CONNECT is refused with H3_REQUEST_REJECTED while the first session is open.
auto capacity_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto first = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, first, session, slot)));
    const auto second = settle(co_await next_request(loop, sv));
    WT_REQUIRE(s, settle(co_await read_connect(loop, sv, second)));
    std::uint32_t other = 0;
    const auto decision = (co_await sv.wt.admit(second, other)).value_or(admission::cancelled);
    WT_REQUIRE(s, decision == admission::rejected);
    WT_REQUIRE(s, sv.connection.reset_stream(second, h3_request_rejected).has_value());
    co_await keep_open(loop, s);
}

auto capacity_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t first = 0;
    std::uint64_t second = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, first)));
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, second)));
    std::vector<std::byte> ignored;
    WT_REQUIRE(s, (settle(co_await read_to_end(loop, cs.connection, second, ignored))) == make_error_code(quic_errc::stream_reset));
    WT_REQUIRE(s, cs.connection.stream_reset_code(second) == h3_request_rejected);
    (void)loop;
}

// The slot survives an admission cancelled before SETTINGS arrive.
auto cancel_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    std::uint32_t slot = 0;
    task_handle<admission> waiter;
    WT_REQUIRE(s, loop.spawn(sv.wt.admit(0, slot), waiter) == task_spawn_result::accepted);
    (void)co_await sleep_for(loop, 10ms);
    (void)waiter.cancel();
    WT_REQUIRE(s, (co_await waiter).value_or(admission::malformed) == admission::cancelled);
    const auto later = (co_await sv.wt.admit(0, slot)).value_or(admission::cancelled);
    WT_REQUIRE(s, later == admission::accepted);
    sv.wt.release(slot);
}

auto cancel_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    (void)co_await sleep_for(loop, 60ms);
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    (void)loop;
}

// ---- Session streams, datagrams, drain ----

auto basic_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    auto& ses = *session;
    WT_REQUIRE(s, ses.valid() && ses.id() == id && ses.protocol() == "chat");
    WT_REQUIRE(s, ses.max_datagram_size() == 1199);

    // Peer bidirectional stream: the header and "hello" arrive together.
    auto peer = flatten_result(co_await ses.async_accept_stream());
    WT_REQUIRE(s, peer.has_value());
    auto bidi = std::move(*peer);
    WT_REQUIRE(s, bidi.direction() == quic_stream_direction::bidirectional && !bidi.local());
    std::vector<std::byte> got;
    std::array<std::byte, 16> buffer {};
    while (got.size() < 5) {
        auto read = flatten_result(co_await bidi.async_read(buffer));
        WT_REQUIRE(s, read.has_value() && *read > 0);
        got.insert(got.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*read));
    }
    WT_REQUIRE(s, text_of(got) == "hello");
    auto wrote = flatten_result(co_await bidi.async_write(bytes_of("world"), false));
    WT_REQUIRE(s, wrote.has_value() && *wrote == 5);

    // Peer unidirectional stream, read to FIN.
    auto uni_peer = flatten_result(co_await ses.async_accept_stream());
    WT_REQUIRE(s, uni_peer.has_value());
    auto uni = std::move(*uni_peer);
    WT_REQUIRE(s, uni.direction() == quic_stream_direction::unidirectional && !uni.local());
    std::vector<std::byte> uni_data;
    for (;;) {
        auto read = flatten_result(co_await uni.async_read(buffer));
        WT_REQUIRE(s, read.has_value());
        if (*read == 0) break;
        uni_data.insert(uni_data.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*read));
    }
    WT_REQUIRE(s, text_of(uni_data) == "uni");

    // Local bidirectional and unidirectional streams: header plus body.
    auto opened = flatten_result(co_await ses.async_open_stream(quic_stream_direction::bidirectional));
    WT_REQUIRE(s, opened.has_value() && opened->local());
    auto local_bidi = std::move(*opened);
    auto sent = flatten_result(co_await local_bidi.async_write(bytes_of("srv"), true));
    WT_REQUIRE(s, sent.has_value() && *sent == 3);
    auto opened_uni = flatten_result(co_await ses.async_open_stream(quic_stream_direction::unidirectional));
    WT_REQUIRE(s, opened_uni.has_value() && opened_uni->direction() == quic_stream_direction::unidirectional);
    auto local_uni = std::move(*opened_uni);
    auto sent_uni = flatten_result(co_await local_uni.async_write(bytes_of("u"), true));
    WT_REQUIRE(s, sent_uni.has_value() && *sent_uni == 1);

    // Datagrams both ways; an oversize payload is refused.
    std::array<std::byte, 1300> datagram {};
    auto received = flatten_result(co_await ses.async_receive_datagram(datagram));
    WT_REQUIRE(s, received.has_value() && *received == 3);
    WT_REQUIRE(s, text_of(std::vector<std::byte>(datagram.begin(), datagram.begin() + 3)) == "dg1");
    auto replied = flatten_result(co_await ses.async_send_datagram(bytes_of("reply")));
    WT_REQUIRE(s, replied.has_value());
    std::vector<std::byte> oversize(1201, std::byte {0x2a});
    auto refused = flatten_result(co_await ses.async_send_datagram(oversize));
    WT_REQUIRE(s, !refused && refused.error() == make_error_code(webtransport_errc::datagram_size));

    // The peer's WT_DRAIN_SESSION shows up on the session.
    for (int i = 0; i < 100 && !ses.draining(); ++i) (void)co_await sleep_for(loop, 5ms);
    WT_REQUIRE(s, ses.draining());
    co_await keep_open(loop, s);
}

auto basic_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, capsule_frame(http3::detail::wt_max_data_capsule, varint_bytes(2 << 20)), connect)));
    WT_REQUIRE(s, connect == 0);
    auto stream = flatten_result(co_await cs.connection.async_open_stream(quic_stream_direction::bidirectional));
    WT_REQUIRE(s, stream.has_value() && *stream == 4);
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, 4, wt_stream_bytes(false, 0, "hello"), false)));
    std::vector<std::byte> reply;
    WT_REQUIRE(s, settle(co_await read_at_least(loop, cs.connection, 4, 5, reply)));
    WT_REQUIRE(s, text_of(reply) == "world");
    auto uni = flatten_result(co_await cs.connection.async_open_stream(quic_stream_direction::unidirectional));
    WT_REQUIRE(s, uni.has_value() && *uni == 6);
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, 6, wt_stream_bytes(true, 0, "uni"), true)));

    // The server opened one bidirectional (id 1) and one unidirectional (id 3) stream.
    std::vector<std::byte> srv_bidi;
    std::vector<std::byte> srv_uni;
    for (int i = 0; i < 2; ++i) {
        auto accepted = flatten_result(co_await cs.connection.async_accept_stream());
        WT_REQUIRE(s, accepted.has_value());
        std::vector<std::byte>& target = *accepted % 4 == 1 ? srv_bidi : srv_uni;
        WT_REQUIRE(s, (settle(co_await read_to_end(loop, cs.connection, *accepted, target))) == std::error_code {});
    }
    WT_REQUIRE(s, srv_bidi == wt_stream_bytes(false, 0, "srv"));
    WT_REQUIRE(s, srv_uni == wt_stream_bytes(true, 0, "u"));

    // Datagram: quarter stream ID 0 (session 0), then the payload.
    auto to_server = std::vector<std::byte>{std::byte {0x00}};
    put_text(to_server, "dg1");
    WT_REQUIRE(s, (flatten_result(co_await cs.connection.async_send_datagram(to_server))).has_value());
    std::array<std::byte, 1300> buffer {};
    auto back = flatten_result(co_await cs.connection.async_receive_datagram(buffer));
    WT_REQUIRE(s, back.has_value() && *back == 6);
    WT_REQUIRE(s, buffer[0] == std::byte {0x00} && text_of(std::vector<std::byte>(buffer.begin() + 1, buffer.begin() + 6)) == "reply");

    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, connect, capsule_frame(http3::detail::wt_drain_session_capsule, {}), false)));
    (void)loop;
}

// Sessions buffer streams that arrive before their CONNECT is admitted; the second
// buffered stream is refused with WT_BUFFERED_STREAM_REJECTED.
auto buffering_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    (void)co_await sleep_for(loop, 40ms);
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    auto peer = flatten_result(co_await session->async_accept_stream());
    WT_REQUIRE(s, peer.has_value());
    auto stream = std::move(*peer);
    std::vector<std::byte> got;
    std::array<std::byte, 16> buffer {};
    while (got.size() < 1) {
        auto read = flatten_result(co_await stream.async_read(buffer));
        WT_REQUIRE(s, read.has_value() && *read > 0);
        got.insert(got.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*read));
    }
    WT_REQUIRE(s, text_of(got) == "a");
    co_await keep_open(loop, s);
}

auto buffering_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, connect)));
    auto first = flatten_result(co_await cs.connection.async_open_stream(quic_stream_direction::bidirectional));
    WT_REQUIRE(s, first.has_value() && *first == 4);
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, 4, wt_stream_bytes(false, 0, "a"), false)));
    auto second = flatten_result(co_await cs.connection.async_open_stream(quic_stream_direction::bidirectional));
    WT_REQUIRE(s, second.has_value() && *second == 8);
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, 8, wt_stream_bytes(false, 0, "b"), false)));
    std::vector<std::byte> ignored;
    WT_REQUIRE(s, (settle(co_await read_to_end(loop, cs.connection, 8, ignored))) == make_error_code(quic_errc::stream_reset));
    WT_REQUIRE(s, cs.connection.stream_reset_code(8) == wt_rejected);
    WT_REQUIRE(s, cs.connection.stream_stop_sending_code(8) == wt_rejected);
    (void)loop;
}

// After the session closes, a stream for it is refused with WT_SESSION_GONE.
auto gone_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    auto closed = flatten_result(co_await session->async_accept_stream());
    WT_REQUIRE(s, !closed && closed.error() == make_error_code(webtransport_errc::session_closed));
    const auto info = session->close_info();
    WT_REQUIRE(s, info && info->code == 5 && info->reason == "x" && info->remote);
    co_await keep_open(loop, s);
}

auto gone_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, connect)));
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, connect, close_capsule(5, "x"), true)));
    (void)co_await sleep_for(loop, 50ms);
    auto stream = flatten_result(co_await cs.connection.async_open_stream(quic_stream_direction::bidirectional));
    WT_REQUIRE(s, stream.has_value() && *stream == 4);
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, 4, wt_stream_bytes(false, 0, "z"), false)));
    std::vector<std::byte> ignored;
    (void)settle(co_await read_to_end(loop, cs.connection, 4, ignored));
    WT_REQUIRE(s, cs.connection.stream_stop_sending_code(4) == wt_gone);
    (void)loop;
}

// The peer's close ends the session: pending accept fails, the server's stream is
// reset with WT_SESSION_GONE after its header.
auto remote_close_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    auto opened = flatten_result(co_await session->async_open_stream(quic_stream_direction::bidirectional));
    WT_REQUIRE(s, opened.has_value());
    auto stream = std::move(*opened);
    WT_REQUIRE(s, (flatten_result(co_await stream.async_write(bytes_of("sv"), false))).has_value());
    auto closed = flatten_result(co_await session->async_accept_stream());
    WT_REQUIRE(s, !closed && closed.error() == make_error_code(webtransport_errc::session_closed));
    const auto info = session->close_info();
    WT_REQUIRE(s, info && info->code == 77 && info->reason == "bye" && info->remote);
    auto late = flatten_result(co_await stream.async_write(bytes_of("zz"), false));
    WT_REQUIRE(s, !late && late.error() == make_error_code(webtransport_errc::session_closed));
    co_await keep_open(loop, s);
}

auto remote_close_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, connect)));
    auto accepted = flatten_result(co_await cs.connection.async_accept_stream());
    WT_REQUIRE(s, accepted.has_value());
    std::vector<std::byte> header_and_body;
    WT_REQUIRE(s, settle(co_await read_at_least(loop, cs.connection, *accepted, 4, header_and_body)));
    WT_REQUIRE(s, header_and_body == wt_stream_bytes(false, 0, "sv"));
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, connect, close_capsule(77, "bye"), true)));
    std::vector<std::byte> rest;
    WT_REQUIRE(s, (settle(co_await read_to_end(loop, cs.connection, *accepted, rest))) == make_error_code(quic_errc::stream_reset));
    WT_REQUIRE(s, cs.connection.stream_reset_code(*accepted) == wt_gone);
    (void)loop;
}

// async_drain sends WT_DRAIN_SESSION; async_close sends WT_CLOSE_SESSION then FIN.
auto close_local_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    WT_REQUIRE(s, (flatten_result(co_await session->async_drain())).has_value());
    WT_REQUIRE(s, (flatten_result(co_await session->async_close(9, "done"))).has_value());
    const auto info = session->close_info();
    WT_REQUIRE(s, info && info->code == 9 && info->reason == "done" && !info->remote);
    co_await keep_open(loop, s);
}

auto close_local_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, connect)));
    auto pumped = std::make_unique<capsule_pump>();
    WT_REQUIRE(s, settle(co_await pump_until(loop, cs.connection, connect, *pumped, http3::detail::wt_drain_session_capsule)));
    WT_REQUIRE(s, settle(co_await pump_until(loop, cs.connection, connect, *pumped, http3::detail::wt_close_session_capsule)));
    WT_REQUIRE(s, pumped->codes.back() == 9 && pumped->reasons.back() == "done");
    while (settle(co_await pump(loop, cs.connection, connect, *pumped))) {}
    WT_REQUIRE(s, pumped->fin && !pumped->broken);
    (void)loop;
}

// The route handler returning closes the session with code 0 and FIN.
auto handler_return_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    sv.wt.handler_returned(slot);
    const auto info = session->close_info();
    WT_REQUIRE(s, info && info->code == 0 && !info->remote && info->reason.empty());
    session.reset();
    co_await keep_open(loop, s);
}

auto handler_return_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, connect)));
    auto pumped = std::make_unique<capsule_pump>();
    WT_REQUIRE(s, settle(co_await pump_until(loop, cs.connection, connect, *pumped, http3::detail::wt_close_session_capsule)));
    WT_REQUIRE(s, pumped->codes.back() == 0 && pumped->reasons.back().empty());
    while (settle(co_await pump(loop, cs.connection, connect, *pumped))) {}
    WT_REQUIRE(s, pumped->fin);
    (void)loop;
}

// A close capsule whose reason is not UTF-8 resets CONNECT with H3_MESSAGE_ERROR.
auto malformed_close_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    auto closed = flatten_result(co_await session->async_accept_stream());
    WT_REQUIRE(s, !closed && closed.error() == make_error_code(webtransport_errc::session_closed));
    const auto info = session->close_info();
    WT_REQUIRE(s, info && !info->remote && info->code == 0);
    co_await keep_open(loop, s);
}

auto malformed_close_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, connect)));
    const std::vector<std::byte> bad_reason {std::byte {0}, std::byte {0}, std::byte {0}, std::byte {0},
                                             std::byte {0xff}};
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, connect, capsule_frame(http3::detail::wt_close_session_capsule, bad_reason), false)));
    auto pumped = std::make_unique<capsule_pump>();
    while (settle(co_await pump(loop, cs.connection, connect, *pumped))) {}
    WT_REQUIRE(s, pumped->broken);
    WT_REQUIRE(s, cs.connection.stream_reset_code(connect) == h3_message_error);
    (void)loop;
}

// Session flow control: the peer's limit blocks a write until a WT_MAX_DATA capsule
// arrives; consumed data renews the window with WT_MAX_DATA.
auto flow_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    auto opened = flatten_result(co_await session->async_open_stream(quic_stream_direction::bidirectional));
    WT_REQUIRE(s, opened.has_value());
    auto stream = std::move(*opened);
    const std::vector<std::byte> payload(3000, std::byte {'x'});
    std::size_t total = 0;
    while (total < payload.size()) {
        auto wrote = flatten_result(co_await stream.async_write(
            std::span<const std::byte>(payload).subspan(total), false));
        WT_REQUIRE(s, wrote.has_value() && *wrote > 0);
        total += *wrote;
    }
    WT_REQUIRE(s, (flatten_result(co_await stream.async_write({}, true))).has_value());
    auto peer = flatten_result(co_await session->async_accept_stream());
    WT_REQUIRE(s, peer.has_value());
    auto incoming = std::move(*peer);
    std::array<std::byte, 256> buffer {};
    std::size_t consumed = 0;
    while (consumed < 600) {
        auto read = flatten_result(co_await incoming.async_read(buffer));
        WT_REQUIRE(s, read.has_value() && *read > 0);
        consumed += *read;
    }
    co_await keep_open(loop, s);
}

auto flow_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, connect)));
    auto pumped = std::make_unique<capsule_pump>();
    WT_REQUIRE(s, settle(co_await pump_until(loop, cs.connection, connect, *pumped, http3::detail::wt_data_blocked_capsule)));
    WT_REQUIRE(s, pumped->values.back() == 1000);
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, connect, capsule_frame(http3::detail::wt_max_data_capsule, varint_bytes(100000)), false)));
    auto accepted = flatten_result(co_await cs.connection.async_accept_stream());
    WT_REQUIRE(s, accepted.has_value());
    std::vector<std::byte> body;
    WT_REQUIRE(s, (settle(co_await read_to_end(loop, cs.connection, *accepted, body))) == std::error_code {});
    WT_REQUIRE(s, body.size() == 3000 + wt_stream_bytes(false, 0, "").size());
    auto stream = flatten_result(co_await cs.connection.async_open_stream(quic_stream_direction::bidirectional));
    WT_REQUIRE(s, stream.has_value());
    const std::vector<std::byte> incoming(600, std::byte {'y'});
    auto bytes = wt_stream_bytes(false, 0, "");
    bytes.insert(bytes.end(), incoming.begin(), incoming.end());
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, *stream, std::move(bytes), false)));
    bool renewed = false;
    while (!renewed) {
        WT_REQUIRE(s, settle(co_await pump(loop, cs.connection, connect, *pumped)));
        for (std::size_t i = 0; i < pumped->types.size(); ++i)
            if (pumped->types[i] == http3::detail::wt_max_data_capsule && pumped->values[i] > (1 << 10))
                renewed = true;
    }
    (void)loop;
}

// The peer exceeds the advertised session data limit: CONNECT is reset with
// WT_FLOW_CONTROL_ERROR.
auto flow_violation_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    auto peer = flatten_result(co_await session->async_accept_stream());
    WT_REQUIRE(s, peer.has_value());
    auto incoming = std::move(*peer);
    std::array<std::byte, 256> buffer {};
    // Let the client's send and reset arrive before reading: the reset's final size
    // then reveals the body the peer sent beyond the window.
    (void)co_await sleep_for(loop, 100ms);
    for (;;) {
        auto read = flatten_result(co_await incoming.async_read(buffer));
        if (!read) {
            WT_REQUIRE(s, read.error() == make_error_code(webtransport_errc::flow_control_error));
            break;
        }
        WT_REQUIRE(s, *read > 0);
    }
    co_await keep_open(loop, s);
}

auto flow_violation_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, connect)));
    auto stream = flatten_result(co_await cs.connection.async_open_stream(quic_stream_direction::bidirectional));
    WT_REQUIRE(s, stream.has_value());
    const std::vector<std::byte> excess(1500, std::byte {'z'});
    auto bytes = wt_stream_bytes(false, 0, "");
    bytes.insert(bytes.end(), excess.begin(), excess.end());
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, *stream, std::move(bytes), false)));
    // The excess is transmitted but unread when the peer resets: the final size reveals
    // it. A reset discards bytes still queued, so wait for the transmission first.
    (void)co_await sleep_for(loop, 50ms);
    WT_REQUIRE(s, cs.connection.reset_stream_at(*stream, http::webtransport_to_http3_error(3),
                                                wt_stream_bytes(false, 0, "").size()).has_value());
    auto pumped = std::make_unique<capsule_pump>();
    while (settle(co_await pump(loop, cs.connection, connect, *pumped))) {}
    WT_REQUIRE(s, pumped->broken);
    WT_REQUIRE(s, cs.connection.stream_reset_code(connect) == wt_flow_error);
    (void)loop;
}

// The peer opens more streams than the session's advertised stream limit.
auto stream_limit_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    (void)co_await sleep_for(loop, 100ms);
    WT_REQUIRE(s, session->close_info() && !session->close_info()->remote);
    co_await keep_open(loop, s);
}

auto stream_limit_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, connect)));
    for (std::uint64_t expected = 4; expected <= 12; expected += 4) {
        auto stream = flatten_result(co_await cs.connection.async_open_stream(quic_stream_direction::bidirectional));
        WT_REQUIRE(s, stream.has_value() && *stream == expected);
        WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, *stream, wt_stream_bytes(false, 0, ""), false)));
    }
    auto pumped = std::make_unique<capsule_pump>();
    while (settle(co_await pump(loop, cs.connection, connect, *pumped))) {}
    WT_REQUIRE(s, pumped->broken);
    WT_REQUIRE(s, cs.connection.stream_reset_code(connect) == wt_flow_error);
    (void)loop;
}

// Datagrams beyond the session queue are dropped; the queued ones come out in order.
auto datagram_queue_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    (void)co_await sleep_for(loop, 50ms);
    std::array<std::byte, 1300> buffer {};
    for (const char* expected : {"d0", "d1"}) {
        auto received = flatten_result(co_await session->async_receive_datagram(buffer));
        WT_REQUIRE(s, received.has_value() && *received == 2);
        WT_REQUIRE(s, text_of(std::vector<std::byte>(buffer.begin(), buffer.begin() + 2)) == expected);
    }
    auto next = flatten_result(co_await session->async_receive_datagram(buffer));
    WT_REQUIRE(s, next.has_value() && *next == 3);
    WT_REQUIRE(s, text_of(std::vector<std::byte>(buffer.begin(), buffer.begin() + 3)) == "end");
    co_await keep_open(loop, s);
}

auto datagram_queue_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, connect)));
    for (const char* text : {"d0", "d1", "d2", "d3"}) {
        auto datagram = std::vector<std::byte>{std::byte {0x00}};
        put_text(datagram, text);
        (void)flatten_result(co_await cs.connection.async_send_datagram(datagram));
    }
    (void)co_await sleep_for(loop, 80ms);
    auto end = std::vector<std::byte>{std::byte {0x00}};
    put_text(end, "end");
    WT_REQUIRE(s, (flatten_result(co_await cs.connection.async_send_datagram(end))).has_value());
    (void)loop;
}

// Shutdown completes pending accept, stream read, and datagram receive with session_closed.
auto shutdown_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    auto opened = flatten_result(co_await session->async_open_stream(quic_stream_direction::bidirectional));
    WT_REQUIRE(s, opened.has_value());
    auto stream = std::move(*opened);
    std::array<std::byte, 64> read_buffer {};
    std::array<std::byte, 64> datagram_buffer {};
    task_handle<std::expected<stream_t, std::error_code>> accept_task;
    task_handle<std::expected<std::size_t, std::error_code>> read_task;
    task_handle<std::expected<std::size_t, std::error_code>> datagram_task;
    WT_REQUIRE(s, loop.spawn(session->async_accept_stream(), accept_task) == task_spawn_result::accepted);
    WT_REQUIRE(s, loop.spawn(stream.async_read(read_buffer), read_task) == task_spawn_result::accepted);
    WT_REQUIRE(s, loop.spawn(session->async_receive_datagram(datagram_buffer), datagram_task) ==
                      task_spawn_result::accepted);
    (void)co_await sleep_for(loop, 30ms);
    // Start with the QUIC queue full, then terminate before the send can complete.
    for (int i = 0; i < 8; ++i)
        WT_REQUIRE(s, flatten_result(co_await sv.connection.async_send_datagram(datagram_buffer)).has_value());
    auto sending = session->async_send_datagram(datagram_buffer);
    WT_REQUIRE(s, sending.start() == task_state::suspended);
    co_await sv.wt.shutdown();
    const auto sent = flatten_result(sending.result());
    WT_REQUIRE(s, !sent && sent.error() == webtransport_errc::session_closed);
    const auto accepted = co_await accept_task;
    WT_REQUIRE(s, accepted.has_value() && !accepted->has_value() &&
                      accepted->error() == make_error_code(webtransport_errc::session_closed));
    const auto read = co_await read_task;
    WT_REQUIRE(s, read.has_value() && !read->has_value() &&
                      read->error() == make_error_code(webtransport_errc::session_closed));
    const auto received = co_await datagram_task;
    WT_REQUIRE(s, received.has_value() && !received->has_value() &&
                      received->error() == make_error_code(webtransport_errc::session_closed));
}

auto shutdown_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, connect)));
    (void)loop;
}

// A closed session retains its slot until both its handler and handle retire.
auto reuse_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto first = settle(co_await next_request(loop, sv));
    std::optional<session_t> old_session;
    std::uint32_t old_slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, first, old_session, old_slot)));
    auto closed = flatten_result(co_await old_session->async_accept_stream());
    WT_REQUIRE(s, !closed && closed.error() == make_error_code(webtransport_errc::session_closed));
    (void)co_await sleep_for(loop, 30ms);
    const auto second = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, (co_await sv.wt.admit(second, slot)).value_or(admission::cancelled) == admission::rejected);
    sv.wt.handler_returned(old_slot);
    WT_REQUIRE(s, (co_await sv.wt.admit(second, slot)).value_or(admission::cancelled) == admission::rejected);
    WT_REQUIRE(s, old_session->close_info() && old_session->close_info()->code == 3);
    old_session.reset();
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, second, session, slot)));
    WT_REQUIRE(s, session->id() == second);
    sv.wt.handler_returned(slot);
    co_await keep_open(loop, s);
}

auto reuse_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t first = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, first)));
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, first, close_capsule(3, "a"), true)));
    (void)co_await sleep_for(loop, 50ms);
    std::uint64_t second = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, second)));
    WT_REQUIRE(s, second == 4);
    (void)loop;
}

// A CONNECT stream whose session ID is not a client bidirectional stream ID closes the connection.
auto invalid_id_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    (void)loop;
    sv.wt.peer_bidirectional(4, 1, 2, {});
    co_await keep_open(loop, s);
}

auto invalid_id_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    auto accepted = flatten_result(co_await cs.connection.async_accept_stream());
    WT_REQUIRE(s, !accepted);
    (void)loop;
}

// Local resets carry the mapped application code; the header stays reliable.
auto reset_server(event_loop& loop, server_side& sv, scenario& s) -> task<void>
{
    const auto id = settle(co_await next_request(loop, sv));
    std::optional<session_t> session;
    std::uint32_t slot = 0;
    WT_REQUIRE(s, settle(co_await accept_connect(loop, sv, id, session, slot)));
    auto opened = flatten_result(co_await session->async_open_stream(quic_stream_direction::bidirectional));
    WT_REQUIRE(s, opened.has_value());
    auto outgoing = std::move(*opened);
    WT_REQUIRE(s, (flatten_result(co_await outgoing.async_write(bytes_of("hd"), false))).has_value());
    WT_REQUIRE(s, outgoing.reset(42).has_value());
    auto peer = flatten_result(co_await session->async_accept_stream());
    WT_REQUIRE(s, peer.has_value());
    auto incoming = std::move(*peer);
    std::vector<std::byte> got;
    std::array<std::byte, 64> buffer {};
    for (;;) {
        auto read = flatten_result(co_await incoming.async_read(buffer));
        if (!read) {
            WT_REQUIRE(s, read.error() == make_error_code(webtransport_errc::stream_reset));
            break;
        }
        WT_REQUIRE(s, *read > 0);
        got.insert(got.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*read));
    }
    WT_REQUIRE(s, text_of(got) == "abc");
    WT_REQUIRE(s, incoming.error_code() == std::optional<std::uint32_t>(7));
    co_await keep_open(loop, s);
}

auto reset_client(event_loop& loop, client_side& cs, scenario& s) -> task<void>
{
    WT_REQUIRE(s, settle(co_await send_settings(loop, cs.connection, cs, s.setup)));
    std::uint64_t connect = 0;
    WT_REQUIRE(s, settle(co_await open_connect(loop, cs.connection, {}, connect)));
    auto stream = flatten_result(co_await cs.connection.async_open_stream(quic_stream_direction::bidirectional));
    WT_REQUIRE(s, stream.has_value());
    const auto header = wt_stream_bytes(false, 0, "abc");
    WT_REQUIRE(s, settle(co_await write_all(loop, cs.connection, *stream, header, false)));
    WT_REQUIRE(s, cs.connection.reset_stream_at(*stream, http::webtransport_to_http3_error(7), header.size()).has_value());
    auto accepted = flatten_result(co_await cs.connection.async_accept_stream());
    WT_REQUIRE(s, accepted.has_value());
    std::vector<std::byte> got;
    WT_REQUIRE(s, (settle(co_await read_to_end(loop, cs.connection, *accepted, got))) == make_error_code(quic_errc::stream_reset));
    const auto server_header = wt_stream_bytes(false, 0, "");
    WT_REQUIRE(s, got.size() >= server_header.size() && std::equal(server_header.begin(), server_header.end(), got.begin()));
    WT_REQUIRE(s, cs.connection.stream_reset_code(*accepted) == http::webtransport_to_http3_error(42));
    (void)loop;
}

} // namespace

auto main() -> int
{
    const auto directory = std::filesystem::temp_directory_path() /
                           ("eventloop-webtransport-engine-" + std::to_string(::getpid()));
    std::filesystem::create_directories(directory);
    if (!make_certificate(directory)) {
        std::fprintf(stderr, "WebTransport engine: certificate generation failed\n");
        return 1;
    }
    const auto config = [](client_setup setup = {}, http::webtransport_options options = {},
                           std::size_t connects = 1, admission expected = admission::accepted) {
        scenario c;
        c.setup = setup;
        c.options = options;
        c.connects = connects;
        c.expected = expected;
        return c;
    };
    http::webtransport_options one_session;
    one_session.max_sessions = 1;
    http::webtransport_options window;
    window.initial_max_data = 1024;
    http::webtransport_options small_streams;
    small_streams.initial_max_streams_bidi = 2;
    http::webtransport_options queue;
    queue.datagram_queue = 2;
    http::webtransport_options buffered;
    buffered.buffered_streams = 1;
    http::webtransport_options one_session_reuse;
    one_session_reuse.max_sessions = 1;
    client_setup no_wt;
    no_wt.wt_enabled = false;
    client_setup no_datagram_setting;
    no_datagram_setting.h3_datagram = false;
    client_setup no_reset_at;
    no_reset_at.reset_stream_at = false;
    client_setup no_datagram_tp;
    no_datagram_tp.datagram_tp = false;
    client_setup small_window;
    small_window.initial_data = 1000;
    client_setup small_bidi;
    small_bidi.initial_bidi = 16;

    std::size_t failures = 0;
    const auto record = [&failures](bool ok) { failures += ok ? 0 : 1; };
    record(run("admit_wt_missing", directory, config(no_wt, {}, 1, admission::malformed), admit_server, settings_client));
    record(run("admit_datagram_setting_missing", directory, config(no_datagram_setting, {}, 1, admission::malformed), admit_server, settings_client));
    record(run("admit_reset_at_missing", directory, config(no_reset_at, {}, 1, admission::malformed), admit_server, settings_client));
    record(run("admit_accepted", directory, config({}, {}, 1, admission::accepted), admit_server, settings_client));
    record(run("settings_error", directory, config(no_datagram_tp), settings_error_server, settings_error_client));
    record(run("capacity_flow_enabled", directory, config({}, one_session, 2), capacity_server, capacity_client));
    record(run("capacity_flow_disabled", directory, config(flow_off_setup(), {}, 2), capacity_server, capacity_client));
    record(run("admit_cancelled", directory, config(), cancel_server, cancel_client));
    record(run("session_streams_datagrams", directory, config(), basic_server, basic_client));
    record(run("buffering", directory, config({}, buffered), buffering_server, buffering_client));
    record(run("gone_session", directory, config(), gone_server, gone_client));
    record(run("remote_close_resets", directory, config(), remote_close_server, remote_close_client));
    record(run("local_close_drain", directory, config(), close_local_server, close_local_client));
    record(run("handler_returned", directory, config(), handler_return_server, handler_return_client));
    record(run("malformed_close", directory, config(), malformed_close_server, malformed_close_client));
    record(run("flow_block_and_renewal", directory, config(small_window, window), flow_server, flow_client));
    record(run("flow_data_violation", directory, config({}, window), flow_violation_server, flow_violation_client));
    record(run("flow_stream_violation", directory, config({}, small_streams), stream_limit_server, stream_limit_client));
    record(run("datagram_queue", directory, config({}, queue), datagram_queue_server, datagram_queue_client));
    record(run("shutdown_pending", directory, config(), shutdown_server, shutdown_client));
    record(run("slot_reuse", directory, config({}, one_session_reuse, 2), reuse_server, reuse_client));
    record(run("invalid_session_id", directory, config(), invalid_id_server, invalid_id_client));
    record(run("stream_resets", directory, config(), reset_server, reset_client));
    (void)small_bidi;
    std::filesystem::remove_all(directory);
    if (failures != 0) return 1;
    std::puts("WebTransport engine tests passed");
    return 0;
}
