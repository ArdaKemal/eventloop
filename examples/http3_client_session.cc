#include "http3_client_session.h"

#include "eventloop/event_loop.h"
#include "http3/frames.h"
#include "http3/qpack.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <limits>
#include <memory>
#include <new>
#include <optional>

namespace http3_client_example {
namespace {
using namespace eventloop;
namespace h3 = eventloop::http3::detail;
namespace wire = eventloop::quic::detail;
constexpr std::size_t peer_stream_limit = 8;
constexpr std::uint64_t body_limit = 16 * 1024 * 1024;
constexpr std::size_t section_limit = 16 * 1024;

// Incremental framing retains only the at-most-16-byte frame header. Payloads
// are delivered in chunks, so large DATA and extension frames need no staging.
struct frame_reader {
    std::array<std::byte, 16> header {};
    std::size_t used {};
    std::uint64_t type {}, remaining {};
    bool payload {false};

    template<class Begin, class Data, class End>
    auto feed(std::span<const std::byte> bytes, Begin begin, Data data, End end) -> bool
    {
        while (!bytes.empty()) {
            if (!payload) {
                if (used == header.size()) return false;
                header[used++] = bytes.front();
                bytes = bytes.subspan(1);
                const auto decoded = h3::decode_frame_header(std::span(header).first(used));
                if (!decoded) {
                    if (decoded.error() == h3::frame_error::incomplete_input) continue;
                    return false;
                }
                type = decoded->type;
                remaining = decoded->payload_size;
                if (!begin(type, remaining)) return false;
                payload = true;
                if (remaining == 0) {
                    if (!end(type)) return false;
                    payload = false; used = 0;
                }
                continue;
            }
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, bytes.size()));
            if (!data(type, bytes.first(count))) return false;
            bytes = bytes.subspan(count);
            remaining -= count;
            if (remaining == 0) {
                if (!end(type)) return false;
                payload = false; used = 0;
            }
        }
        return true;
    }
    auto complete() const noexcept -> bool { return used == 0 && !payload; }
};

// One setup allocation owns all large fixed buffers and stable task handles.
// Nothing is allocated according to lengths advertised by the peer.
struct session {
    explicit session(quic_connection& c) noexcept : connection(c) {}
    quic_connection& connection;
    task_handle<void> acceptor, deadline;
    std::array<task_handle<void>, peer_stream_limit> readers;
    std::size_t reader_count {};
    bool acceptor_started {}, deadline_started {}, stopping {};
    bool have_control {}, have_encoder {}, have_decoder {}, have_settings {};
    std::uint64_t peer_field_limit {std::numeric_limits<std::uint64_t>::max()};
    std::uint64_t request_id {}, request_field_size {}, received_body {};
    std::optional<std::uint64_t> content_length, goaway_id;
    std::error_code failure;
    bool final_headers {}, trailers {};
    unsigned informational {};
    std::array<std::byte, 4096> request {};
    std::array<std::byte, section_limit> headers {};
    std::array<char, section_limit> strings {};
    std::array<h3::field, h3::qpack_max_fields> fields {};
    std::array<std::byte, 1024> settings {};
    std::size_t header_used {}, settings_used {};

    auto fail(std::error_code error = std::make_error_code(std::errc::protocol_error)) -> void
    {
        if (stopping || failure) return;
        failure = error;
        connection.close(error);
    }
};

auto safe_field(const h3::field& f) -> bool
{
    if (f.name.empty()) return false;
    for (std::size_t i = 0; i < f.name.size(); ++i) {
        const auto c = static_cast<unsigned char>(f.name[i]);
        if (c == ':' && i == 0) continue;
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) != std::string_view::npos))
            return false;
    }
    for (const auto c : f.value) {
        const auto byte = static_cast<unsigned char>(c);
        if ((byte < 0x20 && byte != '\t') || byte == 0x7f) return false;
    }
    return f.name != "connection" && f.name != "proxy-connection" &&
        f.name != "keep-alive" && f.name != "transfer-encoding" && f.name != "upgrade";
}

auto response_headers(session& s) -> bool
{
    const auto decoded = h3::qpack_decode(std::span(s.headers).first(s.header_used), s.fields, s.strings);
    if (!decoded) return false;
    std::optional<unsigned> status;
    std::optional<std::uint64_t> length;
    bool regular = false;
    std::size_t field_size = 0;
    for (const auto& f : std::span(s.fields).first(*decoded)) {
        if (!safe_field(f)) return false;
        if (f.name.size() + f.value.size() + 32 > section_limit - field_size) return false;
        field_size += f.name.size() + f.value.size() + 32;
        if (f.name.front() == ':') {
            if (regular || s.final_headers || f.name != ":status" || status || f.value.size() != 3)
                return false;
            unsigned code {};
            const auto result = std::from_chars(f.value.data(), f.value.data() + f.value.size(), code);
            if (result.ec != std::errc{} || result.ptr != f.value.data() + f.value.size() ||
                code < 100 || code > 599 || code == 101) return false;
            status = code;
        } else regular = true;
        if (f.name == "content-length") {
            if (s.final_headers || length || f.value.empty()) return false;
            std::uint64_t value {};
            const auto result = std::from_chars(f.value.data(), f.value.data() + f.value.size(), value);
            if (result.ec != std::errc{} || result.ptr != f.value.data() + f.value.size()) return false;
            length = value;
        }
    }
    if (!s.final_headers) {
        if (!status) return false;
        if (*status < 200) {
            if (length) return false;
            if (++s.informational > 8) return false;
        } else {
            s.final_headers = true;
            s.content_length = length;
            if (*status == 204 && length) return false;
            // These statuses cannot carry DATA. Content-Length on 304 refers
            // to a selected representation rather than this response body.
            if (*status == 204 || *status == 304) s.content_length = 0;
        }
        std::fprintf(stderr, "HTTP/3 %u\n", *status);
    } else {
        if (status) return false;
        s.trailers = true;
        std::fprintf(stderr, "HTTP/3 trailers\n");
    }
    for (const auto& f : std::span(s.fields).first(*decoded)) if (f.name.front() != ':')
        std::fprintf(stderr, "%.*s: %.*s\n", static_cast<int>(f.name.size()), f.name.data(),
            static_cast<int>(f.value.size()), f.value.empty() ? "" : f.value.data());
    std::fputc('\n', stderr);
    return true;
}

auto control_frame_end(session& s, std::uint64_t type) -> bool
{
    const auto bytes = std::span(s.settings).first(s.settings_used);
    if (type == h3::settings_frame) {
        if (!h3::validate_settings(bytes, 64)) return false;
        h3::settings_iterator it(bytes);
        for (;;) {
            const auto item = it.next();
            if (!item) return false;
            if (!*item) break;
            if ((**item).identifier == h3::max_field_section_size)
                s.peer_field_limit = (**item).value;
            // Server table/blocked limits constrain our encoder; it never uses
            // a dynamic reference, regardless of these advertised values.
        }
        s.have_settings = true;
        return true;
    }
    if (type == h3::goaway_frame) {
        const auto id = wire::decode_varint(bytes);
        if (!id || id->encoded_size != bytes.size() || (id->value & 3u) != 0 ||
            (s.goaway_id && id->value > *s.goaway_id) || id->value <= s.request_id) return false;
        s.goaway_id = id->value;
    }
    return true;
}

auto read_peer_stream(event_loop& loop, session& s, std::uint64_t id) -> task<void>
{
    (void)loop;
    std::array<std::byte, 256> buffer {};
    std::array<std::byte, 8> type_bytes {};
    std::size_t type_used = 0;
    std::optional<std::uint64_t> type;
    frame_reader frames;
    while (!s.stopping && !s.failure && s.connection.valid()) {
        const auto count = flatten_result(co_await s.connection.async_read(id, buffer));
        if (!count || *count == 0) {
            if (count && type && *type != 0 && *type != 2 && *type != 3) co_return;
            if (!s.stopping) s.fail(count ? std::make_error_code(std::errc::protocol_error) : count.error());
            co_return;
        }
        auto bytes = std::span<const std::byte>(buffer).first(*count);
        while (!type && !bytes.empty()) {
            if (type_used == type_bytes.size()) { s.fail(); co_return; }
            type_bytes[type_used++] = bytes.front(); bytes = bytes.subspan(1);
            const auto parsed = wire::decode_varint(std::span(type_bytes).first(type_used));
            if (!parsed) continue;
            type = parsed->value;
            bool* seen = *type == 0 ? &s.have_control : *type == 2 ? &s.have_encoder :
                *type == 3 ? &s.have_decoder : nullptr;
            if (seen && *seen) { s.fail(); co_return; }
            if (seen) *seen = true;
            // Push is deliberately disabled (no MAX_PUSH_ID was sent).
            if (*type == 1) { s.fail(std::make_error_code(std::errc::not_supported)); co_return; }
        }
        if (!type) continue;
        if (*type == 0) {
            const auto ok = frames.feed(bytes,
                [&](std::uint64_t f, std::uint64_t n) {
                    if (!s.have_settings && f != h3::settings_frame) return false;
                    if (f == h3::settings_frame && s.have_settings) return false;
                    if (h3::known_frame_type(f) && f != h3::settings_frame && f != h3::goaway_frame)
                        return false;
                    if (n > body_limit || ((f == h3::settings_frame || f == h3::goaway_frame) && n > s.settings.size()))
                        return false;
                    s.settings_used = 0;
                    return true;
                },
                [&](std::uint64_t f, std::span<const std::byte> part) {
                    if (f == h3::settings_frame || f == h3::goaway_frame) {
                        std::copy(part.begin(), part.end(), s.settings.begin() + static_cast<std::ptrdiff_t>(s.settings_used));
                        s.settings_used += part.size();
                    }
                    return true;
                }, [&](std::uint64_t f) { return control_frame_end(s, f); });
            if (!ok) { s.fail(); co_return; }
        } else if (*type == 2) {
            // With capacity zero every permitted instruction is the single
            // octet 0x20. Chunk boundaries cannot split a valid instruction.
            if (!h3::qpack_validate_encoder_instructions(bytes)) { s.fail(); co_return; }
        } else if (*type == 3 && !bytes.empty()) {
            // Our encoder never inserts; there is nothing to acknowledge or
            // cancel and any decoder instruction is invalid in this session.
            s.fail(); co_return;
        }
        // Unknown uni stream types are drained and ignored in fixed storage.
    }
}

auto accept_peer_streams(event_loop& loop, session& s) -> task<void>
{
    while (!s.stopping && !s.failure) {
        const auto id = flatten_result(co_await s.connection.async_accept_stream());
        if (!id) { if (!s.stopping) s.fail(id.error()); co_return; }
        if ((*id & 3u) != 3u || s.reader_count == s.readers.size()) { s.fail(); co_return; }
        auto& observed = s.readers[s.reader_count];
        if (loop.spawn(read_peer_stream(loop, s, *id), observed) != task_spawn_result::accepted) {
            s.fail(std::make_error_code(std::errc::not_enough_memory)); co_return;
        }
        ++s.reader_count;
    }
}

auto timeout(event_loop& loop, session& s) -> task<void>
{
    if (co_await sleep_for(loop, std::chrono::seconds(30)) == timer_wait_result::expired)
        s.fail(std::make_error_code(std::errc::timed_out));
}

auto write_all(event_loop& loop, session& s, std::uint64_t id,
    std::span<const std::byte> bytes, bool fin)
    -> task<std::expected<void, std::error_code>>
{
    (void)loop;
    while (!bytes.empty()) {
        if (s.failure || !s.connection.valid())
            co_return std::unexpected(s.failure ? s.failure : make_error_code(quic_errc::peer_closed));
        const auto count = flatten_result(co_await s.connection.async_write(id, bytes, false));
        if (!count) co_return std::unexpected(count.error());
        if (*count == 0 || *count > bytes.size())
            co_return std::unexpected(std::make_error_code(std::errc::io_error));
        bytes = bytes.subspan(*count);
    }
    // Publish FIN only after every byte was accepted, even if an implementation
    // returns a partial count. Critical uni streams remain open.
    if (fin) {
        if (s.failure || !s.connection.valid())
            co_return std::unexpected(s.failure ? s.failure : make_error_code(quic_errc::peer_closed));
        const auto closed = flatten_result(co_await s.connection.async_write(id, {}, true));
        if (!closed) co_return std::unexpected(closed.error());
        if (*closed != 0) co_return std::unexpected(std::make_error_code(std::errc::io_error));
    }
    co_return std::expected<void, std::error_code>{};
}

auto exchange(event_loop& loop, session& s, std::string_view authority, std::string_view path)
    -> task<std::expected<void, std::error_code>>
{
    if (s.failure || !s.connection.valid())
        co_return std::unexpected(s.failure ? s.failure : make_error_code(quic_errc::peer_closed));
    std::array<std::byte, 128> setup {};
    const std::array<h3::setting, 3> settings {{{h3::qpack_max_table_capacity, 0},
        {h3::qpack_blocked_streams, 0}, {h3::max_field_section_size, section_limit}}};
    const auto settings_size = h3::encode_settings(settings, setup, 3);
    if (!settings_size) co_return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    const auto framed = h3::encode_frame(h3::settings_frame, std::span(setup).first(*settings_size),
        std::span(setup).subspan(1));
    if (!framed) co_return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    setup[0] = std::byte{0};
    auto stream = flatten_result(co_await s.connection.async_open_stream(quic_stream_direction::unidirectional));
    if (!stream) co_return std::unexpected(stream.error());
    auto written = flatten_result(co_await write_all(loop, s, *stream, std::span(setup).first(*framed + 1), false));
    if (!written) co_return std::unexpected(written.error());
    for (unsigned type : {2u, 3u}) {
        if (s.failure || !s.connection.valid())
            co_return std::unexpected(s.failure ? s.failure : make_error_code(quic_errc::peer_closed));
        stream = flatten_result(co_await s.connection.async_open_stream(quic_stream_direction::unidirectional));
        if (!stream) co_return std::unexpected(stream.error());
        setup[0] = static_cast<std::byte>(type);
        written = flatten_result(co_await write_all(loop, s, *stream, std::span(setup).first(1), false));
        if (!written) co_return std::unexpected(written.error());
    }
    // SETTINGS is processed by independent stream readers. A short cancellable
    // timer avoids spinning while this example waits for the peer's limits.
    while (!s.have_settings && !s.failure) {
        if (co_await sleep_for(loop, std::chrono::milliseconds(5)) == timer_wait_result::cancelled)
            co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }
    if (s.failure) co_return std::unexpected(s.failure);
    const std::array<h3::field, 5> request {{{":method", "GET"}, {":scheme", "https"},
        {":authority", authority}, {":path", path}, {"user-agent", "eventloop-http3-example"}}};
    for (const auto& f : request) s.request_field_size += f.name.size() + f.value.size() + 32;
    if (s.request_field_size > s.peer_field_limit)
        co_return std::unexpected(std::make_error_code(std::errc::message_size));
    const auto qpack_size = h3::qpack_encode(request, std::span(s.request).subspan(16));
    if (!qpack_size) co_return std::unexpected(std::make_error_code(std::errc::message_size));
    const auto request_size = h3::encode_frame(h3::headers_frame,
        std::span(s.request).subspan(16, *qpack_size), s.request);
    if (!request_size) co_return std::unexpected(std::make_error_code(std::errc::message_size));
    stream = flatten_result(co_await s.connection.async_open_stream(quic_stream_direction::bidirectional));
    if (!stream) co_return std::unexpected(stream.error());
    s.request_id = *stream;
    written = flatten_result(co_await write_all(loop, s, *stream, std::span(s.request).first(*request_size), true));
    if (!written) co_return std::unexpected(written.error());
    std::array<std::byte, 256> buffer {};
    frame_reader frames;
    for (;;) {
        if (s.failure || !s.connection.valid())
            co_return std::unexpected(s.failure ? s.failure : make_error_code(quic_errc::peer_closed));
        const auto count = flatten_result(co_await s.connection.async_read(*stream, buffer));
        if (!count) co_return std::unexpected(count.error());
        if (*count == 0) break;
        const auto ok = frames.feed(std::span(buffer).first(*count),
            [&](std::uint64_t f, std::uint64_t n) {
                if (f == h3::headers_frame) {
                    if (s.trailers || n > s.headers.size()) return false;
                    s.header_used = 0;
                } else if (f == h3::data_frame) {
                    if (!s.final_headers || s.trailers || n > body_limit - s.received_body ||
                        (s.content_length && n > *s.content_length - s.received_body)) return false;
                } else if (h3::known_frame_type(f) || n > body_limit) return false;
                return true;
            },
            [&](std::uint64_t f, std::span<const std::byte> part) {
                if (f == h3::headers_frame) {
                    std::copy(part.begin(), part.end(), s.headers.begin() + static_cast<std::ptrdiff_t>(s.header_used));
                    s.header_used += part.size();
                } else if (f == h3::data_frame) {
                    if (std::fwrite(part.data(), 1, part.size(), stdout) != part.size()) return false;
                    s.received_body += part.size();
                }
                return true;
            }, [&](std::uint64_t f) { return f != h3::headers_frame || response_headers(s); });
        if (!ok) {
            co_return std::unexpected(std::make_error_code(std::errc::protocol_error));
        }
    }
    if (!frames.complete() || !s.final_headers ||
        (s.content_length && *s.content_length != s.received_body)) {
        co_return std::unexpected(std::make_error_code(std::errc::protocol_error));
    }
    if (std::fflush(stdout) != 0) co_return std::unexpected(std::make_error_code(std::errc::io_error));
    co_return std::expected<void, std::error_code>{};
}
} // namespace

auto perform_get(eventloop::event_loop& loop, eventloop::quic_connection& connection,
    std::string_view authority, std::string_view path)
    -> eventloop::task<std::expected<void, std::error_code>>
{
    if (!connection.valid() || authority.empty() || path.empty() || path.front() != '/' ||
        authority.size() > 512 || path.size() > 2048)
        co_return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    for (const auto text : {authority, path}) for (const auto c : text)
        if (static_cast<unsigned char>(c) <= 0x20 || static_cast<unsigned char>(c) == 0x7f)
            co_return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    // String views supplied by the caller must live until this task returns.
    std::unique_ptr<session> state(new (std::nothrow) session(connection));
    if (!state) co_return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    auto& s = *state;
    s.deadline_started = loop.spawn(timeout(loop, s), s.deadline) == task_spawn_result::accepted;
    s.acceptor_started = loop.spawn(accept_peer_streams(loop, s), s.acceptor) == task_spawn_result::accepted;
    std::expected<void, std::error_code> result;
    if (!s.deadline_started || !s.acceptor_started)
        result = std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    else result = flatten_result(co_await exchange(loop, s, authority, path));
    if (s.failure) result = std::unexpected(s.failure);
    s.stopping = true;
    connection.close();
    if (s.acceptor_started) { (void)s.acceptor.cancel(); (void)co_await s.acceptor; }
    for (std::size_t i = 0; i < s.reader_count; ++i) {
        (void)s.readers[i].cancel();
        (void)co_await s.readers[i];
    }
    if (s.deadline_started) { (void)s.deadline.cancel(); (void)co_await s.deadline; }
    co_return result;
}
} // namespace http3_client_example
