#include "eventloop/http3/client.h"

#include "errors.h"
#include "frames.h"
#include "http/client_fields.h"
#include "qpack.h"
#include "quic/varint.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace eventloop::http3 {
namespace {

using detail::h3_error;
namespace wire = quic::detail;

constexpr std::array<std::uint8_t, 2> alpn {'h', '3'};
// Response field sections are buffered whole; SETTINGS_MAX_FIELD_SECTION_SIZE
// advertises the same bound, and request sections share it.
constexpr std::size_t section_limit = detail::qpack_max_block_size;
constexpr std::size_t chunk_size = 16 * 1024;
// Room for a DATA or HEADERS frame header in front of its payload.
constexpr std::size_t frame_header_room = 16;
constexpr std::size_t control_payload_limit = 1024;
constexpr std::size_t max_peer_settings = 64;

[[nodiscard]] auto failure(std::errc code) -> std::error_code
{
    return std::make_error_code(code);
}

[[nodiscard]] auto close_code(std::error_code error) -> h3_error
{
    return error == failure(std::errc::protocol_error) ? h3_error::general_protocol_error
                                                       : h3_error::request_cancelled;
}

template<class Callback, class... Args>
[[nodiscard]] auto invoke_callback(Callback& callback, Args&&... args) -> std::error_code
{
    try {
        return callback(std::forward<Args>(args)...);
    } catch (const std::system_error& error) {
        return error.code();
    } catch (...) {
        return failure(std::errc::io_error);
    }
}

// Incremental framing retains only the at-most-16-byte frame header. Payloads
// are delivered in chunks, so DATA and extension frames need no staging.
// Callbacks return false to stop; malformed reports a bad frame header.
struct frame_reader {
    std::array<std::byte, frame_header_room> header {};
    std::size_t used {};
    std::uint64_t type {}, remaining {};
    bool payload {false};
    bool malformed {false};

    template<class Begin, class Data, class End>
    auto feed(std::span<const std::byte> bytes, Begin begin, Data data, End end) -> bool
    {
        while (!bytes.empty()) {
            if (!payload) {
                if (used == header.size()) return !(malformed = true);
                header[used++] = bytes.front();
                bytes = bytes.subspan(1);
                const auto decoded = detail::decode_frame_header(std::span(header).first(used));
                if (!decoded) {
                    if (decoded.error() == detail::frame_error::incomplete_input) continue;
                    return !(malformed = true);
                }
                type = decoded->type;
                remaining = decoded->payload_size;
                if (!begin(type, remaining)) return false;
                payload = true;
            } else {
                const auto count = static_cast<std::size_t>(
                    std::min<std::uint64_t>(remaining, bytes.size()));
                if (!data(type, bytes.first(count))) return false;
                bytes = bytes.subspan(count);
                remaining -= count;
            }
            if (remaining == 0) {
                if (!end(type)) return false;
                payload = false;
                used = 0;
            }
        }
        return true;
    }
    [[nodiscard]] auto complete() const noexcept -> bool { return used == 0 && !payload; }
};

// Peer QPACK decoder stream. With no dynamic table only Stream Cancellation
// (RFC 9204 4.4.2) is valid; its stream ID needs no action.
struct decoder_instructions {
    bool continuing {false};
    unsigned shift {0};

    [[nodiscard]] auto feed(std::span<const std::byte> bytes) noexcept -> bool
    {
        for (const auto byte : bytes) {
            const auto value = std::to_integer<unsigned>(byte);
            if (!continuing) {
                if ((value & 0xc0u) != 0x40u) return false;
                continuing = (value & 0x3fu) == 0x3fu;
                shift = 0;
            } else {
                if (shift > 56) return false;
                shift += 7;
                continuing = (value & 0x80u) != 0;
            }
        }
        return true;
    }
};

[[nodiscard]] auto write_all(event_loop& loop, quic_connection& connection,
                             std::uint64_t stream, std::span<const std::byte> bytes, bool fin)
    -> task<std::expected<void, std::error_code>>
{
    (void)loop;
    for (;;) {
        const auto written = flatten_result(co_await connection.async_write(stream, bytes, fin));
        if (!written) co_return std::unexpected(written.error());
        if (*written > bytes.size() || (*written == 0 && !bytes.empty()))
            co_return std::unexpected(failure(std::errc::io_error));
        bytes = bytes.subspan(*written);
        if (bytes.empty()) co_return std::expected<void, std::error_code> {};
    }
}

} // namespace

struct client_connection::state {
    state(event_loop& owner, ip_endpoint peer, std::string name, client_options settings)
        : loop(owner), endpoint(peer), hostname(std::move(name)), options(std::move(settings)) {}

    struct operation_guard {
        explicit operation_guard(bool& active) noexcept : active(active) { active = true; }
        ~operation_guard() { active = false; }
        operation_guard(const operation_guard&) = delete;
        auto operator=(const operation_guard&) -> operation_guard& = delete;
        bool& active;
    };

    // Connection-lifetime storage, allocated once by async_connect(). Requests
    // are sequential, so field and stream buffers are shared between them.
    struct buffers {
        std::array<detail::field, detail::qpack_max_fields> fields {};
        std::array<char, section_limit> strings {};
        std::array<std::byte, frame_header_room + section_limit> request_section {};
        std::array<std::byte, section_limit> response_section {};
        std::array<std::byte, chunk_size> read {};
        std::array<std::byte, frame_header_room + chunk_size> upload {};
        std::array<std::byte, control_payload_limit> control {};
    };

    event_loop& loop;
    ip_endpoint endpoint;
    std::string hostname;
    client_options options;
    std::optional<quic_endpoint> quic;
    quic_connection connection;
    std::unique_ptr<buffers> storage;
    // Peer unidirectional streams: control, QPACK encoder, QPACK decoder.
    std::optional<task_handle<void>> acceptor;
    std::array<std::optional<task_handle<void>>, 3> readers;
    std::optional<task_handle<void>> upload;
    bool started {false};
    bool busy {false};
    bool stopping {false};
    bool have_settings {false};
    std::error_code closed_by;
    std::uint64_t peer_field_limit {std::numeric_limits<std::uint64_t>::max()};
    std::optional<std::uint64_t> goaway_id;
    std::optional<std::uint64_t> active_stream;

    [[nodiscard]] auto usable() const noexcept -> bool
    {
        return connection.valid() && !closed_by && !goaway_id && !stopping;
    }

    // Records the first failure and closes the connection, which wakes every
    // pending stream operation.
    auto fail(std::error_code error, h3_error code) noexcept -> void
    {
        if (stopping || closed_by) return;
        closed_by = error;
        if (connection.valid()) connection.close_application(std::to_underlying(code));
    }

    [[nodiscard]] auto encode_request(const client_request& request, std::string_view authority)
        -> std::expected<std::size_t, std::error_code>;
    [[nodiscard]] auto apply_section(std::span<const std::byte> block,
                                     client_response& response, bool trailers) -> std::error_code;
    [[nodiscard]] auto control_frame(std::uint64_t type, std::span<const std::byte> payload)
        -> h3_error;

    [[nodiscard]] static auto connect(event_loop& loop, state& self)
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] static auto request(event_loop& loop, state& self, client_request request,
                                      response_sink sink, response_header_sink header_sink)
        -> task<std::expected<client_response, std::error_code>>;
    [[nodiscard]] static auto close(event_loop& loop, state& self)
        -> task<std::expected<void, std::error_code>>;
    static auto accept_streams(event_loop& loop, state& self) -> task<void>;
    static auto read_critical_stream(event_loop& loop, state& self, std::uint64_t stream,
                                     std::uint64_t type) -> task<void>;
    static auto send_body(event_loop& loop, state& self, std::uint64_t stream,
                          client_request& request, std::optional<std::uint64_t> length)
        -> task<void>;
};

auto client_connection::state::encode_request(const client_request& request,
                                              std::string_view authority)
    -> std::expected<std::size_t, std::error_code>
{
    auto& fields = storage->fields;
    fields[0] = {":method", request.method};
    fields[1] = {":scheme", "https"};
    fields[2] = {":authority", authority};
    fields[3] = {":path", request.target};
    std::size_t count = 4;
    for (const auto& item : request.headers) fields[count++] = {item.name, item.value};
    // RFC 9114 4.2.2: names, values, and 32 bytes of overhead per field.
    std::uint64_t size = 0;
    for (const auto& field : std::span(fields).first(count))
        size += field.name.size() + field.value.size() + 32;
    if (size > peer_field_limit) return std::unexpected(failure(std::errc::message_size));
    auto& output = storage->request_section;
    const auto encoded = detail::qpack_encode(std::span(fields).first(count),
                                              std::span(output).subspan(frame_header_room));
    if (!encoded)
        return std::unexpected(failure(encoded.error() == detail::qpack_error::limit_exceeded
            ? std::errc::message_size : std::errc::invalid_argument));
    const auto framed = detail::encode_frame(detail::headers_frame,
        std::span(output).subspan(frame_header_room, *encoded), output);
    if (!framed) return std::unexpected(failure(std::errc::message_size));
    return *framed;
}

auto client_connection::state::apply_section(std::span<const std::byte> block,
                                             client_response& response, bool trailers)
    -> std::error_code
{
    const auto decoded = detail::qpack_decode(block, storage->fields, storage->strings);
    if (!decoded)
        return failure(decoded.error() == detail::qpack_error::limit_exceeded
            ? std::errc::message_size : std::errc::protocol_error);
    if (response.headers.size() + *decoded > detail::qpack_max_fields)
        return failure(std::errc::message_size);
    bool status_seen = false;
    bool regular_seen = false;
    for (const auto& field : std::span(storage->fields).first(*decoded)) {
        if (!field.name.empty() && field.name.front() == ':') {
            if (trailers || regular_seen || status_seen || field.name != ":status" ||
                field.value.size() != 3)
                return failure(std::errc::protocol_error);
            unsigned value = 0;
            const auto* end = field.value.data() + field.value.size();
            const auto parsed = std::from_chars(field.value.data(), end, value);
            if (parsed.ec != std::errc {} || parsed.ptr != end || value < 100 || value > 599)
                return failure(std::errc::protocol_error);
            response.status = value;
            status_seen = true;
        } else if (!http::detail::valid_field_name(field.name) ||
                   !http::detail::valid_field_value(field.value) ||
                   http::detail::connection_specific(field.name) || field.name == "te") {
            return failure(std::errc::protocol_error);
        } else {
            regular_seen = true;
            response.headers.push_back({std::string(field.name), std::string(field.value)});
        }
    }
    if (!trailers && !status_seen) return failure(std::errc::protocol_error);
    return {};
}

auto client_connection::state::control_frame(std::uint64_t type,
                                             std::span<const std::byte> payload) -> h3_error
{
    if (type == detail::settings_frame) {
        if (!detail::validate_settings(payload, max_peer_settings))
            return h3_error::settings_error;
        detail::settings_iterator settings(payload);
        for (;;) {
            const auto item = settings.next();
            if (!item) return h3_error::settings_error;
            if (!*item) break;
            // The encoder never references a dynamic table, so the peer's
            // table and blocked-stream limits need no action.
            if ((**item).identifier == detail::max_field_section_size)
                peer_field_limit = (**item).value;
        }
        have_settings = true;
        return h3_error::no_error;
    }
    if (type == detail::goaway_frame) {
        // RFC 9114 5.2: a client-initiated bidirectional stream ID that never
        // increases. Streams at or above it were not processed.
        const auto id = wire::decode_varint(payload);
        if (!id || id->encoded_size != payload.size()) return h3_error::frame_error;
        if ((id->value & 3u) != 0 || (goaway_id && id->value > *goaway_id))
            return h3_error::id_error;
        goaway_id = id->value;
        if (active_stream && *active_stream >= id->value)
            fail(failure(std::errc::connection_reset), h3_error::no_error);
    }
    return h3_error::no_error;
}

auto client_connection::state::connect(event_loop& loop, state& self)
    -> task<std::expected<void, std::error_code>>
{
    if (self.busy) co_return std::unexpected(failure(std::errc::device_or_resource_busy));
    if (self.started) co_return std::unexpected(failure(std::errc::already_connected));
    if (self.hostname.empty()) co_return std::unexpected(failure(std::errc::invalid_argument));
    self.started = true;
    operation_guard guard(self.busy);
    self.storage = std::make_unique<buffers>();
    quic_client_options options;
    options.alpn = alpn;
    options.trusted_ca = self.options.trusted_ca;
    options.version = self.options.version;
    self.quic.emplace(loop, self.endpoint.address_family == ip_endpoint::family::ipv4
        ? ip_endpoint::any_v4() : ip_endpoint::any_v6(), std::move(options));
    auto connected = flatten_result(co_await self.quic->async_connect(self.endpoint, self.hostname));
    if (!connected) {
        self.closed_by = connected.error();
        co_return std::unexpected(connected.error());
    }
    self.connection = std::move(*connected);
    self.acceptor.emplace();
    if (loop.spawn(accept_streams(loop, self), *self.acceptor) != task_spawn_result::accepted) {
        self.acceptor.reset();
        self.fail(failure(std::errc::not_enough_memory), h3_error::internal_error);
        co_return std::unexpected(self.closed_by);
    }
    // RFC 9114 6.2.1: SETTINGS opens the control stream. The zero QPACK table
    // and blocked-stream values are the defaults, stated for clarity.
    std::array<std::byte, 32> setup {};
    const std::array<detail::setting, 3> settings {{{detail::qpack_max_table_capacity, 0},
        {detail::qpack_blocked_streams, 0}, {detail::max_field_section_size, section_limit}}};
    const auto payload = detail::encode_settings(settings, std::span(setup).subspan(8), 3);
    const auto framed = detail::encode_frame(detail::settings_frame,
        std::span(setup).subspan(8, payload.value_or(0)), std::span(setup).subspan(1));
    if (!payload || !framed) {
        self.fail(failure(std::errc::invalid_argument), h3_error::internal_error);
        co_return std::unexpected(self.closed_by);
    }
    std::array<std::span<const std::byte>, 3> openings {std::span(setup).first(1 + *framed)};
    const std::array<std::byte, 2> qpack_types {std::byte {2}, std::byte {3}};
    openings[1] = std::span(qpack_types).first(1);
    openings[2] = std::span(qpack_types).subspan(1);
    for (const auto bytes : openings) {
        const auto stream = flatten_result(co_await self.connection.async_open_stream(
            quic_stream_direction::unidirectional));
        std::error_code error = stream ? std::error_code {} : stream.error();
        if (!error) {
            const auto written = flatten_result(co_await write_all(loop, self.connection,
                *stream, bytes, false));
            if (!written) error = written.error();
        }
        if (error) {
            self.fail(error, h3_error::internal_error);
            co_return std::unexpected(self.closed_by);
        }
    }
    if (self.closed_by) co_return std::unexpected(self.closed_by);
    co_return std::expected<void, std::error_code> {};
}

auto client_connection::state::accept_streams(event_loop& loop, state& self) -> task<void>
{
    while (!self.stopping) {
        const auto stream = flatten_result(co_await self.connection.async_accept_stream());
        if (self.stopping) co_return;
        if (!stream) {
            self.fail(stream.error(), h3_error::internal_error);
            co_return;
        }
        // A server may open only unidirectional streams (RFC 9114 6.1).
        if ((*stream & 3u) != 3u) {
            self.fail(failure(std::errc::protocol_error), h3_error::stream_creation_error);
            co_return;
        }
        // Read the stream type a byte at a time so no frame bytes are consumed.
        std::array<std::byte, 8> type_bytes {};
        std::size_t used = 0;
        std::optional<std::uint64_t> type;
        while (!type) {
            const auto read = flatten_result(co_await self.connection.async_read(
                *stream, std::span(type_bytes).subspan(used, 1)));
            if (self.stopping) co_return;
            if (!read) {
                self.fail(read.error(), h3_error::internal_error);
                co_return;
            }
            if (*read == 0) break;
            const auto decoded = wire::decode_varint(std::span(type_bytes).first(++used));
            if (decoded) type = decoded->value;
        }
        if (!type) continue;
        // Push streams are an error: no MAX_PUSH_ID was sent (RFC 9114 4.6).
        if (*type == 1) {
            self.fail(failure(std::errc::protocol_error), h3_error::id_error);
            co_return;
        }
        const auto slot = *type == 0 ? 0u : *type == 2 ? 1u : *type == 3 ? 2u : 3u;
        if (slot == 3) {
            (void)self.connection.stop_sending(
                *stream, std::to_underlying(h3_error::stream_creation_error));
            continue;
        }
        auto& reader = self.readers[slot];
        if (reader) {
            self.fail(failure(std::errc::protocol_error), h3_error::stream_creation_error);
            co_return;
        }
        reader.emplace();
        if (loop.spawn(read_critical_stream(loop, self, *stream, *type), *reader) !=
            task_spawn_result::accepted) {
            reader.reset();
            self.fail(failure(std::errc::not_enough_memory), h3_error::internal_error);
            co_return;
        }
    }
}

auto client_connection::state::read_critical_stream(event_loop& loop, state& self,
                                                    std::uint64_t stream, std::uint64_t type)
    -> task<void>
{
    (void)loop;
    std::array<std::byte, 256> buffer {};
    frame_reader frames;
    decoder_instructions instructions;
    auto& control = self.storage->control;
    std::size_t control_used = 0;
    for (;;) {
        const auto read = flatten_result(co_await self.connection.async_read(stream, buffer));
        if (self.stopping) co_return;
        if (!read || *read == 0) {
            self.fail(read ? failure(std::errc::protocol_error) : read.error(),
                      h3_error::closed_critical_stream);
            co_return;
        }
        const auto bytes = std::span<const std::byte>(buffer).first(*read);
        auto error = h3_error::no_error;
        if (type == 2) {
            if (!detail::qpack_validate_encoder_instructions(bytes))
                error = h3_error::qpack_encoder_stream_error;
        } else if (type == 3) {
            if (!instructions.feed(bytes)) error = h3_error::qpack_decoder_stream_error;
        } else {
            const auto buffered = [](std::uint64_t frame) {
                return frame == detail::settings_frame || frame == detail::goaway_frame;
            };
            const bool ok = frames.feed(bytes,
                [&](std::uint64_t frame, std::uint64_t size) {
                    if (!self.have_settings && frame != detail::settings_frame)
                        error = h3_error::missing_settings;
                    else if (frame == detail::cancel_push_frame)
                        error = h3_error::id_error;
                    else if ((frame == detail::settings_frame && self.have_settings) ||
                             (detail::known_frame_type(frame) && !buffered(frame)))
                        error = h3_error::frame_unexpected;
                    else if (buffered(frame) && size > control.size())
                        error = h3_error::excessive_load;
                    control_used = 0;
                    return error == h3_error::no_error;
                },
                [&](std::uint64_t frame, std::span<const std::byte> part) {
                    if (buffered(frame)) {
                        std::ranges::copy(part, control.begin() +
                            static_cast<std::ptrdiff_t>(control_used));
                        control_used += part.size();
                    }
                    return true;
                },
                [&](std::uint64_t frame) {
                    error = self.control_frame(frame, std::span(control).first(control_used));
                    return error == h3_error::no_error;
                });
            if (!ok && error == h3_error::no_error) error = h3_error::frame_unexpected;
        }
        if (error != h3_error::no_error) {
            self.fail(failure(std::errc::protocol_error), error);
            co_return;
        }
    }
}

auto client_connection::state::send_body(event_loop& loop, state& self, std::uint64_t stream,
                                         client_request& request,
                                         std::optional<std::uint64_t> length) -> task<void>
{
    auto& buffer = self.storage->upload;
    const auto payload = std::span(buffer).subspan(frame_header_room);
    std::uint64_t sourced = 0;
    std::size_t offset = 0;
    for (bool last = false; !last;) {
        std::size_t count = 0;
        if (request.body_source) {
            const auto produced = [&]() -> std::expected<std::size_t, std::error_code> {
                try {
                    return request.body_source(payload);
                } catch (const std::system_error& error) {
                    return std::unexpected(error.code());
                } catch (...) {
                    return std::unexpected(failure(std::errc::io_error));
                }
            }();
            std::error_code error = produced ? std::error_code {} : produced.error();
            if (!error && *produced > payload.size()) error = failure(std::errc::invalid_argument);
            else if (!error && *produced > http::detail::client_max_streamed_body - sourced)
                error = failure(std::errc::message_size);
            else if (!error && length && (*produced > *length - sourced ||
                                          (*produced == 0 && sourced != *length)))
                error = failure(std::errc::invalid_argument);
            if (error) {
                self.fail(error, h3_error::request_cancelled);
                co_return;
            }
            count = *produced;
            sourced += count;
            last = count == 0;
        } else {
            count = std::min(payload.size(), request.body.size() - offset);
            std::memcpy(payload.data(), request.body.data() + offset, count);
            offset += count;
            last = offset == request.body.size();
        }
        std::size_t header_size = 0;
        if (count != 0) {
            std::array<std::byte, frame_header_room> header {};
            header_size = detail::encode_frame_header(detail::data_frame, count, header).value_or(0);
            std::memcpy(payload.data() - header_size, header.data(), header_size);
        }
        // A peer STOP_SENDING after a complete response (RFC 9114 4.1) or a
        // closed connection ends the upload; the response reader reports any
        // failure. Cancellation leaves the stream to that reader as well.
        const auto written = flatten_result(co_await write_all(loop, self.connection, stream,
            std::span<const std::byte>(payload.data() - header_size, header_size + count), last));
        if (!written) co_return;
    }
}

auto client_connection::state::request(event_loop& loop, state& self, client_request request,
                                       response_sink sink, response_header_sink header_sink)
    -> task<std::expected<client_response, std::error_code>>
{
    if (self.busy) co_return std::unexpected(failure(std::errc::device_or_resource_busy));
    if (!self.usable()) co_return std::unexpected(failure(std::errc::not_connected));
    const std::string authority = request.authority.empty() ? self.hostname : request.authority;
    const auto length = http::detail::validate_client_request(request, authority,
                                                              detail::qpack_max_fields - 4);
    if (!length) co_return std::unexpected(length.error());
    const auto section = self.encode_request(request, authority);
    if (!section) co_return std::unexpected(section.error());
    operation_guard guard(self.busy);

    client_response response;
    std::error_code error;
    const auto stream = flatten_result(co_await self.connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!stream) error = stream.error();
    else if (self.goaway_id && *stream >= *self.goaway_id)
        error = failure(std::errc::connection_reset);
    const bool has_body = !request.body.empty() || static_cast<bool>(request.body_source);
    if (!error) {
        self.active_stream = *stream;
        const auto written = flatten_result(co_await write_all(loop, self.connection, *stream,
            std::span(self.storage->request_section).first(*section), !has_body));
        if (!written) error = written.error();
    }
    // The body is sent beside the response reader, so an early response is
    // read while the upload waits for flow control.
    if (!error && has_body) {
        self.upload.emplace();
        if (loop.spawn(send_body(loop, self, *stream, request, *length), *self.upload) !=
            task_spawn_result::accepted) {
            self.upload.reset();
            error = failure(std::errc::not_enough_memory);
        }
    }

    frame_reader frames;
    bool final_headers = false;
    bool trailers = false;
    bool bodyless = false;
    std::optional<std::uint64_t> response_length;
    std::uint64_t received = 0;
    std::size_t section_used = 0;
    auto& section_buffer = self.storage->response_section;
    const auto headers_end = [&]() -> std::error_code {
        const auto start = response.headers.size();
        const auto block = std::span(section_buffer).first(section_used);
        if (final_headers) {
            trailers = true;
            if (const auto failed = self.apply_section(block, response, true)) return failed;
        } else {
            if (const auto failed = self.apply_section(block, response, false)) return failed;
            if (response.status == 101) return failure(std::errc::protocol_error);
            if (response.status >= 200) {
                final_headers = true;
                bodyless = request.method == "HEAD" || response.status == 204 ||
                           response.status == 304;
                const auto declared = http::detail::content_length(response.headers);
                if (!declared) return declared.error();
                if (!bodyless) response_length = *declared;
            }
        }
        if (header_sink) {
            const auto status = trailers ? 0u : response.status;
            const auto fields = std::span<const header>(response.headers).subspan(start);
            if (const auto failed = invoke_callback(header_sink, status, fields)) return failed;
        }
        if (!final_headers) {
            response.status = 0;
            response.headers.clear();
        }
        return {};
    };
    while (!error) {
        const auto read = flatten_result(co_await self.connection.async_read(
            *stream, self.storage->read));
        if (!read) {
            error = read.error() == make_error_code(quic_errc::stream_reset)
                ? failure(std::errc::connection_reset) : read.error();
            break;
        }
        if (*read == 0) break;
        const bool ok = frames.feed(std::span<const std::byte>(self.storage->read).first(*read),
            [&](std::uint64_t type, std::uint64_t size) {
                if (type == detail::headers_frame) {
                    if (trailers) error = failure(std::errc::protocol_error);
                    else if (size > section_buffer.size()) error = failure(std::errc::message_size);
                    section_used = 0;
                } else if (type == detail::data_frame) {
                    const auto limit = sink ? http::detail::client_max_streamed_body
                                            : http::detail::client_max_body;
                    if (!final_headers || trailers || (bodyless && size != 0) ||
                        (response_length && size > *response_length - received))
                        error = failure(std::errc::protocol_error);
                    else if (size > limit - received) error = failure(std::errc::message_size);
                    else received += size;
                } else if (detail::known_frame_type(type)) {
                    error = failure(std::errc::protocol_error);
                }
                return !error;
            },
            [&](std::uint64_t type, std::span<const std::byte> part) {
                if (type == detail::headers_frame) {
                    std::ranges::copy(part, section_buffer.begin() +
                        static_cast<std::ptrdiff_t>(section_used));
                    section_used += part.size();
                } else if (type == detail::data_frame) {
                    if (sink) error = invoke_callback(sink, part);
                    else response.body.insert(response.body.end(), part.begin(), part.end());
                }
                return !error;
            },
            [&](std::uint64_t type) {
                if (type == detail::headers_frame) error = headers_end();
                return !error;
            });
        if (!ok && !error) error = failure(std::errc::protocol_error);
    }
    if (!error && (!frames.complete() || !final_headers ||
                   (response_length && received != *response_length)))
        error = failure(std::errc::protocol_error);
    // An upload source failure or GOAWAY closes the connection; report its cause.
    if (error && self.closed_by) error = self.closed_by;
    if (self.upload) {
        // A complete response can precede the whole request (RFC 9114 4.1).
        if (!self.upload->done()) {
            (void)self.connection.reset_stream(*stream,
                std::to_underlying(h3_error::request_cancelled));
            (void)self.upload->cancel();
        }
        (void)co_await *self.upload;
        self.upload.reset();
        if (!error && self.closed_by) error = self.closed_by;
    }
    self.active_stream.reset();
    if (error) {
        self.fail(error, close_code(error));
        co_return std::unexpected(error);
    }
    co_return response;
}

auto client_connection::state::close(event_loop& loop, state& self)
    -> task<std::expected<void, std::error_code>>
{
    if (self.busy) co_return std::unexpected(failure(std::errc::device_or_resource_busy));
    if (!self.quic) co_return std::expected<void, std::error_code> {};
    operation_guard guard(self.busy);
    if (self.connection.valid() && !self.closed_by)
        self.connection.close_application(std::to_underlying(h3_error::no_error));
    self.stopping = true;
    if (self.acceptor) {
        (void)self.acceptor->cancel();
        (void)co_await *self.acceptor;
        self.acceptor.reset();
    }
    for (auto& reader : self.readers) {
        if (!reader) continue;
        (void)reader->cancel();
        (void)co_await *reader;
        reader.reset();
    }
    self.connection = {};
    (void)co_await self.quic->async_close();
    self.quic.reset();
    self.storage.reset();
    (void)loop;
    co_return std::expected<void, std::error_code> {};
}

client_connection::client_connection(event_loop& loop, ip_endpoint endpoint,
                                     std::string hostname, client_options options)
    : state_(std::make_unique<state>(loop, endpoint, std::move(hostname), std::move(options)))
{
}

client_connection::~client_connection()
{
    // Background stream readers and the endpoint's drivers still reference
    // this state until async_close() completes.
    if (state_->quic) std::terminate();
}

auto client_connection::async_connect() -> task<std::expected<void, std::error_code>>
{
    return state::connect(state_->loop, *state_);
}

auto client_connection::async_request(client_request request, response_sink sink,
                                      response_header_sink header_sink)
    -> task<std::expected<client_response, std::error_code>>
{
    return state::request(state_->loop, *state_, std::move(request), std::move(sink),
                          std::move(header_sink));
}

auto client_connection::close() noexcept -> void
{
    auto& self = *state_;
    self.fail(failure(std::errc::operation_canceled), h3_error::request_cancelled);
    if (self.quic) self.quic->close();
}

auto client_connection::async_close() -> task<std::expected<void, std::error_code>>
{
    return state::close(state_->loop, *state_);
}

} // namespace eventloop::http3
