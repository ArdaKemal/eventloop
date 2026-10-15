#include "webtransport_client.h"

#include "eventloop/event_loop.h"
#include "http3/frames.h"
#include "http3/qpack.h"
#include "http3/webtransport_wire.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <type_traits>
#include <variant>

// Coroutines take the owning loop first: the library allocates coroutine frames
// from it. Member functions forward to the free coroutines below.
namespace eventloop::webtransport_fixture {
namespace {

namespace h3 = eventloop::http3::detail;
namespace wire = eventloop::http3::detail;

constexpr std::uint64_t control_stream_type = 0x00;
constexpr std::uint64_t encoder_stream_type = 0x02;
constexpr std::uint64_t decoder_stream_type = 0x03;
constexpr std::uint64_t connect_protocol_setting = 0x08;
constexpr std::uint64_t h3_datagram_setting = 0x33;
constexpr std::size_t read_chunk = 4096;
constexpr std::size_t max_header_block = 16 * 1024;
constexpr std::size_t max_settings_payload = 1024;
constexpr std::size_t max_datagram = 1500;

using expected_void = std::expected<void, std::error_code>;
template<typename T>
using expected_t = std::expected<T, std::error_code>;

[[nodiscard]] auto protocol_error() -> std::error_code
{
    return std::make_error_code(std::errc::protocol_error);
}

[[nodiscard]] auto invalid() -> std::error_code
{
    return std::make_error_code(std::errc::invalid_argument);
}

[[nodiscard]] auto peer_closed() -> std::error_code
{
    return make_error_code(quic_errc::peer_closed);
}

} // namespace

// Buffered input for one request stream. The frame and capsule state persists
// across reads, so any byte boundary is allowed.
struct stream_state {
    std::uint64_t id {0};
    std::vector<std::byte> buffer = std::vector<std::byte>(read_chunk);
    std::size_t begin {0};
    std::size_t end {0};
    h3::varint_accumulator type_bits {};
    h3::varint_accumulator length_bits {};
    bool type_done {false};
    bool length_done {false};
    std::uint64_t frame_type {0};
    std::uint64_t remaining {0};
    std::vector<std::byte> header_block;
    wire::capsule_parser parser {true, 1232};
};

// The client's connection state; allocated once, so its address is stable.
struct client_core {
    client_core([[maybe_unused]] event_loop& loop, ip_endpoint local, const client_options& options)
        : settings(options.settings), endpoint(loop, local, endpoint_options(options)) {}

    [[nodiscard]] static auto endpoint_options(const client_options& options) -> quic_client_options
    {
        quic_client_options result;
        result.alpn = h3_alpn;
        result.limits = options.limits;
        result.trusted_ca = options.trusted_ca;
        return result;
    }

    client_settings settings;
    quic_endpoint endpoint;
    quic_connection connection;
    server_settings peer;
    std::uint64_t control_stream {0};
    std::uint64_t encoder_stream {0};
    std::uint64_t decoder_stream {0};
};

namespace {

[[nodiscard]] auto pending(const stream_state& state) noexcept -> std::span<const std::byte>
{
    return std::span<const std::byte>(state.buffer).subspan(state.begin, state.end - state.begin);
}

auto consume(stream_state& state, std::span<const std::byte> rest) noexcept -> void
{
    state.begin = state.end - rest.size();
}

auto reset_frame(stream_state& state) noexcept -> void
{
    state.type_bits = {};
    state.length_bits = {};
    state.type_done = false;
    state.length_done = false;
    state.remaining = 0;
}

// Consumes frame header bytes. True once the frame type and length are known.
auto step_header(stream_state& state, std::span<const std::byte>& input) noexcept -> bool
{
    if (!state.type_done) {
        const auto type = state.type_bits.feed(input);
        if (!type) return false;
        state.frame_type = *type;
        state.type_done = true;
    }
    if (!state.length_done) {
        const auto length = state.length_bits.feed(input);
        if (!length) return false;
        state.remaining = *length;
        state.length_done = true;
    }
    return true;
}

// Skips the unwanted part of the current frame's payload.
auto skip_payload(stream_state& state, std::span<const std::byte>& input) noexcept -> void
{
    const auto take = static_cast<std::size_t>(std::min<std::uint64_t>(state.remaining, input.size()));
    input = input.subspan(take);
    state.remaining -= take;
    if (state.remaining == 0) reset_frame(state);
}

[[nodiscard]] auto to_capsule(const wire::capsule_event& event) -> capsule
{
    using kind = capsule::kind;
    return std::visit([](const auto& value) -> capsule {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, wire::wt_close_session>)
            return {kind::close_session, 0, value.code, std::string(value.message)};
        else if constexpr (std::is_same_v<T, wire::wt_drain_session>)
            return {kind::drain_session, 0, 0, {}};
        else if constexpr (std::is_same_v<T, wire::wt_max_data>)
            return {kind::max_data, value.maximum, 0, {}};
        else if constexpr (std::is_same_v<T, wire::wt_data_blocked>)
            return {kind::data_blocked, value.maximum, 0, {}};
        else if constexpr (std::is_same_v<T, wire::wt_max_streams>)
            return {value.bidirectional ? kind::max_streams_bidi : kind::max_streams_uni,
                    value.maximum, 0, {}};
        else if constexpr (std::is_same_v<T, wire::wt_streams_blocked>)
            return {value.bidirectional ? kind::streams_blocked_bidi : kind::streams_blocked_uni,
                    value.maximum, 0, {}};
        else
            return {kind::datagram, value.payload.size(), 0, {}};
    }, event);
}

auto apply_setting(server_settings& out, const h3::setting& item) -> void
{
    if (item.identifier == connect_protocol_setting) out.connect_protocol = item.value;
    else if (item.identifier == h3_datagram_setting) out.h3_datagram = item.value;
    else if (item.identifier == wire::wt_enabled_setting) out.wt_enabled = item.value;
    else if (item.identifier == wire::wt_initial_max_data_setting) out.initial_max_data = item.value;
    else if (item.identifier == wire::wt_initial_max_streams_bidi_setting)
        out.initial_max_streams_bidi = item.value;
    else if (item.identifier == wire::wt_initial_max_streams_uni_setting)
        out.initial_max_streams_uni = item.value;
}

// ---- Stream primitives ----------------------------------------------------

auto open_uni([[maybe_unused]] event_loop& loop, client_core& core)
    -> task<expected_t<std::uint64_t>>
{
    co_return flatten_result(co_await core.connection.async_open_stream(
        quic_stream_direction::unidirectional));
}

auto write_all([[maybe_unused]] event_loop& loop, client_core& core, std::uint64_t stream_id,
               std::span<const std::byte> bytes, bool fin)
    -> task<expected_void>
{
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        auto written = flatten_result(co_await core.connection.async_write(
            stream_id, bytes.subspan(offset), false));
        if (!written) co_return std::unexpected(written.error());
        offset += *written;
    }
    if (fin) {
        auto closed = flatten_result(co_await core.connection.async_write(stream_id, {}, true));
        if (!closed) co_return std::unexpected(closed.error());
    }
    co_return expected_void();
}

auto read_byte([[maybe_unused]] event_loop& loop, client_core& core, std::uint64_t stream_id)
    -> task<expected_t<std::byte>>
{
    std::array<std::byte, 1> byte {};
    auto count = flatten_result(co_await core.connection.async_read(stream_id, byte));
    if (!count) co_return std::unexpected(count.error());
    if (*count == 0) co_return std::unexpected(peer_closed());
    co_return byte[0];
}

// One byte at a time, so a varint never reads past its own end.
auto read_varint([[maybe_unused]] event_loop& loop, client_core& core, std::uint64_t stream_id)
    -> task<expected_t<std::uint64_t>>
{
    h3::varint_accumulator bits;
    for (;;) {
        auto byte = flatten_result(co_await read_byte(loop, core, stream_id));
        if (!byte) co_return std::unexpected(byte.error());
        std::span<const std::byte> one(&*byte, 1);
        if (const auto value = bits.feed(one)) co_return *value;
    }
}

auto read_exact([[maybe_unused]] event_loop& loop, client_core& core, std::uint64_t stream_id,
                std::span<std::byte> buffer) -> task<expected_void>
{
    std::size_t done = 0;
    while (done < buffer.size()) {
        auto count = flatten_result(co_await core.connection.async_read(stream_id, buffer.subspan(done)));
        if (!count) co_return std::unexpected(count.error());
        if (*count == 0) co_return std::unexpected(peer_closed());
        done += *count;
    }
    co_return expected_void();
}

// Reads the first frame of the control stream, which must be SETTINGS. Later
// frames are left unread.
auto read_settings([[maybe_unused]] event_loop& loop, client_core& core, std::uint64_t stream_id)
    -> task<expected_void>
{
    auto type = flatten_result(co_await read_varint(loop, core, stream_id));
    if (!type) co_return std::unexpected(type.error());
    auto length = flatten_result(co_await read_varint(loop, core, stream_id));
    if (!length) co_return std::unexpected(length.error());
    if (*type != h3::settings_frame || *length > max_settings_payload)
        co_return std::unexpected(protocol_error());
    std::vector<std::byte> payload(static_cast<std::size_t>(*length));
    auto read = flatten_result(co_await read_exact(loop, core, stream_id, payload));
    if (!read) co_return std::unexpected(read.error());
    h3::settings_iterator cursor(payload);
    for (;;) {
        auto item = cursor.next();
        if (!item) co_return std::unexpected(protocol_error());
        if (!*item) break;
        apply_setting(core.peer, **item);
    }
    core.peer.received = true;
    co_return expected_void();
}

// ---- Connection lifecycle -------------------------------------------------

auto connect_task([[maybe_unused]] event_loop& loop, client_core& core, ip_endpoint server)
    -> task<expected_void>
{
    auto connected = flatten_result(co_await core.endpoint.async_connect(server, "localhost"));
    if (!connected) co_return std::unexpected(connected.error());
    core.connection = std::move(*connected);

    std::array<std::byte, 256> control {};
    control[0] = static_cast<std::byte>(control_stream_type);
    const auto frame = encode_settings_frame(core.settings, std::span(control).subspan(1));
    if (!frame) co_return std::unexpected(frame.error());

    auto control_id = flatten_result(co_await open_uni(loop, core));
    if (!control_id) co_return std::unexpected(control_id.error());
    core.control_stream = *control_id;
    auto sent = flatten_result(co_await write_all(loop, core, core.control_stream,
        std::span<const std::byte>(control).first(1 + *frame), false));
    if (!sent) co_return std::unexpected(sent.error());

    const std::array<std::byte, 1> encoder_type {static_cast<std::byte>(encoder_stream_type)};
    auto encoder = flatten_result(co_await open_uni(loop, core));
    if (!encoder) co_return std::unexpected(encoder.error());
    core.encoder_stream = *encoder;
    sent = flatten_result(co_await write_all(loop, core, core.encoder_stream, encoder_type, false));
    if (!sent) co_return std::unexpected(sent.error());

    const std::array<std::byte, 1> decoder_type {static_cast<std::byte>(decoder_stream_type)};
    auto decoder = flatten_result(co_await open_uni(loop, core));
    if (!decoder) co_return std::unexpected(decoder.error());
    core.decoder_stream = *decoder;
    sent = flatten_result(co_await write_all(loop, core, core.decoder_stream, decoder_type, false));
    if (!sent) co_return std::unexpected(sent.error());
    co_return expected_void();
}

auto wait_settings_task([[maybe_unused]] event_loop& loop, client_core& core) -> task<expected_void>
{
    while (!core.peer.received) {
        auto accepted = flatten_result(co_await core.connection.async_accept_stream());
        if (!accepted) co_return std::unexpected(accepted.error());
        auto type = flatten_result(co_await read_varint(loop, core, *accepted));
        if (!type) co_return std::unexpected(type.error());
        // QPACK streams carry no data here, so they stay unread.
        if (*type == control_stream_type) {
            core.control_stream = *accepted;
            auto read = flatten_result(co_await read_settings(loop, core, *accepted));
            if (!read) co_return std::unexpected(read.error());
        } else if (*type != encoder_stream_type && *type != decoder_stream_type) {
            co_return std::unexpected(protocol_error());
        }
    }
    co_return expected_void();
}

auto close_task([[maybe_unused]] event_loop& loop, client_core& core) -> task<void>
{
    core.connection.close();
    co_await core.endpoint.async_close();
}

// ---- Requests and responses -----------------------------------------------

auto send_request_task([[maybe_unused]] event_loop& loop, client_core& core, request_options request)
    -> task<expected_t<request_stream>>
{
    auto id = flatten_result(co_await core.connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!id) co_return std::unexpected(id.error());
    std::array<std::byte, 2048> frame {};
    const auto size = encode_request(request, frame);
    if (!size) co_return std::unexpected(size.error());
    auto sent = flatten_result(co_await write_all(loop, core, *id,
        std::span<const std::byte>(frame).first(*size), false));
    if (!sent) co_return std::unexpected(sent.error());
    co_return request_stream(*id);
}

auto fill([[maybe_unused]] event_loop& loop, client_core& core, stream_state& state) -> task<expected_t<std::size_t>>
{
    auto count = flatten_result(co_await core.connection.async_read(state.id, state.buffer));
    if (!count) co_return std::unexpected(count.error());
    state.begin = 0;
    state.end = *count;
    co_return *count;
}

auto read_response_task([[maybe_unused]] event_loop& loop, client_core& core, stream_state& state)
    -> task<expected_t<response_head>>
{
    for (;;) {
        auto input = pending(state);
        if (input.empty()) {
            auto count = flatten_result(co_await fill(loop, core, state));
            if (!count) co_return std::unexpected(count.error());
            if (*count == 0) co_return std::unexpected(peer_closed());
            continue;
        }
        if (!step_header(state, input)) {
            consume(state, input);
            continue;
        }
        if (state.frame_type != h3::headers_frame) {
            skip_payload(state, input);
            consume(state, input);
            continue;
        }
        const auto take = static_cast<std::size_t>(std::min<std::uint64_t>(state.remaining, input.size()));
        if (state.header_block.size() + take > max_header_block)
            co_return std::unexpected(std::make_error_code(std::errc::message_size));
        state.header_block.insert(state.header_block.end(), input.begin(),
                                  input.begin() + static_cast<std::ptrdiff_t>(take));
        input = input.subspan(take);
        state.remaining -= take;
        consume(state, input);
        if (state.remaining != 0) continue;
        auto decoded = decode_response(state.header_block);
        state.header_block.clear();
        reset_frame(state);
        co_return decoded;
    }
}

auto read_body_task([[maybe_unused]] event_loop& loop, client_core& core, stream_state& state,
                    std::span<std::byte> buffer) -> task<expected_t<std::size_t>>
{
    if (buffer.empty()) co_return std::unexpected(invalid());
    for (;;) {
        auto input = pending(state);
        if (input.empty()) {
            auto count = flatten_result(co_await fill(loop, core, state));
            if (!count) co_return std::unexpected(count.error());
            if (*count == 0) co_return std::size_t {0};
            continue;
        }
        if (!step_header(state, input)) {
            consume(state, input);
            continue;
        }
        if (state.remaining == 0 || state.frame_type != h3::data_frame) {
            skip_payload(state, input);
            consume(state, input);
            continue;
        }
        const auto take = std::min({static_cast<std::size_t>(state.remaining), input.size(), buffer.size()});
        std::memcpy(buffer.data(), input.data(), take);
        input = input.subspan(take);
        state.remaining -= take;
        consume(state, input);
        if (state.remaining == 0) reset_frame(state);
        co_return take;
    }
}

auto read_capsule_task([[maybe_unused]] event_loop& loop, client_core& core, stream_state& state)
    -> task<expected_t<capsule>>
{
    for (;;) {
        auto input = pending(state);
        if (input.empty()) {
            auto count = flatten_result(co_await fill(loop, core, state));
            if (!count) co_return std::unexpected(count.error());
            if (*count == 0) co_return capsule {};
            continue;
        }
        if (!step_header(state, input)) {
            consume(state, input);
            continue;
        }
        if (state.remaining == 0 || state.frame_type != h3::data_frame) {
            skip_payload(state, input);
            consume(state, input);
            continue;
        }
        std::span<const std::byte> chunk = input.first(static_cast<std::size_t>(
            std::min<std::uint64_t>(state.remaining, input.size())));
        const auto before = chunk.size();
        auto event = state.parser.next(chunk);
        const auto used = before - chunk.size();
        input = input.subspan(used);
        state.remaining -= used;
        consume(state, input);
        if (state.remaining == 0) reset_frame(state);
        if (!event) co_return std::unexpected(protocol_error());
        if (*event) co_return to_capsule(**event);
        if (used == 0) co_return std::unexpected(protocol_error());
    }
}

auto send_capsule_task([[maybe_unused]] event_loop& loop, client_core& core, std::uint64_t stream_id,
                       std::span<const std::byte> capsule_bytes) -> task<expected_void>
{
    std::array<std::byte, 16> header {};
    const auto size = h3::encode_frame_header(h3::data_frame, capsule_bytes.size(), header);
    if (!size) co_return std::unexpected(invalid());
    auto sent = flatten_result(co_await write_all(loop, core, stream_id,
        std::span<const std::byte>(header).first(*size), false));
    if (!sent) co_return std::unexpected(sent.error());
    co_return flatten_result(co_await write_all(loop, core, stream_id, capsule_bytes, false));
}

// ---- WebTransport streams and datagrams -----------------------------------

auto open_stream_task([[maybe_unused]] event_loop& loop, client_core& core, std::uint64_t session_id,
                      bool bidirectional) -> task<expected_t<std::uint64_t>>
{
    auto id = flatten_result(co_await core.connection.async_open_stream(
        bidirectional ? quic_stream_direction::bidirectional : quic_stream_direction::unidirectional));
    if (!id) co_return std::unexpected(id.error());
    std::array<std::byte, 16> header {};
    const auto size = wire::encode_stream_header(!bidirectional, session_id, header);
    if (!size) co_return std::unexpected(invalid());
    auto sent = flatten_result(co_await write_all(loop, core, *id,
        std::span<const std::byte>(header).first(*size), false));
    if (!sent) co_return std::unexpected(sent.error());
    co_return *id;
}

auto read_all_task([[maybe_unused]] event_loop& loop, client_core& core, std::uint64_t stream_id,
                   std::span<std::byte> buffer) -> task<expected_t<std::size_t>>
{
    std::size_t total = 0;
    while (total < buffer.size()) {
        auto count = flatten_result(co_await core.connection.async_read(stream_id, buffer.subspan(total)));
        if (!count) co_return std::unexpected(count.error());
        if (*count == 0) break;
        total += *count;
    }
    co_return total;
}

auto accept_peer_task([[maybe_unused]] event_loop& loop, client_core& core) -> task<expected_t<peer_stream>>
{
    peer_stream result;
    for (;;) {
        auto accepted = flatten_result(co_await core.connection.async_accept_stream());
        if (!accepted) co_return std::unexpected(accepted.error());
        result.id = *accepted;
        auto type = flatten_result(co_await read_varint(loop, core, result.id));
        if (!type) co_return std::unexpected(type.error());
        result.type = *type;
        // The server's control and QPACK streams arrive too; they are not WebTransport.
        if (*type == wire::webtransport_uni_stream_type || *type == wire::webtransport_bidi_signal) break;
        if (*type != control_stream_type && *type != encoder_stream_type && *type != decoder_stream_type)
            co_return std::unexpected(protocol_error());
    }
    // The session ID ends the header, so no body byte is consumed.
    wire::stream_header_parser parser;
    std::optional<std::uint64_t> session;
    while (!session) {
        auto byte = flatten_result(co_await read_byte(loop, core, result.id));
        if (!byte) co_return std::unexpected(byte.error());
        std::span<const std::byte> one(&*byte, 1);
        auto parsed = parser.feed(one);
        if (!parsed) co_return std::unexpected(protocol_error());
        session = *parsed;
    }
    result.session_id = *session;
    co_return result;
}

auto send_raw_datagram_task([[maybe_unused]] event_loop& loop, client_core& core, std::span<const std::byte> bytes)
    -> task<expected_void>
{
    co_return flatten_result(co_await core.connection.async_send_datagram(bytes));
}

auto send_datagram_task([[maybe_unused]] event_loop& loop, client_core& core, std::uint64_t session_id,
                        std::span<const std::byte> payload) -> task<expected_void>
{
    std::vector<std::byte> packet(payload.size() + 8);
    const auto prefix = wire::encode_http_datagram_prefix(session_id, packet);
    if (!prefix) co_return std::unexpected(invalid());
    std::copy(payload.begin(), payload.end(), packet.begin() + static_cast<std::ptrdiff_t>(*prefix));
    co_return flatten_result(co_await send_raw_datagram_task(loop, core,
        std::span<const std::byte>(packet).first(*prefix + payload.size())));
}

auto receive_raw_task([[maybe_unused]] event_loop& loop, client_core& core)
    -> task<expected_t<std::vector<std::byte>>>
{
    std::vector<std::byte> buffer(max_datagram);
    auto count = flatten_result(co_await core.connection.async_receive_datagram(buffer));
    if (!count) co_return std::unexpected(count.error());
    buffer.resize(*count);
    co_return buffer;
}

auto receive_datagram_task([[maybe_unused]] event_loop& loop, client_core& core) -> task<expected_t<datagram>>
{
    auto raw = flatten_result(co_await receive_raw_task(loop, core));
    if (!raw) co_return std::unexpected(raw.error());
    auto parsed = wire::parse_http_datagram(*raw);
    if (!parsed) co_return std::unexpected(protocol_error());
    datagram result {.session_id = parsed->session_id, .payload = {}};
    result.payload.assign(parsed->payload.begin(), parsed->payload.end());
    co_return result;
}

} // namespace

// ---- Pure encoders and decoders -------------------------------------------

auto encode_settings_frame(const client_settings& settings, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, std::error_code>
{
    std::array<h3::setting, 8> list {};
    std::size_t count = 0;
    auto add = [&list, &count](std::uint64_t identifier, std::uint64_t value) {
        list[count++] = {identifier, value};
    };
    if (settings.connect_protocol) add(connect_protocol_setting, 1);
    if (settings.h3_datagram) add(h3_datagram_setting, 1);
    if (settings.wt_enabled) add(wire::wt_enabled_setting, 1);
    if (settings.initial_max_data) add(wire::wt_initial_max_data_setting, *settings.initial_max_data);
    if (settings.initial_max_streams_bidi)
        add(wire::wt_initial_max_streams_bidi_setting, *settings.initial_max_streams_bidi);
    if (settings.initial_max_streams_uni)
        add(wire::wt_initial_max_streams_uni_setting, *settings.initial_max_streams_uni);
    std::array<std::byte, 128> payload {};
    const auto payload_size = h3::encode_settings(std::span(list).first(count), payload, list.size());
    if (!payload_size) return std::unexpected(invalid());
    const auto size = h3::encode_frame(h3::settings_frame,
                                       std::span<const std::byte>(payload).first(*payload_size), output);
    if (!size) return std::unexpected(invalid());
    return *size;
}

auto encode_request(const request_options& request, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, std::error_code>
{
    std::array<h3::field, 9> fields {};
    std::size_t count = 0;
    auto add = [&fields, &count](std::string_view name, std::string_view value) {
        fields[count++] = {name, value};
    };
    add(":method", request.method);
    if (!request.protocol.empty()) add(":protocol", request.protocol);
    add(":scheme", request.scheme);
    add(":authority", request.authority);
    add(":path", request.path);
    if (!request.origin.empty()) add("origin", request.origin);
    if (!request.available_protocols.empty())
        add("wt-available-protocols", request.available_protocols);
    if (!request.extra_name.empty()) add(request.extra_name, request.extra_value);
    std::array<std::byte, 2048> block {};
    const auto block_size = h3::qpack_encode(std::span<const h3::field>(fields).first(count), block);
    if (!block_size) return std::unexpected(invalid());
    const auto size = h3::encode_frame(h3::headers_frame,
                                       std::span<const std::byte>(block).first(*block_size), output);
    if (!size) return std::unexpected(invalid());
    return *size;
}

auto decode_response(std::span<const std::byte> field_block) -> std::expected<response_head, std::error_code>
{
    std::array<h3::field, h3::qpack_max_fields> fields {};
    std::array<char, 4096> strings {};
    const auto count = h3::qpack_decode(field_block, fields, strings);
    if (!count) return std::unexpected(protocol_error());
    response_head result;
    bool have_status = false;
    for (std::size_t i = 0; i < *count; ++i) {
        if (fields[i].name == ":status") {
            unsigned status = 0;
            const auto value = fields[i].value;
            const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), status);
            if (error != std::errc {} || end != value.data() + value.size())
                return std::unexpected(protocol_error());
            result.status = status;
            have_status = true;
        } else if (fields[i].name == "wt-protocol") {
            result.wt_protocol = std::string(fields[i].value);
        }
    }
    if (!have_status) return std::unexpected(protocol_error());
    return result;
}

// ---- request_stream -------------------------------------------------------

request_stream::request_stream() noexcept = default;
request_stream::request_stream(std::uint64_t id) : state_(std::make_unique<stream_state>())
{
    state_->id = id;
}
request_stream::~request_stream() = default;
request_stream::request_stream(request_stream&& other) noexcept = default;
auto request_stream::operator=(request_stream&& other) noexcept -> request_stream& = default;
auto request_stream::id() const noexcept -> std::uint64_t
{
    return state_ ? state_->id : 0;
}

// ---- webtransport_client: forwarding --------------------------------------

webtransport_client::webtransport_client(event_loop& loop, ip_endpoint local, client_options options)
    : loop_(loop), core_(std::make_unique<client_core>(loop, local, options))
{
}

webtransport_client::~webtransport_client() = default;

auto webtransport_client::connection() noexcept -> quic_connection&
{
    return core_->connection;
}

auto webtransport_client::peer_settings() const noexcept -> const server_settings&
{
    return core_->peer;
}

auto webtransport_client::async_connect(ip_endpoint server) -> task<expected_void>
{
    return connect_task(loop_, *core_, server);
}

auto webtransport_client::async_wait_server_settings() -> task<expected_void>
{
    return wait_settings_task(loop_, *core_);
}

auto webtransport_client::async_close() -> task<void>
{
    return close_task(loop_, *core_);
}

auto webtransport_client::async_send_request(const request_options& request)
    -> task<expected_t<request_stream>>
{
    return send_request_task(loop_, *core_, request);
}

auto webtransport_client::async_read_response(request_stream& stream)
    -> task<expected_t<response_head>>
{
    return read_response_task(loop_, *core_, *stream.state_);
}

auto webtransport_client::async_read_body(request_stream& stream, std::span<std::byte> buffer)
    -> task<expected_t<std::size_t>>
{
    return read_body_task(loop_, *core_, *stream.state_, buffer);
}

auto webtransport_client::async_read_capsule(request_stream& stream) -> task<expected_t<capsule>>
{
    return read_capsule_task(loop_, *core_, *stream.state_);
}

auto webtransport_client::async_send_capsule(request_stream& stream,
                                             std::span<const std::byte> capsule_bytes)
    -> task<expected_void>
{
    return send_capsule_task(loop_, *core_, stream.id(), capsule_bytes);
}

auto webtransport_client::async_write_raw(request_stream& stream, std::span<const std::byte> bytes,
                                          bool fin) -> task<expected_void>
{
    return write_all(loop_, *core_, stream.id(), bytes, fin);
}

auto webtransport_client::async_open_stream(std::uint64_t session_id, bool bidirectional)
    -> task<expected_t<std::uint64_t>>
{
    return open_stream_task(loop_, *core_, session_id, bidirectional);
}

auto webtransport_client::async_write_all(std::uint64_t stream_id,
                                          std::span<const std::byte> bytes, bool fin)
    -> task<expected_void>
{
    return write_all(loop_, *core_, stream_id, bytes, fin);
}

auto webtransport_client::async_read_all(std::uint64_t stream_id, std::span<std::byte> buffer)
    -> task<expected_t<std::size_t>>
{
    return read_all_task(loop_, *core_, stream_id, buffer);
}

auto webtransport_client::async_accept_peer_stream() -> task<expected_t<peer_stream>>
{
    return accept_peer_task(loop_, *core_);
}

auto webtransport_client::async_send_datagram(std::uint64_t session_id,
                                              std::span<const std::byte> payload)
    -> task<expected_void>
{
    return send_datagram_task(loop_, *core_, session_id, payload);
}

auto webtransport_client::async_send_raw_datagram(std::span<const std::byte> bytes)
    -> task<expected_void>
{
    return send_raw_datagram_task(loop_, *core_, bytes);
}

auto webtransport_client::async_receive_datagram() -> task<expected_t<datagram>>
{
    return receive_datagram_task(loop_, *core_);
}

auto webtransport_client::async_receive_raw_datagram() -> task<expected_t<std::vector<std::byte>>>
{
    return receive_raw_task(loop_, *core_);
}

} // namespace eventloop::webtransport_fixture
