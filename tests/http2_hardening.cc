#include "http2/hpack.h"
#include "http2/session.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

using eventloop::http2::detail::field;
using eventloop::http2::detail::hpack_encode;
using eventloop::http2::detail::hpack_error;
using eventloop::http2::detail::request;
using eventloop::http2::detail::session;

namespace {

constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr std::uint32_t protocol_error = 1;
constexpr std::uint32_t stream_closed_error = 5;
constexpr std::uint32_t frame_size_error = 6;
constexpr std::uint32_t refused_stream_error = 7;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP/2 hardening: " << message << '\n';
    std::exit(1);
}

auto u32(std::span<const std::byte> bytes) -> std::uint32_t
{
    std::uint32_t value = 0;
    for (int index = 0; index < 4; ++index)
        value = (value << 8) | std::to_integer<std::uint32_t>(bytes[static_cast<std::size_t>(index)]);
    return value;
}

auto frame(std::vector<std::byte>& out, std::uint8_t type, std::uint8_t flags,
           std::uint32_t stream, std::span<const std::byte> payload = {}) -> void
{
    const auto size = payload.size();
    out.push_back(static_cast<std::byte>(size >> 16));
    out.push_back(static_cast<std::byte>(size >> 8));
    out.push_back(static_cast<std::byte>(size));
    out.push_back(static_cast<std::byte>(type));
    out.push_back(static_cast<std::byte>(flags));
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::byte>(stream >> shift));
    out.insert(out.end(), payload.begin(), payload.end());
}

auto feed(session& state, const std::vector<std::byte>& input) -> void
{
    std::span<const std::byte> rest = input;
    while (!rest.empty()) {
        auto buffer = state.read_buffer();
        check(!buffer.empty(), "session stopped reading");
        const auto count = std::min(buffer.size(), rest.size());
        std::memcpy(buffer.data(), rest.data(), count);
        state.commit_read(count);
        rest = rest.subspan(count);
    }
}

auto drain(session& state) -> void { state.consume_output(state.output().size()); }

auto connect(session& state) -> void
{
    std::vector<std::byte> input;
    for (const char c : preface) input.push_back(static_cast<std::byte>(c));
    frame(input, 4, 0, 0);
    feed(state, input);
    drain(state);
}

auto get(session& state, std::uint32_t stream, std::uint8_t flags = 5) -> void
{
    std::vector<std::byte> block;
    const std::array<field, 4> fields {{{":method", "GET"}, {":scheme", "https"},
        {":path", "/"}, {":authority", "localhost"}}};
    check(hpack_encode(fields, block) == hpack_error::none, "encode request");
    std::vector<std::byte> input;
    frame(input, 1, flags, stream, block);
    feed(state, input);
}

// Returns the error code of the first frame of `type`, or ~0u when absent.
auto error_of(session& state, std::uint8_t type, std::uint32_t stream) -> std::uint32_t
{
    auto out = state.output();
    while (out.size() >= 9) {
        const auto length = (std::to_integer<std::size_t>(out[0]) << 16) |
                            (std::to_integer<std::size_t>(out[1]) << 8) |
                             std::to_integer<std::size_t>(out[2]);
        check(out.size() >= 9 + length, "truncated frame");
        if (std::to_integer<std::uint8_t>(out[3]) == type && u32(out.subspan(5, 4)) == stream)
            return u32(out.subspan(type == 7 ? 13 : 9, 4));
        out = out.subspan(9 + length);
    }
    return ~0u;
}

// The advertised SETTINGS_MAX_CONCURRENT_STREAMS, or ~0u when absent.
auto advertised_stream_limit(std::span<const std::byte> out) -> std::uint32_t
{
    check(out.size() >= 9 && std::to_integer<std::uint8_t>(out[3]) == 4, "server SETTINGS");
    const auto length = (std::to_integer<std::size_t>(out[1]) << 8) |
                        std::to_integer<std::size_t>(out[2]);
    for (std::size_t offset = 9; offset + 6 <= 9 + length; offset += 6)
        if (std::to_integer<std::uint8_t>(out[offset + 1]) == 3)
            return u32(out.subspan(offset + 2, 4));
    return ~0u;
}

auto stream_limit_refuses_excess_streams() -> void
{
    session state;
    check(advertised_stream_limit(state.output()) == 100, "advertise 100 streams");
    connect(state);
    // Open streams wait for their END_STREAM, so each holds a slot.
    for (std::uint32_t stream = 1; stream <= 199; stream += 2) get(state, stream, 4);
    check(error_of(state, 3, 199) == ~0u, "100th stream accepted");
    get(state, 201, 4);
    check(error_of(state, 3, 201) == refused_stream_error, "101st stream refused");
    drain(state);
    std::vector<std::byte> input;
    const std::array<std::byte, 4> cancel {std::byte {0}, std::byte {0}, std::byte {0},
                                           std::byte {8}};
    frame(input, 3, 0, 1, cancel);
    feed(state, input);
    get(state, 203);
    check(error_of(state, 3, 203) == ~0u, "released slot reused");
    request incoming;
    check(state.pop_request(incoming) && incoming.stream_id == 203, "reused slot serves");
    // Streams opened before and after the reused slot are still found.
    for (const std::uint32_t stream : {101u, 3u, 199u}) {
        input.clear();
        frame(input, 0, 1, stream);
        feed(state, input);
        check(state.pop_request(incoming) && incoming.stream_id == stream, "open stream found");
    }
    // Resetting a stream between open ones keeps its neighbours.
    input.clear();
    frame(input, 3, 0, 51, cancel);
    for (const std::uint32_t stream : {49u, 53u}) frame(input, 0, 1, stream);
    feed(state, input);
    for (const std::uint32_t stream : {49u, 53u})
        check(state.pop_request(incoming) && incoming.stream_id == stream, "neighbour found");
}

// Closing a full set of concurrent streams keeps each one's closure reason.
auto closed_history_covers_stream_limit() -> void
{
    session state;
    connect(state);
    request incoming;
    for (std::uint32_t stream = 1; stream <= 199; stream += 2) get(state, stream);
    while (state.pop_request(incoming)) check(state.respond(incoming.stream_id, 200, {}, {}), "respond");
    drain(state);
    std::vector<std::byte> input;
    const std::array<std::byte, 1> body {};
    frame(input, 0, 0, 1, body);
    feed(state, input);
    check(error_of(state, 7, 0) == stream_closed_error, "DATA on the oldest ended stream");
}

auto data_after_end_stream_is_connection_error() -> void
{
    session state;
    connect(state);
    get(state, 1);
    request incoming;
    check(state.pop_request(incoming), "request delivered");
    check(state.respond(1, 200, {}, {}), "respond");
    drain(state);
    std::vector<std::byte> input;
    const std::array<std::byte, 1> body {};
    frame(input, 0, 0, 1, body);
    feed(state, input);
    check(error_of(state, 7, 0) == stream_closed_error, "DATA after END_STREAM");
}

auto frames_after_peer_reset_are_stream_errors() -> void
{
    session state;
    connect(state);
    get(state, 1, 4); // END_HEADERS only: stream stays open
    std::vector<std::byte> input;
    const std::array<std::byte, 4> cancel {std::byte {0}, std::byte {0}, std::byte {0}, std::byte {8}};
    frame(input, 3, 0, 1, cancel);
    const std::array<std::byte, 1> body {};
    frame(input, 0, 0, 1, body);
    feed(state, input);
    check(error_of(state, 3, 1) == stream_closed_error, "DATA after peer RST_STREAM");
}

auto frames_racing_local_reset_are_discarded() -> void
{
    session state;
    connect(state);
    // Refuse stream 1 locally by exhausting its slot is not possible here, so
    // reset it with an invalid request, then keep sending on it.
    std::vector<std::byte> block;
    const std::array<field, 1> bad {{{":method", "GET"}}};
    check(hpack_encode(bad, block) == hpack_error::none, "encode bad request");
    std::vector<std::byte> input;
    frame(input, 1, 4, 1, block); // missing pseudo-headers: stream PROTOCOL_ERROR
    feed(state, input);
    check(error_of(state, 3, 1) == protocol_error, "invalid request reset");
    drain(state);
    input.clear();
    const std::array<std::byte, 1> body {};
    frame(input, 0, 0, 1, body);
    feed(state, input);
    check(error_of(state, 3, 1) == ~0u && error_of(state, 7, 0) == ~0u,
          "frame racing our own RST_STREAM was answered");
}

auto skipped_stream_id_is_protocol_error() -> void
{
    session state;
    connect(state);
    get(state, 5);
    drain(state);
    get(state, 3);
    check(error_of(state, 7, 0) == protocol_error, "lower unused stream id");
}

// A PRIORITY of the wrong length is a stream error (RFC 9113 6.3).
auto priority_length_is_stream_error() -> void
{
    session state;
    connect(state);
    get(state, 1, 4);
    drain(state);
    const std::array<std::byte, 4> short_priority {};
    std::vector<std::byte> input;
    frame(input, 2, 0, 1, short_priority);
    feed(state, input);
    check(error_of(state, 3, 1) == frame_size_error, "short PRIORITY resets its stream");
    check(error_of(state, 7, 0) == ~0u, "short PRIORITY keeps the connection");
    drain(state);
    get(state, 3);
    request incoming;
    check(state.pop_request(incoming) && incoming.stream_id == 3, "later stream serves");
}

// A malformed request draws a 400 before its PROTOCOL_ERROR reset
// (RFC 9113 8.1.1, 8.2.1).
auto malformed_request_gets_400() -> void
{
    session state;
    connect(state);
    std::vector<std::byte> block;
    const std::array<field, 3> fields {{{":method", "GET"}, {":scheme", "https"},
        {":authority", "localhost"}}};
    check(hpack_encode(fields, block) == hpack_error::none, "encode request");
    std::vector<std::byte> input;
    frame(input, 1, 5, 1, block);
    feed(state, input);
    const auto out = state.output();
    const auto length = std::to_integer<std::size_t>(out[2]);
    const auto block_end = reinterpret_cast<const char*>(out.data()) + 9 + length;
    check(out.size() >= 9 + length && std::to_integer<std::uint8_t>(out[3]) == 1 &&
          (std::to_integer<std::uint8_t>(out[4]) & 1) == 0 && u32(out.subspan(5, 4)) == 1 &&
          std::string_view(block_end - 3, 3) == "400", "400 HEADERS without END_STREAM");
    check(error_of(state, 3, 1) == protocol_error, "then RST_STREAM PROTOCOL_ERROR");
}

auto peer_goaway_is_answered() -> void
{
    // A GOAWAY receiver still sends its own before closing (RFC 9113 6.8),
    // naming the last stream it processed; a repeated GOAWAY draws no second.
    session state;
    connect(state);
    get(state, 1);
    drain(state);
    const std::array<std::byte, 8> payload {std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{1}};
    std::vector<std::byte> input;
    frame(input, 7, 0, 0, payload);
    frame(input, 7, 0, 0, payload);
    feed(state, input);
    auto out = state.output();
    std::size_t goaways = 0;
    while (out.size() >= 9) {
        const auto length = std::to_integer<std::size_t>(out[2]);
        if (std::to_integer<std::uint8_t>(out[3]) == 7) {
            ++goaways;
            check(u32(out.subspan(9, 4)) == 1 && u32(out.subspan(13, 4)) == 0,
                  "GOAWAY names stream 1 with NO_ERROR");
        }
        out = out.subspan(9 + length);
    }
    check(goaways == 1, "one GOAWAY answers the peer's");
}

auto window_overflow_error_scope() -> void
{
    // WINDOW_UPDATE overflow is confined to its stream; a SETTINGS change
    // that overflows any stream window is a connection error (RFC 9113 6.9).
    for (bool settings : {false, true}) {
        session state;
        connect(state);
        get(state, 1, 4);
        const std::array<std::byte, 4> to_maximum {
            std::byte{0x7f}, std::byte{0xff}, std::byte{0}, std::byte{0}};
        std::vector<std::byte> input;
        frame(input, 8, 0, 1, to_maximum);
        feed(state, input);
        check(!state.closed() && error_of(state, 3, 1) == ~0u, "maximum stream window is valid");
        drain(state);
        input.clear();
        if (settings) {
            const std::array<std::byte, 6> increase_initial {
                std::byte{0}, std::byte{4}, std::byte{0}, std::byte{1}, std::byte{0}, std::byte{0}};
            frame(input, 4, 0, 0, increase_initial);
        } else {
            const std::array<std::byte, 4> increment {
                std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}};
            frame(input, 8, 0, 1, increment);
        }
        feed(state, input);
        check(error_of(state, settings ? 7 : 3, settings ? 0 : 1) == 3,
              settings ? "SETTINGS window overflow sends GOAWAY FLOW_CONTROL_ERROR"
                       : "WINDOW_UPDATE overflow sends RST_STREAM FLOW_CONTROL_ERROR");
        drain(state);
        check(state.closed() == settings, "only SETTINGS overflow ends the connection");
    }
}

auto extended_handler(eventloop::event_loop&, eventloop::http::request&,
                      eventloop::http::response&) -> eventloop::task<void> { co_return; }

auto extended_connect() -> void
{
    eventloop::http::router routes;
    check(routes.add(eventloop::http::method_type::connect, "/chat", extended_handler).has_value(),
          "CONNECT route");
    const std::vector<field> valid {{":method", "CONNECT"}, {":scheme", "https"},
        {":path", "/chat"}, {":authority", "localhost"}, {":protocol", "websocket"}};
    const auto send = [](session& state, std::uint32_t id, const std::vector<field>& fields) {
        std::vector<std::byte> block, input;
        check(hpack_encode(fields, block) == hpack_error::none, "encode CONNECT");
        frame(input, 1, 4, id, block);
        feed(state, input);
    };
    {
        session state;
        connect(state);
        send(state, 1, valid);
        check(error_of(state, 3, 1) == protocol_error, "Extended CONNECT without advertisement");
    }
    for (std::size_t i = 0; i < valid.size(); ++i) {
        session state(false, &routes, 32);
        connect(state);
        auto missing = valid;
        missing.erase(missing.begin() + static_cast<std::ptrdiff_t>(i));
        send(state, 1, missing);
        check(error_of(state, 3, 1) == protocol_error, "CONNECT missing required pseudo-header");
    }
    {
        session state(false, &routes, 32);
        connect(state);
        auto duplicate = valid;
        duplicate.push_back({":protocol", "websocket"});
        send(state, 1, duplicate);
        check(error_of(state, 3, 1) == protocol_error, "duplicate :protocol");
    }
    {
        session state(false, &routes, 32);
        connect(state);
        const std::array<std::byte, 6> bad {std::byte{0}, std::byte{8}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{2}};
        std::vector<std::byte> input;
        frame(input, 4, 0, 0, bad);
        feed(state, input);
        check(error_of(state, 7, 0) == protocol_error, "invalid Extended CONNECT setting");
    }
    {
        session state(false, &routes, 32);
        connect(state);
        auto unrouted = valid;
        unrouted[2].value = "/other";
        send(state, 1, unrouted);
        check(error_of(state, 3, 1) == 0, "unrouted CONNECT ends its stream with NO_ERROR");
        check(error_of(state, 3, 0) == ~0u, "unrouted CONNECT resets no stream 0");
    }
    {
        session state(false, &routes, 32);
        connect(state);
        for (std::uint32_t i = 0; i < 9; ++i) send(state, 2 * i + 1, valid);
        check(error_of(state, 3, 17) == 7, "bounded tunnel slots refuse ninth stream");
        eventloop::http2::detail::routed_request routed;
        unsigned count = 0;
        while (state.pop_routed(routed)) ++count;
        check(count == 8 && !state.closed(), "eight live tunnels leave connection alive");
    }
}

} // namespace

// The transport borrows output() until consume_output(); frames queued
// meanwhile must not move the borrowed bytes.
auto queue_growth_keeps_borrowed_output() -> void
{
    session state;
    connect(state);
    const std::array<std::byte, 8> opaque {std::byte {1}};
    std::vector<std::byte> ping;
    frame(ping, 6, 0, 0, opaque);
    feed(state, ping);
    const auto borrowed = state.output();
    const std::vector<std::byte> sent(borrowed.begin(), borrowed.end());
    check(!sent.empty(), "PING ACK queued");
    std::vector<std::byte> pings;
    for (int i = 0; i < 512; ++i) frame(pings, 6, 0, 0, opaque);
    feed(state, pings);
    check(std::ranges::equal(borrowed, sent), "queue growth moved borrowed output");
    state.consume_output(borrowed.size());
    check(state.output().size() == 512 * 17 && !state.closed(), "queued PING ACKs");
}

auto upload_handler(eventloop::event_loop&, eventloop::http::request&,
                    eventloop::http::response&) -> eventloop::task<void>
{
    co_return;
}

// After the client acknowledges SETTINGS, routed streams have the advertised
// 16 KiB window; DATA beyond it is a stream error, not a pause.
auto acknowledged_window_is_enforced() -> void
{
    eventloop::http::router routes;
    check(routes.add(eventloop::http::method_type::post, "/", upload_handler).has_value(),
          "route");
    for (const bool headers_first : {false, true}) {
        session state(false, &routes, 1024 * 1024);
        connect(state);
        std::vector<std::byte> block;
        const std::array<field, 4> fields {{{":method", "POST"}, {":scheme", "https"},
            {":path", "/"}, {":authority", "localhost"}}};
        check(hpack_encode(fields, block) == hpack_error::none, "encode request");
        std::vector<std::byte> input;
        if (headers_first) frame(input, 1, 4, 1, block);
        frame(input, 4, 1, 0);
        if (!headers_first) frame(input, 1, 4, 1, block);
        frame(input, 0, 0, 1, std::vector<std::byte>(16 * 1024));
        frame(input, 0, 0, 1, std::vector<std::byte>(1));
        feed(state, input);
        check(!state.input_paused(), "DATA beyond the acknowledged window paused input");
        check(error_of(state, 3, 1) == 3, "DATA beyond the acknowledged window");
    }
}

int main()
{
    queue_growth_keeps_borrowed_output();
    acknowledged_window_is_enforced();
    stream_limit_refuses_excess_streams();
    closed_history_covers_stream_limit();
    data_after_end_stream_is_connection_error();
    frames_after_peer_reset_are_stream_errors();
    frames_racing_local_reset_are_discarded();
    skipped_stream_id_is_protocol_error();
    priority_length_is_stream_error();
    malformed_request_gets_400();
    peer_goaway_is_answered();
    window_overflow_error_scope();
    extended_connect();
}
