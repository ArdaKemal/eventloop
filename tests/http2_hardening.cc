#include "http2/hpack.h"
#include "http2/session.h"

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
        for (std::uint32_t i = 0; i < 9; ++i) send(state, 2 * i + 1, valid);
        check(error_of(state, 3, 17) == 7, "bounded tunnel slots refuse ninth stream");
        eventloop::http2::detail::routed_request routed;
        unsigned count = 0;
        while (state.pop_routed(routed)) ++count;
        check(count == 8 && !state.closed(), "eight live tunnels leave connection alive");
    }
}

} // namespace

int main()
{
    data_after_end_stream_is_connection_error();
    frames_after_peer_reset_are_stream_errors();
    frames_racing_local_reset_are_discarded();
    skipped_stream_id_is_protocol_error();
    extended_connect();
}
