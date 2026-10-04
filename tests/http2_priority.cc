#include "http2/session.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {
using namespace eventloop::http2::detail;

auto check(bool value, std::string_view message) -> void
{
    if (value) return;
    std::cerr << "HTTP/2 priority: " << message << '\n';
    std::exit(1);
}

auto feed(session& state, std::span<const std::byte> bytes) -> void
{
    while (!bytes.empty()) {
        const auto count = std::min(bytes.size(), state.read_buffer().size());
        std::memcpy(state.read_buffer().data(), bytes.data(), count);
        state.commit_read(count);
        bytes = bytes.subspan(count);
    }
}

auto frame(session& state, unsigned type, unsigned flags, unsigned stream,
           std::span<const std::byte> payload = {}) -> void
{
    std::array<std::byte, 9> header {};
    header[0] = static_cast<std::byte>(payload.size() >> 16);
    header[1] = static_cast<std::byte>(payload.size() >> 8);
    header[2] = static_cast<std::byte>(payload.size());
    header[3] = static_cast<std::byte>(type);
    header[4] = static_cast<std::byte>(flags);
    header[8] = static_cast<std::byte>(stream);
    feed(state, header);
    feed(state, payload);
}

struct sent_frame {
    unsigned type;
    unsigned flags;
    unsigned stream;
    std::vector<std::byte> payload;
};

auto drain(session& state) -> std::vector<sent_frame>
{
    std::vector<std::byte> bytes;
    while (!state.output().empty()) {
        const auto output = state.output();
        bytes.insert(bytes.end(), output.begin(), output.end());
        state.consume_output(output.size());
    }
    std::vector<sent_frame> frames;
    for (std::size_t offset = 0; offset < bytes.size();) {
        check(bytes.size() - offset >= 9, "incomplete frame header");
        const auto size = (std::to_integer<std::size_t>(bytes[offset]) << 16) |
            (std::to_integer<std::size_t>(bytes[offset + 1]) << 8) |
            std::to_integer<std::size_t>(bytes[offset + 2]);
        check(bytes.size() - offset - 9 >= size, "truncated frame");
        const auto begin = bytes.begin() + static_cast<std::ptrdiff_t>(offset + 9);
        frames.push_back({std::to_integer<unsigned>(bytes[offset + 3]),
                          std::to_integer<unsigned>(bytes[offset + 4]),
                          std::to_integer<unsigned>(bytes[offset + 8]),
                          {begin, begin + static_cast<std::ptrdiff_t>(size)}});
        offset += 9 + size;
    }
    return frames;
}

auto settings_payload(unsigned id, unsigned value) -> std::array<std::byte, 6>
{
    return {std::byte {0}, static_cast<std::byte>(id), static_cast<std::byte>(value >> 24),
            static_cast<std::byte>(value >> 16), static_cast<std::byte>(value >> 8),
            static_cast<std::byte>(value)};
}

// Opens the connection with zero stream windows so responses queue until
// open_windows() releases them to one scheduling pass.
auto initialize(session& state) -> std::vector<sent_frame>
{
    constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    auto server = drain(state);
    feed(state, std::as_bytes(std::span(preface)));
    frame(state, 4, 0, 0, settings_payload(4, 0));
    (void)drain(state);
    return server;
}

auto open_windows(session& state) -> void
{
    frame(state, 4, 0, 0, settings_payload(4, 65535));
}

auto request(session& state, unsigned stream, std::initializer_list<std::string_view> priority)
    -> void
{
    std::vector<field> fields {{":method", "GET"}, {":scheme", "https"}, {":path", "/"},
                               {":authority", "localhost"}};
    for (auto value : priority) fields.push_back({"priority", std::string(value)});
    std::vector<std::byte> block;
    check(hpack_encode(fields, block) == hpack_error::none, "request encoding");
    frame(state, 1, 5, stream, block);
    eventloop::http2::detail::request incoming;
    check(state.pop_request(incoming) && incoming.stream_id == stream, "request delivery");
    // Two DATA frames per response make interleaving visible.
    check(state.respond(stream, 200, {}, std::vector<std::byte>(max_frame_payload + 1)),
          "response");
}

auto priority_update(session& state, unsigned stream, std::string_view value,
                     unsigned frame_stream = 0) -> void
{
    std::vector<std::byte> payload {std::byte {0}, std::byte {0}, std::byte {0},
                                    static_cast<std::byte>(stream)};
    const auto text = std::as_bytes(std::span(value));
    payload.insert(payload.end(), text.begin(), text.end());
    frame(state, 0x10, 0, frame_stream, payload);
}

// Streams of the DATA frames sent once windows open.
auto data_order(session& state) -> std::vector<unsigned>
{
    open_windows(state);
    std::vector<unsigned> order;
    for (const auto& sent : drain(state))
        if (sent.type == 0) order.push_back(sent.stream);
    return order;
}

using order = std::vector<unsigned>;

auto scheduling() -> void
{
    {
        session state;
        initialize(state);
        request(state, 1, {});
        request(state, 3, {});
        check(data_order(state) == order {1, 1, 3, 3}, "default responses are sequential");
    }
    {
        session state;
        initialize(state);
        request(state, 1, {"u=5"});
        request(state, 3, {"u=1"});
        request(state, 5, {});
        check(data_order(state) == order {3, 3, 5, 5, 1, 1}, "lower urgency first");
    }
    {
        session state;
        initialize(state);
        request(state, 1, {"i"});
        request(state, 3, {"u=3, i=?1"});
        check(data_order(state) == order {1, 3, 1, 3}, "incremental responses interleave");
    }
    {
        session state;
        initialize(state);
        request(state, 1, {"i"});
        request(state, 3, {});
        check(data_order(state) == order {3, 3, 1, 1}, "non-incremental before incremental");
    }
    {
        session state;
        initialize(state);
        request(state, 1, {"u=1"});
        request(state, 3, {"u=0"});
        // Stream 3 keeps a zero window; stream 1 must still progress.
        const std::array<std::byte, 4> increment {std::byte {0}, std::byte {1},
                                                  std::byte {0}, std::byte {0}};
        frame(state, 8, 0, 1, increment);
        order sent;
        for (const auto& item : drain(state)) if (item.type == 0) sent.push_back(item.stream);
        check(!sent.empty() && sent.front() == 1, "blocked urgent stream stalls others");
    }
}

auto signals() -> void
{
    {
        session state;
        initialize(state);
        request(state, 1, {});
        request(state, 3, {});
        priority_update(state, 3, "u=0");
        check(data_order(state) == order {3, 3, 1, 1}, "PRIORITY_UPDATE reorders");
    }
    {
        session state;
        initialize(state);
        request(state, 1, {"u=5"});
        request(state, 3, {"u=4"});
        // Omitted parameters revert to their defaults.
        priority_update(state, 1, "i=?0");
        check(data_order(state) == order {1, 1, 3, 3}, "update resets omitted urgency");
    }
    {
        session state;
        initialize(state);
        priority_update(state, 7, "u=0");
        request(state, 1, {});
        request(state, 3, {"u=2"});
        check(data_order(state) == order {3, 3, 1, 1}, "update for unopened stream");
    }
    {
        session state;
        initialize(state);
        request(state, 1, {"u=1"});
        request(state, 3, {"u=0"});
        priority_update(state, 3, "u=7,,");
        check(data_order(state) == order {3, 3, 1, 1}, "malformed update is ignored");
    }
    {
        // Members, parameters, and strings that must be skipped correctly.
        session state;
        initialize(state);
        request(state, 1, {"u=2"});
        request(state, 3, {R"v(x="a,u=7", u=1;p=?1, y=(1 "b)"))v"});
        check(data_order(state) == order {3, 3, 1, 1}, "dictionary skipping");
    }
    {
        // Repeated lines are one dictionary; the last u wins.
        session state;
        initialize(state);
        request(state, 1, {"u=1, i"});
        request(state, 3, {"u=6", "i", "u=1"});
        check(data_order(state) == order {1, 3, 1, 3}, "repeated Priority lines");
    }
    {
        // Out-of-range or mistyped values, and syntax errors, leave defaults.
        // Three responses per session fit the 64 KiB connection window.
        for (auto invalid : {std::array<std::string_view, 2> {"u=8", "u=-1"},
                             std::array<std::string_view, 2> {"u=0, ,", "U=0"},
                             std::array<std::string_view, 2> {"u=?1", "u=1;"}}) {
            session state;
            initialize(state);
            request(state, 1, {invalid[0]});
            request(state, 3, {invalid[1]});
            request(state, 5, {"u=2"});
            check(data_order(state) == order {5, 5, 1, 1, 3, 3}, "invalid priority values");
        }
    }
}

auto goaway_error(session& state) -> unsigned
{
    for (const auto& sent : drain(state))
        if (sent.type == 7 && sent.payload.size() == 8)
            return std::to_integer<unsigned>(sent.payload[7]);
    return 0;
}

auto errors() -> void
{
    {
        session state;
        bool advertised = false;
        for (const auto& sent : initialize(state)) {
            if (sent.type != 4) continue;
            for (std::size_t at = 0; at + 6 <= sent.payload.size(); at += 6)
                if (sent.payload[at + 1] == std::byte {9} && sent.payload[at + 5] == std::byte {1})
                    advertised = true;
        }
        check(advertised, "SETTINGS_NO_RFC7540_PRIORITIES is advertised");
    }
    {
        session state;
        initialize(state);
        priority_update(state, 1, "u=1", 1);
        check(goaway_error(state) == 1, "PRIORITY_UPDATE on a request stream");
    }
    {
        session state;
        initialize(state);
        const std::array<std::byte, 3> short_payload {};
        frame(state, 0x10, 0, 0, short_payload);
        check(goaway_error(state) == 6, "short PRIORITY_UPDATE");
    }
    {
        session state;
        initialize(state);
        priority_update(state, 0, "u=1");
        check(goaway_error(state) == 1, "PRIORITY_UPDATE for stream 0");
    }
    {
        session state;
        initialize(state);
        frame(state, 4, 0, 0, settings_payload(9, 2));
        check(goaway_error(state) == 1, "SETTINGS_NO_RFC7540_PRIORITIES above 1");
    }
}
} // namespace

auto main() -> int
{
    scheduling();
    signals();
    errors();
}
