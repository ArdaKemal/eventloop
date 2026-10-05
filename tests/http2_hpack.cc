#include "http2/hpack.h"
#include "http2/session.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <deque>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using eventloop::http2::detail::field;
using eventloop::http2::detail::hpack_decoder;
using eventloop::http2::detail::hpack_encode;
using eventloop::http2::detail::hpack_error;
using eventloop::http2::detail::hpack_max_block_size;
using eventloop::http2::detail::hpack_max_fields;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HPACK: " << message << '\n';
    std::exit(1);
}

[[nodiscard]] auto hex(std::string_view digits) -> std::vector<std::byte>
{
    auto nibble = [](char value) -> unsigned {
        if (value >= '0' && value <= '9') return static_cast<unsigned>(value - '0');
        return static_cast<unsigned>(value - 'a' + 10);
    };
    check(digits.size() % 2 == 0, "bad test vector");
    std::vector<std::byte> result;
    for (std::size_t index = 0; index < digits.size(); index += 2) {
        result.push_back(static_cast<std::byte>(
            (nibble(digits[index]) << 4) | nibble(digits[index + 1])));
    }
    return result;
}

auto rfc_request_vectors() -> void
{
    // RFC 7541 Appendix C.4: Huffman literals, static indices, and a
    // persistent dynamic table shared by successive request blocks.
    hpack_decoder decoder;
    std::vector<field> fields;
    const auto first = hex("828684418cf1e3c2e5f23a6ba0ab90f4ff");
    check(decoder.decode(first, fields) == hpack_error::none, "C.4.1 decode");
    check(fields.size() == 4 && fields[0].name == ":method" &&
              fields[0].value == "GET" && fields[3].name == ":authority" &&
              fields[3].value == "www.example.com", "C.4.1 fields");

    const auto second = hex("828684be5886a8eb10649cbf");
    check(decoder.decode(second, fields) == hpack_error::none, "C.4.2 decode");
    check(fields.size() == 5 && fields[3].value == "www.example.com" &&
              fields[4].name == "cache-control" && fields[4].value == "no-cache",
          "C.4.2 dynamic index");

    const auto third = hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf");
    check(decoder.decode(third, fields) == hpack_error::none, "C.4.3 decode");
    check(fields.size() == 5 && fields[1].value == "https" &&
              fields[4].name == "custom-key" && fields[4].value == "custom-value",
          "C.4.3 fields");
}

auto malformed_and_limits() -> void
{
    std::vector<field> fields;
    for (const auto& input : {"80", "ff7f", "00017881fe", "00017884ffffffff"}) {
        hpack_decoder decoder;
        check(decoder.decode(hex(input), fields) == hpack_error::invalid,
              "invalid index or Huffman code accepted");
        check(fields.empty(), "failed decode retained fields");
    }

    hpack_decoder reduced;
    check(reduced.set_table_size_limit(0) == hpack_error::none,
          "set table limit");
    check(reduced.decode(hex("82"), fields) == hpack_error::invalid,
          "missing required table size update");
    hpack_decoder updated;
    check(updated.set_table_size_limit(0) == hpack_error::none,
          "set table limit again");
    check(updated.decode(hex("2082"), fields) == hpack_error::none &&
              fields.size() == 1, "zero-sized table update");
    check(updated.decode(hex("21"), fields) == hpack_error::invalid,
          "oversized table update accepted");

    hpack_decoder bounded;
    std::vector<std::byte> oversized(hpack_max_block_size + 1, std::byte {0});
    check(bounded.decode(oversized, fields) == hpack_error::limit_exceeded,
          "encoded block limit");
    std::vector<std::byte> many(hpack_max_fields + 1, std::byte {0x82});
    check(bounded.decode(many, fields) == hpack_error::limit_exceeded,
          "decoded field count limit");
}

auto encoder_round_trip() -> void
{
    const std::vector<field> source {
        {":status", "200"}, {"content-type", "text/plain"},
    };
    std::vector<std::byte> encoded;
    check(hpack_encode(source, encoded) == hpack_error::none,
          "encode response");
    hpack_decoder decoder;
    std::vector<field> decoded;
    check(decoder.decode(encoded, decoded) == hpack_error::none &&
              decoded.size() == source.size() &&
              decoded[0].name == source[0].name &&
              decoded[1].value == source[1].value,
          "encoder round trip");
    // Raw literals preserve empty strings and every octet across the
    // one-byte and multi-byte length-prefix boundary.
    std::string octets;
    for (unsigned value = 0; value < 256; ++value) {
        octets.push_back(static_cast<char>(value));
    }
    for (const auto length : {std::size_t {0}, std::size_t {126},
                              std::size_t {127}, std::size_t {128},
                              octets.size()}) {
        const std::vector<field> raw {{"x-raw", octets.substr(0, length)}};
        check(hpack_encode(raw, encoded) == hpack_error::none,
              "encode raw literal");
        check(decoder.decode(encoded, decoded) == hpack_error::none &&
                  decoded.size() == 1 && decoded[0].name == raw[0].name &&
                  decoded[0].value == raw[0].value,
              "raw literal octets or length changed");
    }
    std::vector<field> too_many(hpack_max_fields + 1, field {"x", "y"});
    check(hpack_encode(too_many, encoded) == hpack_error::limit_exceeded,
          "encoder field count limit");
}

// Exercise the session output queue through its transport-facing interface.
// Keep nearly 256 KiB pending while draining fragments and appending PINGs,
// so both frame headers and payloads repeatedly cross the buffer boundary.
auto session_output_wraparound() -> void
{
    eventloop::http2::detail::session state;
    auto feed = [&state](std::span<const std::byte> input) {
        while (!input.empty()) {
            const auto count = std::min(input.size(), state.read_buffer().size());
            std::memcpy(state.read_buffer().data(), input.data(), count);
            state.commit_read(count);
            input = input.subspan(count);
        }
    };
    constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    feed(std::as_bytes(std::span(preface)));
    const std::array<std::byte, 9> settings {std::byte {0}, std::byte {0},
        std::byte {0}, std::byte {4}};
    feed(settings);
    while (!state.output().empty()) state.consume_output(state.output().size());

    std::deque<std::byte> expected;
    auto ping = [&](std::size_t sequence) {
        std::array<std::byte, 17> frame {};
        frame[2] = std::byte {8};
        frame[3] = std::byte {6};
        for (std::size_t index = 9; index < frame.size(); ++index) {
            frame[index] = static_cast<std::byte>((sequence + index * 31) & 255);
        }
        feed(frame);
        frame[4] = std::byte {1};
        expected.insert(expected.end(), frame.begin(), frame.end());
        check(!state.closed(), "session closed while recycling output capacity");
    };
    auto drain = [&](std::size_t count) {
        while (count != 0) {
            const auto bytes = state.output();
            check(!bytes.empty(), "session lost queued bytes");
            const auto consumed = std::min(count, bytes.size());
            for (const auto byte : bytes.first(consumed)) {
                check(!expected.empty() && byte == expected.front(),
                    "session changed frame bytes or order across wraparound");
                expected.pop_front();
            }
            state.consume_output(consumed);
            count -= consumed;
        }
    };
    // Force a size increase after unread bytes have already wrapped around
    // the initial 4 KiB storage, then verify the queue survives reuse.
    for (std::size_t sequence = 0; sequence < 200; ++sequence) ping(sequence);
    drain(1000);
    for (std::size_t sequence = 200; sequence < 300; ++sequence) ping(sequence);
    drain(expected.size());
    for (std::size_t sequence = 0; sequence < 15000; ++sequence) ping(sequence);
    for (std::size_t sequence = 15000; sequence < 55000; ++sequence) {
        drain(sequence % 3 == 0 ? 1 : sequence % 3 == 1 ? 16 : 34);
        ping(sequence);
    }
    drain(expected.size());
    check(state.output().empty(), "session retained fully consumed output");

    // A response larger than the queue must resume after partial transport
    // drains. Widen both HTTP/2 windows to make queue capacity the limiter.
    const std::array<std::byte, 15> large_window {std::byte {0}, std::byte {0},
        std::byte {6}, std::byte {4}, std::byte {0}, std::byte {0}, std::byte {0},
        std::byte {0}, std::byte {0}, std::byte {0}, std::byte {4}, std::byte {0},
        std::byte {64}, std::byte {0}, std::byte {0}};
    feed(large_window);
    const std::array<std::byte, 13> connection_window {std::byte {0}, std::byte {0},
        std::byte {4}, std::byte {8}, std::byte {0}, std::byte {0}, std::byte {0},
        std::byte {0}, std::byte {0}, std::byte {0}, std::byte {64},
        std::byte {0}, std::byte {0}};
    feed(connection_window);
    std::vector<std::byte> block;
    const std::array<field, 4> fields {{{":method", "GET"}, {":scheme", "https"},
        {":path", "/"}, {":authority", "localhost"}}};
    check(hpack_encode(fields, block) == hpack_error::none, "encode session request");
    std::array<std::byte, 9> headers {};
    headers[2] = static_cast<std::byte>(block.size());
    headers[3] = std::byte {1};
    headers[4] = std::byte {5};
    headers[8] = std::byte {1};
    feed(headers);
    feed(block);
    eventloop::http2::detail::request request;
    check(state.pop_request(request), "session did not deliver request");
    std::vector<std::byte> body(1024 * 1024);
    for (std::size_t index = 0; index < body.size(); ++index) {
        body[index] = static_cast<std::byte>((index * 31 + index / 16384) & 255);
    }
    check(state.respond(1, 200, {}, body), "session rejected bounded body");
    std::vector<std::byte> wire;
    while (!state.output().empty()) {
        const auto bytes = state.output().first(std::min<std::size_t>(997, state.output().size()));
        wire.insert(wire.end(), bytes.begin(), bytes.end());
        state.consume_output(bytes.size());
    }
    std::size_t body_offset = 0;
    bool ended = false;
    for (std::size_t offset = 0; offset < wire.size();) {
        check(wire.size() - offset >= 9, "session truncated frame header");
        const auto length = (std::to_integer<std::size_t>(wire[offset]) << 16) |
            (std::to_integer<std::size_t>(wire[offset + 1]) << 8) |
            std::to_integer<std::size_t>(wire[offset + 2]);
        check(length <= wire.size() - offset - 9, "session truncated frame payload");
        if (wire[offset + 3] == std::byte {0}) {
            check(!ended && length <= body.size() - body_offset,
                "session emitted excess or late DATA");
            check(std::equal(wire.begin() + static_cast<std::ptrdiff_t>(offset + 9),
                wire.begin() + static_cast<std::ptrdiff_t>(offset + 9 + length),
                body.begin() + static_cast<std::ptrdiff_t>(body_offset)),
                "session corrupted DATA while resuming full queue");
            body_offset += length;
            ended = (wire[offset + 4] & std::byte {1}) != std::byte {0};
        }
        offset += 9 + length;
    }
    check(body_offset == body.size() && ended && !state.closed(),
        "session did not finish response after full queue retries");
}

// Decodes random blocks against a reference table so that eviction, table
// size updates, and entries wrapping the dynamic table's storage are covered.
auto dynamic_table_model() -> void
{
    struct reference {
        std::deque<field> entries;
        std::size_t bytes = 0;
        std::size_t size = 4096;
        auto evict() -> void
        {
            while (bytes > size) {
                bytes -= entries.back().name.size() + entries.back().value.size() + 32;
                entries.pop_back();
            }
        }
        auto insert(const field& entry) -> void
        {
            const auto cost = entry.name.size() + entry.value.size() + 32;
            if (cost > size) {
                entries.clear();
                bytes = 0;
                return;
            }
            bytes += cost;
            entries.push_front(entry);
            evict();
        }
    };
    auto integer = [](std::vector<std::byte>& out, unsigned bits, unsigned prefix,
                      std::size_t value) {
        const std::size_t mask = (std::size_t {1} << prefix) - 1;
        if (value < mask) {
            out.push_back(static_cast<std::byte>(bits | value));
            return;
        }
        out.push_back(static_cast<std::byte>(bits | mask));
        for (value -= mask; value >= 128; value >>= 7)
            out.push_back(static_cast<std::byte>((value & 0x7f) | 0x80));
        out.push_back(static_cast<std::byte>(value));
    };
    auto text = [&](std::vector<std::byte>& out, const std::string& value) {
        integer(out, 0, 7, value.size());
        for (const char c : value) out.push_back(static_cast<std::byte>(c));
    };
    std::uint32_t state = 12345;
    auto next = [&](std::uint32_t bound) {
        state = state * 1664525u + 1013904223u;
        return (state >> 8) % bound;
    };
    auto random_text = [&](std::size_t size) {
        std::string value(size, ' ');
        for (auto& c : value) c = static_cast<char>('a' + next(26));
        return value;
    };

    hpack_decoder decoder;
    reference model;
    std::vector<field> fields;
    for (int block_index = 0; block_index < 4000; ++block_index) {
        std::vector<std::byte> block;
        std::vector<field> expected;
        if (next(20) == 0) {
            model.size = next(5) == 0 ? next(300) : 4096 - next(1200);
            integer(block, 0x20, 5, model.size);
            model.evict();
        }
        const auto count = 1 + next(6);
        for (std::uint32_t item = 0; item < count; ++item) {
            if (!model.entries.empty() && next(3) == 0) {
                const auto index = next(static_cast<std::uint32_t>(model.entries.size()));
                integer(block, 0x80, 7, 62 + index);
                expected.push_back(model.entries[index]);
                continue;
            }
            const auto length = next(25) == 0 ? 4000 + next(200) : next(300);
            field entry {"x-" + random_text(next(12)), random_text(length)};
            integer(block, 0x40, 6, 0);
            text(block, entry.name);
            text(block, entry.value);
            expected.push_back(entry);
            model.insert(entry);
        }
        check(decoder.decode(block, fields) == hpack_error::none, "model block decode");
        check(fields.size() == expected.size(), "model field count");
        for (std::size_t index = 0; index < fields.size(); ++index) {
            check(fields[index].name == expected[index].name &&
                  fields[index].value == expected[index].value, "model field value");
        }
    }
}

} // namespace

int main()
{
    rfc_request_vectors();
    malformed_and_limits();
    encoder_round_trip();
    session_output_wraparound();
    dynamic_table_model();
}
