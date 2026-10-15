#include "quic/frames.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {

using namespace eventloop::quic::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC frame encoder: " << message << '\n';
    std::exit(1);
}

auto bytes(std::initializer_list<std::uint8_t> values) -> std::vector<std::byte>
{
    std::vector<std::byte> result;
    for (const auto value : values) result.push_back(std::byte {value});
    return result;
}

auto round_trip(std::vector<std::byte> wire) -> void
{
    const auto frame = decode_frame(wire);
    check(frame && frame->encoded_size == wire.size(), "valid source frame");
    std::array<std::byte, 128> output {};
    const auto encoded = encode_frame(*frame, output);
    check(encoded && *encoded == wire.size() &&
          std::equal(wire.begin(), wire.end(), output.begin()),
          "frame round trip");
    const auto decoded = decode_frame(std::span(output).first(*encoded));
    check(decoded && decoded->encoded_size == *encoded &&
          decoded->type == frame->type, "encoded frame decodes");
}

auto supported_forms() -> void
{
    for (const auto type : {0x00, 0x01, 0x1e})
        round_trip(bytes({static_cast<std::uint8_t>(type)}));
    round_trip(bytes({0x02, 10, 3, 2, 1, 0, 2, 0, 1}));
    round_trip(bytes({0x03, 10, 3, 1, 1, 0, 2, 1, 2, 3}));
    round_trip(bytes({0x04, 2, 3, 4}));
    round_trip(bytes({0x05, 2, 3}));
    round_trip(bytes({0x24, 2, 3, 9, 4}));
    round_trip(bytes({0x24, 2, 3, 4, 4}));
    round_trip(bytes({0x06, 4, 2, 0xaa, 0xbb}));
    round_trip(bytes({0x07, 2, 0xaa, 0xbb}));
    for (std::uint8_t type = 0x08; type <= 0x0f; ++type) {
        std::vector<std::byte> wire {std::byte {type}, std::byte {1}};
        if (type & 0x04) wire.push_back(std::byte {2});
        if (type & 0x02) wire.push_back(std::byte {1});
        wire.push_back(std::byte {0xaa});
        round_trip(wire);
    }
    for (const auto type : {0x10, 0x12, 0x13, 0x14, 0x16, 0x17})
        round_trip(bytes({static_cast<std::uint8_t>(type), 7}));
    for (const auto type : {0x11, 0x15})
        round_trip(bytes({static_cast<std::uint8_t>(type), 3, 7}));
    round_trip(bytes({0x18, 2, 1, 1, 0xaa, 0, 1, 2, 3, 4, 5, 6, 7,
                      8, 9, 10, 11, 12, 13, 14, 15}));
    round_trip(bytes({0x19, 4}));
    for (const auto type : {0x1a, 0x1b})
        round_trip(bytes({static_cast<std::uint8_t>(type),
                          1, 2, 3, 4, 5, 6, 7, 8}));
    round_trip(bytes({0x1c, 5, 6, 2, 'o', 'k'}));
    round_trip(bytes({0x1d, 5, 0}));
    round_trip(bytes({0x30, 0xaa, 0xbb}));
    round_trip(bytes({0x31, 1, 0xaa}));
}

auto canonical_ack_ranges() -> void
{
    // Both pairs use two-byte, nonminimal varints on input.
    const auto pairs = bytes({0x40, 0, 0x40, 2});
    decoded_frame frame;
    frame.type = 0x02;
    frame.largest_acknowledged = 10;
    frame.first_ack_range = 1;
    frame.ack_range_count = 1;
    frame.ack_ranges = pairs;
    std::array<std::byte, 32> output {};
    const auto encoded = encode_frame(frame, output);
    const auto expected = bytes({0x02, 10, 0, 1, 1, 0, 2});
    check(encoded && *encoded == expected.size() &&
          std::equal(expected.begin(), expected.end(), output.begin()),
          "canonical ACK pair varints");
}

auto failures_are_atomic() -> void
{
    const auto payload = bytes({1, 2, 3});
    decoded_frame frame;
    frame.type = 0x31;
    frame.data = payload;
    std::array<std::byte, 32> output;
    const auto untouched = [&] {
        return std::all_of(output.begin(), output.end(),
                           [](auto value) { return value == std::byte {0xa5}; });
    };
    const auto reject = [&](frame_error error) {
        output.fill(std::byte {0xa5});
        const auto encoded = encode_frame(frame, output);
        check(!encoded && encoded.error() == error && untouched(),
              "invalid input leaves output unchanged");
    };
    output.fill(std::byte {0xa5});
    const auto short_output = encode_frame(frame, std::span(output).first(4));
    check(!short_output && short_output.error() == frame_error::output_too_small &&
          untouched(), "insufficient output leaves output unchanged");
    frame.type = 0x1f;
    reject(frame_error::invalid_frame);
    frame.type = 0x06;
    frame.offset = max_varint_value;
    reject(frame_error::invalid_value);
    frame.type = 0x07;
    frame.data = {};
    reject(frame_error::invalid_value);
    frame.type = 0x12;
    frame.limit = (std::uint64_t {1} << 60) + 1;
    reject(frame_error::invalid_value);
    frame.type = 0x0b;
    frame.fin = false;
    reject(frame_error::invalid_value);
    frame.type = 0x18;
    frame.sequence_number = 0;
    frame.retire_prior_to = 1;
    reject(frame_error::invalid_connection_id);
    frame.type = 0x1a;
    frame.data = payload;
    reject(frame_error::invalid_value);
    const auto invalid_pair = bytes({0, 3});
    frame.type = 0x02;
    frame.largest_acknowledged = 4;
    frame.first_ack_range = 0;
    frame.ack_range_count = 1;
    frame.ack_ranges = invalid_pair;
    reject(frame_error::invalid_ack_range);
    frame.ack_ranges = {};
    reject(frame_error::invalid_ack_range);
}

auto reliable_size_bounds() -> void
{
    // The encoder refuses a reliable size above the final size, as the decoder does.
    decoded_frame frame;
    frame.type = 0x24;
    frame.stream_id = 2;
    frame.error_code = 3;
    frame.final_size = 4;
    frame.reliable_size = 5;
    std::array<std::byte, 32> output {};
    const auto encoded = encode_frame(frame, output);
    check(!encoded && encoded.error() == frame_error::invalid_value,
          "encoder rejects reliable size above final size");
}

} // namespace

auto main() -> int
{
    supported_forms();
    canonical_ack_ranges();
    failures_are_atomic();
    reliable_size_bounds();
}
