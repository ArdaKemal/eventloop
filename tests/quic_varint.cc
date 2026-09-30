#include "quic/varint.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>

namespace {

using eventloop::quic::detail::decode_varint;
using eventloop::quic::detail::encode_varint;
using eventloop::quic::detail::max_varint_value;
using eventloop::quic::detail::varint_error;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC varint: " << message << '\n';
    std::exit(1);
}

auto rfc9000_vectors() -> void
{
    struct vector {
        std::uint64_t value;
        std::array<std::uint8_t, 8> bytes;
        std::size_t size;
    };
    constexpr std::array vectors {
        vector {37, {0x25}, 1},
        vector {15293, {0x7b, 0xbd}, 2},
        vector {494878333, {0x9d, 0x7f, 0x3e, 0x7d}, 4},
        vector {151288809941952652, {0xc2, 0x19, 0x7c, 0x5e,
                                     0xff, 0x14, 0xe8, 0x8c}, 8},
    };

    for (const auto& item : vectors) {
        std::array<std::byte, 8> bytes {};
        const auto written = encode_varint(item.value, bytes);
        check(written && *written == item.size, "RFC vector encoded size");
        for (std::size_t i = 0; i < item.size; ++i) {
            check(std::to_integer<std::uint8_t>(bytes[i]) == item.bytes[i],
                  "RFC vector encoding");
        }

        const auto decoded = decode_varint(
            std::span<const std::byte>(bytes.data(), item.size));
        check(decoded && decoded->value == item.value &&
                  decoded->encoded_size == item.size,
              "RFC vector decoding");
    }
}

auto boundaries_and_errors() -> void
{
    constexpr std::array values {
        std::uint64_t {0}, std::uint64_t {63}, std::uint64_t {64},
        std::uint64_t {16383}, std::uint64_t {16384},
        std::uint64_t {1073741823}, std::uint64_t {1073741824},
        max_varint_value,
    };
    for (const auto value : values) {
        std::array<std::byte, 8> bytes {};
        const auto written = encode_varint(value, bytes);
        check(written.has_value(), "boundary value accepted");
        const auto decoded = decode_varint(
            std::span<const std::byte>(bytes.data(), *written));
        check(decoded && decoded->value == value, "boundary round trip");
    }

    std::array<std::byte, 8> bytes {};
    check(encode_varint(max_varint_value + 1, bytes).error() ==
              varint_error::value_out_of_range,
          "oversized integer rejected");
    check(encode_varint(64, std::span<std::byte>(bytes.data(), 1)).error() ==
              varint_error::output_too_small,
          "short output rejected");

    check(decode_varint({}).error() == varint_error::incomplete_input,
          "empty input is incomplete");
    constexpr std::array<std::byte, 1> two_byte_prefix {std::byte {0x40}};
    check(decode_varint(two_byte_prefix).error() ==
              varint_error::incomplete_input,
          "truncated two-byte integer rejected");
    constexpr std::array<std::byte, 3> four_byte_prefix {
        std::byte {0x80}, std::byte {0x00}, std::byte {0x00},
    };
    check(decode_varint(four_byte_prefix).error() ==
              varint_error::incomplete_input,
          "truncated four-byte integer rejected");

    // Receivers accept wider encodings of values that could use fewer bytes.
    constexpr std::array<std::byte, 2> noncanonical {std::byte {0x40},
                                                     std::byte {0x01}};
    const auto decoded = decode_varint(noncanonical);
    check(decoded && decoded->value == 1 && decoded->encoded_size == 2,
          "non-minimal encoding accepted");
}

} // namespace

auto main() -> int
{
    rfc9000_vectors();
    boundaries_and_errors();
}
