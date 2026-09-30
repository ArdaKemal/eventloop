#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace eventloop::quic::detail {

inline constexpr std::uint64_t max_varint_value =
    (std::uint64_t {1} << 62) - 1;

enum class varint_error {
    incomplete_input,
    value_out_of_range,
    output_too_small,
};

struct decoded_varint {
    std::uint64_t value {0};
    std::size_t encoded_size {0};
};

[[nodiscard]] constexpr auto varint_size(std::uint64_t value) noexcept
    -> std::size_t
{
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    if (value <= max_varint_value) return 8;
    return 0;
}

[[nodiscard]] constexpr auto decode_varint(std::span<const std::byte> input)
    noexcept -> std::expected<decoded_varint, varint_error>
{
    if (input.empty()) {
        return std::unexpected(varint_error::incomplete_input);
    }

    const auto first = std::to_integer<std::uint8_t>(input.front());
    const auto length = std::size_t {1} << (first >> 6);
    if (input.size() < length) {
        return std::unexpected(varint_error::incomplete_input);
    }

    std::uint64_t value = first & 0x3f;
    for (std::size_t index = 1; index < length; ++index) {
        value = (value << 8) |
                std::to_integer<std::uint8_t>(input[index]);
    }
    return decoded_varint {value, length};
}

[[nodiscard]] constexpr auto encode_varint(
    std::uint64_t value, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, varint_error>
{
    const auto length = varint_size(value);
    if (length == 0) {
        return std::unexpected(varint_error::value_out_of_range);
    }
    if (output.size() < length) {
        return std::unexpected(varint_error::output_too_small);
    }

    auto encoded = value;
    for (std::size_t index = length; index > 0; --index) {
        output[index - 1] = static_cast<std::byte>(encoded & 0xff);
        encoded >>= 8;
    }
    const auto prefix = static_cast<std::uint8_t>((length == 1 ? 0 :
        length == 2 ? 1 : length == 4 ? 2 : 3) << 6);
    output[0] |= static_cast<std::byte>(prefix);
    return length;
}

} // namespace eventloop::quic::detail
