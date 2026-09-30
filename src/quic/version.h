#pragma once

#include <cstdint>

namespace eventloop::quic::detail {

inline constexpr std::uint32_t version_1 = 0x00000001;
inline constexpr std::uint32_t version_2 = 0x6b3343cf;

enum class long_packet_type : std::uint8_t {
    initial,
    zero_rtt,
    handshake,
    retry,
};

[[nodiscard]] constexpr auto is_supported_version(std::uint32_t version)
    noexcept -> bool
{
    return version == version_1 || version == version_2;
}

[[nodiscard]] constexpr auto long_header_type_bits(
    std::uint32_t version, long_packet_type type) noexcept -> std::uint8_t
{
    const auto index = static_cast<std::uint8_t>(type);
    return version == version_2 ? static_cast<std::uint8_t>((index + 1) & 3)
                                : index;
}

[[nodiscard]] constexpr auto decode_long_header_type(
    std::uint32_t version, std::uint8_t bits) noexcept -> long_packet_type
{
    const auto index = version == version_2
        ? static_cast<std::uint8_t>((bits + 3) & 3)
        : static_cast<std::uint8_t>(bits & 3);
    return static_cast<long_packet_type>(index);
}

} // namespace eventloop::quic::detail
