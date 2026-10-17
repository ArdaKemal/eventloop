#pragma once

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string_view>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

namespace eventloop {

// Address bytes are in network display order; port and scope ID are host order.
struct ip_endpoint {
    enum class family { ipv4, ipv6 };

    family address_family {family::ipv4};
    std::array<std::uint8_t, 16> address {};
    std::uint16_t port {0};
    std::uint32_t scope_id {0};

    [[nodiscard]] constexpr auto operator==(const ip_endpoint&) const -> bool = default;

    [[nodiscard]] static constexpr auto from_ipv4(
        std::array<std::uint8_t, 4> bytes, std::uint16_t port = 0) noexcept
        -> ip_endpoint
    {
        ip_endpoint result;
        std::copy(bytes.begin(), bytes.end(), result.address.begin());
        result.port = port;
        return result;
    }

    [[nodiscard]] static constexpr auto from_ipv6(
        std::array<std::uint8_t, 16> bytes, std::uint16_t port = 0,
        std::uint32_t scope_id = 0) noexcept -> ip_endpoint
    {
        return {family::ipv6, bytes, port, scope_id};
    }

    [[nodiscard]] static constexpr auto loopback_v4(std::uint16_t port = 0) noexcept
        -> ip_endpoint { return from_ipv4({127, 0, 0, 1}, port); }
    [[nodiscard]] static constexpr auto any_v4(std::uint16_t port = 0) noexcept
        -> ip_endpoint { return from_ipv4({0, 0, 0, 0}, port); }
    [[nodiscard]] static constexpr auto loopback_v6(std::uint16_t port = 0) noexcept
        -> ip_endpoint
    {
        std::array<std::uint8_t, 16> bytes {};
        bytes[15] = 1;
        return from_ipv6(bytes, port);
    }
    [[nodiscard]] static constexpr auto any_v6(std::uint16_t port = 0) noexcept
        -> ip_endpoint { return from_ipv6({}, port); }

    [[nodiscard]] static auto parse(std::string_view text, std::uint16_t port)
        -> ip_endpoint
    {
        if (text.empty() || text.size() >= INET6_ADDRSTRLEN + 11 ||
            text.contains('\0')) {
            throw std::invalid_argument("invalid IP address");
        }
        std::uint32_t scope = 0;
        const auto percent = text.find('%');
        if (percent != std::string_view::npos) {
            const auto suffix = text.substr(percent + 1);
            if (suffix.empty() || suffix.contains('%')) {
                throw std::invalid_argument("invalid IPv6 scope ID");
            }
            const auto [end, error] = std::from_chars(
                suffix.data(), suffix.data() + suffix.size(), scope);
            if (error != std::errc {} || end != suffix.data() + suffix.size()) {
                throw std::invalid_argument("invalid IPv6 scope ID");
            }
            text = text.substr(0, percent);
        }
        std::array<char, INET6_ADDRSTRLEN> terminated {};
        if (text.empty() || text.size() >= terminated.size()) {
            throw std::invalid_argument("invalid IP address");
        }
        std::memcpy(terminated.data(), text.data(), text.size());
        std::array<std::uint8_t, 16> bytes {};
        if (percent == std::string_view::npos &&
            ::inet_pton(AF_INET, terminated.data(), bytes.data()) == 1) {
            return from_ipv4({bytes[0], bytes[1], bytes[2], bytes[3]}, port);
        }
        if (::inet_pton(AF_INET6, terminated.data(), bytes.data()) == 1) {
            return from_ipv6(bytes, port, scope);
        }
        throw std::invalid_argument("invalid IP address");
    }
};

} // namespace eventloop
