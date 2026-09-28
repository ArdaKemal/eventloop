#pragma once

#include <array>
#include <cstring>
#include <cstdint>
#include <stdexcept>
#include <string_view>

#include <arpa/inet.h>

namespace eventloop {

// Address octets are in display order; port is in host order.
struct ipv4_endpoint {
    std::array<std::uint8_t, 4> address {};
    std::uint16_t port {0};

    [[nodiscard]] static constexpr auto loopback(std::uint16_t port = 0) noexcept
        -> ipv4_endpoint
    {
        return {{127, 0, 0, 1}, port};
    }

    [[nodiscard]] static constexpr auto any(std::uint16_t port = 0) noexcept
        -> ipv4_endpoint
    {
        return {{0, 0, 0, 0}, port};
    }

    [[nodiscard]] static auto parse(std::string_view address,
                                    std::uint16_t port) -> ipv4_endpoint
    {
        if (address.empty() || address.size() >= INET_ADDRSTRLEN ||
            address.find('\0') != std::string_view::npos) {
            throw std::invalid_argument("invalid IPv4 address");
        }
        std::array<char, INET_ADDRSTRLEN> text {};
        std::memcpy(text.data(), address.data(), address.size());
        in_addr native {};
        if (::inet_pton(AF_INET, text.data(), &native) != 1) {
            throw std::invalid_argument("invalid IPv4 address");
        }
        ipv4_endpoint result {{}, port};
        std::memcpy(result.address.data(), &native, result.address.size());
        return result;
    }
};

} // namespace eventloop
