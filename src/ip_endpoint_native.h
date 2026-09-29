#pragma once

#include "eventloop/ip_endpoint.h"
#include "eventloop/native_socket.h"

#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace eventloop::detail {

struct native_ip_endpoint {
    sockaddr_storage storage {};
#ifdef _WIN32
    int length {0};
#else
    socklen_t length {0};
#endif

    [[nodiscard]] auto address() const noexcept -> const sockaddr*
    {
        return reinterpret_cast<const sockaddr*>(&storage);
    }
};

[[nodiscard]] inline auto native_endpoint(ip_endpoint endpoint) noexcept
    -> native_ip_endpoint
{
    native_ip_endpoint result;
    if (endpoint.address_family == ip_endpoint::family::ipv6) {
        sockaddr_in6 native {};
        native.sin6_family = AF_INET6;
        native.sin6_port = htons(endpoint.port);
        native.sin6_scope_id = endpoint.scope_id;
        std::memcpy(&native.sin6_addr, endpoint.address.data(), 16);
        std::memcpy(&result.storage, &native, sizeof(native));
        result.length = sizeof(native);
    } else {
        sockaddr_in native {};
        native.sin_family = AF_INET;
        native.sin_port = htons(endpoint.port);
        std::memcpy(&native.sin_addr, endpoint.address.data(), 4);
        std::memcpy(&result.storage, &native, sizeof(native));
        result.length = sizeof(native);
    }
    return result;
}

[[nodiscard]] inline auto public_endpoint(const sockaddr_storage& storage)
    -> ip_endpoint
{
    if (storage.ss_family == AF_INET6) {
        sockaddr_in6 native {};
        std::memcpy(&native, &storage, sizeof(native));
        std::array<std::uint8_t, 16> bytes {};
        std::memcpy(bytes.data(), &native.sin6_addr, bytes.size());
        return ip_endpoint::from_ipv6(bytes, ntohs(native.sin6_port),
                                      native.sin6_scope_id);
    }
    if (storage.ss_family == AF_INET) {
        sockaddr_in native {};
        std::memcpy(&native, &storage, sizeof(native));
        std::array<std::uint8_t, 4> bytes {};
        std::memcpy(bytes.data(), &native.sin_addr, bytes.size());
        return ip_endpoint::from_ipv4(bytes, ntohs(native.sin_port));
    }
    throw std::invalid_argument("unsupported socket address family");
}

[[nodiscard]] inline auto socket_family(ip_endpoint endpoint) noexcept -> int
{
    return endpoint.address_family == ip_endpoint::family::ipv6 ? AF_INET6 : AF_INET;
}

inline auto set_ipv6_only(native_socket descriptor, ip_endpoint endpoint) -> int
{
    if (endpoint.address_family != ip_endpoint::family::ipv6) return 0;
    const int enabled = 1;
#ifdef _WIN32
    return ::setsockopt(static_cast<SOCKET>(descriptor), IPPROTO_IPV6,
                        IPV6_V6ONLY, reinterpret_cast<const char*>(&enabled),
                        sizeof(enabled));
#else
    return ::setsockopt(descriptor, IPPROTO_IPV6, IPV6_V6ONLY, &enabled,
                        sizeof(enabled));
#endif
}

} // namespace eventloop::detail
