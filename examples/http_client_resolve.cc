#include "http_client_resolve.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <array>
#include <charconv>
#include <cstring>

namespace http_client_example {

auto resolve_addresses(const std::string& host,
                                     std::uint16_t port) noexcept
    -> resolved_addresses
{
    resolved_addresses result;
    std::array<char, 6> service {};
    const auto [service_end, conversion_error] = std::to_chars(
        service.data(), service.data() + service.size() - 1, port);
    if (conversion_error != std::errc {}) {
        result.error = EAI_SERVICE;
        return result;
    }
    *service_end = '\0';
    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;
    addrinfo* records = nullptr;
    result.error = ::getaddrinfo(host.c_str(), service.data(), &hints,
                                 &records);
    if (result.error != 0) return result;

    for (auto* record = records;
         record != nullptr && result.count < result.endpoints.size();
         record = record->ai_next) {
        if (record->ai_family == AF_INET &&
            record->ai_addrlen >= sizeof(sockaddr_in)) {
            const auto* address = reinterpret_cast<const sockaddr_in*>(
                record->ai_addr);
            std::array<std::uint8_t, 4> bytes {};
            std::memcpy(bytes.data(), &address->sin_addr, bytes.size());
            result.endpoints[result.count++] =
                eventloop::ip_endpoint::from_ipv4(bytes,
                                                  ntohs(address->sin_port));
        } else if (record->ai_family == AF_INET6 &&
                   record->ai_addrlen >= sizeof(sockaddr_in6)) {
            const auto* address = reinterpret_cast<const sockaddr_in6*>(
                record->ai_addr);
            std::array<std::uint8_t, 16> bytes {};
            std::memcpy(bytes.data(), &address->sin6_addr, bytes.size());
            result.endpoints[result.count++] =
                eventloop::ip_endpoint::from_ipv6(
                    bytes, ntohs(address->sin6_port),
                    address->sin6_scope_id);
        }
    }
    ::freeaddrinfo(records);
    return result;
}

} // namespace http_client_example
