#include "socket_operations.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/udp_socket.h"
#include "ip_endpoint_native.h"

#include <array>
#include <cerrno>
#include <sys/ioctl.h>
#include <limits>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cstring>
#include <unistd.h>

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif

namespace eventloop::detail {
namespace {
[[nodiscard]] auto code(int error) noexcept -> std::error_code
{
    return {error, std::generic_category()};
}
[[nodiscard]] auto retryable_accept_error(int error) noexcept -> bool
{
    switch (error) {
    case EINTR: case ECONNABORTED: case ENETDOWN: case EPROTO:
    case ENOPROTOOPT: case EHOSTDOWN: case ENONET: case EHOSTUNREACH:
    case EOPNOTSUPP: case ENETUNREACH: return true;
    default: return false;
    }
}
} // namespace

auto socket_operations::create(int family, int type, int protocol)
    -> native_socket
{
    const int descriptor = ::socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC,
                                    protocol);
    if (descriptor == -1)
        throw std::system_error(errno, std::system_category(), "socket");
    return descriptor;
}

auto socket_operations::create_stream(ip_endpoint endpoint) -> native_socket
{ return create(socket_family(endpoint), SOCK_STREAM, 0); }
auto socket_operations::create_listener(ip_endpoint endpoint) -> native_socket
{ return create(socket_family(endpoint), SOCK_STREAM, 0); }
auto socket_operations::create_datagram(ip_endpoint endpoint) -> native_socket
{ return create(socket_family(endpoint), SOCK_DGRAM, 0); }

auto socket_operations::prepare_listener(native_socket socket,
                                         ip_endpoint endpoint,
                                         bool reuse_port) -> void
{
    const int enabled = 1;
    if (set_ipv6_only(socket, endpoint) == -1)
        throw std::system_error(errno, std::system_category(), "IPV6_V6ONLY");
    if (::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enabled,
                     sizeof(enabled)) == -1)
        throw std::system_error(errno, std::system_category(), "SO_REUSEADDR");
    if (reuse_port && ::setsockopt(socket, SOL_SOCKET, SO_REUSEPORT,
                                    &enabled, sizeof(enabled)) == -1)
        throw std::system_error(errno, std::system_category(), "SO_REUSEPORT");
    // Accepted sockets inherit TCP_NODELAY, saving a syscall per connection.
    if (::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &enabled,
                     sizeof(enabled)) == -1)
        throw std::system_error(errno, std::system_category(), "TCP_NODELAY");
    const auto address = native_endpoint(endpoint);
    if (::bind(socket, address.address(), address.length) == -1)
        throw std::system_error(errno, std::system_category(), "bind");
    if (::listen(socket, SOMAXCONN) == -1)
        throw std::system_error(errno, std::system_category(), "listen");
}

auto socket_operations::prepare_datagram(native_socket socket,
                                         ip_endpoint endpoint,
                                         bool reuse_port) -> void
{
    const int enabled = 1;
    if (set_ipv6_only(socket, endpoint) == -1)
        throw std::system_error(errno, std::system_category(), "IPV6_V6ONLY");
    if (::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enabled,
                     sizeof(enabled)) == -1)
        throw std::system_error(errno, std::system_category(), "SO_REUSEADDR");
    if (reuse_port && ::setsockopt(socket, SOL_SOCKET, SO_REUSEPORT,
                                    &enabled, sizeof(enabled)) == -1)
        throw std::system_error(errno, std::system_category(), "SO_REUSEPORT");
    const auto address = native_endpoint(endpoint);
    if (::bind(socket, address.address(), address.length) == -1)
        throw std::system_error(errno, std::system_category(), "bind");
}

auto socket_operations::local_endpoint(native_socket socket) -> ip_endpoint
{
    sockaddr_storage address {};
    socklen_t length = sizeof(address);
    if (::getsockname(socket, reinterpret_cast<sockaddr*>(&address),
                      &length) == -1)
        throw std::system_error(errno, std::system_category(), "getsockname");
    return public_endpoint(address);
}

auto socket_operations::peer_endpoint(native_socket socket) noexcept
    -> std::expected<ip_endpoint, std::error_code>
{
    sockaddr_storage address {};
    socklen_t length = sizeof(address);
    if (::getpeername(socket, reinterpret_cast<sockaddr*>(&address),
                      &length) == -1)
        return std::unexpected(code(errno));
    try {
        return public_endpoint(address);
    } catch (...) {
        return std::unexpected(code(EAFNOSUPPORT));
    }
}

auto socket_operations::configure_client(native_socket socket,
                                         ip_endpoint endpoint) noexcept
    -> std::error_code
{
    if (set_ipv6_only(socket, endpoint) == -1) return code(errno);
    // As for accepted sockets: Nagle would hold a small write until the
    // previous one is acknowledged, often a delayed-ACK interval.
    const int enabled = 1;
    if (::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &enabled,
                     sizeof(enabled)) == -1) return code(errno);
    return {};
}

auto socket_operations::activate(native_socket socket) noexcept
    -> std::error_code
{
    // One syscall, unlike F_GETFL/F_SETFL; accepted sockets pay it per stream.
    int enabled = 1;
    if (::ioctl(socket, FIONBIO, &enabled) == -1) return code(errno);
    return {};
}

auto socket_operations::pending_error(native_socket socket,
                                      int fallback_error) noexcept
    -> std::error_code
{
    int error = 0;
    socklen_t length = sizeof(error);
    if (::getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &length) == -1)
        error = errno;
    if (error == 0) error = fallback_error;
    return code(error);
}

auto socket_operations::start_accept(native_socket listener, int,
                                     std::span<std::byte>,
                                     socket_operation&) noexcept
    -> socket_result
{
    for (int attempt = 0; attempt < 64; ++attempt) {
        // TCP_NODELAY is inherited from the listener; see prepare_listener().
        const int accepted = ::accept4(listener, nullptr, nullptr,
                                       SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (accepted >= 0) return {.accepted = accepted};
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {.pending = true};
        if (!retryable_accept_error(errno)) return {.error = code(errno)};
    }
    return {.pending = true};
}

auto socket_operations::start_connect(native_socket socket,
                                      ip_endpoint endpoint,
                                      socket_operation&) noexcept
    -> socket_result
{
    const auto address = native_endpoint(endpoint);
    const int result = ::connect(socket, address.address(), address.length);
    if (result == 0 || errno == EISCONN) return {};
    if (errno == EINPROGRESS || errno == EINTR) return {.pending = true};
    return {.error = code(errno)};
}

auto socket_operations::start_unix_connect(native_socket socket,
                                           std::string_view path,
                                           socket_operation&) noexcept
    -> socket_result
{
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.data(), path.size());
    const auto length = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + path.size() + 1);
    const int result = ::connect(socket,
        reinterpret_cast<const sockaddr*>(&address), length);
    if (result == 0 || errno == EISCONN) return {};
    if (errno == EINPROGRESS || errno == EINTR || errno == EAGAIN)
        return {.pending = true};
    return {.error = code(errno)};
}

auto socket_operations::finish_connect(native_socket socket) noexcept
    -> std::error_code
{
    int error = 0;
    socklen_t length = sizeof(error);
    if (::getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &length) == -1)
        error = errno;
    return code(error);
}

auto socket_operations::start_read(native_socket socket, void* buffer,
                                   std::size_t size, socket_operation&) noexcept
    -> socket_result
{
    if (size == 0) return {};
    if (buffer == nullptr ||
        size > static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()))
        return {.error = code(EINVAL)};
    for (;;) {
        const auto result = ::recv(socket, buffer, size, 0);
        if (result >= 0) return {.transferred = static_cast<std::size_t>(result)};
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {.pending = true};
        return {.error = code(errno)};
    }
}

auto socket_operations::start_write(native_socket socket, const void* buffer,
                                    std::size_t size, socket_operation&) noexcept
    -> socket_result
{
    if (size == 0) return {};
    if (buffer == nullptr ||
        size > static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()))
        return {.error = code(EINVAL)};
    for (;;) {
        const auto result = ::send(socket, buffer, size, MSG_NOSIGNAL);
        if (result >= 0) return {.transferred = static_cast<std::size_t>(result)};
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {.pending = true};
        return {.error = code(errno)};
    }
}

auto socket_operations::start_write_gather(native_socket socket,
    std::span<const std::span<const std::byte>> buffers,
    socket_operation&) noexcept -> socket_result
{
    std::array<iovec, tcp_stream::max_write_buffers> vectors {};
    msghdr message {};
    message.msg_iov = vectors.data();
    std::size_t total = 0;
    for (const auto buffer : buffers) {
        if (buffer.empty()) continue;
        if (buffer.size() > static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()) - total)
            break;
        vectors[message.msg_iovlen++] = {const_cast<std::byte*>(buffer.data()), buffer.size()};
        total += buffer.size();
    }
    if (total == 0) return {};
    for (;;) {
        const auto result = ::sendmsg(socket, &message, MSG_NOSIGNAL);
        if (result >= 0) return {.transferred = static_cast<std::size_t>(result)};
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {.pending = true};
        return {.error = code(errno)};
    }
}

auto socket_operations::start_send_file(native_socket socket,
                                        native_socket file, std::uint64_t offset,
                                        std::size_t size,
                                        socket_operation&) noexcept -> socket_result
{
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()))
        return {.error = code(EOVERFLOW)};
    for (;;) {
        auto position = static_cast<off_t>(offset);
        const auto result = ::sendfile(socket, file, &position, size);
        if (result >= 0)
            return {.transferred = static_cast<std::size_t>(result)};
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {.pending = true};
        return {.error = code(errno)};
    }
}

auto socket_operations::send_more_now(native_socket socket,
                                      std::span<const std::byte> buffer) noexcept
    -> std::size_t
{
    std::size_t sent = 0;
    while (sent < buffer.size()) {
        const auto result = ::send(socket, buffer.data() + sent, buffer.size() - sent,
                                   MSG_NOSIGNAL | MSG_MORE);
        if (result > 0) sent += static_cast<std::size_t>(result);
        else if (result == -1 && errno == EINTR) continue;
        else break;
    }
    return sent;
}

auto socket_operations::set_cork(native_socket socket, bool enabled) noexcept -> bool
{
    const int value = enabled ? 1 : 0;
    return ::setsockopt(socket, IPPROTO_TCP, TCP_CORK, &value, sizeof(value)) == 0;
}

auto socket_operations::start_receive_from(native_socket socket, void* buffer,
                                           std::size_t size,
                                           socket_operation&) noexcept
    -> socket_result
{
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        return {.error = code(EINVAL)};
    sockaddr_storage address {};
    iovec iov {.iov_base = buffer, .iov_len = size};
    std::array<std::byte, 64> control {};
    msghdr message {};
    message.msg_name = &address;
    message.msg_namelen = sizeof(address);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    for (;;) {
        const auto received = ::recvmsg(socket, &message, MSG_TRUNC);
        if (received >= 0) {
            if ((message.msg_flags & MSG_TRUNC) != 0 ||
                static_cast<std::size_t>(received) > size)
                return {.error = code(EMSGSIZE)};
            std::size_t segment = 0;
            if ((message.msg_flags & MSG_CTRUNC) == 0) {
                for (auto* cmsg = CMSG_FIRSTHDR(&message); cmsg != nullptr;
                     cmsg = CMSG_NXTHDR(&message, cmsg)) {
                    if (cmsg->cmsg_level == IPPROTO_UDP &&
                        cmsg->cmsg_type == UDP_GRO) {
                        std::uint16_t value = 0;
                        std::memcpy(&value, CMSG_DATA(cmsg), sizeof(value));
                        segment = value;
                        break;
                    }
                }
            }
            try {
                return {.transferred = static_cast<std::size_t>(received),
                        .source = public_endpoint(address),
                        .segment_size = segment};
            } catch (...) { return {.error = code(EIO)}; }
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {.pending = true};
        return {.error = code(errno)};
    }
}

auto socket_operations::start_send_to(native_socket socket,
                                      const void* buffer, std::size_t size,
                                      ip_endpoint destination,
                                      socket_operation&) noexcept
    -> socket_result
{
    const bool ipv6 = destination.address_family == ip_endpoint::family::ipv6;
    if (size > (ipv6 ? 65527U : 65507U)) return {.error = code(EMSGSIZE)};
    const auto address = native_endpoint(destination);
    for (;;) {
        const auto sent = ::sendto(socket, buffer, size, MSG_NOSIGNAL,
                                   address.address(), address.length);
        if (sent >= 0) return {.transferred = static_cast<std::size_t>(sent)};
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {.pending = true};
        return {.error = code(errno)};
    }
}

auto socket_operations::start_send_segments(native_socket socket,
                                            const void* buffer, std::size_t size,
                                            std::size_t segment,
                                            ip_endpoint destination,
                                            socket_operation& operation) noexcept
    -> socket_result
{
    if (segment == 0 || segment > 0xffffU) return {.error = code(EINVAL)};
    if (segment >= size) return start_send_to(socket, buffer, size, destination, operation);
    const bool ipv6 = destination.address_family == ip_endpoint::family::ipv6;
    if (size > (ipv6 ? 65535U : 65507U)) return {.error = code(EMSGSIZE)};
    const auto address = native_endpoint(destination);
    std::array<char, CMSG_SPACE(sizeof(std::uint16_t))> control {};
    iovec vector {};
    vector.iov_base = const_cast<void*>(buffer);
    vector.iov_len = size;
    msghdr message {};
    message.msg_name = const_cast<sockaddr*>(address.address());
    message.msg_namelen = address.length;
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    auto* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = IPPROTO_UDP;
    header->cmsg_type = UDP_SEGMENT;
    header->cmsg_len = CMSG_LEN(sizeof(std::uint16_t));
    const auto value = static_cast<std::uint16_t>(segment);
    std::memcpy(CMSG_DATA(header), &value, sizeof(value));
    for (;;) {
        const auto sent = ::sendmsg(socket, &message, MSG_NOSIGNAL);
        if (sent >= 0) return {.transferred = static_cast<std::size_t>(sent)};
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {.pending = true};
        return {.error = code(errno)};
    }
}

} // namespace eventloop::detail
