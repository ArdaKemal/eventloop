#include "socket_operations.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/udp_socket.h"
#include "ip_endpoint_native.h"

#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <netinet/tcp.h>
#ifndef __APPLE__
#include <sys/sendfile.h>
#endif
#include <sys/socket.h>
#include <unistd.h>

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
    case ENOPROTOOPT: case EHOSTDOWN: case EHOSTUNREACH:
#ifndef __APPLE__
    case ENONET:
#endif
    case EOPNOTSUPP: case ENETUNREACH: return true;
    default: return false;
    }
}
} // namespace

auto socket_operations::create(int family, int type, int protocol)
    -> native_socket
{
#ifdef __APPLE__
    unique_fd descriptor(::socket(family, type, protocol));
    if (!descriptor)
        throw std::system_error(errno, std::system_category(), "socket");
    if (const auto error = activate(descriptor.get()))
        throw std::system_error(error, "activate socket");
    return descriptor.release();
#else
    const int descriptor = ::socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC,
                                    protocol);
    if (descriptor == -1)
        throw std::system_error(errno, std::system_category(), "socket");
    return descriptor;
#endif
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
    return {};
}

auto socket_operations::activate(native_socket socket) noexcept
    -> std::error_code
{
    const int flags = ::fcntl(socket, F_GETFL);
    if (flags == -1 || ::fcntl(socket, F_SETFL, flags | O_NONBLOCK) == -1)
        return code(errno);
#ifdef __APPLE__
    const int descriptor_flags = ::fcntl(socket, F_GETFD);
    if (descriptor_flags == -1 ||
        ::fcntl(socket, F_SETFD, descriptor_flags | FD_CLOEXEC) == -1)
        return code(errno);
    const int enabled = 1;
    if (::setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                     sizeof(enabled)) == -1)
        return code(errno);
#endif
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
#ifdef __APPLE__
        const int accepted = ::accept(listener, nullptr, nullptr);
#else
        const int accepted = ::accept4(listener, nullptr, nullptr,
                                       SOCK_NONBLOCK | SOCK_CLOEXEC);
#endif
        if (accepted >= 0) {
#ifdef __APPLE__
            if (const auto error = activate(accepted)) {
                ::close(accepted);
                return {.error = error};
            }
#endif
            const int enabled = 1;
            if (::setsockopt(accepted, IPPROTO_TCP, TCP_NODELAY, &enabled,
                             sizeof(enabled)) != 0) {
                const int error = errno;
                ::close(accepted);
                return {.error = code(error)};
            }
            return {.accepted = accepted};
        }
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
        const auto result = ::send(socket, buffer, size,
#ifdef __APPLE__
                                   0); // SO_NOSIGPIPE is set by activate().
#else
                                   MSG_NOSIGNAL);
#endif
        if (result >= 0) return {.transferred = static_cast<std::size_t>(result)};
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {.pending = true};
        return {.error = code(errno)};
    }
}

auto socket_operations::start_send_file(native_socket socket,
                                        native_socket file, std::size_t size,
                                        socket_operation&) noexcept -> socket_result
{
    // Darwin interprets a zero sendfile length as "through EOF".
    if (size == 0) return {};
    for (;;) {
#ifdef __APPLE__
        // Darwin sendfile does not advance the input file's offset. Preserve
        // the Linux API's current-offset contract, including partial progress
        // returned alongside EAGAIN/EINTR.
        const off_t offset = ::lseek(file, 0, SEEK_CUR);
        if (offset == -1) return {.error = code(errno)};
        if (size > static_cast<std::size_t>(std::numeric_limits<off_t>::max()) ||
            offset > std::numeric_limits<off_t>::max() - static_cast<off_t>(size))
            return {.error = code(EOVERFLOW)};
        off_t transferred = static_cast<off_t>(size);
        const int result = ::sendfile(file, socket, offset, &transferred, nullptr, 0);
        const int error = result == -1 ? errno : 0;
        if (transferred > 0) {
            if (::lseek(file, offset + transferred, SEEK_SET) == -1)
                return {.error = code(errno)};
            if (error != 0 && error != EINTR && error != EAGAIN && error != EWOULDBLOCK)
                return {.error = code(error)};
            return {.transferred = static_cast<std::size_t>(transferred)};
        }
        if (result == 0) return {};
        if (error == EINTR) continue;
        if (error == EAGAIN || error == EWOULDBLOCK) return {.pending = true};
        return {.error = code(error)};
#else
        const auto result = ::sendfile(socket, file, nullptr, size);
        if (result >= 0)
            return {.transferred = static_cast<std::size_t>(result)};
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {.pending = true};
        return {.error = code(errno)};
#endif
    }
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
    msghdr message {};
    message.msg_name = &address;
    message.msg_namelen = sizeof(address);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    for (;;) {
        const auto received = ::recvmsg(socket, &message,
#ifdef __APPLE__
                                        0); // Darwin reports truncation in msg_flags.
#else
                                        MSG_TRUNC);
#endif
        if (received >= 0) {
            if ((message.msg_flags & MSG_TRUNC) != 0 ||
                static_cast<std::size_t>(received) > size)
                return {.error = code(EMSGSIZE)};
            try {
                return {.transferred = static_cast<std::size_t>(received),
                        .source = public_endpoint(address)};
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
        const auto sent = ::sendto(socket, buffer, size,
#ifdef __APPLE__
                                   0,
#else
                                   MSG_NOSIGNAL,
#endif
                                   address.address(), address.length);
        if (sent >= 0) return {.transferred = static_cast<std::size_t>(sent)};
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {.pending = true};
        return {.error = code(errno)};
    }
}

} // namespace eventloop::detail
