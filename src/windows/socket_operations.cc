#include "socket_operations.h"
#include "ip_endpoint_native.h"

#include <mswsock.h>
#include <limits>
#include <stdexcept>

namespace eventloop::detail {
namespace {
[[nodiscard]] auto last_error() noexcept -> std::error_code
{
    return {::WSAGetLastError(), std::system_category()};
}

[[nodiscard]] auto submission_result(int status,
                                     socket_operation& operation) noexcept
    -> socket_result
{
    if (status == 0) {
        operation.pending_completion = true;
        return {.pending = true};
    }
    const int error = ::WSAGetLastError();
    if (error == WSA_IO_PENDING) {
        operation.pending_completion = true;
        return {.pending = true};
    }
    return {.error = {error, std::system_category()}};
}

template<typename Function>
[[nodiscard]] auto extension(native_socket socket, GUID guid) noexcept
    -> Function
{
    Function function = nullptr;
    DWORD bytes = 0;
    if (::WSAIoctl(static_cast<SOCKET>(socket),
                   SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid),
                   &function, sizeof(function), &bytes, nullptr, nullptr) != 0)
        return nullptr;
    return function;
}
} // namespace

auto socket_operations::create(int family, int type, int protocol)
    -> native_socket
{
    const SOCKET socket = ::WSASocketW(family, type, protocol, nullptr, 0,
                                       WSA_FLAG_OVERLAPPED);
    if (socket == INVALID_SOCKET)
        throw std::system_error(last_error(), "WSASocket");
    return static_cast<native_socket>(socket);
}

auto socket_operations::prepare_listener(native_socket socket,
                                         ip_endpoint endpoint,
                                         bool reuse_port) -> void
{
    if (reuse_port) throw std::invalid_argument("SO_REUSEPORT is unavailable");
    if (set_ipv6_only(socket, endpoint) == SOCKET_ERROR)
        throw std::system_error(last_error(), "IPV6_V6ONLY");
    const BOOL exclusive = TRUE;
    if (::setsockopt(static_cast<SOCKET>(socket), SOL_SOCKET,
                     SO_EXCLUSIVEADDRUSE,
                     reinterpret_cast<const char*>(&exclusive),
                     sizeof(exclusive)) == SOCKET_ERROR)
        throw std::system_error(last_error(), "SO_EXCLUSIVEADDRUSE");
    const auto address = native_endpoint(endpoint);
    if (::bind(static_cast<SOCKET>(socket), address.address(),
               address.length) == SOCKET_ERROR)
        throw std::system_error(last_error(), "bind");
    if (::listen(static_cast<SOCKET>(socket), SOMAXCONN) == SOCKET_ERROR)
        throw std::system_error(last_error(), "listen");
}

auto socket_operations::prepare_datagram(native_socket socket,
                                         ip_endpoint endpoint,
                                         bool reuse_port) -> void
{
    if (reuse_port) throw std::invalid_argument("SO_REUSEPORT is unavailable");
    if (set_ipv6_only(socket, endpoint) == SOCKET_ERROR)
        throw std::system_error(last_error(), "IPV6_V6ONLY");
    const BOOL exclusive = TRUE;
    if (::setsockopt(static_cast<SOCKET>(socket), SOL_SOCKET,
                     SO_EXCLUSIVEADDRUSE,
                     reinterpret_cast<const char*>(&exclusive),
                     sizeof(exclusive)) == SOCKET_ERROR)
        throw std::system_error(last_error(), "SO_EXCLUSIVEADDRUSE");
    const auto address = native_endpoint(endpoint);
    if (::bind(static_cast<SOCKET>(socket), address.address(),
               address.length) == SOCKET_ERROR)
        throw std::system_error(last_error(), "bind");
}

auto socket_operations::local_endpoint(native_socket socket) -> ip_endpoint
{
    sockaddr_storage address {};
    int length = sizeof(address);
    if (::getsockname(static_cast<SOCKET>(socket),
                      reinterpret_cast<sockaddr*>(&address), &length) ==
        SOCKET_ERROR) throw std::system_error(last_error(), "getsockname");
    return public_endpoint(address);
}

auto socket_operations::peer_endpoint(native_socket socket) noexcept
    -> std::expected<ip_endpoint, std::error_code>
{
    sockaddr_storage address {};
    int length = sizeof(address);
    if (::getpeername(static_cast<SOCKET>(socket),
                      reinterpret_cast<sockaddr*>(&address), &length) ==
        SOCKET_ERROR)
        return std::unexpected(last_error());
    try {
        return public_endpoint(address);
    } catch (...) {
        return std::unexpected(std::make_error_code(
            std::errc::address_family_not_supported));
    }
}

auto socket_operations::received_source(const socket_operation& operation)
    noexcept -> ip_endpoint
{
    try { return public_endpoint(operation.address); }
    catch (...) { return {}; }
}

auto socket_operations::configure_client(native_socket socket,
                                         ip_endpoint endpoint) noexcept
    -> std::error_code
{
    if (set_ipv6_only(socket, endpoint) == SOCKET_ERROR) return last_error();
    return {};
}

auto socket_operations::activate(native_socket) noexcept -> std::error_code
{
    return {};
}

auto socket_operations::pending_error(native_socket socket,
                                      int fallback_error) noexcept
    -> std::error_code
{
    int error = 0;
    int length = sizeof(error);
    if (::getsockopt(static_cast<SOCKET>(socket), SOL_SOCKET, SO_ERROR,
                     reinterpret_cast<char*>(&error), &length) == SOCKET_ERROR)
        return last_error();
    if (error == 0)
        return {fallback_error, std::generic_category()};
    return {error, std::system_category()};
}

auto socket_operations::start_accept(native_socket listener, int family,
                                     std::span<std::byte> address_buffer,
                                     socket_operation& operation) noexcept
    -> socket_result
{
    const SOCKET accepted = ::WSASocketW(family, SOCK_STREAM, IPPROTO_TCP,
                                         nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (accepted == INVALID_SOCKET) return {.error = last_error()};
    const auto accept_ex = extension<LPFN_ACCEPTEX>(listener, WSAID_ACCEPTEX);
    if (accept_ex == nullptr) {
        const auto error = last_error();
        ::closesocket(accepted);
        return {.error = error};
    }
    if (address_buffer.size() < 2 * (sizeof(sockaddr_storage) + 16)) {
        ::closesocket(accepted);
        return {.error = std::make_error_code(std::errc::invalid_argument)};
    }
    DWORD bytes = 0;
    const BOOL started = accept_ex(
        static_cast<SOCKET>(listener), static_cast<SOCKET>(accepted),
        address_buffer.data(), 0,
        static_cast<DWORD>(sizeof(sockaddr_storage) + 16),
        static_cast<DWORD>(sizeof(sockaddr_storage) + 16), &bytes,
        &operation.overlapped);
    auto result = submission_result(started ? 0 : SOCKET_ERROR, operation);
    if (result.pending) result.accepted = static_cast<native_socket>(accepted);
    else ::closesocket(accepted);
    return result;
}

auto socket_operations::finish_accept(native_socket listener,
                                      native_socket accepted) noexcept
    -> std::error_code
{
    const SOCKET listening_socket = static_cast<SOCKET>(listener);
    if (::setsockopt(static_cast<SOCKET>(accepted), SOL_SOCKET,
                     SO_UPDATE_ACCEPT_CONTEXT,
                     reinterpret_cast<const char*>(&listening_socket),
                     sizeof(listening_socket)) != 0) return last_error();
    const BOOL enabled = TRUE;
    if (::setsockopt(static_cast<SOCKET>(accepted), IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&enabled), sizeof(enabled)) != 0)
        return last_error();
    return {};
}

auto socket_operations::start_connect(native_socket socket,
                                      ip_endpoint endpoint,
                                      socket_operation& operation) noexcept
    -> socket_result
{
    const auto connect_ex = extension<LPFN_CONNECTEX>(socket, WSAID_CONNECTEX);
    if (connect_ex == nullptr) return {.error = last_error()};
    const int family = socket_family(endpoint);
    if (family == AF_INET6) {
        sockaddr_in6 local {};
        local.sin6_family = AF_INET6;
        if (::bind(static_cast<SOCKET>(socket),
                   reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0)
            return {.error = last_error()};
    } else {
        sockaddr_in local {};
        local.sin_family = AF_INET;
        if (::bind(static_cast<SOCKET>(socket),
                   reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0)
            return {.error = last_error()};
    }
    const auto remote = native_endpoint(endpoint);
    const BOOL started = connect_ex(static_cast<SOCKET>(socket),
                                    remote.address(), remote.length,
                                    nullptr, 0, nullptr, &operation.overlapped);
    return submission_result(started ? 0 : SOCKET_ERROR, operation);
}

auto socket_operations::finish_connect(native_socket socket) noexcept
    -> std::error_code
{
    if (::setsockopt(static_cast<SOCKET>(socket), SOL_SOCKET,
                     SO_UPDATE_CONNECT_CONTEXT, nullptr, 0) != 0)
        return last_error();
    return {};
}

auto socket_operations::start_read(native_socket socket, void* buffer,
                                   std::size_t size,
                                   socket_operation& operation) noexcept
    -> socket_result
{
    if (size == 0) return {};
    if (size > std::numeric_limits<ULONG>::max())
        return {.error = std::make_error_code(std::errc::invalid_argument)};
    operation.buffer = {static_cast<ULONG>(size), static_cast<char*>(buffer)};
    operation.flags = 0;
    return submission_result(::WSARecv(static_cast<SOCKET>(socket),
                                       &operation.buffer, 1, nullptr,
                                       &operation.flags,
                                       &operation.overlapped, nullptr), operation);
}

auto socket_operations::start_write(native_socket socket, const void* buffer,
                                    std::size_t size,
                                    socket_operation& operation) noexcept
    -> socket_result
{
    if (size == 0) return {};
    if (size > std::numeric_limits<ULONG>::max())
        return {.error = std::make_error_code(std::errc::invalid_argument)};
    operation.buffer = {static_cast<ULONG>(size),
                        const_cast<char*>(static_cast<const char*>(buffer))};
    return submission_result(::WSASend(static_cast<SOCKET>(socket),
                                       &operation.buffer, 1, nullptr, 0,
                                       &operation.overlapped, nullptr), operation);
}

auto socket_operations::start_receive_from(
    native_socket socket, void* buffer, std::size_t size,
    socket_operation& operation) noexcept -> socket_result
{
    if (size > std::numeric_limits<ULONG>::max())
        return {.error = std::make_error_code(std::errc::invalid_argument)};
    operation.buffer = {static_cast<ULONG>(size), static_cast<char*>(buffer)};
    operation.flags = 0;
    operation.address_length = sizeof(sockaddr_storage);
    return submission_result(::WSARecvFrom(
        static_cast<SOCKET>(socket), &operation.buffer, 1, nullptr,
        &operation.flags, reinterpret_cast<sockaddr*>(&operation.address),
        &operation.address_length, &operation.overlapped, nullptr), operation);
}

auto socket_operations::start_send_to(native_socket socket,
                                      const void* buffer, std::size_t size,
                                      ip_endpoint destination,
                                      socket_operation& operation) noexcept
    -> socket_result
{
    if (size > std::numeric_limits<ULONG>::max())
        return {.error = std::make_error_code(std::errc::invalid_argument)};
    const auto native = native_endpoint(destination);
    operation.address = native.storage;
    operation.address_length = native.length;
    operation.buffer = {static_cast<ULONG>(size),
                        const_cast<char*>(static_cast<const char*>(buffer))};
    return submission_result(::WSASendTo(
        static_cast<SOCKET>(socket), &operation.buffer, 1, nullptr, 0,
        reinterpret_cast<const sockaddr*>(&operation.address),
        operation.address_length, &operation.overlapped, nullptr), operation);
}

auto socket_operations::cancel(native_socket socket,
                               socket_operation& operation) noexcept -> void
{
    (void)::CancelIoEx(reinterpret_cast<HANDLE>(socket),
                       &operation.overlapped);
}

} // namespace eventloop::detail
