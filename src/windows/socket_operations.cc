#include "socket_operations.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/udp_socket.h"
#include "ip_endpoint_native.h"

#include <mswsock.h>
#include <mstcpip.h>
#include <cerrno>
#include <io.h>
#include <limits>
#include <stdexcept>

namespace eventloop::detail {
auto socket_operations::accept_register(tcp_acceptor& acceptor,
    ip_endpoint endpoint) noexcept -> void
{
    acceptor.backend_state_.registered_descriptor = acceptor.descriptor_.get();
    acceptor.backend_state_.family = socket_family(endpoint);
}
auto socket_operations::accept_bind(tcp_acceptor::accept_awaiter& awaiter)
    noexcept -> void
{
    auto& operation = awaiter.operation_;
    operation.context = &awaiter;
    operation.complete = [](socket_operation& op, std::size_t, int error) noexcept {
        auto& self = *static_cast<tcp_acceptor::accept_awaiter*>(op.context);
        std::error_code result;
        if (op.cancelled || self.owner_.closed_)
            result = {ECANCELED, std::generic_category()};
        else if (error != 0) result = {error, std::system_category()};
        else result = finish_accept(self.owner_.descriptor_.get(),
                                    self.backend_state_.accepted.get());
        unique_fd accepted = std::move(self.backend_state_.accepted);
        if (result) accepted.reset();
        self.owner_.complete_accept(std::move(accepted), result);
    };
}
auto socket_operations::accept_start(tcp_acceptor& acceptor,
    tcp_acceptor::accept_awaiter& awaiter) noexcept -> socket_result
{
    auto result = start_accept(acceptor.descriptor_.get(),
        acceptor.backend_state_.family, awaiter.backend_state_.addresses,
        awaiter.operation_);
    if (result.pending && result.accepted != static_cast<native_socket>(-1))
        awaiter.backend_state_.accepted.reset(result.accepted);
    return result;
}
auto socket_operations::accept_try_immediate(tcp_acceptor&,
    tcp_acceptor::accept_awaiter&) noexcept -> socket_result
{ return {.pending = true}; }
auto socket_operations::accept_submit(tcp_acceptor& acceptor,
    tcp_acceptor::accept_awaiter& awaiter) noexcept -> socket_result
{ return accept_start(acceptor, awaiter); }
auto socket_operations::accept_cancel(tcp_acceptor& acceptor,
    tcp_acceptor::accept_awaiter& awaiter) noexcept -> bool
{
    if (!awaiter.operation_.pending_completion) return false;
    awaiter.operation_.cancelled = true;
    cancel(acceptor.descriptor_.get(), awaiter.operation_);
    return true;
}
auto socket_operations::accept_retire(tcp_acceptor& acceptor,
    tcp_acceptor::accept_awaiter& awaiter) noexcept -> void
{
    awaiter.operation_.pending_completion = false;
    if (acceptor.closed_)
        acceptor.loop_.remove(acceptor.backend_state_.registered_descriptor);
}
auto socket_operations::accept_close(tcp_acceptor& acceptor) -> void
{ acceptor.loop_.remove(acceptor.backend_state_.registered_descriptor); }

auto socket_operations::datagram_register(udp_socket& socket) noexcept -> void
{ socket.backend_state_.registered_descriptor = socket.descriptor_.get(); }
auto socket_operations::datagram_bind(udp_socket::receive_awaiter& awaiter)
    noexcept -> void
{
    auto& operation = awaiter.operation_;
    operation.context = &awaiter;
    operation.complete = [](socket_operation& op, std::size_t bytes,
                            int error) noexcept {
        auto& self = *static_cast<udp_socket::receive_awaiter*>(op.context);
        socket_result result {.transferred = bytes};
        if (error != 0) result.error = {error, std::system_category()};
        const int value = op.cancelled || self.socket_.closing_
            ? -ECANCELED : datagram_result(result);
        self.socket_.complete_receive(value, received_source(op));
    };
}
auto socket_operations::datagram_bind(udp_socket::send_awaiter& awaiter)
    noexcept -> void
{
    auto& operation = awaiter.operation_;
    operation.context = &awaiter;
    operation.complete = [](socket_operation& op, std::size_t bytes,
                            int error) noexcept {
        auto& self = *static_cast<udp_socket::send_awaiter*>(op.context);
        socket_result result {.transferred = bytes};
        if (error != 0) result.error = {error, std::system_category()};
        self.socket_.complete_send(op.cancelled || self.socket_.closing_
            ? -ECANCELED : datagram_result(result));
    };
}
auto socket_operations::datagram_receive(udp_socket& socket,
    udp_socket::receive_awaiter& awaiter) noexcept -> socket_result
{ return start_receive_from(socket.descriptor_.get(), awaiter.buffer_.data(),
                            awaiter.buffer_.size(), awaiter.operation_); }
auto socket_operations::datagram_send(udp_socket& socket,
    udp_socket::send_awaiter& awaiter) noexcept -> socket_result
{ return start_send_to(socket.descriptor_.get(), awaiter.buffer_.data(),
                       awaiter.buffer_.size(), awaiter.destination_,
                       awaiter.operation_); }
auto socket_operations::datagram_submitted(udp_socket& socket,
    socket_operation& operation) noexcept -> void
{ if (operation.pending_completion) ++socket.backend_state_.pending_operations; }
auto socket_operations::datagram_cancel(udp_socket& socket,
    socket_operation& operation) noexcept -> bool
{
    if (!operation.pending_completion) return false;
    operation.cancelled = true;
    cancel(socket.descriptor_.get(), operation);
    return true;
}
auto socket_operations::datagram_retire(udp_socket& socket,
    socket_operation& operation) noexcept -> void
{
    if (operation.pending_completion) {
        operation.pending_completion = false;
        if (socket.backend_state_.pending_operations == 0) std::terminate();
        --socket.backend_state_.pending_operations;
    }
    if (socket.closing_ && socket.backend_state_.pending_operations == 0)
        socket.loop_.remove(socket.backend_state_.registered_descriptor);
}
auto socket_operations::datagram_close(udp_socket& socket) -> void
{
    if (socket.backend_state_.pending_operations != 0) socket.descriptor_.reset();
    else socket.loop_.remove(socket.backend_state_.registered_descriptor);
}
auto socket_operations::datagram_pending(const udp_socket& socket) noexcept -> bool
{ return socket.backend_state_.pending_operations != 0; }
auto socket_operations::datagram_result(const socket_result& result) noexcept -> int
{
    if (!result.error) return static_cast<int>(result.transferred);
    if (result.error.value() == WSAEMSGSIZE ||
        result.error.value() == ERROR_MORE_DATA) return -EMSGSIZE;
    if (result.error.value() == WSAEINVAL ||
        result.error.value() == ERROR_INVALID_PARAMETER) return -EINVAL;
    if (result.error.value() == ERROR_OPERATION_ABORTED) return -ECANCELED;
    return -EIO;
}
auto socket_operations::datagram_error(udp_socket& socket, int result) noexcept -> void
{
    if (socket.backend_state_.pending_operations != 0) socket.close();
    else socket.complete_pending(result);
}

auto socket_operations::stream_register(tcp_stream& stream) noexcept -> void
{ stream.socket_state_.registered_descriptor = stream.descriptor_.get(); }

auto socket_operations::stream_has_pending(const tcp_stream& stream) noexcept
    -> bool
{ return stream.socket_state_.pending_operations != 0; }

auto socket_operations::stream_bind(tcp_stream&, socket_operation& operation,
                                    void* awaiter,
                                    stream_operation_kind kind) noexcept -> void
{
    operation.context = awaiter;
    switch (kind) {
    case stream_operation_kind::connect:
        operation.complete = [](socket_operation& op, std::size_t,
                                int error) noexcept {
            auto& self = *static_cast<tcp_stream::connect_awaiter*>(op.context);
            std::error_code result;
            if (op.cancelled || self.owner_.closed_)
                result = {ECANCELED, std::generic_category()};
            else if (error == ERROR_CONNECTION_REFUSED)
                result = {WSAECONNREFUSED, std::system_category()};
            else if (error != 0)
                result = {error, std::system_category()};
            else result = finish_connect(self.owner_.descriptor_.get());
            if (result && !self.owner_.closed_) {
                self.owner_.closed_ = true;
                self.owner_.descriptor_.reset();
            }
            if (!result) self.owner_.connected_ = true;
            self.owner_.complete_connect(result);
        };
        break;
    case stream_operation_kind::read:
        operation.complete = [](socket_operation& op, std::size_t bytes,
                                int error) noexcept {
            auto& self = *static_cast<tcp_stream::io_awaiter<true>*>(op.context);
            std::error_code result;
            if (op.cancelled || self.owner_.closed_)
                result = {ECANCELED, std::generic_category()};
            else if (error != 0) result = {error, std::system_category()};
            self.owner_.complete_read(bytes, result);
        };
        break;
    case stream_operation_kind::write:
        operation.complete = [](socket_operation& op, std::size_t bytes,
                                int error) noexcept {
            auto& self = *static_cast<tcp_stream::io_awaiter<false>*>(op.context);
            std::error_code result;
            if (op.cancelled || self.owner_.closed_)
                result = {ECANCELED, std::generic_category()};
            else if (error != 0) result = {error, std::system_category()};
            self.owner_.complete_write(bytes, result);
        };
        break;
    case stream_operation_kind::file:
        operation.complete = [](socket_operation& op, std::size_t bytes,
                                int error) noexcept {
            auto& self = *static_cast<tcp_stream::file_awaiter*>(op.context);
            if (!op.pending_completion ||
                self.owner_.socket_state_.pending_operations == 0)
                std::terminate();
            stream_retire(self.owner_, op);
            if (op.cancelled || self.owner_.closed_) {
                self.owner_.complete_file({ECANCELED, std::generic_category()});
                return;
            }
            if (error != 0) {
                self.owner_.complete_file({error, std::system_category()});
                return;
            }
            if (bytes == 0 || bytes > op.file_requested ||
                bytes > self.remaining_) {
                self.owner_.complete_file({EIO, std::generic_category()});
                return;
            }
            self.remaining_ -= bytes;
            self.offset_ += bytes;
            const auto next = self.advance();
            if (next.value() != EAGAIN) self.owner_.complete_file(next);
        };
        break;
    }
}

auto socket_operations::stream_submitted(tcp_stream& stream,
                                         socket_operation& operation) noexcept
    -> void
{ if (operation.pending_completion) ++stream.socket_state_.pending_operations; }

auto socket_operations::stream_retire(tcp_stream& stream,
                                      socket_operation& operation) noexcept -> void
{
    if (operation.pending_completion) {
        operation.pending_completion = false;
        if (stream.socket_state_.pending_operations == 0) std::terminate();
        --stream.socket_state_.pending_operations;
    }
    if (stream.closed_ && stream.socket_state_.pending_operations == 0)
        stream.loop_.remove(stream.socket_state_.registered_descriptor);
}

auto socket_operations::stream_pending(const socket_operation& operation)
    noexcept -> bool
{ return operation.pending_completion; }

auto socket_operations::stream_cancel(tcp_stream& stream,
                                      socket_operation& operation) noexcept
    -> bool
{
    if (!operation.pending_completion) return false;
    operation.cancelled = true;
    cancel(stream.descriptor_.get(), operation);
    return true;
}

auto socket_operations::stream_close(tcp_stream& stream) -> void
{
    if (stream.socket_state_.pending_operations != 0) stream.descriptor_.reset();
    else stream.loop_.remove(stream.socket_state_.registered_descriptor);
}

auto socket_operations::stream_send_file(tcp_stream& stream,
                                         unique_fd& file, std::uint64_t offset,
                                         std::size_t size,
                                         socket_operation& operation) noexcept
    -> socket_result
{
    // TransmitFile advances the handle's file pointer, which duplicates and
    // CRT descriptors share. Send from a private file object instead.
    if (!operation.file_reopened) {
        native_socket native_file = file.get();
        if (file.kind_ == unique_fd::kind::file) {
            const auto handle = ::_get_osfhandle(static_cast<int>(file.get()));
            if (handle == -1)
                return {.error = {EBADF, std::generic_category()}};
            native_file = static_cast<native_socket>(handle);
        }
        const HANDLE reopened = ::ReOpenFile(reinterpret_cast<HANDLE>(native_file),
            GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
        if (reopened == INVALID_HANDLE_VALUE)
            return {.error = {static_cast<int>(::GetLastError()), std::system_category()}};
        file = unique_fd(reinterpret_cast<native_socket>(reopened),
                         unique_fd::kind::native_file);
        operation.file_reopened = true;
    }
    operation.file_requested = size;
    return start_send_file(stream.descriptor_.get(), file.get(), offset, size, operation);
}

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

auto socket_operations::create_stream(ip_endpoint endpoint) -> native_socket
{ return create(socket_family(endpoint), SOCK_STREAM, 0); }
auto socket_operations::create_listener(ip_endpoint endpoint) -> native_socket
{ return create(socket_family(endpoint), SOCK_STREAM, 0); }
auto socket_operations::create_datagram(ip_endpoint endpoint) -> native_socket
{
    const auto socket = create(socket_family(endpoint), SOCK_DGRAM, 0);
    // Otherwise an ICMP port unreachable for an earlier send fails the next
    // receive with WSAECONNRESET, which closes a QUIC server's whole endpoint.
    BOOL report = FALSE;
    DWORD bytes = 0;
    (void)::WSAIoctl(static_cast<SOCKET>(socket), SIO_UDP_CONNRESET, &report, sizeof(report),
                     nullptr, 0, &bytes, nullptr, nullptr);
    return socket;
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
    // send_datagram_now must not block; overlapped operations ignore FIONBIO.
    u_long nonblocking = 1;
    if (::ioctlsocket(static_cast<SOCKET>(socket), FIONBIO, &nonblocking) ==
        SOCKET_ERROR) throw std::system_error(last_error(), "FIONBIO");
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
    // As for accepted sockets: Nagle would hold a small write until the
    // previous one is acknowledged, often a delayed-ACK interval.
    const BOOL enabled = TRUE;
    if (::setsockopt(static_cast<SOCKET>(socket), IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&enabled), sizeof(enabled)) != 0)
        return last_error();
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

auto socket_operations::start_send_file(native_socket socket,
                                        native_socket file, std::uint64_t offset,
                                        std::size_t size,
                                        socket_operation& operation) noexcept
    -> socket_result
{
    if (size == 0) return {};
    if (size > std::numeric_limits<DWORD>::max())
        return {.error = std::make_error_code(std::errc::invalid_argument)};
    // TransmitFile reads at the overlapped offset.
    operation.overlapped = {};
    operation.overlapped.Offset = static_cast<DWORD>(offset);
    operation.overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32);
    const BOOL started = ::TransmitFile(
        static_cast<SOCKET>(socket), reinterpret_cast<HANDLE>(file),
        static_cast<DWORD>(size), 0, &operation.overlapped, nullptr, 0);
    return submission_result(started ? 0 : SOCKET_ERROR, operation);
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
    const std::size_t maximum_payload =
        destination.address_family == ip_endpoint::family::ipv6 ? 65527 : 65507;
    if (size > maximum_payload)
        return {.error = {WSAEMSGSIZE, std::system_category()}};
    if (destination.port == 0)
        return {.error = {WSAEINVAL, std::system_category()}};
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

// Without an OVERLAPPED, IOCP posts no completion that could outlive the
// caller's stack.
auto socket_operations::send_datagram_now(native_socket socket,
                                          const void* buffer, std::size_t size,
                                          ip_endpoint destination) noexcept
    -> socket_result
{
    const std::size_t maximum_payload =
        destination.address_family == ip_endpoint::family::ipv6 ? 65527 : 65507;
    if (size > maximum_payload)
        return {.error = {WSAEMSGSIZE, std::system_category()}};
    if (destination.port == 0)
        return {.error = {WSAEINVAL, std::system_category()}};
    const auto native = native_endpoint(destination);
    WSABUF data {static_cast<ULONG>(size),
                 const_cast<char*>(static_cast<const char*>(buffer))};
    DWORD sent = 0;
    if (::WSASendTo(static_cast<SOCKET>(socket), &data, 1, &sent, 0,
                    native.address(), native.length, nullptr, nullptr) == 0)
        return {.transferred = sent};
    const int error = ::WSAGetLastError();
    if (error == WSAEWOULDBLOCK) return {.pending = true};
    return {.error = {error, std::system_category()}};
}

auto socket_operations::cancel(native_socket socket,
                               socket_operation& operation) noexcept -> void
{
    (void)::CancelIoEx(reinterpret_cast<HANDLE>(socket),
                       &operation.overlapped);
}

} // namespace eventloop::detail
