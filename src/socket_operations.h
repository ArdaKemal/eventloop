#pragma once

#include "eventloop/detail/socket_operation.h"
#include "eventloop/native_socket.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/udp_socket.h"
#include "eventloop/unique_fd.h"

#include <cstddef>
#include <expected>
#include <span>
#include <string_view>
#include <system_error>
#ifndef _WIN32
#include <sys/socket.h>
#endif

namespace eventloop { class tcp_stream; class tcp_acceptor; class udp_socket; }

namespace eventloop::detail {

enum class stream_operation_kind { connect, read, write, file };

// Shared socket classes own awaiters and cancellation. Each platform provides
// submission and completion semantics: EAGAIN leaves a Linux readiness waiter;
// a submitted Windows operation retains its frame until its IOCP packet arrives.
class socket_operations {
public:
    static auto accept_register(tcp_acceptor& acceptor,
                                ip_endpoint endpoint) noexcept -> void;
    static auto accept_bind(tcp_acceptor::accept_awaiter& awaiter) noexcept -> void;
    [[nodiscard]] static auto accept_start(tcp_acceptor& acceptor,
        tcp_acceptor::accept_awaiter& awaiter) noexcept -> socket_result;
    [[nodiscard]] static auto accept_try_immediate(tcp_acceptor& acceptor,
        tcp_acceptor::accept_awaiter& awaiter) noexcept -> socket_result;
    [[nodiscard]] static auto accept_submit(tcp_acceptor& acceptor,
        tcp_acceptor::accept_awaiter& awaiter) noexcept -> socket_result;
    [[nodiscard]] static auto accept_cancel(tcp_acceptor& acceptor,
        tcp_acceptor::accept_awaiter& awaiter) noexcept -> bool;
    static auto accept_retire(tcp_acceptor& acceptor,
        tcp_acceptor::accept_awaiter& awaiter) noexcept -> void;
    static auto accept_close(tcp_acceptor& acceptor) -> void;
    static auto datagram_register(udp_socket& socket) noexcept -> void;
    static auto datagram_bind(udp_socket::receive_awaiter& awaiter) noexcept -> void;
    static auto datagram_bind(udp_socket::send_awaiter& awaiter) noexcept -> void;
    [[nodiscard]] static auto datagram_receive(udp_socket& socket,
        udp_socket::receive_awaiter& awaiter) noexcept -> socket_result;
    [[nodiscard]] static auto datagram_send(udp_socket& socket,
        udp_socket::send_awaiter& awaiter) noexcept -> socket_result;
    static auto datagram_submitted(udp_socket& socket,
        socket_operation& operation) noexcept -> void;
    [[nodiscard]] static auto datagram_cancel(udp_socket& socket,
        socket_operation& operation) noexcept -> bool;
    static auto datagram_retire(udp_socket& socket,
        socket_operation& operation) noexcept -> void;
    static auto datagram_close(udp_socket& socket) -> void;
    [[nodiscard]] static auto datagram_pending(const udp_socket& socket) noexcept -> bool;
    [[nodiscard]] static auto datagram_result(const socket_result& result) noexcept -> int;
    static auto datagram_error(udp_socket& socket, int result) noexcept -> void;
    static auto stream_register(tcp_stream& stream) noexcept -> void;
    [[nodiscard]] static auto stream_has_pending(const tcp_stream& stream) noexcept -> bool;
    static auto stream_bind(tcp_stream& stream, socket_operation& operation,
                            void* awaiter, stream_operation_kind kind) noexcept -> void;
    static auto stream_submitted(tcp_stream& stream,
                                 socket_operation& operation) noexcept -> void;
    static auto stream_retire(tcp_stream& stream,
                              socket_operation& operation) noexcept -> void;
    [[nodiscard]] static auto stream_pending(const socket_operation& operation)
        noexcept -> bool;
    [[nodiscard]] static auto stream_cancel(tcp_stream& stream,
                                            socket_operation& operation) noexcept -> bool;
    static auto stream_close(tcp_stream& stream) -> void;
    // See notifiable::pin(): keeps a loop-owned stream valid for an internal
    // owner after a reset, failed TLS operation, or cancellation removes it.
    static auto stream_pin(tcp_stream& stream) noexcept -> void
    { static_cast<notifiable&>(stream).pin(); }
    static auto stream_unpin(tcp_stream& stream) noexcept -> void
    { static_cast<notifiable&>(stream).unpin(); }
    // Windows replaces file with a private reopened handle on first use.
    [[nodiscard]] static auto stream_send_file(tcp_stream& stream,
                                               unique_fd& file,
                                               std::uint64_t offset,
                                               std::size_t size,
                                               socket_operation& operation) noexcept
        -> socket_result;
    [[nodiscard]] static auto create(int family, int type, int protocol)
        -> native_socket;
    [[nodiscard]] static auto create_listener(ip_endpoint endpoint)
        -> native_socket;
    [[nodiscard]] static auto create_datagram(ip_endpoint endpoint)
        -> native_socket;
    [[nodiscard]] static auto create_stream(ip_endpoint endpoint)
        -> native_socket;
    static auto prepare_listener(native_socket socket, ip_endpoint endpoint,
                                 bool reuse_port) -> void;
    static auto prepare_datagram(native_socket socket, ip_endpoint endpoint,
                                 bool reuse_port) -> void;
    [[nodiscard]] static auto configure_client(native_socket socket,
                                               ip_endpoint endpoint) noexcept
        -> std::error_code;
    [[nodiscard]] static auto activate(native_socket socket) noexcept
        -> std::error_code;
    [[nodiscard]] static auto pending_error(native_socket socket,
                                            int fallback_error) noexcept
        -> std::error_code;
    [[nodiscard]] static auto local_endpoint(native_socket socket)
        -> ip_endpoint;
    [[nodiscard]] static auto peer_endpoint(native_socket socket) noexcept
        -> std::expected<ip_endpoint, std::error_code>;
    [[nodiscard]] static auto received_source(
        const socket_operation& operation) noexcept -> ip_endpoint;
    [[nodiscard]] static auto start_accept(native_socket listener, int family,
                                           std::span<std::byte> address_buffer,
                                           socket_operation& operation) noexcept
        -> socket_result;
    [[nodiscard]] static auto finish_accept(native_socket listener,
                                            native_socket accepted) noexcept
        -> std::error_code;
    [[nodiscard]] static auto start_connect(native_socket socket,
                                            ip_endpoint endpoint,
                                            socket_operation& operation) noexcept
        -> socket_result;
#ifndef _WIN32
    [[nodiscard]] static auto start_unix_connect(native_socket socket,
                                                 std::string_view path,
                                                 socket_operation& operation) noexcept
        -> socket_result;
#endif
    [[nodiscard]] static auto finish_connect(native_socket socket) noexcept
        -> std::error_code;
    [[nodiscard]] static auto start_read(native_socket socket, void* buffer,
                                         std::size_t size,
                                         socket_operation& operation) noexcept
        -> socket_result;
    [[nodiscard]] static auto start_write(native_socket socket,
                                          const void* buffer,
                                          std::size_t size,
                                          socket_operation& operation) noexcept
        -> socket_result;
    // At most tcp_stream::max_write_buffers buffers.
    [[nodiscard]] static auto start_write_gather(native_socket socket,
        std::span<const std::span<const std::byte>> buffers,
        socket_operation& operation) noexcept -> socket_result;
    // Reads at offset; the file position does not move.
    [[nodiscard]] static auto start_send_file(native_socket socket,
                                              native_socket file,
                                              std::uint64_t offset,
                                              std::size_t size,
                                              socket_operation& operation) noexcept
        -> socket_result;
    [[nodiscard]] static auto start_receive_from(
        native_socket socket, void* buffer, std::size_t size,
        socket_operation& operation) noexcept -> socket_result;
    [[nodiscard]] static auto start_send_to(native_socket socket,
                                            const void* buffer,
                                            std::size_t size,
                                            ip_endpoint destination,
                                            socket_operation& operation) noexcept
        -> socket_result;
    // Sends one datagram now without leaving a kernel operation in flight;
    // `pending` means the socket would block.
    [[nodiscard]] static auto send_datagram_now(native_socket socket,
                                                const void* buffer,
                                                std::size_t size,
                                                ip_endpoint destination) noexcept
        -> socket_result;
    // UDP segmentation offload: submit `size` bytes as `segment`-sized
    // datagrams (the final segment may be shorter). Platforms without offload
    // report EINVAL/EOPNOTSUPP so the caller can fall back to per-segment sends.
    [[nodiscard]] static auto start_send_segments(native_socket socket,
                                                  const void* buffer,
                                                  std::size_t size,
                                                  std::size_t segment,
                                                  ip_endpoint destination,
                                                  socket_operation& operation) noexcept
        -> socket_result;
    static auto cancel(native_socket socket, socket_operation& operation) noexcept
        -> void;
};

#ifndef _WIN32
inline auto socket_operations::accept_register(tcp_acceptor&, ip_endpoint) noexcept -> void {}
inline auto socket_operations::accept_bind(tcp_acceptor::accept_awaiter&) noexcept -> void {}
inline auto socket_operations::accept_start(tcp_acceptor& acceptor,
    tcp_acceptor::accept_awaiter& awaiter) noexcept -> socket_result
{ return start_accept(acceptor.descriptor_.get(), acceptor.unix_socket_ ? 1 : 0,
                      {}, awaiter.operation_); }
inline auto socket_operations::accept_try_immediate(tcp_acceptor& acceptor,
    tcp_acceptor::accept_awaiter& awaiter) noexcept -> socket_result
{ return accept_start(acceptor, awaiter); }
inline auto socket_operations::accept_submit(tcp_acceptor&,
    tcp_acceptor::accept_awaiter&) noexcept -> socket_result
{ return {.pending = true}; }
inline auto socket_operations::accept_cancel(tcp_acceptor&,
    tcp_acceptor::accept_awaiter&) noexcept -> bool { return false; }
inline auto socket_operations::accept_retire(tcp_acceptor&,
    tcp_acceptor::accept_awaiter&) noexcept -> void {}
inline auto socket_operations::accept_close(tcp_acceptor& acceptor) -> void
{ acceptor.loop_.remove(acceptor.descriptor_.get()); }

// POSIX start_send_to is already a synchronous non-blocking send.
inline auto socket_operations::send_datagram_now(native_socket socket,
    const void* buffer, std::size_t size, ip_endpoint destination) noexcept
    -> socket_result
{
    socket_operation operation {};
    return start_send_to(socket, buffer, size, destination, operation);
}

inline auto socket_operations::datagram_register(udp_socket&) noexcept -> void {}
inline auto socket_operations::datagram_bind(udp_socket::receive_awaiter&) noexcept -> void {}
inline auto socket_operations::datagram_bind(udp_socket::send_awaiter&) noexcept -> void {}
inline auto socket_operations::datagram_receive(udp_socket& socket,
    udp_socket::receive_awaiter& awaiter) noexcept -> socket_result
{ return start_receive_from(socket.descriptor_.get(), awaiter.buffer_.data(),
                            awaiter.buffer_.size(), awaiter.operation_); }
inline auto socket_operations::datagram_send(udp_socket& socket,
    udp_socket::send_awaiter& awaiter) noexcept -> socket_result
{ return start_send_to(socket.descriptor_.get(), awaiter.buffer_.data(),
                       awaiter.buffer_.size(), awaiter.destination_,
                       awaiter.operation_); }
inline auto socket_operations::datagram_submitted(udp_socket&,
    socket_operation&) noexcept -> void {}
inline auto socket_operations::datagram_cancel(udp_socket&,
    socket_operation&) noexcept -> bool { return false; }
inline auto socket_operations::datagram_retire(udp_socket&,
    socket_operation&) noexcept -> void {}
inline auto socket_operations::datagram_close(udp_socket& socket) -> void
{ socket.loop_.remove(socket.descriptor_.get()); }
inline auto socket_operations::datagram_pending(const udp_socket&) noexcept -> bool
{ return false; }
inline auto socket_operations::datagram_result(const socket_result& result) noexcept -> int
{ return result.error ? -result.error.value() : static_cast<int>(result.transferred); }
inline auto socket_operations::datagram_error(udp_socket& socket, int result) noexcept -> void
{ socket.complete_pending(result); }

inline auto socket_operations::stream_register(tcp_stream&) noexcept -> void {}
inline auto socket_operations::stream_has_pending(const tcp_stream&) noexcept -> bool
{ return false; }
inline auto socket_operations::stream_bind(tcp_stream&, socket_operation&,
                                    void*, stream_operation_kind) noexcept -> void {}
inline auto socket_operations::stream_submitted(tcp_stream&,
                                         socket_operation&) noexcept -> void {}
inline auto socket_operations::stream_retire(tcp_stream&,
                                      socket_operation&) noexcept -> void {}
inline auto socket_operations::stream_pending(const socket_operation&) noexcept -> bool
{ return false; }
inline auto socket_operations::stream_cancel(tcp_stream&,
                                      socket_operation&) noexcept -> bool
{ return false; }
inline auto socket_operations::stream_close(tcp_stream& stream) -> void
{
    // The descriptor closes when the loop retires the handler, after the
    // current dispatch batch. Send the FIN now so the peer does not wait for
    // the rest of that batch.
    (void)::shutdown(stream.descriptor_.get(), SHUT_RDWR);
    stream.loop_.remove(stream.descriptor_.get());
}
inline auto socket_operations::stream_send_file(tcp_stream& stream,
                                         unique_fd& file, std::uint64_t offset,
                                         std::size_t size,
                                         socket_operation& operation) noexcept
    -> socket_result
{ return start_send_file(stream.descriptor_.get(), file.get(), offset, size, operation); }

inline auto socket_operations::received_source(const socket_operation&) noexcept
    -> ip_endpoint { return {}; }

inline auto socket_operations::finish_accept(native_socket, native_socket) noexcept
    -> std::error_code { return {}; }

inline auto socket_operations::cancel(native_socket, socket_operation&) noexcept
    -> void {}
#endif

} // namespace eventloop::detail
