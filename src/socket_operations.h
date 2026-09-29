#pragma once

#include "eventloop/detail/socket_operation.h"
#include "eventloop/native_socket.h"
#include "eventloop/ip_endpoint.h"

#include <cstddef>
#include <expected>
#include <span>
#include <system_error>

namespace eventloop::detail {

// Shared socket classes own awaiters and cancellation. Each platform provides
// submission and completion semantics: EAGAIN leaves a Linux readiness waiter;
// a submitted Windows operation retains its frame until its IOCP packet arrives.
class socket_operations {
public:
    [[nodiscard]] static auto create(int family, int type, int protocol)
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
    [[nodiscard]] static auto start_receive_from(
        native_socket socket, void* buffer, std::size_t size,
        socket_operation& operation) noexcept -> socket_result;
    [[nodiscard]] static auto start_send_to(native_socket socket,
                                            const void* buffer,
                                            std::size_t size,
                                            ip_endpoint destination,
                                            socket_operation& operation) noexcept
        -> socket_result;
    static auto cancel(native_socket socket, socket_operation& operation) noexcept
        -> void;
};

} // namespace eventloop::detail
