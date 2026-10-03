#pragma once

#include "eventloop/task.h"
#include "eventloop/detail/notifiable.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/unique_fd.h"
#include "eventloop/detail/socket_operation.h"

#include <array>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <span>
#include <system_error>

namespace eventloop {
namespace detail { class socket_operations; }
namespace quic::detail { class udp_endpoint; }

struct udp_datagram {
    std::size_t size {0};
    ip_endpoint source;
};

class udp_socket final : private detail::notifiable {
public:
    udp_socket(event_loop& loop, ip_endpoint endpoint,
               bool reuse_port = false);
    ~udp_socket() override;

    udp_socket(const udp_socket&) = delete;
    auto operator=(const udp_socket&) -> udp_socket& = delete;

    [[nodiscard]] auto descriptor() const noexcept -> native_socket override;
    [[nodiscard]] auto local_endpoint() const -> ip_endpoint;
    auto close() -> void;

    // A buffer remains caller-owned and valid until the await completes.
    // At most one receive and one send may be pending per socket. A second
    // operation in the same direction completes with EBUSY; cancellation or
    // close completes with ECANCELED. These direct awaiters store state in the
    // caller's coroutine frame.
    class receive_awaiter {
    public:
        receive_awaiter(udp_socket& socket, std::span<std::byte> buffer) noexcept;
        receive_awaiter(const receive_awaiter&) = delete;
        auto operator=(const receive_awaiter&) -> receive_awaiter& = delete;
        receive_awaiter(receive_awaiter&&) = delete;
        auto operator=(receive_awaiter&&) -> receive_awaiter& = delete;

        [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }

        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
        {
            if (handle.promise().owner_loop() != &socket_.loop_) std::terminate();
            return start(handle, *handle.promise().cancellation_state());
        }

        [[nodiscard]] auto await_resume() const noexcept
            -> std::expected<udp_datagram, std::error_code>;

    private:
        friend class udp_socket;
        friend class detail::socket_operations;
        [[nodiscard]] auto start(
            std::coroutine_handle<> continuation,
            detail::coroutine_cancellation_state& cancellation) noexcept
            -> bool;
        static auto cancel(detail::coroutine_cancellation_node& node)
            noexcept -> void;

        udp_socket& socket_;
        std::span<std::byte> buffer_;
        std::coroutine_handle<> continuation_ {};
        detail::coroutine_cancellation_node cancellation_ {};
        ip_endpoint source_;
        int result_ {0};
        [[no_unique_address]] detail::socket_operation operation_ {};
    };

    class send_awaiter {
    public:
        send_awaiter(udp_socket& socket, std::span<const std::byte> buffer,
                     ip_endpoint destination) noexcept;
        send_awaiter(const send_awaiter&) = delete;
        auto operator=(const send_awaiter&) -> send_awaiter& = delete;
        send_awaiter(send_awaiter&&) = delete;
        auto operator=(send_awaiter&&) -> send_awaiter& = delete;

        [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }

        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
        {
            if (handle.promise().owner_loop() != &socket_.loop_) std::terminate();
            return start(handle, *handle.promise().cancellation_state());
        }

        [[nodiscard]] auto await_resume() const noexcept
            -> std::expected<std::size_t, std::error_code>;

    private:
        friend class udp_socket;
        friend class detail::socket_operations;
        [[nodiscard]] auto start(
            std::coroutine_handle<> continuation,
            detail::coroutine_cancellation_state& cancellation) noexcept
            -> bool;
        static auto cancel(detail::coroutine_cancellation_node& node)
            noexcept -> void;

        udp_socket& socket_;
        std::span<const std::byte> buffer_;
        ip_endpoint destination_;
        std::coroutine_handle<> continuation_ {};
        detail::coroutine_cancellation_node cancellation_ {};
        int result_ {0};
        [[no_unique_address]] detail::socket_operation operation_ {};
    };

    [[nodiscard]] auto async_receive_from(std::span<std::byte> buffer) noexcept
        -> receive_awaiter;
    [[nodiscard]] auto async_send_to(std::span<const std::byte> buffer,
                                     ip_endpoint destination) noexcept
        -> send_awaiter;

    // Best-effort batch send of one or more equal-sized datagrams packed in
    // `buffer` at `segment_size` boundaries (the final segment may be shorter).
    // Uses UDP segmentation offload where the platform supports it and falls
    // back to one send per segment otherwise. Non-blocking: returns the number
    // of bytes accepted, or a readiness/error code. `buffer` is caller-owned
    // and remains valid until this call returns.
    [[nodiscard]] auto send_batch(std::span<const std::byte> buffer,
                                  std::size_t segment_size,
                                  ip_endpoint destination) noexcept
        -> std::expected<std::size_t, std::error_code>;

private:
    friend class event_loop;
    friend class receive_awaiter;
    friend class send_awaiter;
    friend class detail::socket_operations;
    friend class quic::detail::udp_endpoint;

    auto set_lifetime_observer(void* context,
        void (*observer)(void*) noexcept) noexcept -> void;

    [[nodiscard]] auto initial_read_interest() const noexcept -> bool override
    {
        return false;
    }

    auto on_read() -> void override;
    auto on_write() -> void override;
    auto on_error() -> void override;
    auto on_shutdown() -> void override;
    auto update_interest() -> void;
    auto complete_receive(int result, ip_endpoint source = {}) noexcept -> void;
    auto complete_send(int result) noexcept -> void;
    auto complete_pending(int result) noexcept -> void;

    event_loop& loop_;
    unique_fd descriptor_;
    receive_awaiter* receive_ {nullptr};
    send_awaiter* send_ {nullptr};
    bool closing_ {false};
    bool gso_disabled_ {false};
    void* lifetime_observer_context_ {nullptr};
    void (*lifetime_observer_)(void*) noexcept {nullptr};
    [[no_unique_address]] detail::socket_datagram_state backend_state_ {};
};

} // namespace eventloop
