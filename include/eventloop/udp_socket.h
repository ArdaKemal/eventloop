#pragma once

#include "eventloop/task.h"
#include "eventloop/detail/notifiable.h"
#include "eventloop/ipv4_endpoint.h"
#include "eventloop/unique_fd.h"

#include <array>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <span>
#include <system_error>

namespace eventloop {

struct udp_datagram {
    std::size_t size {0};
    ipv4_endpoint source;
};

class udp_socket final : private detail::notifiable {
public:
    udp_socket(event_loop& loop, ipv4_endpoint endpoint,
               bool reuse_port = false);
    ~udp_socket() override;

    udp_socket(const udp_socket&) = delete;
    auto operator=(const udp_socket&) -> udp_socket& = delete;

    [[nodiscard]] auto descriptor() const noexcept -> int override;
    [[nodiscard]] auto local_endpoint() const -> ipv4_endpoint;
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
        ipv4_endpoint source_;
        int result_ {0};
    };

    class send_awaiter {
    public:
        send_awaiter(udp_socket& socket, std::span<const std::byte> buffer,
                     ipv4_endpoint destination) noexcept;
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
        [[nodiscard]] auto start(
            std::coroutine_handle<> continuation,
            detail::coroutine_cancellation_state& cancellation) noexcept
            -> bool;
        static auto cancel(detail::coroutine_cancellation_node& node)
            noexcept -> void;

        udp_socket& socket_;
        std::span<const std::byte> buffer_;
        ipv4_endpoint destination_;
        std::coroutine_handle<> continuation_ {};
        detail::coroutine_cancellation_node cancellation_ {};
        int result_ {0};
    };

    [[nodiscard]] auto async_receive_from(std::span<std::byte> buffer) noexcept
        -> receive_awaiter;
    [[nodiscard]] auto async_send_to(std::span<const std::byte> buffer,
                                     ipv4_endpoint destination) noexcept
        -> send_awaiter;

private:
    friend class event_loop;
    friend class receive_awaiter;
    friend class send_awaiter;

    [[nodiscard]] auto initial_read_interest() const noexcept -> bool override
    {
        return false;
    }

    auto on_read() -> void override;
    auto on_write() -> void override;
    auto on_error() -> void override;
    auto on_shutdown() -> void override;
    auto update_interest() -> void;
    auto complete_receive(int result, ipv4_endpoint source = {}) noexcept -> void;
    auto complete_send(int result) noexcept -> void;
    auto complete_pending(int result) noexcept -> void;

    event_loop& loop_;
    unique_fd descriptor_;
    receive_awaiter* receive_ {nullptr};
    send_awaiter* send_ {nullptr};
    bool closing_ {false};
};

} // namespace eventloop
