#pragma once

#include "eventloop/event_loop.h"
#include "eventloop/detail/notifiable.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/unique_fd.h"
#include "eventloop/detail/socket_operation.h"

#include <cstdint>
#include <array>
#include <cstddef>
#include <coroutine>
#include <exception>
#include <expected>
#include <system_error>

namespace eventloop {
namespace detail { class socket_operations; }

class tcp_acceptor : private detail::notifiable {
public:
    tcp_acceptor(event_loop& loop, ip_endpoint endpoint,
                 bool reuse_port = false);
    ~tcp_acceptor() override;

    tcp_acceptor(const tcp_acceptor&) = delete;
    auto operator=(const tcp_acceptor&) -> tcp_acceptor& = delete;

    [[nodiscard]] auto descriptor() const noexcept -> native_socket override;
    virtual auto close() -> void;

    class accept_awaiter {
    public:
        explicit accept_awaiter(tcp_acceptor& owner) noexcept;
        ~accept_awaiter();
        accept_awaiter(const accept_awaiter&) = delete;
        auto operator=(const accept_awaiter&) -> accept_awaiter& = delete;
        accept_awaiter(accept_awaiter&&) = delete;
        [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }
        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> handle) -> bool
        {
            if (handle.promise().owner_loop() != &owner_.loop_) std::terminate();
            return suspend(handle, *handle.promise().cancellation_state());
        }
        [[nodiscard]] auto await_resume() noexcept
            -> std::expected<unique_fd, std::error_code>;

    private:
        friend class tcp_acceptor;
        friend class detail::socket_operations;
        static auto cancel(detail::coroutine_cancellation_node& node)
            noexcept -> void;
        auto suspend(std::coroutine_handle<> handle,
                     detail::coroutine_cancellation_state& state) -> bool;
        auto finish(unique_fd descriptor, std::error_code error) noexcept -> void;
        tcp_acceptor& owner_;
        detail::coroutine_cancellation_node cancellation_ {};
        std::coroutine_handle<> continuation_ {};
        std::expected<unique_fd, std::error_code> result_ {unique_fd {}};
        [[no_unique_address]] detail::socket_operation operation_ {};
        [[no_unique_address]] detail::socket_accept_awaiter_state backend_state_ {};
    };

    // Returns an owned descriptor. A duplicate accept returns EBUSY;
    // cancellation or close of a pending accept returns ECANCELED. This
    // awaiter stores state in the caller's coroutine frame.
    [[nodiscard]] auto async_accept() noexcept -> accept_awaiter
    {
        return accept_awaiter(*this);
    }

protected:
    // Used by other POSIX stream transports with the same accept semantics.
    tcp_acceptor(event_loop& loop, unique_fd descriptor, bool unix_socket);
    [[nodiscard]] auto owner() noexcept -> event_loop&;

private:
    friend class event_loop;
    friend class detail::socket_operations;

    [[nodiscard]] auto initial_read_interest() const noexcept -> bool override
    {
        return false;
    }

    auto on_read() -> void override;
    auto on_write() -> void override {}
    auto on_error() -> void override;
    auto on_shutdown() -> void override;
    auto set_read_interest(bool enabled) -> void;
    auto complete_accept(unique_fd descriptor, std::error_code error) noexcept
        -> void;
    auto fail_and_close(std::error_code error) -> void;

    event_loop& loop_;
    unique_fd descriptor_;
    accept_awaiter* waiter_ {nullptr};
    bool read_interest_enabled_ {false};
    bool closed_ {false};
    bool unix_socket_ {false};
    [[no_unique_address]] detail::socket_accept_state backend_state_ {};
};

} // namespace eventloop
