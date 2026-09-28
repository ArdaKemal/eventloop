#pragma once

#include "eventloop/event_loop.h"
#include "eventloop/detail/notifiable.h"
#include "eventloop/unique_fd.h"

#include <cstdint>
#include <coroutine>
#include <exception>
#include <expected>
#include <string_view>
#include <system_error>

class tcp_acceptor : private eventloop_detail::notifiable {
public:
    tcp_acceptor(event_loop& loop, std::uint16_t port,
                 std::string_view address = "127.0.0.1",
                 bool reuse_port = false);
    ~tcp_acceptor() override;

    tcp_acceptor(const tcp_acceptor&) = delete;
    auto operator=(const tcp_acceptor&) -> tcp_acceptor& = delete;

    [[nodiscard]] auto descriptor() const noexcept -> int override;
    [[nodiscard]] auto initial_read_interest() const noexcept -> bool override
    {
        return false;
    }
    auto close() -> void;

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
        static auto cancel(eventloop_detail::coroutine_cancellation_node& node)
            noexcept -> void;
        auto suspend(std::coroutine_handle<> handle,
                     eventloop_detail::coroutine_cancellation_state& state) -> bool;
        auto finish(unique_fd descriptor, std::error_code error) noexcept -> void;
        tcp_acceptor& owner_;
        eventloop_detail::coroutine_cancellation_node cancellation_ {};
        std::coroutine_handle<> continuation_ {};
        std::expected<unique_fd, std::error_code> result_ {unique_fd {}};
    };

    [[nodiscard]] auto async_accept() noexcept -> accept_awaiter
    {
        return accept_awaiter(*this);
    }

protected:
    [[nodiscard]] auto owner() noexcept -> event_loop&;

private:
    friend class event_loop;

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
};
