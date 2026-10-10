#pragma once

#include "eventloop/event_loop.h"

#include <coroutine>

namespace eventloop::http::detail {

// Ends a connection task whose wait outlasts its deadline. Expiry requests
// cancellation of the task's coroutine chain, so pending I/O completes with
// ECANCELED and the task closes its stream. The connection task owns it.
class connection_deadline {
public:
    connection_deadline(event_loop& loop,
                        eventloop::detail::coroutine_cancellation_state& task) noexcept
        : loop_(loop), task_(task)
    {
        timer_.cancellation.operation = this;
        timer_.expire = &expire;
    }
    connection_deadline(const connection_deadline&) = delete;
    auto operator=(const connection_deadline&) -> connection_deadline& = delete;
    ~connection_deadline() { stop(); }

    // Restarts the deadline; zero only stops it.
    auto start(event_loop::clock::duration timeout) -> void
    {
        stop();
        if (timeout <= event_loop::clock::duration::zero()) return;
        timer_.deadline = eventloop::detail::deadline_after(timeout);
        timer_.owner = &loop_;
        eventloop::detail::coroutine_frame_access::register_timer(loop_, timer_);
    }
    auto stop() noexcept -> void
    {
        if (running()) eventloop::detail::coroutine_frame_access::cancel_timer(timer_);
    }
    [[nodiscard]] auto running() const noexcept -> bool { return timer_.owner != nullptr; }

private:
    static auto expire(eventloop::detail::coroutine_timer_node& timer) noexcept -> void
    {
        auto& self = *static_cast<connection_deadline*>(timer.cancellation.operation);
        eventloop::detail::coroutine_frame_access::request_cancellation(self.task_);
    }

    event_loop& loop_;
    eventloop::detail::coroutine_cancellation_state& task_;
    eventloop::detail::coroutine_timer_node timer_ {};
};

// co_await yields the awaiting task's cancellation state without suspending.
struct current_cancellation {
    eventloop::detail::coroutine_cancellation_state* state {nullptr};

    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }
    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
    {
        state = handle.promise().cancellation_state();
        return false;
    }
    [[nodiscard]] auto await_resume() const noexcept
        -> eventloop::detail::coroutine_cancellation_state&
    {
        return *state;
    }
};

} // namespace eventloop::http::detail
