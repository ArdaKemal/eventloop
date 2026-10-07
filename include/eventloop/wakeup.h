#pragma once

#include "eventloop/event_loop.h"
#include "eventloop/task.h"

#include <cerrno>
#include <coroutine>
#include <exception>
#include <expected>
#include <system_error>
#include <utility>

namespace eventloop {

// Wakes one coroutine on the owning loop when another has work for it.
//
// notify() with a coroutine waiting queues it on the loop, which resumes it
// after the notifier returns to the loop; with none waiting, it lets the
// next async_wait() complete at once. Notifications before the waiter runs
// count once. The wait lives in the awaiting coroutine frame: no allocation,
// no coroutine frame, and no capacity limit. Use it on the loop thread only.
class wakeup {
public:
    class wait_awaiter;

    explicit wakeup(event_loop& loop) noexcept : loop_(loop) {}
    wakeup(const wakeup&) = delete;
    auto operator=(const wakeup&) -> wakeup& = delete;
    // Destroying a wakeup while a coroutine waits on it is a programming error.
    ~wakeup()
    {
        if (waiter_ != nullptr) std::terminate();
    }

    auto notify() noexcept -> void;

    // Completes after notify(). Reports ECANCELED when the waiting task is
    // cancelled before a notification, and EBUSY while another coroutine
    // waits. Wrong-loop use is a programming error.
    [[nodiscard]] auto async_wait() noexcept -> wait_awaiter;

private:
    event_loop& loop_;
    wait_awaiter* waiter_ {nullptr};
    bool notified_ {false};
};

class wakeup::wait_awaiter {
public:
    explicit wait_awaiter(wakeup& owner) noexcept : owner_(owner)
    {
        cancellation_.operation = this;
        cancellation_.cancel = &cancel;
    }
    wait_awaiter(const wait_awaiter&) = delete;
    auto operator=(const wait_awaiter&) -> wait_awaiter& = delete;

    [[nodiscard]] auto await_ready() const noexcept -> bool
    {
        return std::exchange(owner_.notified_, false);
    }

    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
    {
        if (handle.promise().owner_loop() != &owner_.loop_) std::terminate();
        if (owner_.waiter_ != nullptr) {
            error_ = EBUSY;
            return false;
        }
        auto& state = *handle.promise().cancellation_state();
        if (state.requested ||
            !detail::coroutine_frame_access::attach_cancellation(state, cancellation_)) {
            error_ = ECANCELED;
            return false;
        }
        node_.handle = handle;
        owner_.waiter_ = this;
        return true;
    }

    [[nodiscard]] auto await_resume() const noexcept -> std::expected<void, std::error_code>
    {
        if (owner_.waiter_ == this) owner_.waiter_ = nullptr;
        if (error_ != 0) return std::unexpected(std::error_code(error_, std::generic_category()));
        return {};
    }

private:
    friend class wakeup;

    // Only an unqueued waiter is attached: a queued notification wins.
    static auto cancel(detail::coroutine_cancellation_node& node) noexcept -> void
    {
        auto& self = *static_cast<wait_awaiter*>(node.operation);
        detail::coroutine_frame_access::detach_cancellation(node);
        self.owner_.waiter_ = nullptr;
        self.error_ = ECANCELED;
        self.node_.handle.resume();
    }

    wakeup& owner_;
    detail::wakeup_node node_;
    detail::coroutine_cancellation_node cancellation_;
    int error_ {0};
    bool queued_ {false};
};

inline auto wakeup::notify() noexcept -> void
{
    if (waiter_ == nullptr) {
        notified_ = true;
        return;
    }
    if (waiter_->queued_) return;
    waiter_->queued_ = true;
    detail::coroutine_frame_access::detach_cancellation(waiter_->cancellation_);
    detail::coroutine_frame_access::schedule_wakeup(loop_, waiter_->node_);
}

inline auto wakeup::async_wait() noexcept -> wait_awaiter
{
    return wait_awaiter(*this);
}

} // namespace eventloop
