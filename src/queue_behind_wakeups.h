#pragma once

#include "eventloop/event_loop.h"

#include <coroutine>

namespace eventloop::detail {

// Resumes the awaiting coroutine after every wakeup already queued, such as
// other readers woken by the datagram that woke this one.
struct queue_behind_wakeups {
    event_loop& loop;
    wakeup_node node {};
    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }
    auto await_suspend(std::coroutine_handle<> handle) noexcept -> void
    {
        node.handle = handle;
        coroutine_frame_access::schedule_wakeup(loop, node);
    }
    static auto await_resume() noexcept -> void {}
};

} // namespace eventloop::detail
