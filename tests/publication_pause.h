#pragma once

#include "eventloop/executor.h"

#include <atomic>
#include <chrono>
#include <thread>
#include <utility>

namespace test_publication {

template<typename Predicate>
auto wait_until(Predicate predicate) -> bool
{
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds {2};
    while (!predicate()) {
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds {1});
    }
    return true;
}

struct pause {
    std::atomic<bool> armed {false};
    std::atomic<bool> entered {false};
    std::atomic<bool> released {false};

    auto open() noexcept -> void
    {
        released.store(true, std::memory_order_release);
        released.notify_all();
    }
};

// Arm after constructing execution_task. Its next move is into the claimed
// queue slot, letting callers pause publication through the public task API.
template<typename Function>
struct paused_callable {
    paused_callable(pause& gate, Function function) noexcept
        : gate_(&gate), function_(std::move(function)) {}

    paused_callable(paused_callable&& other) noexcept
        : gate_(other.gate_), function_(std::move(other.function_))
    {
        if (gate_->armed.exchange(false, std::memory_order_acq_rel)) {
            gate_->entered.store(true, std::memory_order_release);
            while (!gate_->released.load(std::memory_order_acquire)) {
                gate_->released.wait(false, std::memory_order_acquire);
            }
        }
    }

    auto operator()() noexcept -> void { function_(); }

    pause* gate_;
    Function function_;
};

template<typename Function>
auto make_task(pause& gate, Function function) -> eventloop::execution_task
{
    return eventloop::execution_task(
        paused_callable<Function>(gate, std::move(function)));
}

} // namespace test_publication
