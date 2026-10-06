#pragma once

#include "eventloop/unique_fd.h"
#include "readiness_events.h"

#include <chrono>
#include <csignal>
#include <optional>
#include <span>
#include <thread>

namespace eventloop {

class kqueue_loop {
public:
    kqueue_loop();
    ~kqueue_loop() = default;
    kqueue_loop(const kqueue_loop&) = delete;
    auto operator=(const kqueue_loop&) -> kqueue_loop& = delete;

    auto add_descriptor(int descriptor, bool read_enabled = true) -> void;
    auto remove_descriptor(int descriptor) -> void;
    auto set_io_interest(int descriptor, bool read_enabled,
                         bool write_enabled) -> void;
    auto set_write_interest(int descriptor, bool enabled) -> void;
    auto request_stop() -> void;
    auto wake() noexcept -> void;
    auto arm_timer(std::optional<std::chrono::steady_clock::duration> delay)
        noexcept -> void;
    [[nodiscard]] auto poll(std::span<ready_event> events,
                            bool nonblocking = false) -> poll_result;

private:
    class signal_guard {
    public:
        signal_guard();
        ~signal_guard();
        signal_guard(const signal_guard&) = delete;
        auto operator=(const signal_guard&) -> signal_guard& = delete;

    private:
        sigset_t signals_ {};
        std::thread::id owner_thread_;
    };

    auto trigger(unsigned int identifier) -> void;

    // Restore the owner thread's signal mask after the queue closes.
    signal_guard signals_;
    unique_fd queue_;
    std::optional<std::chrono::steady_clock::time_point> deadline_;
};

} // namespace eventloop
