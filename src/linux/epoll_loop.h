#pragma once

#include "eventloop/unique_fd.h"

#include <chrono>
#include <cstddef>
#include <csignal>
#include <optional>
#include <span>
#include <thread>

struct epoll_event;

namespace eventloop {

struct ready_event {
    int descriptor;
    bool readable;
    bool writable;
    bool error;
};

struct poll_result {
    std::size_t event_count;
    bool stop_requested;
    bool signal_requested;
};

class epoll_loop {
public:
    epoll_loop();
    ~epoll_loop();

    epoll_loop(const epoll_loop&) = delete;
    auto operator=(const epoll_loop&) -> epoll_loop& = delete;

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
    class signal_mask_guard {
    public:
        signal_mask_guard();
        ~signal_mask_guard();

        signal_mask_guard(const signal_mask_guard&) = delete;
        auto operator=(const signal_mask_guard&) -> signal_mask_guard& = delete;

        [[nodiscard]] auto signals() const noexcept -> const sigset_t&
        {
            return signals_;
        }

    private:
        sigset_t signals_ {};
        std::thread::id owner_thread_;
    };

    auto update_descriptor(int descriptor, bool read_enabled,
                           bool write_enabled, int operation) -> void;
    [[nodiscard]] auto wait(epoll_event* events, int capacity,
                            bool nonblocking) -> int;

    signal_mask_guard signal_mask_;
    unique_fd signal_descriptor_;
    unique_fd stop_descriptor_;
    unique_fd wake_descriptor_;
    unique_fd epoll_descriptor_;
    // The earliest timer deadline, which bounds each wait.
    std::optional<std::chrono::steady_clock::time_point> deadline_;
    // Cleared when the kernel lacks epoll_pwait2 (Linux < 5.11); epoll_wait
    // then rounds timeouts up to whole milliseconds.
    bool nanosecond_timeouts_ {true};
};

} // namespace eventloop
