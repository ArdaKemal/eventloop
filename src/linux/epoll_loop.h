#pragma once

#include "eventloop/unique_fd.h"

#include <chrono>
#include <cstddef>
#include <csignal>
#include <optional>
#include <span>

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
    bool wake_requested;
    bool timer_requested;
};

class epoll_loop {
public:
    epoll_loop();
    ~epoll_loop();

    epoll_loop(const epoll_loop&) = delete;
    auto operator=(const epoll_loop&) -> epoll_loop& = delete;

    auto add_descriptor(int descriptor) -> void;
    auto remove_descriptor(int descriptor) -> void;
    auto set_write_interest(int descriptor, bool enabled) -> void;
    auto request_stop() -> void;
    auto wake() noexcept -> void;
    auto arm_timer(std::optional<std::chrono::steady_clock::duration> delay)
        -> void;
    [[nodiscard]] auto poll(std::span<ready_event> events) -> poll_result;

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
        sigset_t original_ {};
    };

    auto update_descriptor(int descriptor, bool write_enabled, int operation) -> void;

    signal_mask_guard signal_mask_;
    unique_fd signal_descriptor_;
    unique_fd stop_descriptor_;
    unique_fd wake_descriptor_;
    unique_fd timer_descriptor_;
    unique_fd epoll_descriptor_;
};
