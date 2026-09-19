#pragma once

#include <cstddef>
#include <csignal>
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
    bool wake_requested;
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
    auto wake() -> void;
    [[nodiscard]] auto poll(std::span<ready_event> events) -> poll_result;

private:
    auto update_descriptor(int descriptor, bool write_enabled, int operation) -> void;

    int signal_descriptor_ {-1};
    int stop_descriptor_ {-1};
    int wake_descriptor_ {-1};
    int epoll_descriptor_ {-1};
    sigset_t original_signal_mask_ {};
};
