#pragma once

#include "eventloop/detail/socket_operation.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace eventloop {

// The OVERLAPPED member must remain alive until its packet is dequeued.
// Each socket operation owns one of these in its awaiting coroutine frame.
struct ready_event {
    detail::socket_operation* operation {nullptr};
    DWORD bytes {0};
    DWORD error {0};
};

struct poll_result {
    std::size_t event_count {0};
    bool stop_requested {false};
    bool signal_requested {false};
    bool wake_requested {false};
    bool timer_requested {false};
};

class iocp_loop {
public:
    iocp_loop();
    ~iocp_loop();
    iocp_loop(const iocp_loop&) = delete;
    auto operator=(const iocp_loop&) -> iocp_loop& = delete;

    auto add_descriptor(native_socket descriptor, bool = false) -> void;
    auto remove_descriptor(native_socket) -> void;
    auto set_io_interest(native_socket, bool, bool) -> void;
    auto set_write_interest(native_socket, bool) -> void;
    auto request_stop() -> void;
    auto wake() noexcept -> void;
    auto arm_timer(std::optional<std::chrono::steady_clock::duration> delay)
        noexcept -> void;
    [[nodiscard]] auto poll(std::span<ready_event> events, bool nonblocking = false)
        -> poll_result;
    [[nodiscard]] auto native_handle() const noexcept -> HANDLE { return port_; }

private:
    HANDLE port_ {nullptr};
    std::optional<std::chrono::steady_clock::time_point> deadline_;
};

} // namespace eventloop
