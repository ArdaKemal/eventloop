#pragma once

#include "eventloop/executor.h"

#include <cstddef>
#include <memory>

class notifiable {
public:
    virtual ~notifiable() = default;
    [[nodiscard]] virtual auto descriptor() const noexcept -> int = 0;
    virtual auto on_read() -> void = 0;
    virtual auto on_write() -> void = 0;
    virtual auto on_error() -> void = 0;
};

struct event_loop_options {
    // 0 selects a single-thread executor; any other value creates a worker
    // pool of that size for independent background work.
    std::size_t worker_count {0};
    // Capacity of the bounded completion queue used by post(); must be a power
    // of two and at least two.
    std::size_t post_capacity {1024};
};

class event_loop {
public:
    event_loop();
    explicit event_loop(event_loop_options options);
    ~event_loop();

    event_loop(const event_loop&) = delete;
    auto operator=(const event_loop&) -> event_loop& = delete;

    auto run() -> void;
    auto stop() -> void;
    auto add(std::unique_ptr<notifiable> handler) -> void;
    auto remove(int descriptor) -> void;
    auto set_write_interest(int descriptor, bool enabled) -> void;

    // Thread-safe. Enqueues a task to run on the event-loop thread and wakes
    // the poller. Returns false if the bounded queue is full. A named task is
    // left intact on failure. The caller must stop posting before destroying
    // the loop; a posted task must not access loop-owned objects other than
    // through this loop's own thread.
    [[nodiscard]] auto post(execution_task&& task) noexcept -> bool;

    // Executor for independent background work. Work submitted here must not
    // access event-loop-owned objects; use post() to deliver results back.
    [[nodiscard]] auto task_executor() noexcept -> executor&;

private:
    class implementation;
    std::unique_ptr<implementation> implementation_;
};
