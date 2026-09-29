#pragma once

#include "eventloop/executor.h"
#include "eventloop/native_socket.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <coroutine>
#include <cstdint>
#include <memory>

namespace eventloop {

class event_loop;
class tcp_acceptor;
class tcp_stream;
class udp_socket;
template<typename T>
class task;
template<typename T>
class task_handle;

namespace detail {

struct file_io_operation;
class notifiable;
enum class file_opcode;

enum class completion_reservation_result {
    accepted,
    capacity_exhausted,
    shutting_down,
};

enum class blocking_submission_result {
    accepted,
    no_worker_threads,
    queue_full,
};

struct coroutine_cancellation_node;

struct coroutine_cancellation_state {
    coroutine_cancellation_node* head {nullptr};
    bool requested {false};
};

struct coroutine_cancellation_node {
    coroutine_cancellation_node* previous {nullptr};
    coroutine_cancellation_node* next {nullptr};
    coroutine_cancellation_state* state {nullptr};
    void* operation {nullptr};
    void (*cancel)(coroutine_cancellation_node&) noexcept {nullptr};
};

struct coroutine_root_node {
    coroutine_root_node* previous {nullptr};
    coroutine_root_node* next {nullptr};
    std::coroutine_handle<> handle {};
    event_loop* owner {nullptr};
    coroutine_cancellation_state cancellation;
};

struct coroutine_timer_node {
    coroutine_timer_node* previous {nullptr};
    coroutine_timer_node* next {nullptr};
    std::chrono::steady_clock::time_point deadline;
    std::coroutine_handle<> handle {};
    event_loop* owner {nullptr};
    coroutine_cancellation_node cancellation;
};

struct coroutine_frame_access {
    [[nodiscard]] static auto allocate(event_loop& loop,
                                       std::size_t size) noexcept -> void*;
    static auto deallocate(void* pointer, std::size_t size) noexcept -> void;
    static auto complete_root(coroutine_root_node& root) noexcept -> void;
    static auto register_timer(event_loop& loop, coroutine_timer_node& timer)
        -> void;
    static auto cancel_timer(coroutine_timer_node& timer) noexcept -> void;
    static auto attach_cancellation(coroutine_cancellation_state& state,
                                    coroutine_cancellation_node& node) noexcept
        -> bool;
    static auto detach_cancellation(coroutine_cancellation_node& node) noexcept
        -> void;
    static auto request_cancellation(coroutine_cancellation_state& state) noexcept
        -> void;
    [[nodiscard]] static auto reserve_completion(event_loop& loop) noexcept
        -> completion_reservation_result;
    static auto release_completion(event_loop& loop) noexcept -> void;
    static auto post_completion(event_loop& loop,
                                execution_task&& completion) noexcept -> void;
    [[nodiscard]] static auto submit_blocking(event_loop& loop,
                                              execution_task&& work) noexcept
        -> blocking_submission_result;
    [[nodiscard]] static auto submit_file(event_loop& loop,
                                          file_io_operation& operation) noexcept
        -> int;
};

} // namespace detail

enum class event_loop_result { stopped, interrupted };

enum class task_spawn_result {
    accepted,
    frame_allocation_failure,
    invalid_task,
    shutting_down,
};

struct event_loop_options {
    // 0 selects a single-thread executor; any other value creates a worker
    // pool of that size for independent background work.
    std::size_t worker_count {0};
    // Capacity of the bounded completion queue used by post(); must be a power
    // of two and at least two.
    std::size_t post_capacity {1024};
    // Reserved worker-to-loop completions for run_blocking(). Every accepted
    // blocking operation owns one slot until its completion is dequeued.
    std::size_t coroutine_completion_capacity {128};
    // File operations are bounded independently of the existing post queue.
    std::size_t file_io_depth {128};
    // Per-loop maximum coroutine-frame slots by payload size class. Growth is
    // bounded by these limits; a zero capacity disables a class. The 1 KiB
    // class defaults to 10,240 slots so one loop can serve the 10k-connection
    // target without reserving those slots at startup.
    std::array<std::size_t, 6> coroutine_frame_capacities {
        64, 32, 16, 10240, 4, 2,
    };
    // Warm slots allocated when the loop is constructed. Further slots are
    // added in bounded slabs as needed and empty growth slabs are released.
    // Values above their corresponding maximum are clamped to that maximum.
    std::array<std::size_t, 6> coroutine_frame_initial_capacities {
        64, 32, 16, 160, 4, 2,
    };
    // Frame-resident state must not require alignment beyond max_align_t.
};

inline constexpr std::array<std::size_t, 6> coroutine_frame_sizes {
    128, 256, 512, 1024, 2048, 4096,
};

struct coroutine_pool_statistics {
    // Configured hard limit and currently backed slots across all classes.
    std::size_t capacity {0};
    std::size_t live {0};
    std::size_t high_watermark {0};
    std::size_t allocation_failures {0};
    std::size_t active_roots {0};
    std::size_t backed_capacity {0};
};

namespace detail {
[[nodiscard]] inline auto deadline_after(
    std::chrono::steady_clock::duration delay) noexcept
    -> std::chrono::steady_clock::time_point
{
    using clock = std::chrono::steady_clock;
    const auto now = clock::now();
    if (delay <= clock::duration::zero()) return now;
    const auto latest = clock::time_point::max();
    return now >= latest - delay ? latest : now + delay;
}
} // namespace detail

class event_loop {
public:
    using clock = std::chrono::steady_clock;

    // Construct, run, and destroy on the same thread. post() and stop() may
    // be called from other threads while the loop remains alive.
    event_loop();
    explicit event_loop(event_loop_options options);
    ~event_loop();

    event_loop(const event_loop&) = delete;
    auto operator=(const event_loop&) -> event_loop& = delete;

    auto run() -> event_loop_result;
    auto stop() -> void;

    // Stops accepting new handlers, asks existing handlers to drain, and
    // force-closes any that remain at the deadline. A second call forces the
    // shutdown immediately. Shutdown is terminal for this event loop.
    auto shutdown(clock::duration timeout) -> void;
    auto add(std::unique_ptr<tcp_acceptor> handler) -> void;
    auto add(std::unique_ptr<tcp_stream> handler) -> void;
    auto add(std::unique_ptr<udp_socket> handler) -> void;

    // Thread-safe. Enqueues a task to run on the event-loop thread and wakes
    // the poller. Returns false if the task is empty or the bounded queue is
    // full. A named task is left intact on failure. The caller must stop
    // posting before destroying the loop; a posted task must access
    // loop-owned objects only on this loop's thread.
    [[nodiscard]] auto post(execution_task&& task) noexcept -> bool;

    // Executor for independent background work. Work submitted here must not
    // access event-loop-owned objects; use post() to deliver results back.
    [[nodiscard]] auto task_executor() noexcept -> executor&;
    [[nodiscard]] auto spawn(task<void>&& operation) -> task_spawn_result;
    template<typename T>
    [[nodiscard]] auto spawn(task<T>&& operation, task_handle<T>& observer)
        -> task_spawn_result;
    [[nodiscard]] auto coroutine_statistics() const noexcept
        -> coroutine_pool_statistics;

private:
    friend struct detail::coroutine_frame_access;
    friend class event_loop_yield_awaiter;
    friend class tcp_acceptor;
    friend class udp_socket;
    friend class tcp_stream;
    friend class tls_stream;

    class handler_call_scope {
    public:
        explicit handler_call_scope(event_loop& loop) noexcept;
        ~handler_call_scope() noexcept;

        handler_call_scope(const handler_call_scope&) = delete;
        auto operator=(const handler_call_scope&) -> handler_call_scope& = delete;

    private:
        event_loop* loop_ {nullptr};
    };

    [[nodiscard]] auto spawn_root(detail::coroutine_root_node& root,
                                  std::coroutine_handle<> handle,
                                  bool started) -> task_spawn_result;
    [[nodiscard]] auto can_spawn() const noexcept -> bool;
    [[nodiscard]] auto post_local(execution_task&& task) noexcept -> bool;
    auto add_handler(std::unique_ptr<detail::notifiable> handler) -> void;
    auto remove(native_socket descriptor) -> void;
    auto set_io_interest(native_socket descriptor, bool read_enabled,
                         bool write_enabled) -> void;
    auto set_write_interest(native_socket descriptor, bool enabled) -> void;

    class implementation;
    std::unique_ptr<implementation> implementation_;
};

} // namespace eventloop
