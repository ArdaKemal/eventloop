#pragma once

#include "eventloop/executor.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <coroutine>
#include <cstdint>
#include <memory>

class notifiable {
public:
    virtual ~notifiable() = default;
    [[nodiscard]] virtual auto descriptor() const noexcept -> int = 0;
    virtual auto on_read() -> void = 0;
    virtual auto on_write() -> void = 0;
    virtual auto on_error() -> void = 0;
    virtual auto on_shutdown() -> void {}
};

class event_loop;
template<typename T>
class task;
template<typename T>
class task_handle;

enum class file_io_backend { automatic, executor, io_uring };
enum class active_file_io_backend { executor, io_uring };

namespace eventloop_detail {

struct file_io_operation;
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

} // namespace eventloop_detail

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
    file_io_backend file_backend {file_io_backend::automatic};
    // Coroutine frames are served from fixed, per-loop size classes. A zero
    // capacity disables a class. Exhaustion never falls back to the heap.
    // Frame-resident state must not require alignment beyond max_align_t.
    std::array<std::size_t, 6> coroutine_frame_capacities {
        64, 32, 16, 8, 4, 2,
    };
};

inline constexpr std::array<std::size_t, 6> coroutine_frame_sizes {
    128, 256, 512, 1024, 2048, 4096,
};

struct coroutine_pool_statistics {
    std::size_t capacity {0};
    std::size_t live {0};
    std::size_t high_watermark {0};
    std::size_t allocation_failures {0};
    std::size_t active_roots {0};
};

class event_loop {
public:
    using clock = std::chrono::steady_clock;
    using timer_id = std::uint64_t;

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
    auto add(std::unique_ptr<notifiable> handler) -> void;
    auto remove(int descriptor) -> void;
    auto set_write_interest(int descriptor, bool enabled) -> void;

    // Thread-safe. Enqueues a task to run on the event-loop thread and wakes
    // the poller. Returns false if the task is empty or the bounded queue is
    // full. A named task is left intact on failure. The caller must stop
    // posting before destroying the loop; a posted task must access
    // loop-owned objects only on this loop's thread.
    [[nodiscard]] auto post(execution_task&& task) noexcept -> bool;

    // Timers run on the event-loop thread. Scheduling and cancellation must
    // also be performed on that thread; use post() from other threads.
    [[nodiscard]] auto schedule_at(clock::time_point deadline,
                                   execution_task&& task) -> timer_id;
    [[nodiscard]] auto schedule_after(clock::duration delay,
                                      execution_task&& task) -> timer_id;
    auto cancel(timer_id timer) noexcept -> bool;

    // Executor for independent background work. Work submitted here must not
    // access event-loop-owned objects; use post() to deliver results back.
    [[nodiscard]] auto task_executor() noexcept -> executor&;
    [[nodiscard]] auto spawn(task<void>&& operation) -> task_spawn_result;
    template<typename T>
    [[nodiscard]] auto spawn(task<T>&& operation, task_handle<T>& observer)
        -> task_spawn_result;
    [[nodiscard]] auto coroutine_statistics() const noexcept
        -> coroutine_pool_statistics;
    [[nodiscard]] auto file_backend() -> active_file_io_backend;

private:
    friend struct eventloop_detail::coroutine_frame_access;
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

    [[nodiscard]] auto spawn_root(eventloop_detail::coroutine_root_node& root,
                                  std::coroutine_handle<> handle,
                                  bool started) -> task_spawn_result;
    [[nodiscard]] auto can_spawn() const noexcept -> bool;

    class implementation;
    std::unique_ptr<implementation> implementation_;
};
