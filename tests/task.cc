#include "eventloop/task.h"

#include <chrono>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <new>
#include <thread>

namespace {
std::size_t allocations = 0;
}

auto operator new(std::size_t size) -> void*
{
    ++allocations;
    if (void* memory = std::malloc(size)) return memory;
    throw std::bad_alloc {};
}

auto operator new(std::size_t size, std::align_val_t alignment) -> void*
{
    ++allocations;
    void* memory = nullptr;
    if (posix_memalign(&memory, static_cast<std::size_t>(alignment), size) == 0) {
        return memory;
    }
    throw std::bad_alloc {};
}

void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }
void operator delete(void* memory, std::align_val_t) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t, std::align_val_t) noexcept
{
    std::free(memory);
}

namespace {

auto increment(event_loop&, int& value) -> task<void>
{
    ++value;
    co_return;
}

auto noop(event_loop&) -> task<void> { co_return; }

auto nested(event_loop& loop, int& value, task_result& child_result)
    -> task<void>
{
    child_result = co_await increment(loop, value);
    ++value;
}

struct naturally_aligned {
    long double value;
};

auto aligned_frame(event_loop& loop, std::uintptr_t& address) -> task<void>
{
    naturally_aligned storage {1.0L};
    const auto result = co_await noop(loop);
    if (result == task_result::success && storage.value == 1.0L) {
        address = reinterpret_cast<std::uintptr_t>(&storage);
    }
}

auto oversized_frame(event_loop& loop, int& value) -> task<void>
{
    volatile std::byte storage[5000] {};
    storage[0] = std::byte {1};
    const auto result = co_await noop(loop);
    if (result == task_result::success) {
        value = std::to_integer<int>(storage[0]);
    }
}

auto yielding(event_loop& loop, int& value, bool& queued) -> task<void>
{
    ++value;
    queued = co_await yield(loop);
    ++value;
    loop.stop();
}

auto cancellable_root(event_loop& loop, bool& cancellation_seen) -> task<void>
{
    (void)co_await yield(loop);
    cancellation_seen = co_await cancellation_requested();
}

auto timer_root(event_loop& loop, timer_wait_result& result) -> task<void>
{
    result = co_await sleep_for(loop, std::chrono::milliseconds {1});
    loop.stop();
}

auto timer_child(event_loop& loop, timer_wait_result& result) -> task<void>
{
    result = co_await sleep_for(loop, std::chrono::hours {1});
}

auto nested_timer_root(event_loop& loop, timer_wait_result& result,
                       bool& cancellation_seen) -> task<void>
{
    const auto child = co_await timer_child(loop, result);
    cancellation_seen =
        child == task_result::success && co_await cancellation_requested();
}

auto blocking_root(event_loop& loop, std::thread::id loop_thread,
                   bool& ran_on_worker, bool& resumed_on_loop, int& value,
                   blocking_error& error) -> task<void>
{
    auto result = co_await run_blocking(loop, [loop_thread, &ran_on_worker]()
                                            noexcept {
        ran_on_worker = std::this_thread::get_id() != loop_thread;
        return 42;
    });
    resumed_on_loop = std::this_thread::get_id() == loop_thread;
    if (result) value = *result;
    else error = result.error();
    loop.stop();
}

auto cancellable_blocking_root(event_loop& loop, std::atomic<bool>& started,
                               std::atomic<bool>& release,
                               blocking_error& error) -> task<void>
{
    auto result = co_await run_blocking(loop, [&started, &release]() noexcept {
        started.store(true, std::memory_order_release);
        while (!release.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        return 7;
    });
    if (!result) error = result.error();
}

auto rejected_blocking_root(event_loop& loop, bool& ran,
                            blocking_error& error) -> task<void>
{
    auto result = co_await run_blocking(loop, [&ran]() noexcept {
        ran = true;
        return 1;
    });
    if (!result) error = result.error();
}

auto capacity_blocking_root(event_loop& loop, std::atomic<bool>* started,
                            std::atomic<bool>* release, int& completed,
                            blocking_error& error) -> task<void>
{
    auto result = co_await run_blocking(loop, [started, release]() noexcept {
        if (started != nullptr) {
            started->store(true, std::memory_order_release);
            while (!release->load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
        }
    });
    if (!result) error = result.error();
    ++completed;
    if (completed == 3) loop.stop();
}

auto allocation_and_transfer_test() -> bool
{
    event_loop loop;
    int value = 0;
    task_result child_result = task_result::frame_allocation_failure;
    const auto before = allocations;

    {
        auto operation = nested(loop, value, child_result);
        if (allocations != before || operation.state() != task_state::not_started ||
            loop.coroutine_statistics().live != 1 || value != 0) {
            return false;
        }
        if (operation.start() != task_state::completed || value != 2 ||
            child_result != task_result::success ||
            operation.result() != task_result::success || allocations != before) {
            return false;
        }
        const auto statistics = loop.coroutine_statistics();
        if (statistics.live != 1 || statistics.high_watermark < 2 ||
            statistics.allocation_failures != 0) {
            return false;
        }
    }

    return loop.coroutine_statistics().live == 0 && allocations == before;
}

auto exhaustion_test() -> bool
{
    event_loop_options options;
    options.coroutine_frame_capacities.fill(0);
    event_loop loop(options);
    int value = 0;
    const auto before = allocations;
    auto operation = increment(loop, value);
    const auto statistics = loop.coroutine_statistics();
    return allocations == before &&
           operation.state() == task_state::frame_allocation_failure &&
           operation.start() == task_state::frame_allocation_failure &&
           operation.result() == task_result::frame_allocation_failure &&
           value == 0 && statistics.live == 0 &&
           statistics.allocation_failures == 1;
}

auto nested_exhaustion_test() -> bool
{
    event_loop_options options;
    options.coroutine_frame_capacities.fill(0);
    options.coroutine_frame_capacities.back() = 1;
    event_loop loop(options);
    int value = 0;
    task_result child_result = task_result::success;
    auto operation = nested(loop, value, child_result);
    if (operation.state() != task_state::not_started ||
        operation.start() != task_state::completed) {
        return false;
    }
    const auto statistics = loop.coroutine_statistics();
    return value == 1 && child_result == task_result::frame_allocation_failure &&
           statistics.live == 1 && statistics.high_watermark == 1 &&
           statistics.allocation_failures == 1;
}

auto alignment_and_oversize_test() -> bool
{
    event_loop loop;
    std::uintptr_t address = 0;
    auto aligned = aligned_frame(loop, address);
    if (aligned.start() != task_state::completed || address == 0 ||
        address % alignof(std::max_align_t) != 0) {
        return false;
    }

    int value = 0;
    auto oversized = oversized_frame(loop, value);
    return oversized.state() == task_state::frame_allocation_failure &&
           value == 0 && loop.coroutine_statistics().allocation_failures == 1;
}

auto event_loop_resume_test() -> bool
{
    event_loop loop;
    int value = 0;
    bool queued = false;
    auto operation = yielding(loop, value, queued);
    const auto before = allocations;
    if (operation.start() != task_state::suspended || value != 1 ||
        operation.state() != task_state::suspended || allocations != before) {
        return false;
    }
    if (loop.run() != event_loop_result::stopped) return false;
    return operation.state() == task_state::completed && value == 2 && queued &&
           operation.result() == task_result::success && allocations == before;
}

auto event_loop_queue_full_test() -> bool
{
    event_loop_options options;
    options.post_capacity = 2;
    event_loop loop(options);
    execution_task first([]() noexcept {});
    execution_task second([]() noexcept {});
    if (!loop.post(std::move(first)) || !loop.post(std::move(second))) return false;

    int value = 0;
    bool queued = true;
    auto operation = yielding(loop, value, queued);
    const auto before = allocations;
    return operation.start() == task_state::completed && value == 2 && !queued &&
           operation.result() == task_result::success && allocations == before;
}

auto root_task_test() -> bool
{
    event_loop loop;
    int value = 0;
    bool queued = false;
    const auto before = allocations;

    auto immediate = increment(loop, value);
    if (loop.spawn(std::move(immediate)) != task_spawn_result::accepted ||
        value != 1 || loop.coroutine_statistics().active_roots != 0 ||
        loop.coroutine_statistics().live != 0 || allocations != before) {
        return false;
    }

    auto root = yielding(loop, value, queued);
    if (loop.spawn(std::move(root)) != task_spawn_result::accepted || value != 2 ||
        loop.coroutine_statistics().active_roots != 1 || allocations != before) {
        return false;
    }
    if (loop.run() != event_loop_result::stopped) return false;
    const auto statistics = loop.coroutine_statistics();
    return value == 3 && queued && statistics.active_roots == 0 &&
           statistics.live == 0 && allocations == before;
}

auto root_shutdown_test() -> bool
{
    event_loop loop;
    bool cancellation_seen = false;
    auto root = cancellable_root(loop, cancellation_seen);
    if (loop.spawn(std::move(root)) != task_spawn_result::accepted ||
        loop.coroutine_statistics().active_roots != 1) {
        return false;
    }
    loop.shutdown(event_loop::clock::duration::zero());
    if (loop.run() != event_loop_result::stopped) return false;
    const auto statistics = loop.coroutine_statistics();
    return cancellation_seen && statistics.active_roots == 0 &&
           statistics.live == 0;
}

auto coroutine_timer_test() -> bool
{
    event_loop loop;
    timer_wait_result result = timer_wait_result::cancelled;
    const auto before = allocations;
    auto root = timer_root(loop, result);
    if (loop.spawn(std::move(root)) != task_spawn_result::accepted ||
        allocations != before || loop.coroutine_statistics().active_roots != 1) {
        return false;
    }
    if (loop.run() != event_loop_result::stopped) return false;
    const auto statistics = loop.coroutine_statistics();
    return result == timer_wait_result::expired && allocations == before &&
           statistics.active_roots == 0 && statistics.live == 0;
}

auto coroutine_timer_cancellation_test() -> bool
{
    event_loop loop;
    timer_wait_result result = timer_wait_result::expired;
    bool cancellation_seen = false;
    const auto before = allocations;
    auto root = nested_timer_root(loop, result, cancellation_seen);
    if (loop.spawn(std::move(root)) != task_spawn_result::accepted ||
        allocations != before || loop.coroutine_statistics().active_roots != 1) {
        return false;
    }
    loop.shutdown(event_loop::clock::duration::zero());
    if (allocations != before || loop.run() != event_loop_result::stopped) {
        return false;
    }
    const auto statistics = loop.coroutine_statistics();
    return result == timer_wait_result::cancelled && cancellation_seen &&
           statistics.active_roots == 0 && statistics.live == 0;
}

auto run_blocking_test() -> bool
{
    event_loop loop(event_loop_options {.worker_count = 1});
    const auto loop_thread = std::this_thread::get_id();
    bool ran_on_worker = false;
    bool resumed_on_loop = false;
    int value = 0;
    blocking_error error = blocking_error::cancelled;
    const auto before = allocations;
    auto root = blocking_root(loop, loop_thread, ran_on_worker,
                              resumed_on_loop, value, error);
    if (loop.spawn(std::move(root)) != task_spawn_result::accepted ||
        allocations != before || loop.coroutine_statistics().active_roots != 1) {
        return false;
    }
    if (loop.run() != event_loop_result::stopped) return false;
    const auto statistics = loop.coroutine_statistics();
    return ran_on_worker && resumed_on_loop && value == 42 &&
           allocations == before && statistics.active_roots == 0 &&
           statistics.live == 0;
}

auto run_blocking_cancellation_test() -> bool
{
    event_loop loop(event_loop_options {.worker_count = 1});
    std::atomic<bool> started {false};
    std::atomic<bool> release {false};
    blocking_error error = blocking_error::executor_queue_full;
    auto root = cancellable_blocking_root(loop, started, release, error);
    if (loop.spawn(std::move(root)) != task_spawn_result::accepted) return false;
    while (!started.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    loop.shutdown(event_loop::clock::duration::zero());
    release.store(true, std::memory_order_release);
    if (loop.run() != event_loop_result::stopped) return false;
    const auto statistics = loop.coroutine_statistics();
    return error == blocking_error::cancelled &&
           statistics.active_roots == 0 && statistics.live == 0;
}

auto run_blocking_requires_worker_test() -> bool
{
    event_loop loop;
    bool ran = false;
    blocking_error error = blocking_error::cancelled;
    auto root = rejected_blocking_root(loop, ran, error);
    if (loop.spawn(std::move(root)) != task_spawn_result::accepted) return false;
    const auto statistics = loop.coroutine_statistics();
    return !ran && error == blocking_error::no_worker_threads &&
           statistics.active_roots == 0 && statistics.live == 0;
}

auto run_blocking_completion_capacity_test() -> bool
{
    event_loop_options options;
    options.worker_count = 1;
    options.coroutine_completion_capacity = 2;
    event_loop loop(options);
    std::atomic<bool> started {false};
    std::atomic<bool> release {false};
    int completed = 0;
    blocking_error first_error = blocking_error::cancelled;
    blocking_error second_error = blocking_error::cancelled;
    blocking_error rejected_error = blocking_error::cancelled;

    auto first = capacity_blocking_root(
        loop, &started, &release, completed, first_error);
    auto second = capacity_blocking_root(
        loop, nullptr, nullptr, completed, second_error);
    auto rejected = capacity_blocking_root(
        loop, nullptr, nullptr, completed, rejected_error);
    if (loop.spawn(std::move(first)) != task_spawn_result::accepted ||
        loop.spawn(std::move(second)) != task_spawn_result::accepted ||
        loop.spawn(std::move(rejected)) != task_spawn_result::accepted ||
        completed != 1 ||
        rejected_error != blocking_error::completion_capacity_exhausted) {
        return false;
    }
    while (!started.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    release.store(true, std::memory_order_release);
    if (loop.run() != event_loop_result::stopped) return false;
    const auto statistics = loop.coroutine_statistics();
    return completed == 3 && statistics.active_roots == 0 &&
           statistics.live == 0;
}

auto spawn_failure_test() -> bool
{
    event_loop_options empty_options;
    empty_options.coroutine_frame_capacities.fill(0);
    event_loop empty_loop(empty_options);
    int value = 0;
    auto failed = increment(empty_loop, value);
    if (empty_loop.spawn(std::move(failed)) !=
        task_spawn_result::frame_allocation_failure) {
        return false;
    }

    event_loop stopped_loop;
    stopped_loop.shutdown(event_loop::clock::duration::zero());
    auto rejected = increment(stopped_loop, value);
    if (stopped_loop.spawn(std::move(rejected)) !=
        task_spawn_result::shutting_down) {
        return false;
    }

    event_loop other_loop;
    auto wrong_loop = increment(other_loop, value);
    return stopped_loop.spawn(std::move(wrong_loop)) ==
               task_spawn_result::invalid_task &&
           value == 0;
}

} // namespace

auto main() -> int
{
    if (!allocation_and_transfer_test()) {
        std::cerr << "task allocation/symmetric-transfer test failed\n";
        return 1;
    }
    if (!exhaustion_test()) {
        std::cerr << "task frame-pool exhaustion test failed\n";
        return 1;
    }
    if (!nested_exhaustion_test()) {
        std::cerr << "nested task frame-pool exhaustion test failed\n";
        return 1;
    }
    if (!alignment_and_oversize_test()) {
        std::cerr << "task frame alignment/oversize test failed\n";
        return 1;
    }
    if (!event_loop_resume_test()) {
        std::cerr << "event-loop coroutine resume test failed\n";
        return 1;
    }
    if (!event_loop_queue_full_test()) {
        std::cerr << "event-loop coroutine queue-full test failed\n";
        return 1;
    }
    if (!root_task_test()) {
        std::cerr << "event-loop root task test failed\n";
        return 1;
    }
    if (!root_shutdown_test()) {
        std::cerr << "event-loop root shutdown test failed\n";
        return 1;
    }
    if (!coroutine_timer_test()) {
        std::cerr << "coroutine timer test failed\n";
        return 1;
    }
    if (!coroutine_timer_cancellation_test()) {
        std::cerr << "coroutine timer cancellation test failed\n";
        return 1;
    }
    if (!run_blocking_test()) {
        std::cerr << "run-blocking test failed\n";
        return 1;
    }
    if (!run_blocking_cancellation_test()) {
        std::cerr << "run-blocking cancellation test failed\n";
        return 1;
    }
    if (!run_blocking_requires_worker_test()) {
        std::cerr << "run-blocking worker requirement test failed\n";
        return 1;
    }
    if (!run_blocking_completion_capacity_test()) {
        std::cerr << "run-blocking completion-capacity test failed\n";
        return 1;
    }
    if (!spawn_failure_test()) {
        std::cerr << "event-loop root spawn failure test failed\n";
        return 1;
    }
    return 0;
}
