#include "eventloop/task.h"

#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

namespace {
auto immediate(event_loop&, int value) -> task<int> { co_return value; }
auto delayed(event_loop& loop, bool& cancelled) -> task<int>
{
    cancelled = co_await sleep_for(loop, 1h) == timer_wait_result::cancelled;
    co_return 17;
}
auto observed_void(event_loop& loop, bool& cancelled) -> task<void>
{
    cancelled = co_await sleep_for(loop, 1h) == timer_wait_result::cancelled;
}
auto cancel_after(event_loop& loop, task_handle<int>& child,
                  std::chrono::milliseconds delay) -> task<void>
{
    if (co_await sleep_for(loop, delay) == timer_wait_result::expired) {
        (void)child.cancel();
    }
}
auto release_after(event_loop& loop, std::atomic<bool>& release,
                   std::chrono::milliseconds delay) -> task<void>
{
    if (co_await sleep_for(loop, delay) == timer_wait_result::expired) {
        release.store(true, std::memory_order_release);
    }
}
auto stop_after(event_loop& loop, std::chrono::milliseconds delay) -> task<void>
{
    if (co_await sleep_for(loop, delay) == timer_wait_result::expired) {
        loop.stop();
    }
}
auto parent(event_loop& loop, bool& passed) -> task<void>
{
    task_handle<int> child;
    bool cancelled = false;
    const auto spawned = loop.spawn(delayed(loop, cancelled), child);
    if (spawned != task_spawn_result::accepted) {
        passed = false;
        loop.stop();
        co_return;
    }
    if (loop.spawn(cancel_after(loop, child, 1ms)) !=
        task_spawn_result::accepted) {
        passed = false;
        (void)child.cancel();
        loop.stop();
        co_return;
    }
    auto result = co_await child;
    passed = result && *result == 17 && cancelled && child.done();
    loop.stop();
}
auto blocking(event_loop& loop, std::atomic<bool>& release,
              bool& cancelled) -> task<int>
{
    auto result = co_await run_blocking(loop, [&release]() noexcept {
        while (!release.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        return 3;
    });
    cancelled = !result && result.error() == blocking_error::cancelled;
    co_return 3;
}
auto immediate_test() -> bool
{
    event_loop loop;
    task_handle<int> result;
    const auto spawned = loop.spawn(immediate(loop, 42), result);
    if (spawned != task_spawn_result::accepted || !result.done() ||
        result.cancel()) return false;
    auto value = result.take_result();
    return value && *value == 42 &&
           loop.coroutine_statistics().live == 0;
}
auto await_test() -> bool
{
    event_loop loop;
    bool passed = false;
    if (loop.spawn(parent(loop, passed)) != task_spawn_result::accepted) return false;
    (void)loop.run();
    return passed && loop.coroutine_statistics().live == 0;
}
auto cancellation_test() -> bool
{
    event_loop loop;
    task_handle<int> result;
    bool cancelled = false;
    if (loop.spawn(delayed(loop, cancelled), result) !=
        task_spawn_result::accepted) return false;
    if (result.done() || !result.cancel() || !result.done()) return false;
    auto value = result.take_result();
    loop.stop();
    (void)loop.run();
    return cancelled && value && *value == 17 &&
           loop.coroutine_statistics().live == 0;
}
auto void_test() -> bool
{
    event_loop loop;
    task_handle<void> result;
    bool cancelled = false;
    if (loop.spawn(observed_void(loop, cancelled), result) !=
        task_spawn_result::accepted) return false;
    if (!result.cancel() || !result.done()) return false;
    const auto value = result.take_result();
    loop.stop();
    (void)loop.run();
    return cancelled && value == task_result::success &&
           loop.coroutine_statistics().live == 0;
}
auto worker_test() -> bool
{
    event_loop_options options;
    options.worker_count = 1;
    event_loop loop(options);
    task_handle<int> result;
    std::atomic<bool> release {false};
    bool cancelled = false;
    if (loop.spawn(blocking(loop, release, cancelled), result) !=
        task_spawn_result::accepted) return false;
    if (!result.cancel() || result.done()) return false;
    if (loop.spawn(release_after(loop, release, 5ms)) !=
            task_spawn_result::accepted ||
        loop.spawn(stop_after(loop, 20ms)) != task_spawn_result::accepted) {
        return false;
    }
    (void)loop.run();
    if (!result.done()) return false;
    auto value = result.take_result();
    return cancelled && value && *value == 3 &&
           loop.coroutine_statistics().live == 0 &&
           loop.coroutine_statistics().high_watermark > 0;
}
auto shutdown_test() -> bool
{
    event_loop loop;
    task_handle<int> result;
    bool cancelled = false;
    if (loop.spawn(delayed(loop, cancelled), result) !=
        task_spawn_result::accepted) return false;
    loop.shutdown(event_loop::clock::duration::zero());
    (void)loop.run();
    if (!result.done()) return false;
    auto value = result.take_result();
    return cancelled && value && *value == 17 &&
           loop.coroutine_statistics().live == 0;
}
auto awaiting_parent(event_loop& loop, std::atomic<bool>& release,
                     bool& child_cancelled, bool& reached) -> task<void>
{
    task_handle<int> child;
    if (loop.spawn(blocking(loop, release, child_cancelled), child) !=
        task_spawn_result::accepted) co_return;
    auto result = co_await child;
    reached = result && *result == 3 && child_cancelled;
}
auto parent_shutdown_test() -> bool
{
    event_loop_options options;
    options.worker_count = 1;
    event_loop loop(options);
    std::atomic<bool> release {false};
    bool child_cancelled = false;
    bool reached = false;
    if (loop.spawn(awaiting_parent(loop, release, child_cancelled, reached)) !=
        task_spawn_result::accepted) return false;
    std::thread worker_release([&release] {
        std::this_thread::sleep_for(5ms);
        release.store(true, std::memory_order_release);
    });
    loop.shutdown(event_loop::clock::duration::zero());
    (void)loop.run();
    worker_release.join();
    return reached && loop.coroutine_statistics().live == 0;
}
auto exhausted_test() -> bool
{
    event_loop_options options;
    options.coroutine_frame_capacities.fill(0);
    event_loop loop(options);
    task_handle<int> result;
    auto operation = immediate(loop, 1);
    return loop.spawn(std::move(operation), result) ==
               task_spawn_result::frame_allocation_failure &&
           !result.done() && loop.coroutine_statistics().live == 0;
}
}
int main()
{
    const bool immediate = immediate_test();
    const bool await = await_test();
    const bool cancellation = cancellation_test();
    const bool void_result = void_test();
    const bool worker = worker_test();
    const bool shutdown = shutdown_test();
    const bool parent_shutdown = parent_shutdown_test();
    const bool exhausted = exhausted_test();
    if (!immediate || !await || !cancellation || !void_result || !worker ||
        !shutdown || !parent_shutdown || !exhausted) {
        std::cerr << "immediate=" << immediate << " await=" << await
                  << " cancellation=" << cancellation
                  << " void=" << void_result << " worker=" << worker
                  << " shutdown=" << shutdown
                  << " parent_shutdown=" << parent_shutdown
                  << " exhausted=" << exhausted << '\n';
        std::cerr << "observed task test failed\n";
        return 1;
    }
}
