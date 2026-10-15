#include "eventloop/task.h"

#include <chrono>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <malloc.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace eventloop;

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
#ifdef _WIN32
    if (void* memory = _aligned_malloc(size, static_cast<std::size_t>(alignment))) {
        return memory;
    }
#else
    void* memory = nullptr;
    if (posix_memalign(&memory, static_cast<std::size_t>(alignment), size) == 0) {
        return memory;
    }
#endif
    throw std::bad_alloc {};
}

void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }
void operator delete(void* memory, std::align_val_t) noexcept
{
#ifdef _WIN32
    _aligned_free(memory);
#else
    std::free(memory);
#endif
}
void operator delete(void* memory, std::size_t, std::align_val_t) noexcept
{
#ifdef _WIN32
    _aligned_free(memory);
#else
    std::free(memory);
#endif
}

namespace {

#ifdef _WIN32
auto child_exits_77(const wchar_t* argument) -> bool
{
    std::array<wchar_t, MAX_PATH> path {};
    const auto length = ::GetModuleFileNameW(nullptr, path.data(),
                                              static_cast<DWORD>(path.size()));
    if (length == 0 || length == path.size()) return false;
    std::wstring command = L"\"" + std::wstring(path.data()) + L"\" " + argument;
    STARTUPINFOW startup {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process {};
    if (!::CreateProcessW(path.data(), command.data(), nullptr, nullptr, FALSE,
                          CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                          &process)) return false;
    ::CloseHandle(process.hThread);
    const auto wait = ::WaitForSingleObject(process.hProcess, 5000);
    if (wait != WAIT_OBJECT_0) {
        ::TerminateProcess(process.hProcess, 1);
        ::WaitForSingleObject(process.hProcess, INFINITE);
    }
    DWORD code = 0;
    const bool passed = wait == WAIT_OBJECT_0 &&
                        ::GetExitCodeProcess(process.hProcess, &code) && code == 77;
    ::CloseHandle(process.hProcess);
    return passed;
}
#endif

auto increment(event_loop&, int& value) -> task<void>
{
    ++value;
    co_return;
}

auto noop(event_loop&) -> task<void> { co_return; }

auto foreign_awaiter_root(event_loop& owner, event_loop& foreign, int kind)
    -> task<void>
{
    (void)owner;
    if (kind == 0) (void)co_await yield(foreign);
    else if (kind == 1) (void)co_await sleep_for(foreign, std::chrono::hours {1});
    else if (kind == 2) (void)co_await sleep_for(foreign, {});
    else (void)co_await run_blocking(foreign, []() noexcept {});
}

#ifndef _WIN32
auto wrong_loop_awaiter_test() -> bool
{
    for (int kind = 0; kind < 4; ++kind) {
        const pid_t child = ::fork();
        if (child == -1) return false;
        if (child == 0) {
            std::set_terminate([] { std::_Exit(77); });
            event_loop owner;
            event_loop foreign(event_loop_options {.worker_count = 1});
            (void)owner.spawn(foreign_awaiter_root(owner, foreign, kind));
            std::_Exit(1);
        }
        int status = 0;
        if (::waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 77) return false;
    }
    return true;
}
#else
auto wrong_loop_awaiter_test() -> bool
{
    constexpr std::array arguments {
        L"--wrong-loop-yield", L"--wrong-loop-timer",
        L"--wrong-loop-immediate-timer", L"--wrong-loop-blocking"};
    for (const auto* argument : arguments) {
        if (!child_exits_77(argument)) return false;
    }
    return true;
}
#endif

auto value_task(event_loop&) -> task<int> { co_return 42; }

auto value_result_test() -> bool
{
    event_loop loop;
    auto operation = value_task(loop);
    if (operation.start() != task_state::completed) return false;
    const auto result = operation.result();
    if (!result || *result != 42) return false;
    try {
        (void)operation.result();
    } catch (const std::logic_error&) {
        return true;
    }
    return false;
}

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
    volatile std::byte storage[coroutine_frame_sizes.back() + 1] {};
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

auto repeated_yields(event_loop& loop, int& count) -> task<void>
{
    for (int index = 0; index < 1024; ++index) {
        if (!co_await yield(loop)) co_return;
        ++count;
    }
    loop.stop();
}

auto immediate_timer(event_loop& loop, bool& fired) -> task<void>
{
    fired = co_await sleep_for(loop, event_loop::clock::duration::zero()) ==
            timer_wait_result::expired;
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
    result = co_await sleep_for(loop, event_loop::clock::duration::max());
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

#ifndef _WIN32
auto active_worker_destruction_test() -> bool
{
    const pid_t child = ::fork();
    if (child == -1) return false;
    if (child == 0) {
        std::set_terminate([] { std::_Exit(77); });
        ::alarm(3);
        std::atomic<bool> started {false};
        std::atomic<bool> release {false};
        blocking_error error = blocking_error::cancelled;
        {
            event_loop loop(event_loop_options {.worker_count = 1});
            if (loop.spawn(cancellable_blocking_root(loop, started, release,
                                                    error)) !=
                task_spawn_result::accepted) {
                std::_Exit(1);
            }
            while (!started.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
        }
        std::_Exit(1);
    }
    int status = 0;
    return ::waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 77;
}
#else
auto active_worker_destruction_test() -> bool
{
    return child_exits_77(L"--active-worker-destruction");
}
#endif

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

auto bounded_growth_and_release_test() -> bool
{
    event_loop_options options;
    options.coroutine_frame_capacities.fill(0);
    options.coroutine_frame_initial_capacities.fill(0);
    options.coroutine_frame_capacities.back() = 3;
    options.coroutine_frame_initial_capacities.back() = 1;
    event_loop loop(options);
    const auto before_growth = allocations;
#if defined(_WIN32) && defined(EVENTLOOP_TEST_SHARED_LIBRARY)
    // An eventloop DLL uses its own operator new; executable interposition
    // does not observe its slab allocations.
    const auto growth_allocations_valid = [&] {
        return allocations == before_growth;
    };
#else
    const auto growth_allocations_valid = [&] {
        return allocations == before_growth + 2;
    };
#endif
    int value = 0;
    {
        auto first = increment(loop, value);
        auto second = increment(loop, value);
        auto third = increment(loop, value);
        auto rejected = increment(loop, value);
        const auto statistics = loop.coroutine_statistics();
        if (first.state() != task_state::not_started ||
            second.state() != task_state::not_started ||
            third.state() != task_state::not_started ||
            rejected.state() != task_state::frame_allocation_failure ||
            statistics.capacity != 3 || statistics.backed_capacity != 3 ||
            statistics.live != 3 || statistics.allocation_failures != 1 ||
            !growth_allocations_valid()) {
            return false;
        }
    }
    const auto statistics = loop.coroutine_statistics();
    return statistics.live == 0 && statistics.backed_capacity == 1;
}

auto frame_class_lifecycle_test() -> bool
{
    for (std::size_t index = 0; index < coroutine_frame_sizes.size(); ++index) {
        event_loop_options options;
        options.coroutine_frame_capacities.fill(0);
        options.coroutine_frame_initial_capacities.fill(0);
        options.coroutine_frame_capacities[index] = 3;
        options.coroutine_frame_initial_capacities[index] = 1;
        event_loop loop(options);
        const auto size = coroutine_frame_sizes[index];
        auto* first = detail::coroutine_frame_access::allocate(loop, size);
        auto* second = detail::coroutine_frame_access::allocate(loop, size);
        auto* third = detail::coroutine_frame_access::allocate(loop, size);
        if (first == nullptr || second == nullptr || third == nullptr ||
            detail::coroutine_frame_access::allocate(loop, size) != nullptr) {
            return false;
        }
        static_cast<std::byte*>(first)[size - 1] = std::byte {1};
        static_cast<std::byte*>(second)[size - 1] = std::byte {2};
        static_cast<std::byte*>(third)[size - 1] = std::byte {3};
        const auto full = loop.coroutine_statistics();
        if (full.live != 3 || full.backed_capacity != 3 ||
            full.allocation_failures != 1) return false;
        detail::coroutine_frame_access::deallocate(third, size);
        detail::coroutine_frame_access::deallocate(second, size);
        detail::coroutine_frame_access::deallocate(first, size);
        const auto released = loop.coroutine_statistics();
        if (released.live != 0 || released.backed_capacity != 1) return false;
    }
    return true;
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

auto event_loop_dispatch_yield_test() -> bool
{
    event_loop loop;
    int count = 0;
    bool timer_ran = false;
    bool spawned = false;
    if (!loop.post(execution_task([&]() noexcept {
            spawned = loop.spawn(repeated_yields(loop, count)) ==
                      task_spawn_result::accepted;
            spawned = spawned && loop.spawn(immediate_timer(loop, timer_ran)) ==
                                     task_spawn_result::accepted;
        }))) {
        return false;
    }
    return loop.run() == event_loop_result::stopped && spawned &&
           count == 1024 && timer_ran;
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

#ifdef _WIN32
auto run_child_mode(std::string_view mode) -> int
{
    std::set_terminate([] { std::_Exit(77); });
    constexpr std::array modes {
        std::string_view {"--wrong-loop-yield"},
        std::string_view {"--wrong-loop-timer"},
        std::string_view {"--wrong-loop-immediate-timer"},
        std::string_view {"--wrong-loop-blocking"}};
    for (int kind = 0; kind < static_cast<int>(modes.size()); ++kind) {
        if (mode == modes[static_cast<std::size_t>(kind)]) {
            event_loop owner;
            event_loop foreign(event_loop_options {.worker_count = 1});
            (void)owner.spawn(foreign_awaiter_root(owner, foreign, kind));
            return 1;
        }
    }
    if (mode == "--active-worker-destruction") {
        std::atomic<bool> started {false};
        std::atomic<bool> release {false};
        blocking_error error = blocking_error::cancelled;
        {
            event_loop loop(event_loop_options {.worker_count = 1});
            if (loop.spawn(cancellable_blocking_root(loop, started, release,
                                                    error)) !=
                task_spawn_result::accepted) return 1;
            while (!started.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
        }
        return 1;
    }
    return 1;
}
#endif
auto ordered_sleeper(event_loop& loop, event_loop::clock::time_point deadline, int id,
                     std::array<int, 16>& order, std::size_t& count) -> task<void>
{
    if (co_await sleep_until(loop, deadline) == timer_wait_result::expired)
        order[count++] = id;
}

auto stop_at(event_loop& loop, event_loop::clock::time_point deadline) -> task<void>
{
    (void)co_await sleep_until(loop, deadline);
    loop.stop();
}

struct fired_timer {
    event_loop::clock::time_point deadline;
    int id;
};

auto recorded_sleeper(event_loop& loop, event_loop::clock::time_point deadline, int id,
                      std::vector<fired_timer>& fired) -> task<void>
{
    if (co_await sleep_until(loop, deadline) == timer_wait_result::expired)
        fired.push_back({deadline, id});
}

// Many timers with colliding deadlines and random cancellations exercise the
// timer heap's pairing and removal paths.
auto timer_heap_stress_test() -> bool
{
    constexpr int count = 3000;
    event_loop_options options;
    options.coroutine_frame_capacities = {4096, 4096, 4096, 10240, 4, 2};
    event_loop loop(options);
    std::vector<fired_timer> fired;
    fired.reserve(count);
    std::vector<event_loop::clock::time_point> deadlines;
    deadlines.reserve(count);
    std::vector<task_handle<void>> handles(count);
    std::vector<bool> cancelled(count);
    auto latest_deadline = event_loop::clock::time_point::min();
    std::uint32_t state = 7;
    auto next = [&state](std::uint32_t bound) {
        state = state * 1664525u + 1013904223u;
        return (state >> 8) % bound;
    };
    for (int id = 0; id < count; ++id) {
        // Give each registration its own headroom; rounding preserves collisions.
        const auto registration_base =
            std::chrono::ceil<std::chrono::milliseconds>(
                event_loop::clock::now()) + std::chrono::milliseconds {30};
        deadlines.push_back(
            registration_base + std::chrono::milliseconds {next(40)});
        if (deadlines.back() > latest_deadline) {
            latest_deadline = deadlines.back();
        }
        if (loop.spawn(recorded_sleeper(loop, deadlines.back(), id, fired),
                       handles[static_cast<std::size_t>(id)]) != task_spawn_result::accepted)
            return false;
        // Cancel earlier timers at random while registration continues.
        if (next(10) < 3) {
            const auto victim = static_cast<std::size_t>(next(static_cast<std::uint32_t>(id + 1)));
            if (!cancelled[victim] && handles[victim].cancel()) cancelled[victim] = true;
        }
    }
    const auto stop_deadline = latest_deadline + std::chrono::milliseconds {40};
    if (loop.spawn(stop_at(loop, stop_deadline)) !=
        task_spawn_result::accepted)
        return false;
    (void)loop.run();
    std::size_t expected = 0;
    for (const bool value : cancelled) expected += value ? 0 : 1;
    if (fired.size() != expected) return false;
    for (std::size_t index = 0; index < fired.size(); ++index) {
        const auto& entry = fired[index];
        if (cancelled[static_cast<std::size_t>(entry.id)] ||
            entry.deadline != deadlines[static_cast<std::size_t>(entry.id)])
            return false;
        if (index != 0) {
            const auto& previous = fired[index - 1];
            if (entry.deadline < previous.deadline ||
                (entry.deadline == previous.deadline && entry.id < previous.id))
                return false;
        }
    }
    for (const auto& handle : handles)
        if (!handle.done()) return false;
    return true;
}

// Timers registered at the tail, before the head, in the middle, and with
// equal deadlines, with the head and a middle timer cancelled, fire in
// deadline order and keep registration order for equal deadlines.
auto timer_order_test() -> bool
{
    event_loop loop;
    const auto base = event_loop::clock::now() + std::chrono::milliseconds {30};
    constexpr std::array<int, 9> offsets {10, 10, 5, 20, 15, 10, 1, 25, 20};
    std::array<int, 16> order {};
    std::size_t count = 0;
    std::array<task_handle<void>, 9> handles;
    for (std::size_t id = 0; id < offsets.size(); ++id) {
        const auto deadline = base + std::chrono::milliseconds {offsets[id]};
        if (loop.spawn(ordered_sleeper(loop, deadline, static_cast<int>(id), order, count),
                       handles[id]) != task_spawn_result::accepted)
            return false;
    }
    if (!handles[6].cancel() || !handles[4].cancel()) return false;
    if (loop.spawn(stop_at(loop, base + std::chrono::milliseconds {60})) !=
        task_spawn_result::accepted)
        return false;
    (void)loop.run();
    constexpr std::array<int, 7> expected {2, 0, 1, 5, 3, 8, 7};
    if (count != expected.size()) return false;
    for (std::size_t index = 0; index < expected.size(); ++index)
        if (order[index] != expected[index]) return false;
    for (const auto& handle : handles)
        if (!handle.done()) return false;
    return true;
}

} // namespace

auto main(int argc, char** argv) -> int
{
#ifdef _WIN32
    if (argc == 2) return run_child_mode(argv[1]);
#endif
    if (!timer_heap_stress_test()) {
        std::cerr << "timer heap stress test failed\n";
        return 1;
    }
    if (!timer_order_test()) {
        std::cerr << "timer order test failed\n";
        return 1;
    }
    if (!wrong_loop_awaiter_test()) {
        std::cerr << "wrong-loop awaiter test failed\n";
        return 1;
    }
    if (!value_result_test()) {
        std::cerr << "task value result test failed\n";
        return 1;
    }
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
    if (!bounded_growth_and_release_test()) {
        std::cerr << "task frame-pool bounded growth/release test failed\n";
        return 1;
    }
    if (!frame_class_lifecycle_test()) {
        std::cerr << "task frame-pool class lifecycle test failed\n";
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
    if (!event_loop_dispatch_yield_test()) {
        std::cerr << "event-loop dispatch yield test failed\n";
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
    if (!active_worker_destruction_test()) {
        std::cerr << "active worker destruction test failed\n";
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
