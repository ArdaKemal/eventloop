#include "eventloop/task.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <thread>

#include <sys/timerfd.h>
#include <unistd.h>

using namespace eventloop;

#if defined(EVENTLOOP_TEST_WRAP_TIMERFD)
namespace {
int injected_timer_arm_errors = 0;
}

extern "C" auto __real_timerfd_settime(int descriptor, int flags,
                                         const itimerspec* value,
                                         itimerspec* old_value) -> int;

extern "C" auto __wrap_timerfd_settime(int descriptor, int flags,
                                         const itimerspec* value,
                                         itimerspec* old_value) -> int
{
    if (injected_timer_arm_errors != 0) {
        --injected_timer_arm_errors;
        errno = EIO;
        return -1;
    }
    return __real_timerfd_settime(descriptor, flags, value, old_value);
}
#endif

namespace {
using namespace std::chrono_literals;

auto wait_then_stop(event_loop& loop, event_loop::clock::duration delay,
                    timer_wait_result& result) -> task<void>
{
    result = co_await sleep_for(loop, delay);
    loop.stop();
}

auto wait_until(event_loop& loop, event_loop::clock::time_point deadline,
                timer_wait_result& result, bool stop) -> task<void>
{
    result = co_await sleep_until(loop, deadline);
    if (stop) loop.stop();
}

auto post_tests() -> bool
{
    {
        event_loop loop;
        bool ran = false;
        std::thread::id observed;
        const auto expected = std::this_thread::get_id();
        if (!loop.post(execution_task([&]() noexcept {
                ran = true;
                observed = std::this_thread::get_id();
                loop.stop();
            }))) return false;
        if (loop.run() != event_loop_result::stopped || !ran ||
            observed != expected) return false;
    }
    {
        event_loop loop;
        std::atomic<bool> ran {false};
        std::atomic<bool> on_loop {false};
        const auto expected = std::this_thread::get_id();
        std::thread poster([&] {
            std::this_thread::sleep_for(5ms);
            if (!loop.post(execution_task([&]() noexcept {
                    ran.store(true);
                    on_loop.store(std::this_thread::get_id() == expected);
                    loop.stop();
                }))) loop.stop();
        });
        const auto result = loop.run();
        poster.join();
        if (result != event_loop_result::stopped || !ran.load() ||
            !on_loop.load()) return false;
    }
    {
        event_loop loop(event_loop_options {.post_capacity = 2});
        int count = 0;
        execution_task empty;
        if (loop.post(std::move(empty))) return false;
        const bool first = loop.post(execution_task([&]() noexcept { ++count; }));
        const bool second = loop.post(execution_task([&]() noexcept {
            ++count;
            loop.stop();
        }));
        execution_task third([&]() noexcept { ++count; });
        if (!first || !second || loop.post(std::move(third)) || !third) {
            return false;
        }
        if (loop.run() != event_loop_result::stopped || count != 2) {
            return false;
        }
    }
    return true;
}

auto executor_integration_test() -> bool
{
    event_loop loop(event_loop_options {.worker_count = 2});
    const auto loop_thread = std::this_thread::get_id();
    std::atomic<bool> on_worker {false};
    bool returned = false;
    bool on_loop = false;

    if (!loop.task_executor().execute(execution_task([&]() noexcept {
            on_worker.store(std::this_thread::get_id() != loop_thread);
            if (!loop.post(execution_task([&]() noexcept {
                    returned = true;
                    on_loop = std::this_thread::get_id() == loop_thread;
                    loop.stop();
                }))) loop.stop();
        }))) return false;

    return loop.run() == event_loop_result::stopped && on_worker.load() &&
           returned && on_loop;
}

auto timer_tests() -> bool
{
    event_loop loop;
    timer_wait_result first = timer_wait_result::cancelled;
    timer_wait_result second = timer_wait_result::cancelled;
    timer_wait_result cancelled = timer_wait_result::expired;
    task_handle<void> pending;
    const auto deadline = event_loop::clock::now() + 5ms;
    if (loop.spawn(wait_until(loop, deadline, first, false)) !=
            task_spawn_result::accepted ||
        loop.spawn(wait_until(loop, deadline, second, true)) !=
            task_spawn_result::accepted ||
        loop.spawn(wait_until(loop, event_loop::clock::time_point::max(),
                              cancelled, false), pending) !=
            task_spawn_result::accepted) return false;
    if (!pending.cancel() || !pending.done()) return false;
    const auto result = pending.take_result();
    if (result != task_result::success ||
        cancelled != timer_wait_result::cancelled) return false;
    if (loop.run() != event_loop_result::stopped) return false;
    return first == timer_wait_result::expired &&
           second == timer_wait_result::expired &&
           event_loop::clock::now() >= deadline &&
           eventloop::detail::deadline_after(event_loop::clock::duration::max()) ==
               event_loop::clock::time_point::max();
}

#if defined(EVENTLOOP_TEST_WRAP_TIMERFD)
auto failed_timer_registration(event_loop& loop, bool& caught) -> task<void>
{
    try {
        (void)co_await sleep_for(loop, 1ms);
    } catch (const std::system_error& error) {
        caught = error.code().value() == EIO;
    }
}
#endif

auto timer_arm_failure_test() -> bool
{
#if defined(EVENTLOOP_TEST_WRAP_TIMERFD)
    event_loop loop;
    bool caught = false;
    timer_wait_result accepted = timer_wait_result::cancelled;
    if (loop.spawn(wait_then_stop(loop, 5ms, accepted)) !=
        task_spawn_result::accepted) return false;
    injected_timer_arm_errors = 1;
    if (loop.spawn(failed_timer_registration(loop, caught)) !=
        task_spawn_result::accepted) return false;
    return injected_timer_arm_errors == 0 && caught &&
           loop.run() == event_loop_result::stopped &&
           accepted == timer_wait_result::expired;
#else
    return true;
#endif
}

auto shutdown_tests() -> bool
{
    {
        event_loop loop;
        task_handle<void> pending;
        timer_wait_result result = timer_wait_result::expired;
        if (loop.spawn(wait_until(loop, event_loop::clock::now() + 1h,
                                  result, false), pending) !=
            task_spawn_result::accepted) return false;
        loop.shutdown(1s);
        if (!pending.done() || result != timer_wait_result::cancelled ||
            pending.take_result() != task_result::success ||
            loop.run() != event_loop_result::stopped) return false;
        timer_wait_result unused = timer_wait_result::expired;
        if (loop.spawn(wait_then_stop(loop, 1ms, unused)) !=
            task_spawn_result::shutting_down) return false;
        loop.shutdown(event_loop::clock::duration::zero());
    }
    {
        event_loop loop;
        task_handle<void> pending;
        timer_wait_result result = timer_wait_result::expired;
        if (loop.spawn(wait_until(loop, event_loop::clock::time_point::max(),
                                  result, false), pending) !=
            task_spawn_result::accepted) return false;
        loop.shutdown(event_loop::clock::duration::max());
        return pending.done() &&
               result == timer_wait_result::cancelled &&
               pending.take_result() == task_result::success &&
               loop.run() == event_loop_result::stopped;
    }
}

auto signal_test() -> bool
{
    event_loop loop;
    std::thread interrupter([] {
        std::this_thread::sleep_for(5ms);
        (void)::kill(::getpid(), SIGTERM);
    });
    const auto result = loop.run();
    interrupter.join();
    return result == event_loop_result::interrupted;
}

auto nested_signal_mask_test() -> bool
{
    sigset_t signals {};
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    sigset_t original {};
    if (sigprocmask(SIG_UNBLOCK, &signals, &original) == -1) return false;

    bool valid = false;
    try {
        auto first = std::make_unique<event_loop>();
        auto second = std::make_unique<event_loop>();
        first.reset();
        sigset_t current {};
        valid = sigprocmask(SIG_SETMASK, nullptr, &current) == 0 &&
                sigismember(&current, SIGINT) == 1 &&
                sigismember(&current, SIGTERM) == 1;
        second.reset();
        valid = valid && sigprocmask(SIG_SETMASK, nullptr, &current) == 0 &&
                sigismember(&current, SIGINT) == 0 &&
                sigismember(&current, SIGTERM) == 0;
    } catch (...) {
        sigprocmask(SIG_SETMASK, &original, nullptr);
        return false;
    }
    sigprocmask(SIG_SETMASK, &original, nullptr);
    return valid;
}
} // namespace

auto main() -> int
{
    if (!nested_signal_mask_test()) return 1;
    if (!post_tests()) return 1;
    if (!executor_integration_test()) return 1;
    if (!timer_tests()) return 1;
    if (!timer_arm_failure_test()) return 1;
    if (!shutdown_tests()) return 1;
    if (!signal_test()) return 1;
    return 0;
}
