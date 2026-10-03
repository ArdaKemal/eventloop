#include "eventloop/task.h"
#include "eventloop/udp_socket.h"
#include "publication_pause.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <csignal>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>

#ifndef _WIN32
#if defined(EVENTLOOP_TEST_WRAP_TIMERFD)
#include <sys/timerfd.h>
#endif
#include <unistd.h>
#endif

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

struct publication_progress {
    event_loop& loop;
    test_publication::pause gate {};
    std::array<int, 2> order {};
    int posted_count {0};
    bool timer_ok {false};
    bool send_ok {false};
    bool receive_ok {false};
    bool blocking_ok {false};
    bool sender_done {false};
    bool receiver_done {false};
    std::atomic<bool> progressed {false};

    auto finish() -> void
    {
        if (sender_done && receiver_done) {
            progressed.store(true, std::memory_order_release);
            if (posted_count == 2) loop.stop();
        }
    }
};

auto receive_during_publication(event_loop& loop, udp_socket& receiver,
                                publication_progress& progress) -> task<void>
{
    (void)loop;
    std::array<std::byte, 1> buffer {};
    const auto result = co_await receiver.async_receive_from(buffer);
    progress.receive_ok = result && result->size == 1 &&
        buffer[0] == std::byte {42} && !progress.gate.released.load();
    progress.receiver_done = true;
    progress.finish();
}

auto work_during_publication(event_loop& loop, udp_socket& sender,
                             ip_endpoint destination,
                             publication_progress& progress) -> task<void>
{
    progress.timer_ok = co_await sleep_for(loop, 5ms) == timer_wait_result::expired &&
                        !progress.gate.released.load();
    const std::array<std::byte, 1> payload {std::byte {42}};
    const auto sent = co_await sender.async_send_to(payload, destination);
    progress.send_ok = sent && *sent == 1 && !progress.gate.released.load();
    const auto result = co_await run_blocking(loop, []() noexcept { return 7; });
    progress.blocking_ok = result && *result == 7 && !progress.gate.released.load();
    progress.sender_done = true;
    progress.finish();
}

auto pending_post_progress_test(bool local_second) -> bool
{
    event_loop loop(event_loop_options {.worker_count = 1, .post_capacity = 2});
    publication_progress progress {loop};
    auto receiver = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto sender = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto* receiver_ptr = receiver.get();
    auto* sender_ptr = sender.get();
    const auto destination = receiver->local_endpoint();
    loop.add(std::move(receiver));
    loop.add(std::move(sender));
    auto first = test_publication::make_task(progress.gate, [&]() noexcept {
        progress.order[static_cast<std::size_t>(progress.posted_count++)] = 1;
    });
    progress.gate.armed.store(true, std::memory_order_release);
    bool first_accepted = false;
    std::thread producer([&] { first_accepted = loop.post(std::move(first)); });
    if (!test_publication::wait_until([&] {
            return progress.gate.entered.load(std::memory_order_acquire);
        })) {
        progress.gate.open();
        producer.join();
        return false;
    }

    bool second_accepted = false;
    execution_task second([&]() noexcept {
        progress.order[static_cast<std::size_t>(progress.posted_count++)] = 2;
        progress.finish();
    });
    if (local_second) {
        second_accepted = loop.post(std::move(second));
    } else {
        std::thread later([&] { second_accepted = loop.post(std::move(second)); });
        later.join();
    }
    if (!second_accepted ||
        loop.spawn(receive_during_publication(loop, *receiver_ptr, progress)) !=
            task_spawn_result::accepted ||
        loop.spawn(work_during_publication(loop, *sender_ptr, destination, progress)) !=
            task_spawn_result::accepted) {
        progress.gate.open();
        producer.join();
        loop.shutdown(event_loop::clock::duration::zero());
        (void)loop.run();
        return false;
    }

    // Keep publication paused until the loop services a timer, pending UDP
    // receive, and independent worker completion. The deadline lets a broken
    // drain finish so the test reports failure instead of hanging.
    bool before_release = false;
    std::thread watchdog([&] {
        before_release = test_publication::wait_until([&] {
            return progress.progressed.load(std::memory_order_acquire);
        });
        progress.gate.open();
    });
    const auto result = loop.run();
    watchdog.join();
    producer.join();
    return result == event_loop_result::stopped && before_release && first_accepted &&
        progress.timer_ok && progress.send_ok && progress.receive_ok &&
        progress.blocking_ok && progress.posted_count == 2 &&
        progress.order == std::array<int, 2> {1, 2} &&
        loop.coroutine_statistics().live == 0;
}

auto completion_pause_timer(event_loop& loop, test_publication::pause& gate,
                            std::atomic<bool>& expired) -> task<void>
{
    const auto result = co_await sleep_for(loop, 5ms);
    expired.store(result == timer_wait_result::expired && !gate.released.load(),
                  std::memory_order_release);
}

auto pending_completion_progress_test() -> bool
{
    event_loop loop;
    test_publication::pause gate;
    std::array<int, 2> order {};
    int count = 0;
    std::atomic<bool> expired {false};
    std::atomic<bool> posted {false};
    // Internal completion producers have fixed callback types. Reserve and
    // publish through their existing detail entry points to pause this queue
    // independently of the public post/timer/UDP caller tested above.
    for (int index = 0; index < 2; ++index) {
        if (detail::coroutine_frame_access::reserve_completion(loop) !=
            detail::completion_reservation_result::accepted) return false;
    }
    auto first = test_publication::make_task(gate, [&]() noexcept {
        order[static_cast<std::size_t>(count++)] = 1;
    });
    gate.armed.store(true, std::memory_order_release);
    std::thread producer([&] {
        detail::coroutine_frame_access::post_completion(loop, std::move(first));
    });
    if (!test_publication::wait_until([&] {
            return gate.entered.load(std::memory_order_acquire);
        })) {
        gate.open();
        producer.join();
        return false;
    }
    detail::coroutine_frame_access::post_completion(loop, execution_task([&]() noexcept {
        order[static_cast<std::size_t>(count++)] = 2;
        loop.stop();
    }));
    if (!loop.post(execution_task([&]() noexcept {
            posted.store(!gate.released.load(), std::memory_order_release);
        })) ||
        loop.spawn(completion_pause_timer(loop, gate, expired)) !=
            task_spawn_result::accepted) {
        gate.open();
        producer.join();
        return false;
    }
    bool before_release = false;
    std::thread watchdog([&] {
        before_release = test_publication::wait_until([&] {
            return expired.load(std::memory_order_acquire) &&
                   posted.load(std::memory_order_acquire);
        });
        gate.open();
    });
    const auto result = loop.run();
    watchdog.join();
    producer.join();
    if (loop.coroutine_statistics().live != 0) {
        loop.shutdown(event_loop::clock::duration::zero());
        (void)loop.run();
    }
    return result == event_loop_result::stopped && before_release && count == 2 &&
        order == std::array<int, 2> {1, 2} && loop.coroutine_statistics().live == 0;
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

#ifndef _WIN32
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
#endif
} // namespace

auto main() -> int
{
#ifndef _WIN32
    if (!nested_signal_mask_test()) return 1;
#endif
    if (!post_tests()) return 1;
    if (!pending_post_progress_test(true) ||
        !pending_post_progress_test(false)) return 1;
    if (!pending_completion_progress_test()) return 1;
    if (!executor_integration_test()) return 1;
    if (!timer_tests()) return 1;
    if (!timer_arm_failure_test()) return 1;
    if (!shutdown_tests()) return 1;
#ifndef _WIN32
    if (!signal_test()) return 1;
#endif
    return 0;
}
