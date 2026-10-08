#include "eventloop/task.h"
#include "eventloop/tcp_stream.h"

#include <array>
#include <atomic>
#include <pthread.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <functional>
#include <iostream>
#include <memory>
#include <vector>
#include <stdexcept>
#include <system_error>
#include <thread>

#ifndef _WIN32
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace eventloop;

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

auto post_after_blocking(event_loop& loop, bool& ran) -> task<void>
{
    (void)co_await run_blocking(loop, []() noexcept {});
    if (!loop.post(execution_task([&]() noexcept {
            ran = true;
            loop.stop();
        }))) loop.stop();
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
        // An owner stop() before run() still drains queued posts; one issued
        // during that final iteration ends the next run().
        event_loop loop;
        int count = 0;
        if (!loop.post(execution_task([&]() noexcept {
                ++count;
                loop.stop();
            }))) return false;
        loop.stop();
        if (loop.run() != event_loop_result::stopped || count != 1) {
            return false;
        }
        if (!loop.post(execution_task([&]() noexcept { ++count; }))) {
            return false;
        }
        if (loop.run() != event_loop_result::stopped || count != 2) {
            return false;
        }
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
        // A worker completion resumes a coroutine that posts on the owner
        // thread; that post relies on the owner's local hint, not a wakeup.
        event_loop loop(event_loop_options {.worker_count = 1});
        bool ran = false;
        if (loop.spawn(post_after_blocking(loop, ran)) !=
            task_spawn_result::accepted) return false;
        std::thread stopper([&] {
            std::this_thread::sleep_for(2s);
            loop.stop();
        });
        const auto result = loop.run();
        stopper.join();
        if (result != event_loop_result::stopped || !ran) return false;
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

auto blocking_completions(event_loop& loop, std::size_t count,
                          std::size_t& completed) -> task<void>
{
    for (std::size_t index = 0; index < count; ++index) {
        auto result = co_await run_blocking(loop, []() noexcept {});
        if (result) ++completed;
    }
}

auto blocking_ping_pong(event_loop& loop, std::size_t count,
                        bool& passed) -> task<void>
{
    std::size_t completed = 0;
    co_await blocking_completions(loop, count, completed);
    passed = completed == count;
    loop.stop();
}

// One publisher in lockstep with the owner: each publication races the
// owner's return to its poll with no other publisher to mask a lost wakeup.
auto wakeup_ping_pong_test() -> bool
{
    constexpr std::size_t iterations = 100'000;
    std::atomic<bool> timed_out {false};
    std::atomic<bool> finished {false};
    const auto watch = [&](event_loop& loop) {
        return std::thread([&] {
            const auto deadline = std::chrono::steady_clock::now() + 20s;
            while (!finished.load()) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    timed_out.store(true);
                    loop.stop();
                    return;
                }
                std::this_thread::sleep_for(1ms);
            }
        });
    };
    {
        event_loop loop;
        std::atomic<std::size_t> executed {0};
        std::thread watchdog = watch(loop);
        std::thread producer([&] {
            for (std::size_t index = 0; index < iterations; ++index) {
                if (!loop.post(execution_task([&]() noexcept {
                        executed.fetch_add(1, std::memory_order_release);
                    }))) break;
                while (executed.load(std::memory_order_acquire) == index) {
                    if (timed_out.load()) return;
                }
            }
            loop.stop();
        });
        const auto result = loop.run();
        producer.join();
        finished.store(true);
        watchdog.join();
        if (result != event_loop_result::stopped || timed_out.load() ||
            executed.load() != iterations) return false;
    }
    finished.store(false);
    {
        event_loop loop(event_loop_options {.worker_count = 1});
        bool passed = false;
        std::thread watchdog = watch(loop);
        if (loop.spawn(blocking_ping_pong(loop, iterations, passed)) !=
            task_spawn_result::accepted) return false;
        const auto result = loop.run();
        finished.store(true);
        watchdog.join();
        if (result != event_loop_result::stopped || timed_out.load() ||
            !passed) return false;
    }
    return true;
}

// Producers alternate pressure bursts with waits that let the owner block in
// its poll, while worker completions publish to the second queue. A lost
// wakeup leaves a producer or root waiting until the watchdog stops the loop.
auto cross_thread_wakeup_stress_test() -> bool
{
    constexpr std::size_t producer_count = 4;
    constexpr std::size_t rounds = 2'000;
    constexpr std::size_t root_count = 16;
    constexpr std::size_t completions_per_root = 500;

    event_loop loop(event_loop_options {.worker_count = 4});
    std::array<std::atomic<std::size_t>, producer_count> executed {};
    std::array<std::size_t, producer_count> posted {};
    std::atomic<bool> timed_out {false};
    std::atomic<bool> finished {false};
    std::size_t completions = 0;
    for (std::size_t root = 0; root < root_count; ++root) {
        if (loop.spawn(blocking_completions(loop, completions_per_root,
                                            completions)) !=
            task_spawn_result::accepted) return false;
    }

    std::array<std::thread, producer_count> producers;
    for (std::size_t id = 0; id < producer_count; ++id) {
        producers[id] = std::thread([&, id] {
            for (std::size_t round = 0; round < rounds; ++round) {
                const std::size_t burst = (round * 7 + id * 13) % 100 + 1;
                for (std::size_t index = 0; index < burst; ++index) {
                    execution_task task([&, id]() noexcept {
                        executed[id].fetch_add(1, std::memory_order_release);
                    });
                    while (!loop.post(std::move(task))) {
                        if (timed_out.load()) return;
                        std::this_thread::yield();
                    }
                    ++posted[id];
                }
                if (round % 2 != 0) continue;
                while (executed[id].load(std::memory_order_acquire) !=
                       posted[id]) {
                    if (timed_out.load()) return;
                    std::this_thread::yield();
                }
            }
        });
    }
    std::thread watchdog([&] {
        const auto deadline = std::chrono::steady_clock::now() + 20s;
        while (!finished.load()) {
            if (std::chrono::steady_clock::now() >= deadline) {
                timed_out.store(true);
                loop.stop();
                return;
            }
            std::this_thread::sleep_for(1ms);
        }
    });
    std::thread joiner([&] {
        for (auto& producer : producers) producer.join();
        // Producer counts are final; the owner checks them from a task.
        for (;;) {
            execution_task check([&]() noexcept {
                bool all = completions == root_count * completions_per_root;
                for (std::size_t id = 0; id < producer_count; ++id) {
                    all = all && executed[id].load() == posted[id];
                }
                if (all) {
                    finished.store(true);
                    loop.stop();
                }
            });
            while (!loop.post(std::move(check))) std::this_thread::yield();
            for (int wait = 0; wait < 100 && !finished.load() &&
                               !timed_out.load(); ++wait) {
                std::this_thread::sleep_for(1ms);
            }
            if (finished.load() || timed_out.load()) return;
        }
    });

    const auto result = loop.run();
    joiner.join();
    finished.store(true);
    watchdog.join();
    return result == event_loop_result::stopped && !timed_out.load();
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

auto stop_after_post(event_loop& loop, timer_wait_result& result) -> void
{
    if (!loop.post(execution_task([&]() noexcept {
            if (loop.spawn(wait_then_stop(loop, 5ms, result)) !=
                task_spawn_result::accepted) loop.stop();
        }))) loop.stop();
}

// Posted work that registers an earlier timer must shorten a wait that
// started with a later deadline.
auto posted_deadline_test() -> bool
{
    event_loop loop;
    timer_wait_result distant = timer_wait_result::expired;
    timer_wait_result near = timer_wait_result::cancelled;
    task_handle<void> waiting;
    if (loop.spawn(wait_until(loop, event_loop::clock::now() + 1h, distant, false),
                   waiting) != task_spawn_result::accepted) return false;
    std::jthread poster([&] {
        std::this_thread::sleep_for(20ms);
        stop_after_post(loop, near);
    });
    const auto started = event_loop::clock::now();
    const bool stopped = loop.run() == event_loop_result::stopped;
    const auto elapsed = event_loop::clock::now() - started;
    poster.join();
    (void)waiting.cancel();
    loop.stop();
    (void)loop.run();
    return stopped && near == timer_wait_result::expired && elapsed < 5s &&
           distant == timer_wait_result::cancelled;
}

#ifndef _WIN32
// Signals interrupting the wait must not restart its full timeout.
auto interrupted_wait_test() -> bool
{
    struct sigaction action {};
    struct sigaction previous {};
    action.sa_handler = [](int) {};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, &previous) == -1) return false;
    event_loop loop;
    timer_wait_result result = timer_wait_result::cancelled;
    const auto deadline = event_loop::clock::now() + 50ms;
    if (loop.spawn(wait_until(loop, deadline, result, true)) !=
        task_spawn_result::accepted) return false;
    std::atomic<bool> done {false};
    const auto target = pthread_self();
    std::jthread interrupter([&] {
        while (!done.load()) {
            (void)pthread_kill(target, SIGUSR1);
            std::this_thread::sleep_for(2ms);
        }
    });
    const bool stopped = loop.run() == event_loop_result::stopped;
    const auto finished = event_loop::clock::now();
    done = true;
    interrupter.join();
    (void)sigaction(SIGUSR1, &previous, nullptr);
    return stopped && result == timer_wait_result::expired &&
           finished >= deadline && finished - deadline < 2s;
}

// About 200 descriptors stay ready, more than one poll batch returns. Work
// that becomes due or is posted while a batch is dispatched must run within
// a batch or two instead of waiting for the poller to return its descriptor
// behind every ready socket.
struct ready_ring {
    std::atomic<std::size_t> completions {0};
    std::size_t delay {0};
    bool fired {false};
    bool stopping {false};
    // Runs once, inside a completion, when the ring is in steady state.
    std::function<void()> trigger;
};

constexpr std::size_t ring_pairs = 200;
constexpr std::size_t batch_capacity = 64;

auto finish_ring(event_loop& loop, ready_ring& ring, std::size_t since) -> void
{
    const auto now = ring.completions.load(std::memory_order_relaxed);
    ring.delay = now > since ? now - since : 0;
    ring.fired = true;
    ring.stopping = true;
    loop.stop();
}

auto ring_peer(event_loop&, tcp_stream& stream, bool first, ready_ring& ring)
    -> task<void>
{
    std::array<std::byte, 1> byte {};
    if (first && !co_await stream.async_write_some(byte)) co_return;
    while (!ring.stopping) {
        if (!co_await stream.async_read_some(byte)) co_return;
        if (ring.completions.fetch_add(1, std::memory_order_relaxed) + 1 ==
            10 * ring_pairs) ring.trigger();
        if (!co_await stream.async_write_some(byte)) co_return;
    }
}

// Builds the ring, then lets drive() run the loop with any helpers it needs.
template<typename Drive>
auto run_ready_ring(ready_ring& ring, Drive&& drive) -> bool
{
    event_loop_options options;
    options.coroutine_frame_capacities.fill(1024);
    event_loop loop(options);
    std::vector<tcp_stream*> streams;
    for (std::size_t pair = 0; pair < ring_pairs; ++pair) {
        int sockets[2] {};
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == -1)
            return false;
        for (int side = 0; side < 2; ++side) {
            auto stream = std::make_unique<tcp_stream>(loop, unique_fd(sockets[side]));
            streams.push_back(stream.get());
            loop.add(std::move(stream));
            if (loop.spawn(ring_peer(loop, *streams.back(), side == 0, ring)) !=
                task_spawn_result::accepted) return false;
        }
    }
    drive(loop);
    for (auto* stream : streams) stream->close();
    loop.stop();
    (void)loop.run();
    return ring.fired;
}

auto timer_after_batch(event_loop& loop, ready_ring& ring) -> task<void>
{
    const auto registered = ring.completions.load(std::memory_order_relaxed);
    (void)co_await sleep_until(loop, event_loop::clock::now() + 1us);
    finish_ring(loop, ring, registered);
}

// A timer that becomes due during a batch runs before the next one.
auto ready_ring_timer_test() -> bool
{
    ready_ring ring;
    const bool ran = run_ready_ring(ring, [&](event_loop& loop) {
        ring.trigger = [&] {
            if (loop.spawn(timer_after_batch(loop, ring)) !=
                task_spawn_result::accepted) return;
            // Make sure the deadline passes before this batch ends.
            const auto due = event_loop::clock::now() + 5us;
            while (event_loop::clock::now() < due) {}
        };
        (void)loop.run();
    });
    if (!ran || ring.delay >= batch_capacity)
        std::cerr << "ready ring timer delay " << ring.delay << '\n';
    return ran && ring.delay < batch_capacity;
}

// Work posted from another thread is drained within two batches: the one
// running when it was published and, if the owner had already checked for
// cross-thread work, the next.
auto ready_ring_post_test() -> bool
{
    ready_ring ring;
    const bool ran = run_ready_ring(ring, [&](event_loop& loop) {
        std::atomic<bool> requested {false};
        std::jthread poster([&] {
            while (!requested.load(std::memory_order_acquire)) {}
            const auto published = ring.completions.load(std::memory_order_relaxed);
            if (!loop.post(execution_task([&loop, &ring, published]() noexcept {
                    finish_ring(loop, ring, published);
                }))) loop.stop();
        });
        ring.trigger = [&] { requested.store(true, std::memory_order_release); };
        (void)loop.run();
    });
    if (!ran || ring.delay >= 2 * batch_capacity)
        std::cerr << "ready ring post delay " << ring.delay << '\n';
    return ran && ring.delay < 2 * batch_capacity;
}
#endif

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

// While a loop lives on this thread, a write to a closed socket without
// MSG_NOSIGNAL (as OpenSSL kTLS does) returns EPIPE instead of ending the
// process. The last loop discards the pending signal and restores the mask.
auto sigpipe_test() -> bool
{
    int sockets[2] {};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) return false;
    bool written = false;
    bool still_blocked = false;
    {
        auto first = std::make_unique<event_loop>();
        auto second = std::make_unique<event_loop>();
        close(sockets[1]);
        const char byte = 'x';
        errno = 0;
        written = ::write(sockets[0], &byte, 1) == -1 && errno == EPIPE;
        first.reset();
        sigset_t current {};
        still_blocked = pthread_sigmask(SIG_SETMASK, nullptr, &current) == 0 &&
                        sigismember(&current, SIGPIPE) == 1;
    }
    close(sockets[0]);
    sigset_t current {};
    sigset_t pending {};
    return written && still_blocked &&
           pthread_sigmask(SIG_SETMASK, nullptr, &current) == 0 &&
           sigismember(&current, SIGPIPE) == 0 &&
           sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 0;
}
#endif
} // namespace

auto main() -> int
{
#ifndef _WIN32
    if (!nested_signal_mask_test()) return 1;
    if (!sigpipe_test()) return 1;
#endif
    if (!post_tests()) return 1;
    if (!wakeup_ping_pong_test()) return 1;
    if (!cross_thread_wakeup_stress_test()) return 1;
    if (!executor_integration_test()) return 1;
    if (!timer_tests()) return 1;
    if (!posted_deadline_test()) return 1;
#ifndef _WIN32
    if (!interrupted_wait_test()) return 1;
    if (!ready_ring_timer_test()) return 1;
    if (!ready_ring_post_test()) return 1;
#endif
    if (!shutdown_tests()) return 1;
#ifndef _WIN32
    if (!signal_test()) return 1;
#endif
    return 0;
}
