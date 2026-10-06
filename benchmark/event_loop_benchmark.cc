#include "eventloop/task.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace eventloop;

namespace {

constexpr std::size_t construction_iterations = 20'000;
constexpr std::size_t post_iterations = 1'000'000;
constexpr std::size_t cross_thread_iterations = 100'000;
constexpr std::size_t burst_size = 64;
constexpr std::size_t burst_count = 10'000;
constexpr std::size_t completion_roots = 64;
constexpr std::size_t completions_per_root = 2'000;

// Write syscalls made by this process, including exited threads. The
// benchmarked producers and workers make no other writes, so the delta
// counts loop wakeups (plus one for stop()). Linux only.
[[nodiscard]] auto process_write_syscalls() -> std::uint64_t
{
#ifdef __linux__
    std::ifstream io("/proc/self/io");
    std::string key;
    std::uint64_t value = 0;
    while (io >> key >> value) {
        if (key == "syscw:") return value;
    }
#endif
    return 0;
}

template<typename Function>
auto measure(const char* name, std::size_t operations, Function&& function) -> void
{
    const auto started = std::chrono::steady_clock::now();
    function();
    const auto elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started);
    std::cout << name << ": " << operations << " operations in "
              << elapsed.count() << " s ("
              << static_cast<double>(operations) / elapsed.count()
              << " operations/s)\n";
}

struct post_chain {
    auto run() noexcept -> void
    {
        ++completed;
        if (completed == target) {
            loop.stop();
            return;
        }
        if (!loop.post(execution_task([this]() noexcept { run(); }))) {
            std::terminate();
        }
    }

    event_loop& loop;
    std::size_t target;
    std::size_t completed {0};
};

auto construction() -> void
{
    measure("event-loop construct/destroy", construction_iterations,
            [] {
                for (std::size_t index = 0; index < construction_iterations;
                     ++index) {
                    event_loop loop;
                }
            });
}

auto post_round_trip() -> void
{
    event_loop loop;
    post_chain chain {loop, post_iterations};
    if (!loop.post(execution_task([&chain]() noexcept { chain.run(); }))) {
        std::terminate();
    }
    measure("event-loop post round-trip", post_iterations,
            [&loop] { (void)loop.run(); });
}

auto cross_thread_post() -> void
{
    using clock = std::chrono::steady_clock;
    event_loop loop;
    // Allocate a fixed number of samples before starting either measurement.
    std::vector<clock::duration> latency(cross_thread_iterations);
    clock::time_point started;
    clock::time_point finished;
    std::size_t completed = 0;
    std::size_t queue_full_retries = 0;
    std::uint64_t writes = 0;
    std::thread producer([&] {
        // Let the owner enter its blocking poll before the first wakeup.
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        writes = process_write_syscalls();
        started = clock::now();
        for (std::size_t index = 0; index < cross_thread_iterations; ++index) {
            const auto posted = clock::now();
            execution_task task([&, index, posted]() noexcept {
                const auto dispatched = clock::now();
                latency[index] = dispatched - posted;
                if (++completed == cross_thread_iterations) {
                    finished = dispatched;
                    loop.stop();
                }
            });
            // post() preserves a named task on failure. Retry it without
            // dropping work; the owner keeps draining while we yield.
            while (!loop.post(std::move(task))) {
                ++queue_full_retries;
                std::this_thread::yield();
            }
        }
    });
    (void)loop.run();
    // Even the final callback may precede the producer's return from post().
    // Join before accessing producer state or destroying the loop.
    producer.join();
    writes = process_write_syscalls() - writes;
    if (completed != cross_thread_iterations) std::terminate();
    const auto elapsed = std::chrono::duration<double>(finished - started);
    const auto zero_samples = std::count(latency.begin(), latency.end(),
                                         clock::duration::zero());
    std::sort(latency.begin(), latency.end());
    const auto nanoseconds = [](clock::duration duration) {
        return std::chrono::duration<double, std::nano>(duration).count();
    };
    // Nearest-rank percentiles; queue-full retry time is included in latency.
    std::cout << "event-loop cross-thread post/wake: " << completed
              << " operations in " << elapsed.count() << " s ("
              << static_cast<double>(completed) / elapsed.count()
              << " operations/s), post-to-dispatch min "
              << nanoseconds(latency.front()) << " ns, p50 "
              << nanoseconds(latency[cross_thread_iterations / 2 - 1])
              << " ns, p99 "
              << nanoseconds(latency[cross_thread_iterations * 99 / 100 - 1])
              << " ns, zero-duration samples " << zero_samples << '/' << completed
              << ", queue-full retries " << queue_full_retries
              << " (latency includes retry time), wake writes per post "
              << static_cast<double>(writes) / static_cast<double>(completed)
              << '\n';
}

// A producer publishes bursts and waits for each to run, so every burst
// starts while the owner may be blocked in its poll.
auto cross_thread_burst() -> void
{
    event_loop loop;
    std::atomic<std::size_t> completed {0};
    std::uint64_t writes = 0;
    std::thread producer([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        writes = process_write_syscalls();
        for (std::size_t burst = 0; burst < burst_count; ++burst) {
            for (std::size_t index = 0; index < burst_size; ++index) {
                execution_task task([&]() noexcept {
                    completed.fetch_add(1, std::memory_order_release);
                });
                while (!loop.post(std::move(task))) std::this_thread::yield();
            }
            const auto target = (burst + 1) * burst_size;
            while (completed.load(std::memory_order_acquire) != target) {
                std::this_thread::yield();
            }
        }
        writes = process_write_syscalls() - writes;
        loop.stop();
    });
    measure("event-loop cross-thread bursts of 64", burst_count * burst_size,
            [&loop] { (void)loop.run(); });
    producer.join();
    std::cout << "  wake writes per burst "
              << static_cast<double>(writes) / burst_count << '\n';
}

auto blocking_root(event_loop& loop, std::size_t& remaining) -> task<void>
{
    for (std::size_t index = 0; index < completions_per_root; ++index) {
        auto result = co_await run_blocking(loop, []() noexcept {});
        if (!result) std::terminate();
    }
    if (--remaining == 0) loop.stop();
}

// Concurrent run_blocking() roots publish worker completions to the owner.
auto worker_completions() -> void
{
    event_loop loop(event_loop_options {.worker_count = 4});
    std::size_t remaining = completion_roots;
    for (std::size_t root = 0; root < completion_roots; ++root) {
        if (loop.spawn(blocking_root(loop, remaining)) !=
            task_spawn_result::accepted) {
            std::terminate();
        }
    }
    const auto operations = completion_roots * completions_per_root;
    const auto writes = process_write_syscalls();
    const auto cpu = std::clock();
    measure("event-loop worker completions", operations,
            [&loop] { (void)loop.run(); });
    const auto cpu_seconds =
        static_cast<double>(std::clock() - cpu) / CLOCKS_PER_SEC;
    std::cout << "  wake writes per completion "
              << static_cast<double>(process_write_syscalls() - writes) /
                     static_cast<double>(operations)
              << ", process CPU per completion "
              << cpu_seconds * 1e9 / static_cast<double>(operations)
              << " ns\n";
}

auto clock_observations() -> void
{
    using clock = std::chrono::steady_clock;
    constexpr std::size_t reads = 100'000;
    auto minimum_step = clock::duration::max();
    std::size_t equal_reads = 0;
    std::size_t backwards_reads = 0;
    auto previous = clock::now();
    for (std::size_t index = 0; index < reads; ++index) {
        const auto current = clock::now();
        const auto step = current - previous;
        if (step > clock::duration::zero()) {
            minimum_step = std::min(minimum_step, step);
        } else if (step == clock::duration::zero()) {
            ++equal_reads;
        } else {
            ++backwards_reads;
        }
        previous = current;
    }
    std::cout << "steady_clock: nominal tick "
              << std::chrono::duration<double, std::nano>(clock::duration(1)).count()
              << " ns, minimum observed positive step ";
    if (minimum_step == clock::duration::max()) {
        std::cout << "none";
    } else {
        std::cout << std::chrono::duration<double, std::nano>(minimum_step).count()
                  << " ns";
    }
    std::cout << ", equal consecutive reads " << equal_reads << '/' << reads
              << ", backwards reads " << backwards_reads
              << " (observed steps are not a resolution guarantee; zero latency"
                 " means equal clock readings)\n";
}

} // namespace

auto main() -> int
{
    construction();
    post_round_trip();
    cross_thread_post();
    cross_thread_burst();
    worker_completions();
    clock_observations();
    return 0;
}
