#include "eventloop/executor.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <thread>
#include <vector>

namespace {

[[nodiscard]] auto worker_count() -> std::size_t
{
    const auto hardware = std::thread::hardware_concurrency();
    return hardware == 0 ? std::size_t {1} : static_cast<std::size_t>(hardware);
}

template<typename Function>
auto measure(const char* name, Function&& function) -> void
{
    const auto start = std::chrono::steady_clock::now();
    const std::size_t operations = function();
    const auto stop = std::chrono::steady_clock::now();
    const double seconds = std::chrono::duration<double>(stop - start).count();
    const double rate = static_cast<double>(operations) / seconds;
    std::cout << name << ": " << operations << " operations in " << seconds
              << " s (" << rate << " operations/s)\n";
}

constexpr std::size_t iterations = 20'000;

auto immediate_overhead() -> void
{
    measure("single-thread invoke", []() -> std::size_t {
        auto executor = make_single_thread_executor();
        std::size_t count = 0;
        for (std::size_t index = 0; index < iterations; ++index) {
            executor->execute(execution_task([&count]() noexcept { ++count; }));
        }
        return count;
    });
}

auto handoff_throughput() -> void
{
    measure("single-producer handoff", []() -> std::size_t {
        auto executor = make_multi_thread_executor(
            {.worker_count = worker_count(), .queue_capacity = 4096});
        std::atomic<std::size_t> completed {0};
        std::size_t submitted = 0;
        while (submitted < iterations) {
            if (executor->execute(execution_task([&completed]() noexcept {
                    completed.fetch_add(1, std::memory_order_relaxed);
                }))) {
                ++submitted;
            }
        }
        while (completed.load(std::memory_order_acquire) < submitted) {
            std::this_thread::yield();
        }
        return submitted;
    });
}

auto contended_throughput() -> void
{
    measure("multi-producer handoff", []() -> std::size_t {
        auto executor = make_multi_thread_executor(
            {.worker_count = worker_count(), .queue_capacity = 4096});
        const std::size_t producers = worker_count();
        const std::size_t per_producer = iterations / producers;
        std::atomic<std::size_t> completed {0};
        std::vector<std::thread> threads;
        threads.reserve(producers);
        for (std::size_t producer = 0; producer < producers; ++producer) {
            threads.emplace_back([&executor, &completed, per_producer] {
                for (std::size_t index = 0; index < per_producer; ++index) {
                    while (!executor->execute(execution_task([&completed]() noexcept {
                        completed.fetch_add(1, std::memory_order_relaxed);
                    }))) {
                        std::this_thread::yield();
                    }
                }
            });
        }
        for (auto& thread : threads) thread.join();
        const std::size_t total = per_producer * producers;
        while (completed.load(std::memory_order_acquire) < total) {
            std::this_thread::yield();
        }
        return total;
    });
}

auto rejection_cost() -> void
{
    measure("queue-full rejection", []() -> std::size_t {
        std::atomic<bool> started {false};
        std::atomic<bool> release {false};
        auto executor =
            make_multi_thread_executor({.worker_count = 1, .queue_capacity = 2});
        executor->execute(execution_task([&]() noexcept {
            started.store(true, std::memory_order_release);
            while (!release.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
        }));
        while (!started.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        executor->execute(execution_task([]() noexcept {}));
        executor->execute(execution_task([]() noexcept {}));
        std::size_t rejected = 0;
        for (std::size_t index = 0; index < iterations; ++index) {
            if (!executor->execute(execution_task([]() noexcept {}))) ++rejected;
        }
        release.store(true, std::memory_order_release);
        return rejected;
    });
}

} // namespace

auto main() -> int
{
    immediate_overhead();
    handoff_throughput();
    contended_throughput();
    rejection_cost();
    return 0;
}
