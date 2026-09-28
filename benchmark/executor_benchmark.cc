#include "eventloop/executor.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <thread>
#include <vector>

using namespace eventloop;

namespace {

constexpr std::size_t immediate_iterations = 20'000'000;
constexpr std::size_t handoff_iterations = 1'000'000;
constexpr std::size_t warmup_iterations = 10'000;

[[nodiscard]] auto worker_count() -> std::size_t
{
    const auto hardware = std::thread::hardware_concurrency();
    const auto available = hardware == 0 ? std::size_t {1}
                                         : static_cast<std::size_t>(hardware);
    return std::min(available, std::size_t {4});
}

template<typename Function>
auto measure(const char* name, std::size_t operations, Function&& function) -> void
{
    const auto start = std::chrono::steady_clock::now();
    function();
    const auto stop = std::chrono::steady_clock::now();
    const double seconds = std::chrono::duration<double>(stop - start).count();
    const double rate = static_cast<double>(operations) / seconds;
    std::cout << name << ": " << operations << " operations in " << seconds
              << " s (" << rate << " operations/s)\n";
}

auto submit(executor& target, std::atomic<std::size_t>& completed,
            std::size_t count) -> void
{
    for (std::size_t index = 0; index < count; ++index) {
        while (!target.execute(execution_task([&completed]() noexcept {
            completed.fetch_add(1, std::memory_order_relaxed);
        }))) {
            std::this_thread::yield();
        }
    }
}

auto wait_for(std::atomic<std::size_t>& completed, std::size_t expected) -> void
{
    while (completed.load(std::memory_order_relaxed) != expected) {
        std::this_thread::yield();
    }
}

auto warm_up(executor& target) -> void
{
    std::atomic<std::size_t> completed {0};
    submit(target, completed, warmup_iterations);
    wait_for(completed, warmup_iterations);
}

auto immediate_overhead() -> void
{
    auto target = make_single_thread_executor();
    std::size_t completed = 0;
    for (std::size_t index = 0; index < warmup_iterations; ++index) {
        target->execute(execution_task([&completed]() noexcept { ++completed; }));
    }

    measure("single-thread invoke", immediate_iterations, [&] {
        for (std::size_t index = 0; index < immediate_iterations; ++index) {
            target->execute(execution_task(
                [&completed]() noexcept { ++completed; }));
        }
    });
}

auto handoff_throughput() -> void
{
    auto target = make_multi_thread_executor(
        {.worker_count = 1, .queue_capacity = 4096});
    warm_up(*target);

    std::atomic<std::size_t> completed {0};
    measure("single-producer handoff", handoff_iterations, [&] {
        submit(*target, completed, handoff_iterations);
        wait_for(completed, handoff_iterations);
    });
}

auto contended_throughput() -> void
{
    const std::size_t producers = worker_count();
    const std::size_t per_producer = handoff_iterations / producers;
    const std::size_t total = per_producer * producers;
    auto target = make_multi_thread_executor(
        {.worker_count = worker_count(), .queue_capacity = 4096});
    warm_up(*target);

    std::atomic<std::size_t> completed {0};
    measure("multi-producer handoff", total, [&] {
        std::vector<std::thread> threads;
        threads.reserve(producers);
        for (std::size_t producer = 0; producer < producers; ++producer) {
            threads.emplace_back([&] {
                submit(*target, completed, per_producer);
            });
        }
        for (auto& thread : threads) thread.join();
        wait_for(completed, total);
    });
}

auto rejection_cost() -> void
{
    std::atomic<bool> started {false};
    std::atomic<bool> release {false};
    auto target =
        make_multi_thread_executor({.worker_count = 1, .queue_capacity = 2});
    target->execute(execution_task([&]() noexcept {
        started.store(true, std::memory_order_release);
        while (!release.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    }));
    while (!started.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    target->execute(execution_task([]() noexcept {}));
    target->execute(execution_task([]() noexcept {}));

    std::size_t rejected = 0;
    measure("queue-full rejection", immediate_iterations, [&] {
        for (std::size_t index = 0; index < immediate_iterations; ++index) {
            if (!target->execute(execution_task([]() noexcept {}))) ++rejected;
        }
    });
    release.store(true, std::memory_order_release);
    if (rejected != immediate_iterations) std::terminate();
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
