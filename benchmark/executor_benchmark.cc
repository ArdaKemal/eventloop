#include "eventloop/executor.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string_view>
#include <thread>
#include <vector>

using namespace eventloop;

namespace {

constexpr std::size_t immediate_iterations = 20'000'000;
constexpr std::size_t handoff_iterations = 5'000'000;
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

auto rejection_cost(std::size_t capacity = 2,
                    const char* name = "queue-full rejection") -> void
{
    std::atomic<bool> started {false};
    std::atomic<bool> release {false};
    auto target =
        make_multi_thread_executor({.worker_count = 1, .queue_capacity = capacity});
    target->execute(execution_task([&]() noexcept {
        started.store(true, std::memory_order_release);
        while (!release.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    }));
    while (!started.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    for (std::size_t slot = 0; slot < capacity; ++slot) {
        if (!target->execute(execution_task([]() noexcept {}))) std::terminate();
    }

    std::size_t rejected = 0;
    measure(name, immediate_iterations, [&] {
        for (std::size_t index = 0; index < immediate_iterations; ++index) {
            if (!target->execute(execution_task([]() noexcept {}))) ++rejected;
        }
    });
    release.store(true, std::memory_order_release);
    if (rejected != immediate_iterations) std::terminate();
}

[[nodiscard]] auto calculate(std::size_t id, std::size_t iterations) noexcept
    -> std::uint64_t
{
    auto value = static_cast<std::uint64_t>(id) + 0x9e3779b97f4a7c15ULL;
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
    }
    return value;
}

auto worker_fanout(bool mixed) -> void
{
    const auto parents = worker_count();
    constexpr std::size_t children = 65536;
    const auto total = parents * children;
    auto results = std::make_unique<std::uint64_t[]>(total);
    auto target = make_multi_thread_executor(
        {.worker_count = parents, .queue_capacity = 4096});
    warm_up(*target);
    std::atomic<std::size_t> completed {0};
    std::atomic<std::size_t> parents_done {0};
    measure(mixed ? "mixed-work worker fanout" : "fine-task worker fanout", total, [&] {
        for (std::size_t parent = 0; parent < parents; ++parent) {
            execution_task root([&, parent]() noexcept {
                for (std::size_t child = 0; child < children; ++child) {
                    const auto id = parent * children + child;
                    execution_task task([&, id]() noexcept {
                        const auto iterations = mixed ? (id % 32 == 0 ? 8192U : 64U) : 0U;
                        results[id] = calculate(id, iterations);
                        completed.fetch_add(1, std::memory_order_release);
                    });
                    // A bounded executor can reject nested work. Execute the
                    // retained task inline rather than park all parent workers.
                    if (!target->execute(std::move(task))) task();
                }
                parents_done.fetch_add(1, std::memory_order_release);
            });
            while (!target->execute(std::move(root))) std::this_thread::yield();
        }
        while (completed.load(std::memory_order_acquire) != total ||
               parents_done.load(std::memory_order_acquire) != parents) {
            std::this_thread::yield();
        }
    });
    for (std::size_t id = 0; id < total; ++id) {
        const auto iterations = mixed ? (id % 32 == 0 ? 8192U : 64U) : 0U;
        if (results[id] != calculate(id, iterations)) std::terminate();
    }
}

struct publication_gate {
    std::atomic<bool> armed {false};
    std::atomic<bool> entered {false};
    std::atomic<bool> released {false};
};

struct paused_publication {
    publication_gate* gate;

    explicit paused_publication(publication_gate& input) noexcept : gate(&input) {}
    paused_publication(paused_publication&& other) noexcept : gate(other.gate)
    {
        if (gate->armed.exchange(false, std::memory_order_acq_rel)) {
            gate->entered.store(true, std::memory_order_release);
            while (!gate->released.load(std::memory_order_acquire)) {
                gate->released.wait(false, std::memory_order_acquire);
            }
        }
    }
    auto operator()() noexcept -> void {}
};

auto stalled_publisher_latency() -> void
{
    auto target = make_multi_thread_executor({.worker_count = 1, .queue_capacity = 2});
    publication_gate gate;
    execution_task paused(paused_publication {gate});
    gate.armed.store(true, std::memory_order_release);
    std::thread producer([&] {
        if (!target->execute(std::move(paused))) std::terminate();
    });
    while (!gate.entered.load(std::memory_order_acquire)) std::this_thread::yield();
    const auto start = std::chrono::steady_clock::now();
    std::atomic<std::int64_t> elapsed {0};
    if (!target->execute(execution_task([&]() noexcept {
            elapsed.store(std::chrono::duration_cast<std::chrono::nanoseconds>(
                              std::chrono::steady_clock::now() - start).count(),
                          std::memory_order_release);
        }))) std::terminate();
    std::this_thread::sleep_for(std::chrono::milliseconds {100});
    gate.released.store(true, std::memory_order_release);
    gate.released.notify_all();
    producer.join();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {2};
    while (elapsed.load(std::memory_order_acquire) == 0) {
        if (std::chrono::steady_clock::now() >= deadline) std::abort();
        std::this_thread::yield();
    }
    std::cout << "stalled-publisher later-task latency: "
              << static_cast<double>(elapsed.load()) / 1000.0 << " us\n";
}

} // namespace

auto main(int argc, char** argv) -> int
{
    if (argc > 2) return 2;
    const std::string_view selected = argc == 2 ? argv[1] : "all";
    bool matched = false;
    const auto run = [&](std::string_view name, auto function) {
        if (selected == "all" || selected == name) { function(); matched = true; }
    };
    run("inline", immediate_overhead);
    run("handoff", handoff_throughput);
    run("contended", contended_throughput);
    run("rejection", [] {
        rejection_cost();
        rejection_cost(4096, "queue-full rejection (capacity 4096)");
    });
    run("fine", [] { worker_fanout(false); });
    run("mixed", [] { worker_fanout(true); });
    run("progress", stalled_publisher_latency);
    return matched ? 0 : 2;
}
