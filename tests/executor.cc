#include "eventloop/executor.h"

#include "executor/bounded_task_queue.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <new>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace {
std::atomic<std::size_t> allocations {0};
}

auto operator new(std::size_t size) -> void*
{
    allocations.fetch_add(1, std::memory_order_relaxed);
    if (void* memory = std::malloc(size)) return memory;
    throw std::bad_alloc {};
}

auto operator new[](std::size_t size) -> void*
{
    allocations.fetch_add(1, std::memory_order_relaxed);
    if (void* memory = std::malloc(size)) return memory;
    throw std::bad_alloc {};
}

auto operator delete(void* memory) noexcept -> void { std::free(memory); }
auto operator delete[](void* memory) noexcept -> void { std::free(memory); }
auto operator delete(void* memory, std::size_t) noexcept -> void { std::free(memory); }
auto operator delete[](void* memory, std::size_t) noexcept -> void { std::free(memory); }

namespace {

auto check(bool condition, const char* name) -> bool
{
    if (!condition) {
        std::cerr << "FAILED: " << name << '\n';
    }
    return condition;
}

struct lifetime_callable {
    lifetime_callable() noexcept = default;
    explicit lifetime_callable(std::atomic<int>* counter) noexcept
        : counter_(counter)
    {
    }

    lifetime_callable(lifetime_callable&& other) noexcept
        : counter_(other.counter_)
    {
        other.counter_ = nullptr;
    }

    lifetime_callable(const lifetime_callable&) = delete;
    auto operator=(const lifetime_callable&) -> lifetime_callable& = delete;
    auto operator=(lifetime_callable&&) -> lifetime_callable& = delete;

    ~lifetime_callable()
    {
        if (counter_ != nullptr) {
            counter_->fetch_add(1, std::memory_order_relaxed);
        }
    }

    auto operator()() noexcept -> void {}

    std::atomic<int>* counter_ {nullptr};
};

struct large_callable {
    std::array<char, 128> payload {};
    auto operator()() const noexcept -> void {}
};

struct over_aligned_callable {
    alignas(32) char payload {};
    auto operator()() const noexcept -> void {}
};

struct throwing_callable {
    auto operator()() const -> void { throw 1; }
};

struct not_callable {};

static_assert(executor_detail::inline_callable<decltype([]() noexcept {})>);
static_assert(!executor_detail::inline_callable<large_callable>);
static_assert(!executor_detail::inline_callable<over_aligned_callable>);
static_assert(!executor_detail::inline_callable<throwing_callable>);
static_assert(!executor_detail::inline_callable<not_callable>);
static_assert(executor_detail::inline_callable<lifetime_callable>);
static_assert(std::is_nothrow_move_constructible_v<execution_task>);
static_assert(std::is_nothrow_destructible_v<execution_task>);
static_assert(!std::is_copy_constructible_v<execution_task>);
static_assert(!std::is_copy_assignable_v<execution_task>);
static_assert(std::is_constructible_v<
              execution_task,
              decltype([pointer = std::unique_ptr<int> {}]() noexcept {
                  (void)pointer;
              })>);

auto task_tests() -> bool
{
    bool ok = true;

    int value = 0;
    execution_task task([&value]() noexcept { value = 42; });
    ok &= check(static_cast<bool>(task), "task non-empty");
    task();
    ok &= check(value == 42, "task invocation");

    execution_task moved(std::move(task));
    ok &= check(!task, "moved-from task empty");
    ok &= check(static_cast<bool>(moved), "moved-to task non-empty");
    value = 0;
    moved();
    ok &= check(value == 42, "moved task invocation");

    auto owner = std::make_unique<int>(7);
    int* raw = owner.get();
    execution_task owning([pointer = std::move(owner)]() noexcept { *pointer += 1; });
    ok &= check(owner == nullptr, "unique_ptr captured");
    owning();
    ok &= check(*raw == 8, "unique_ptr capture invoked");

    std::atomic<int> destructions {0};
    {
        execution_task tracked(lifetime_callable {&destructions});
        execution_task transferred(std::move(tracked));
        ok &= check(destructions.load() == 0, "callable alive after move");
    }
    ok &= check(destructions.load() == 1, "callable destroyed exactly once");

    std::atomic<int> first {0};
    std::atomic<int> second {0};
    execution_task target(lifetime_callable {&first});
    execution_task other(lifetime_callable {&second});
    target = std::move(other);
    ok &= check(first.load() == 1, "move assignment destroys old callable");
    ok &= check(second.load() == 0, "move assignment keeps new callable");
    target = execution_task {};
    ok &= check(second.load() == 1, "moving empty destroys held callable");
    ok &= check(!target, "target empty after empty move assignment");

    auto pointer = std::make_unique<int>(5);
    const auto before = allocations.load(std::memory_order_relaxed);
    execution_task allocation_free(
        [held = std::move(pointer)]() noexcept { ++*held; });
    execution_task allocation_free_moved(std::move(allocation_free));
    allocation_free_moved();
    const auto after = allocations.load(std::memory_order_relaxed);
    ok &= check(before == after, "task operations do not allocate");

    return ok;
}

auto single_thread_tests() -> bool
{
    bool ok = true;
    auto executor = make_single_thread_executor();
    const auto submitter = std::this_thread::get_id();

    bool ran = false;
    std::thread::id observed;
    const bool accepted = executor->execute(execution_task([&]() noexcept {
        ran = true;
        observed = std::this_thread::get_id();
    }));
    ok &= check(accepted, "single-thread accepted");
    ok &= check(ran, "single-thread runs before return");
    ok &= check(observed == submitter, "single-thread uses submitting thread");

    int nested = 0;
    executor->execute(execution_task([&]() noexcept {
        executor->execute(execution_task([&nested]() noexcept { nested = 1; }));
    }));
    ok &= check(nested == 1, "single-thread nested execution");

    auto owner = std::make_unique<int>(11);
    int observed_value = 0;
    executor->execute(execution_task(
        [pointer = std::move(owner), &observed_value]() noexcept {
            observed_value = *pointer;
        }));
    ok &= check(observed_value == 11, "single-thread move-only capture");

    return ok;
}

auto queue_tests() -> bool
{
    bool ok = true;

    {
        bounded_task_queue queue(4);
        std::vector<int> order;
        for (int index = 0; index < 4; ++index) {
            ok &= check(queue.try_push(execution_task(
                            [&order, index]() noexcept { order.push_back(index); })),
                        "queue push");
        }
        execution_task output;
        for (int index = 0; index < 4; ++index) {
            ok &= check(queue.try_pop(output), "queue pop");
            output();
        }
        ok &= check(order == std::vector<int>({0, 1, 2, 3}), "queue FIFO");
    }

    {
        bounded_task_queue queue(2);
        execution_task first([]() noexcept {});
        execution_task second([]() noexcept {});
        execution_task third([]() noexcept {});
        ok &= check(queue.try_push(std::move(first)), "queue push first");
        ok &= check(queue.try_push(std::move(second)), "queue push second");
        ok &= check(!queue.try_push(std::move(third)), "queue full rejected");
        ok &= check(static_cast<bool>(third), "failed push keeps input");

        execution_task output;
        ok &= check(queue.try_pop(output), "queue pop first");
        ok &= check(queue.try_pop(output), "queue pop second");
        ok &= check(!queue.try_pop(output), "queue empty rejected");
        ok &= check(queue.try_push(std::move(third)), "queue reuse after pop");
    }

    {
        bounded_task_queue queue(2);
        execution_task output;
        int count = 0;
        for (int index = 0; index < 100; ++index) {
            ok &= check(queue.try_push(execution_task(
                            [&count]() noexcept { ++count; })),
                        "wrap push");
            ok &= check(queue.try_pop(output), "wrap pop");
            output();
        }
        ok &= check(count == 100, "wrap count");
    }

    {
        std::atomic<int> destroyed {0};
        bounded_task_queue queue(4);
        ok &= check(queue.try_push(execution_task(lifetime_callable {&destroyed})),
                    "destruction push");
        ok &= check(destroyed.load() == 0, "callable alive in queue");
        {
            execution_task output;
            ok &= check(queue.try_pop(output), "destruction pop");
            ok &= check(destroyed.load() == 0, "callable alive after pop");
        }
        ok &= check(destroyed.load() == 1, "callable destroyed with popped task");
    }

    {
        std::atomic<int> destroyed {0};
        {
            bounded_task_queue queue(4);
            queue.try_push(execution_task(lifetime_callable {&destroyed}));
            queue.try_push(execution_task(lifetime_callable {&destroyed}));
            ok &= check(destroyed.load() == 0, "callables alive before queue drop");
        }
        ok &= check(destroyed.load() == 2, "queue destruction destroys callables");
    }

    {
        constexpr int producer_count = 4;
        constexpr int tasks_per_producer = 1000;
        constexpr int consumer_count = 4;
        constexpr int total = producer_count * tasks_per_producer;

        bounded_task_queue queue(64);
        std::unique_ptr<std::atomic<int>[]> seen =
            std::make_unique<std::atomic<int>[]>(static_cast<std::size_t>(total));
        std::atomic<int> executed {0};
        std::atomic<bool> producers_done {false};

        std::vector<std::thread> producers;
        for (int producer = 0; producer < producer_count; ++producer) {
            producers.emplace_back([&, producer] {
                for (int index = 0; index < tasks_per_producer; ++index) {
                    const int id = producer * tasks_per_producer + index;
                    while (!queue.try_push(execution_task(
                        [&seen, &executed, id]() noexcept {
                            seen[static_cast<std::size_t>(id)].fetch_add(
                                1, std::memory_order_relaxed);
                            executed.fetch_add(1, std::memory_order_relaxed);
                        }))) {
                        std::this_thread::yield();
                    }
                }
            });
        }

        std::vector<std::thread> consumers;
        for (int consumer = 0; consumer < consumer_count; ++consumer) {
            consumers.emplace_back([&] {
                execution_task output;
                for (;;) {
                    if (queue.try_pop(output)) {
                        output();
                        continue;
                    }
                    if (producers_done.load(std::memory_order_acquire)) return;
                    std::this_thread::yield();
                }
            });
        }

        for (auto& producer : producers) producer.join();
        producers_done.store(true, std::memory_order_release);
        for (auto& consumer : consumers) consumer.join();

        bool unique = true;
        for (int index = 0; index < total; ++index) {
            if (seen[static_cast<std::size_t>(index)].load() != 1) unique = false;
        }
        ok &= check(executed.load() == total, "queue stress executes all tasks");
        ok &= check(unique, "queue stress executes each task once");
    }

    return ok;
}

auto multi_thread_tests() -> bool
{
    bool ok = true;

    {
        const auto submitter = std::this_thread::get_id();
        std::atomic<int> count {0};
        std::atomic<bool> on_worker {false};
        {
            auto executor = make_multi_thread_executor({.worker_count = 2});
            for (int index = 0; index < 100; ++index) {
                ok &= check(executor->execute(execution_task([&]() noexcept {
                                count.fetch_add(1, std::memory_order_relaxed);
                                if (std::this_thread::get_id() != submitter) {
                                    on_worker.store(true, std::memory_order_relaxed);
                                }
                            })),
                            "multi-thread accepted");
            }
        }
        ok &= check(count.load() == 100, "multi-thread executes accepted tasks once");
        ok &= check(on_worker.load(), "multi-thread runs on worker");
    }

    {
        std::atomic<int> count {0};
        {
            auto executor = make_multi_thread_executor(
                {.worker_count = 4, .queue_capacity = 1024});
            std::vector<std::thread> submitters;
            for (int submitter = 0; submitter < 4; ++submitter) {
                submitters.emplace_back([&] {
                    for (int index = 0; index < 500; ++index) {
                        while (!executor->execute(execution_task([&count]() noexcept {
                            count.fetch_add(1, std::memory_order_relaxed);
                        }))) {
                            std::this_thread::yield();
                        }
                    }
                });
            }
            for (auto& submitter : submitters) submitter.join();
        }
        ok &= check(count.load() == 2000, "multi-thread multiple submitters");
    }

    {
        std::atomic<bool> started {false};
        std::atomic<bool> release {false};
        auto executor =
            make_multi_thread_executor({.worker_count = 1, .queue_capacity = 2});
        ok &= check(executor->execute(execution_task([&]() noexcept {
                        started.store(true, std::memory_order_release);
                        while (!release.load(std::memory_order_acquire)) {
                            std::this_thread::yield();
                        }
                    })),
                    "saturation blocking task accepted");
        while (!started.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        ok &= check(executor->execute(execution_task([]() noexcept {})),
                    "saturation fill one");
        ok &= check(executor->execute(execution_task([]() noexcept {})),
                    "saturation fill two");
        ok &= check(!executor->execute(execution_task([]() noexcept {})),
                    "saturation rejects without waiting");
        release.store(true, std::memory_order_release);
    }

    {
        const std::array<std::size_t, 4> capacities {0, 1, 3, 6};
        bool threw = false;
        try {
            make_multi_thread_executor({.worker_count = 0});
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        ok &= check(threw, "reject zero workers");
        for (const std::size_t capacity : capacities) {
            threw = false;
            try {
                make_multi_thread_executor(
                    {.worker_count = 1, .queue_capacity = capacity});
            } catch (const std::invalid_argument&) {
                threw = true;
            }
            ok &= check(threw, "reject invalid queue capacity");
        }
    }

    {
        std::atomic<bool> started {false};
        std::atomic<bool> release {false};
        std::atomic<int> destroyed {0};
        {
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
            ok &= check(executor->execute(execution_task(lifetime_callable {&destroyed})),
                        "ownership queue push one");
            ok &= check(executor->execute(execution_task(lifetime_callable {&destroyed})),
                        "ownership queue push two");
            execution_task rejected(lifetime_callable {&destroyed});
            ok &= check(!executor->execute(std::move(rejected)),
                        "ownership rejected when full");
            ok &= check(static_cast<bool>(rejected), "rejected task retains ownership");
            ok &= check(destroyed.load() == 0, "rejected task alive before fallback");
            release.store(true, std::memory_order_release);
        }
        ok &= check(destroyed.load() == 3, "queued and rejected callables destroyed once");
    }

    return ok;
}

} // namespace

auto main() -> int
{
    if (!task_tests() || !single_thread_tests() || !queue_tests() ||
        !multi_thread_tests()) {
        std::cerr << "executor tests failed\n";
        return 1;
    }
    return 0;
}
