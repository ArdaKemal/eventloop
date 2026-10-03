#include "eventloop/executor.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <new>
#include <thread>
#include <type_traits>
#include <utility>

#ifdef _MSC_VER
#include <malloc.h>
#endif

namespace {
std::atomic<std::size_t> allocations {0};
auto allocate(std::size_t size) -> void*
{
    allocations.fetch_add(1, std::memory_order_relaxed);
    if (auto* memory = std::malloc(size == 0 ? 1 : size)) return memory;
    throw std::bad_alloc {};
}
auto allocate_aligned(std::size_t size, std::size_t alignment) -> void*
{
    allocations.fetch_add(1, std::memory_order_relaxed);
#ifdef _MSC_VER
    auto* memory = _aligned_malloc(size == 0 ? 1 : size, alignment);
#else
    auto* memory = std::aligned_alloc(alignment,
        ((size == 0 ? 1 : size) + alignment - 1) / alignment * alignment);
#endif
    if (memory != nullptr) return memory;
    throw std::bad_alloc {};
}
auto free_aligned(void* memory) noexcept -> void
{
#ifdef _MSC_VER
    _aligned_free(memory);
#else
    std::free(memory);
#endif
}
} // namespace

auto operator new(std::size_t size) -> void* { return allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocate(size); }
auto operator new(std::size_t size, std::align_val_t alignment) -> void*
{ return allocate_aligned(size, static_cast<std::size_t>(alignment)); }
auto operator new[](std::size_t size, std::align_val_t alignment) -> void*
{ return allocate_aligned(size, static_cast<std::size_t>(alignment)); }
auto operator delete(void* memory) noexcept -> void { std::free(memory); }
auto operator delete[](void* memory) noexcept -> void { std::free(memory); }
auto operator delete(void* memory, std::size_t) noexcept -> void { std::free(memory); }
auto operator delete[](void* memory, std::size_t) noexcept -> void { std::free(memory); }
auto operator delete(void* memory, std::align_val_t) noexcept -> void { free_aligned(memory); }
auto operator delete[](void* memory, std::align_val_t) noexcept -> void { free_aligned(memory); }
auto operator delete(void* memory, std::size_t, std::align_val_t) noexcept -> void
{ free_aligned(memory); }
auto operator delete[](void* memory, std::size_t, std::align_val_t) noexcept -> void
{ free_aligned(memory); }

namespace {
using namespace eventloop;
struct exactly_full {
    std::array<std::byte, 64> storage;
    auto operator()() noexcept -> void {}
};
struct too_large {
    std::array<std::byte, 65> storage;
    auto operator()() noexcept -> void {}
};
struct too_aligned {
    alignas(64) std::byte storage;
    auto operator()() noexcept -> void {}
};
struct throwing_invocation { auto operator()() -> void {} };
struct throwing_move {
    throwing_move(throwing_move&&) noexcept(false);
    auto operator()() noexcept -> void {}
};
struct throwing_destructor {
    ~throwing_destructor() noexcept(false);
    auto operator()() noexcept -> void {}
};
static_assert(std::is_constructible_v<execution_task, exactly_full>);
static_assert(!std::is_constructible_v<execution_task, too_large>);
static_assert(!std::is_constructible_v<execution_task, too_aligned>);
static_assert(!std::is_constructible_v<execution_task, throwing_invocation>);
static_assert(!std::is_constructible_v<execution_task, throwing_move>);
static_assert(!std::is_constructible_v<execution_task, throwing_destructor>);
static_assert(std::is_nothrow_move_constructible_v<execution_task>);
static_assert(!std::is_copy_constructible_v<execution_task>);

struct counters { int moves {0}; int destructors {0}; int releases {0}; int calls {0}; };
struct tracked {
    counters* count;
    bool owns {true};
    explicit tracked(counters& state) noexcept : count(&state) {}
    tracked(const tracked&) = delete;
    tracked(tracked&& other) noexcept
        : count(other.count), owns(std::exchange(other.owns, false)) { ++count->moves; }
    ~tracked() noexcept
    {
        ++count->destructors;
        if (owns) ++count->releases;
    }
    auto operator()() noexcept -> void { ++count->calls; }
};

auto recursion(executor& executor_ref) -> bool
{
    std::array<int, 5> order {};
    std::size_t next = 0;
    bool accepted = true;
    accepted &= executor_ref.execute(execution_task([&]() noexcept {
        order[next++] = 1;
        accepted &= executor_ref.execute(execution_task([&]() noexcept {
            order[next++] = 2;
            accepted &= executor_ref.execute(execution_task([&]() noexcept { order[next++] = 3; }));
            order[next++] = 4;
        }));
        order[next++] = 5;
    }));
    return accepted && next == order.size() && order == std::array<int, 5> {1, 2, 3, 4, 5};
}

auto lifetime(executor& executor_ref) -> bool
{
    counters count;
    bool ok = true;
    {
        execution_task source {tracked(count)};
        execution_task destination(std::move(source));
        ok &= !source && destination && count.moves == 2 && count.destructors == 2;
        ok &= executor_ref.execute(std::move(destination));
        ok &= count.calls == 1 && count.moves == 2 && count.releases == 0;
        auto& alias = destination;
        destination = std::move(alias);
        ok &= static_cast<bool>(destination) && count.moves == 2;
        source = std::move(destination);
        ok &= source && !destination && count.moves == 3 && count.destructors == 3;
        source = execution_task {};
        ok &= !source && count.releases == 1 && count.destructors == 4;
    }
    return ok && count.destructors == 4 && count.releases == 1;
}

// Concurrent execute() calls share one executor. Each task, including nested
// submissions, must run exactly once on its own submitting thread, and the
// submissions themselves must not allocate.
auto concurrent(executor& executor_ref) -> bool
{
    constexpr std::size_t thread_count = 4;
    constexpr int iterations = 20000;
    struct result {
        int calls {0};
        bool ok {true};
    };
    std::array<result, thread_count> results {};
    std::atomic<std::size_t> ready {0};
    std::atomic<std::size_t> finished {0};
    std::atomic<bool> start {false};
    std::array<std::thread, thread_count> threads;
    for (std::size_t index = 0; index < thread_count; ++index) {
        threads[index] = std::thread([&, index] {
            auto& state = results[index];
            const auto self = std::this_thread::get_id();
            ready.fetch_add(1, std::memory_order_release);
            while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
            for (int iteration = 0; iteration < iterations; ++iteration) {
                const bool accepted = executor_ref.execute(execution_task(
                    [&executor_ref, &state, self]() noexcept {
                        state.ok &= std::this_thread::get_id() == self;
                        ++state.calls;
                        state.ok &= executor_ref.execute(execution_task(
                            [&state, self]() noexcept {
                                state.ok &= std::this_thread::get_id() == self;
                                ++state.calls;
                            }));
                    }));
                state.ok &= accepted;
            }
            finished.fetch_add(1, std::memory_order_release);
        });
    }
    while (ready.load(std::memory_order_acquire) != thread_count) std::this_thread::yield();
    const auto before = allocations.load(std::memory_order_relaxed);
    start.store(true, std::memory_order_release);
    while (finished.load(std::memory_order_acquire) != thread_count) std::this_thread::yield();
    const auto after = allocations.load(std::memory_order_relaxed);
    for (auto& thread : threads) thread.join();
    bool ok = after == before;
    for (const auto& state : results) ok &= state.ok && state.calls == 2 * iterations;
    return ok;
}
} // namespace

auto main() -> int
{
    // Factory, payload allocation, and thread identity initialization are setup.
    auto executor_owner = eventloop::make_single_thread_executor();
    auto payload = std::make_unique<int>(41);
    auto* raw = payload.get();
    const auto submitter = std::this_thread::get_id();
    auto invoked_on = submitter;
    bool completed = false;
    bool released = false;
    struct deleter {
        bool* released;
        auto operator()(int* value) const noexcept -> void { *released = true; delete value; }
    };
    std::unique_ptr<int, deleter> owned(payload.release(), {&released});
    const auto before = allocations.load(std::memory_order_relaxed);
    bool ok = true;
    {
        eventloop::execution_task empty;
        ok &= !executor_owner->execute(std::move(empty)) && !empty;
        eventloop::execution_task current([held = std::move(owned), &completed,
                                          &invoked_on]() noexcept {
            ++*held;
            invoked_on = std::this_thread::get_id();
            completed = true;
        });
        ok &= !owned && executor_owner->execute(std::move(current));
        ok &= completed && invoked_on == submitter && *raw == 42 && !released;
        ok &= recursion(*executor_owner) && lifetime(*executor_owner);
    }
    ok &= released && allocations.load(std::memory_order_relaxed) == before;
    if (!ok) std::cerr << "single-thread execution, lifetime, or allocation check failed\n";
    if (!concurrent(*executor_owner)) {
        std::cerr << "single-thread concurrent execution check failed\n";
        ok = false;
    }
    return ok ? 0 : 1;
}
