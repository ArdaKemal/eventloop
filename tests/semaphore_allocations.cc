#include "eventloop/semaphore.h"
#include "eventloop/task.h"

#include <array>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <new>
#include <string_view>

#ifdef _WIN32
#include <malloc.h>
#endif

namespace {
std::atomic<std::size_t> allocations {0};
}

auto operator new(std::size_t size) -> void*
{
    allocations.fetch_add(1, std::memory_order_relaxed);
    if (auto* pointer = std::malloc(size == 0 ? 1 : size)) return pointer;
    throw std::bad_alloc();
}
auto operator new[](std::size_t size) -> void* { return operator new(size); }
auto operator new(std::size_t size, std::align_val_t alignment) -> void*
{
    allocations.fetch_add(1, std::memory_order_relaxed);
#ifdef _WIN32
    if (auto* pointer = _aligned_malloc(size == 0 ? 1 : size, static_cast<std::size_t>(alignment)))
        return pointer;
#else
    void* pointer = nullptr;
    if (posix_memalign(&pointer, static_cast<std::size_t>(alignment), size == 0 ? 1 : size) == 0)
        return pointer;
#endif
    throw std::bad_alloc();
}
auto operator new[](std::size_t size, std::align_val_t alignment) -> void*
{
    return operator new(size, alignment);
}
auto operator new(std::size_t size, const std::nothrow_t&) noexcept -> void*
{
    try { return operator new(size); } catch (...) { return nullptr; }
}
auto operator new[](std::size_t size, const std::nothrow_t& tag) noexcept -> void*
{
    return operator new(size, tag);
}
auto operator new(std::size_t size, std::align_val_t alignment, const std::nothrow_t&) noexcept -> void*
{
    try { return operator new(size, alignment); } catch (...) { return nullptr; }
}
auto operator new[](std::size_t size, std::align_val_t alignment, const std::nothrow_t& tag) noexcept -> void*
{
    return operator new(size, alignment, tag);
}
auto operator delete(void* pointer) noexcept -> void { std::free(pointer); }
auto operator delete[](void* pointer) noexcept -> void { std::free(pointer); }
auto operator delete(void* pointer, std::size_t) noexcept -> void { std::free(pointer); }
auto operator delete[](void* pointer, std::size_t) noexcept -> void { std::free(pointer); }
auto operator delete(void* pointer, std::align_val_t) noexcept -> void
{
#ifdef _WIN32
    _aligned_free(pointer);
#else
    std::free(pointer);
#endif
}
auto operator delete[](void* pointer, std::align_val_t alignment) noexcept -> void
{
    operator delete(pointer, alignment);
}
auto operator delete(void* pointer, std::size_t, std::align_val_t alignment) noexcept -> void
{
    operator delete(pointer, alignment);
}
auto operator delete[](void* pointer, std::size_t, std::align_val_t alignment) noexcept -> void
{
    operator delete(pointer, alignment);
}
auto operator delete(void* pointer, const std::nothrow_t&) noexcept -> void { std::free(pointer); }
auto operator delete[](void* pointer, const std::nothrow_t&) noexcept -> void { std::free(pointer); }
auto operator delete(void* pointer, std::align_val_t alignment, const std::nothrow_t&) noexcept -> void
{
    operator delete(pointer, alignment);
}
auto operator delete[](void* pointer, std::align_val_t alignment, const std::nothrow_t&) noexcept -> void
{
    operator delete(pointer, alignment);
}

using namespace eventloop;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "semaphore allocations: " << message << '\n';
    std::exit(1);
}

constexpr std::size_t workers = 5;
constexpr int per_worker = 2000;

auto worker(event_loop& loop, semaphore& slots, int& completed) -> task<void>
{
    for (int operation = 0; operation < per_worker; ++operation) {
        auto held = co_await slots.async_acquire();
        check(held.has_value(), "worker acquisition");
        check(co_await yield(loop), "worker suspension");
        ++completed;
    }
}

auto pending(event_loop&, semaphore& slots) -> task<void>
{
    auto held = co_await slots.async_acquire();
    check(!held && held.error() == std::errc::operation_canceled, "pending cancellation");
}

auto measure(event_loop& loop, std::size_t& measured) -> task<void>
{
    const auto before = allocations.load();
    const auto frames = loop.coroutine_statistics();
    {
        semaphore slots(loop, 2);
        int completed = 0;
        std::array<task_handle<void>, workers> operations;
        for (auto& operation : operations)
            check(loop.spawn(worker(loop, slots, completed), operation) == task_spawn_result::accepted, "spawn worker");
        for (auto& operation : operations)
            check(co_await operation == task_result::success, "worker retires");
        check(completed == static_cast<int>(workers) * per_worker, "all operations completed");
        check(slots.available() == slots.capacity(), "all permits returned");
    }
    // Completed roots are reclaimed on the next loop turn, before more spawn.
    check(co_await yield(loop), "retire completed roots");
    {
        semaphore slots(loop, 1);
        auto held = slots.try_acquire();
        check(held.has_value(), "hold before cancellation");
        std::array<task_handle<void>, 3> waiting;
        for (auto& operation : waiting)
            check(loop.spawn(pending(loop, slots), operation) == task_spawn_result::accepted, "spawn pending operation");
        for (auto& operation : waiting) check(operation.cancel(), "cancel pending operation");
        held->release();
        for (auto& operation : waiting)
            check(co_await operation == task_result::success, "cancelled operation retires");
        check(slots.available() == 1, "cancelled operations consumed no permits");
    }
    check(co_await yield(loop), "retire cancelled roots");
    const auto after = loop.coroutine_statistics();
    check(after.high_watermark <= frames.live + workers, "no additional coroutine frames");
    check(after.backed_capacity == frames.backed_capacity, "no pool growth");
    measured = allocations.load() - before;
    check(measured == 0, "semaphore paths allocated");
    loop.stop();
}

} // namespace

auto main() -> int
{
    event_loop loop;
    std::size_t measured = 0;
    check(loop.spawn(measure(loop, measured)) == task_spawn_result::accepted, "spawn measurement");
    while (loop.run() == event_loop_result::interrupted) {}
    std::cout << workers * per_worker << " contended acquisitions plus cancellation: "
              << measured << " heap allocations; no additional coroutine frames\n";
}
