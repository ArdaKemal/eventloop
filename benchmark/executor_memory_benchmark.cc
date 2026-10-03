// Standalone public-API probe; see docs/executor-performance.md for commands.
// Counts C++ allocation requests, excluding allocator overhead and OS stacks.
#include "eventloop/executor.h"

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <new>

#ifdef _WIN32
#include <malloc.h>
#endif

namespace {
std::atomic<std::size_t> bytes {0};
std::atomic<std::size_t> allocations {0};
}

auto operator new(std::size_t size) -> void*
{
    bytes.fetch_add(size);
    allocations.fetch_add(1);
    if (auto* memory = std::malloc(size)) return memory;
    throw std::bad_alloc {};
}
auto operator new[](std::size_t size) -> void* { return ::operator new(size); }
auto operator delete(void* memory) noexcept -> void { std::free(memory); }
auto operator delete[](void* memory) noexcept -> void { std::free(memory); }
auto operator delete(void* memory, std::size_t) noexcept -> void { std::free(memory); }
auto operator delete[](void* memory, std::size_t) noexcept -> void { std::free(memory); }

auto operator new(std::size_t size, std::align_val_t alignment) -> void*
{
    bytes.fetch_add(size);
    allocations.fetch_add(1);
    const auto align = static_cast<std::size_t>(alignment);
#ifdef _WIN32
    auto* memory = _aligned_malloc(size, align);
#else
    auto* memory = std::aligned_alloc(align, ((size + align - 1) / align) * align);
#endif
    if (memory) return memory;
    throw std::bad_alloc {};
}
auto operator new[](std::size_t size, std::align_val_t alignment) -> void*
{
    return ::operator new(size, alignment);
}
auto operator delete(void* memory, std::align_val_t) noexcept -> void
{
#ifdef _WIN32
    _aligned_free(memory);
#else
    std::free(memory);
#endif
}
auto operator delete[](void* memory, std::align_val_t alignment) noexcept -> void
{
    ::operator delete(memory, alignment);
}
auto operator delete(void* memory, std::size_t, std::align_val_t alignment) noexcept -> void
{
    ::operator delete(memory, alignment);
}
auto operator delete[](void* memory, std::size_t, std::align_val_t alignment) noexcept -> void
{
    ::operator delete(memory, alignment);
}

auto main() -> int
{
    const auto before_bytes = bytes.load();
    const auto before_allocations = allocations.load();
    auto target = eventloop::make_multi_thread_executor(
        {.worker_count = 4, .queue_capacity = 4096});
    const auto construction_bytes = bytes.load() - before_bytes;
    const auto construction_allocations = allocations.load() - before_allocations;
    target.reset();
    std::cout << construction_bytes << " bytes in " << construction_allocations
              << " C++ allocation requests\n";
}
