#include "eventloop/channel.h"
#include "eventloop/task.h"

#include <array>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <new>
#include <optional>
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
    std::cerr << "channel allocations: " << message << '\n';
    std::exit(1);
}

constexpr int transfers = 10000;

auto produce(event_loop&, channel<int>& messages) -> task<void>
{
    for (int value = 0; value < transfers; ++value)
        check((co_await messages.async_send(value)).has_value(), "send");
}

auto consume(event_loop&, channel<int>& messages) -> task<void>
{
    for (int expected = 0; expected < transfers; ++expected)
        check(co_await messages.async_receive() == expected, "ordered receive");
}

auto pending_send(event_loop&, channel<int>& messages, std::errc expected) -> task<void>
{
    auto result = co_await messages.async_send(1);
    check(!result && result.error() == expected, "pending send outcome");
}

auto pending_receive(event_loop&, channel<int>& messages, std::errc expected) -> task<void>
{
    auto result = co_await messages.async_receive();
    check(!result && result.error() == expected, "pending receive outcome");
}

auto measure(event_loop& loop, std::size_t& measured) -> task<void>
{
    const auto before = allocations.load();
    const auto frames = loop.coroutine_statistics();
    {
        std::array<std::optional<int>, 1> storage;
        channel<int> messages(loop, storage);
        task_handle<void> producer, consumer;
        check(loop.spawn(produce(loop, messages), producer) == task_spawn_result::accepted, "spawn producer");
        check(loop.spawn(consume(loop, messages), consumer) == task_spawn_result::accepted, "spawn consumer");
        check(co_await producer == task_result::success, "producer retires");
        check(co_await consumer == task_result::success, "consumer retires");
        messages.close();
    }
    // Give the loop a turn to release completed root frames before spawning
    // the next pair; a completed handle does not imply frame reclamation yet.
    (void)co_await yield(loop);
    for (bool cancel : {true, false}) {
        std::array<std::optional<int>, 1> send_storage, receive_storage;
        channel<int> outgoing(loop, send_storage), incoming(loop, receive_storage);
        task_handle<void> sender, receiver;
        const auto expected = cancel ? std::errc::operation_canceled : std::errc::broken_pipe;
        check(outgoing.try_send(0).has_value(), "fill buffer");
        check(loop.spawn(pending_send(loop, outgoing, expected), sender) == task_spawn_result::accepted, "spawn pending sender");
        check(loop.spawn(pending_receive(loop, incoming, expected), receiver) == task_spawn_result::accepted, "spawn pending receiver");
        if (cancel) {
            check(sender.cancel() && receiver.cancel(), "cancel waits");
        } else {
            outgoing.close();
            incoming.close();
        }
        check(co_await sender == task_result::success, "sender retires");
        check(co_await receiver == task_result::success, "receiver retires");
        (void)co_await yield(loop);
    }
    const auto after = loop.coroutine_statistics();
    check(after.high_watermark <= frames.live + 2, "channel creates no additional coroutine frames");
    check(after.backed_capacity == frames.backed_capacity, "measurement needed no pool growth");
    measured = allocations.load() - before;
    check(measured == 0, "int channel paths allocated");
    loop.stop();
}

} // namespace

auto main() -> int
{
    event_loop loop;
    std::size_t measured = 0;
    check(loop.spawn(measure(loop, measured)) == task_spawn_result::accepted, "spawn measurement");
    while (loop.run() == event_loop_result::interrupted) {}
    std::cout << transfers << " ordered transfers plus cancellation/close: "
              << measured << " heap allocations; no additional coroutine frames\n";
}
