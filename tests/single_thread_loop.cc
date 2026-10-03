#include "eventloop/event_loop.h"
#include "eventloop/task.h"
#include "eventloop/udp_socket.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <memory>
#include <system_error>
#include <utility>

namespace {
using namespace eventloop;
using namespace std::chrono_literals;

auto wake_at(event_loop& loop, event_loop::clock::time_point deadline,
             std::size_t& completed, std::size_t target) -> task<void>
{
    if (co_await sleep_until(loop, deadline) != timer_wait_result::expired)
        co_return;
    if (++completed == target) loop.stop();
}

auto timer_budget() -> bool
{
    event_loop_options options;
    options.worker_count = 0;
    options.coroutine_frame_capacities.fill(256);
    options.coroutine_frame_initial_capacities = options.coroutine_frame_capacities;
    event_loop loop(options);
    constexpr std::size_t count = 160; // More than two due-timer dispatch batches.
    std::size_t completed = 0;
    const auto deadline = event_loop::clock::now() + 20ms;
    for (std::size_t index = 0; index < count; ++index) {
        if (loop.spawn(wake_at(loop, deadline, completed, count)) != task_spawn_result::accepted)
            std::terminate();
    }
    return loop.run() == event_loop_result::stopped && completed == count &&
           loop.coroutine_statistics().live == 0;
}

auto observed_timer(event_loop& loop, event_loop::clock::time_point deadline,
                    timer_wait_result& result) -> task<void>
{
    result = co_await sleep_until(loop, deadline);
}

auto cancellation_rearm() -> bool
{
    event_loop loop;
    task_handle<void> head;
    task_handle<void> middle;
    task_handle<void> tail;
    task_handle<void> last;
    auto head_result = timer_wait_result::expired;
    auto middle_result = timer_wait_result::expired;
    auto tail_result = timer_wait_result::expired;
    auto last_result = timer_wait_result::expired;
    std::size_t completed = 0;
    const auto now = event_loop::clock::now();
    // Insert out of order so the new-head and non-head cases are both used.
    if (loop.spawn(observed_timer(loop, now + 1h, middle_result), middle) != task_spawn_result::accepted ||
        loop.spawn(observed_timer(loop, now + 2h, tail_result), tail) != task_spawn_result::accepted ||
        loop.spawn(observed_timer(loop, now + 50ms, head_result), head) != task_spawn_result::accepted ||
        loop.spawn(wake_at(loop, now + 100ms, completed, 1)) != task_spawn_result::accepted)
        std::terminate();
    bool ok = middle.cancel() && middle.done() && middle_result == timer_wait_result::cancelled;
    ok &= tail.cancel() && tail.done() && tail_result == timer_wait_result::cancelled;
    ok &= head.cancel() && head.done() && head_result == timer_wait_result::cancelled;
    // No further registration before run: cancelling the head must rearm the
    // surviving timer, while cancelling the other entries preserves it.
    ok &= loop.run() == event_loop_result::stopped && completed == 1;
    if (loop.spawn(observed_timer(loop, event_loop::clock::now() + 1h, last_result), last) !=
        task_spawn_result::accepted) std::terminate();
    ok &= last.cancel() && last.done() && last_result == timer_wait_result::cancelled;
    // Cancelling the final head disarms the poller. New timers must arm it
    // again; running twice also exercises reuse after an expiry and stop.
    for (std::size_t target = 2; target <= 3; ++target) {
        if (loop.spawn(wake_at(loop, event_loop::clock::now() + 1ms, completed, target)) !=
            task_spawn_result::accepted) std::terminate();
        ok &= loop.run() == event_loop_result::stopped && completed == target;
    }
    return ok && loop.coroutine_statistics().active_roots == 0;
}

struct progress {
    event_loop& loop;
    std::size_t posts {0};
    std::size_t timers {0};
    std::size_t roots {0};
    bool valid {true};
    bool io {false};
    bool expired {false};
    auto fail() -> void { valid = false; loop.shutdown(0s); }
    auto post() noexcept -> void
    {
        ++posts;
        if (!valid || (roots == 3 && io)) { loop.stop(); return; }
        if (!loop.post(execution_task([this]() noexcept { post(); }))) std::terminate();
    }
};

auto concurrent_timers(event_loop& loop, progress& state) -> task<void>
{
    for (int index = 0; index < 32; ++index) {
        if (co_await sleep_for(loop, 50us) != timer_wait_result::expired) co_return;
        ++state.timers;
    }
    ++state.roots;
}

using message = std::array<std::byte, 64>;
auto echo_once(event_loop&, udp_socket& socket, progress& state) -> task<void>
{
    message buffer {};
    const auto received = co_await socket.async_receive_from(buffer);
    if (!received || received->size != buffer.size()) { state.fail(); co_return; }
    const auto sent = co_await socket.async_send_to(buffer, received->source);
    if (!sent || *sent != buffer.size()) { state.fail(); co_return; }
    ++state.roots;
}

auto send_once(event_loop& loop, udp_socket& socket, ip_endpoint destination,
               progress& state) -> task<void>
{
    if (co_await sleep_for(loop, 100us) != timer_wait_result::expired) co_return;
    message sent {};
    message received {};
    sent.fill(std::byte {0x5a});
    const auto size = co_await socket.async_send_to(sent, destination);
    if (!size || *size != sent.size()) { state.fail(); co_return; }
    const auto reply = co_await socket.async_receive_from(received);
    if (!reply || reply->size != received.size() || received != sent) {
        state.fail();
        co_return;
    }
    state.io = true;
    ++state.roots;
}

auto watchdog(event_loop& loop, progress& state) -> task<void>
{
    if (co_await sleep_for(loop, 2s) == timer_wait_result::expired) {
        state.expired = true;
        state.fail();
    }
}

auto io_timer_post_progress() -> bool
{
    event_loop_options options;
    options.worker_count = 0;
    options.post_capacity = 8;
    event_loop loop(options);
    auto receiver = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto sender = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto* server = receiver.get();
    auto* client = sender.get();
    const auto destination = server->local_endpoint();
    loop.add(std::move(receiver));
    loop.add(std::move(sender));
    progress state {loop};
    task_handle<void> timeout;
    if (loop.spawn(echo_once(loop, *server, state)) != task_spawn_result::accepted ||
        loop.spawn(send_once(loop, *client, destination, state)) != task_spawn_result::accepted ||
        loop.spawn(concurrent_timers(loop, state)) != task_spawn_result::accepted ||
        loop.spawn(watchdog(loop, state), timeout) != task_spawn_result::accepted ||
        !loop.post(execution_task([&state]() noexcept { state.post(); })))
        std::terminate();
    const auto result = loop.run();
    const bool cancelled = timeout.done() || timeout.cancel();
    loop.stop();
    (void)loop.run(); // Retire the observed timer's completed root.
    return result == event_loop_result::stopped && state.valid && state.io &&
           !state.expired && state.roots == 3 && state.timers == 32 &&
           state.posts > 64 && cancelled && timeout.done() &&
           loop.coroutine_statistics().active_roots == 0;
}
} // namespace

auto main() -> int
{
    if (!timer_budget() || !cancellation_rearm() || !io_timer_post_progress()) {
        std::cerr << "single-thread timer rearm, cancellation, or progress check failed\n";
        return 1;
    }
    return 0;
}
