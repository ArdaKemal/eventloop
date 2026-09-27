#include "eventloop/udp_socket.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <exception>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>

using namespace std::chrono_literals;

namespace {

auto shutdown_after(event_loop& loop, std::chrono::seconds delay) -> task<void>
{
    if (co_await sleep_for(loop, delay) == timer_wait_result::expired) {
        loop.shutdown(event_loop::clock::duration::zero());
    }
}

auto add_socket(event_loop& loop) -> udp_socket*
{
    auto socket = std::make_unique<udp_socket>(loop, 0);
    auto* result = socket.get();
    loop.add(std::move(socket));
    return result;
}

auto receive_two(event_loop& loop, udp_socket& receiver,
                 udp_endpoint expected_source, bool& passed) -> task<void>
{
    std::array<std::byte, 3> buffer {};
    const auto first = co_await receiver.async_receive_from(buffer);
    const bool first_ok = first && first->size == buffer.size() &&
                          first->source.address == expected_source.address &&
                          first->source.port == expected_source.port &&
                          buffer == std::array<std::byte, 3> {
                              std::byte {'u'}, std::byte {'d'}, std::byte {'p'}};

    // This await starts after the first readiness notification. A later send
    // must wake the newly armed receive operation.
    const auto second = co_await receiver.async_receive_from(buffer);
    passed = first_ok && second && second->size == 0 &&
             second->source.address == expected_source.address &&
             second->source.port == expected_source.port;
    loop.stop();
}

auto send_two(event_loop& loop, udp_socket& sender,
              udp_endpoint destination, bool& passed) -> task<void>
{
    const std::array<std::byte, 3> payload {
        std::byte {'u'}, std::byte {'d'}, std::byte {'p'}};
    const auto first = co_await sender.async_send_to(payload, destination);
    if (!first || *first != payload.size()) {
        passed = false;
        loop.stop();
        co_return;
    }
    if (co_await sleep_for(loop, 10ms) != timer_wait_result::expired) {
        passed = false;
        loop.stop();
        co_return;
    }
    const auto second = co_await sender.async_send_to(
        std::span<const std::byte> {}, destination);
    passed = second && *second == 0;
    if (!passed) loop.stop();
}

auto roundtrip_and_rearm() -> bool
{
    event_loop loop;
    auto* receiver = add_socket(loop);
    auto* sender = add_socket(loop);
    const auto source = sender->local_endpoint();
    const auto destination = receiver->local_endpoint();
    bool received = false;
    bool sent = false;
    if (loop.spawn(receive_two(loop, *receiver, source, received)) !=
            task_spawn_result::accepted ||
        loop.spawn(send_two(loop, *sender, destination, sent)) !=
            task_spawn_result::accepted) {
        loop.shutdown(event_loop::clock::duration::zero());
        (void)loop.run();
        return false;
    }
    task_handle<void> watchdog;
    if (loop.spawn(shutdown_after(loop, 1s), watchdog) !=
        task_spawn_result::accepted) return false;
    const auto result = loop.run();
    if (!watchdog.done()) {
        (void)watchdog.cancel();
        loop.stop();
        (void)loop.run();
    }
    return result == event_loop_result::stopped && received && sent &&
           loop.coroutine_statistics().live == 0;
}

auto receive_truncated(event_loop& loop, udp_socket& receiver,
                       bool& passed) -> task<void>
{
    std::array<std::byte, 2> small {};
    const auto truncated = co_await receiver.async_receive_from(small);
    std::array<std::byte, 3> full {};
    const auto next = co_await receiver.async_receive_from(full);
    passed = !truncated && truncated.error().value() == EMSGSIZE &&
             next && next->size == full.size() &&
             full == std::array<std::byte, 3> {
                 std::byte {'o'}, std::byte {'k'}, std::byte {'!'}};
    loop.stop();
}

auto send_payload(event_loop&, udp_socket& sender, udp_endpoint destination,
                  bool& passed) -> task<void>
{
    const std::array<std::byte, 3> payload {
        std::byte {'o'}, std::byte {'k'}, std::byte {'!'}};
    const auto first = co_await sender.async_send_to(payload, destination);
    const auto second = co_await sender.async_send_to(payload, destination);
    passed = first && *first == payload.size() && second &&
             *second == payload.size();
}

auto truncated_receive() -> bool
{
    event_loop loop;
    auto* receiver = add_socket(loop);
    auto* sender = add_socket(loop);
    bool received = false;
    bool sent = false;
    if (loop.spawn(receive_truncated(loop, *receiver, received)) !=
            task_spawn_result::accepted ||
        loop.spawn(send_payload(loop, *sender, receiver->local_endpoint(), sent)) !=
            task_spawn_result::accepted) {
        loop.shutdown(event_loop::clock::duration::zero());
        (void)loop.run();
        return false;
    }
    task_handle<void> watchdog;
    if (loop.spawn(shutdown_after(loop, 1s), watchdog) !=
        task_spawn_result::accepted) return false;
    const auto result = loop.run();
    if (!watchdog.done()) {
        (void)watchdog.cancel();
        loop.stop();
        (void)loop.run();
    }
    return result == event_loop_result::stopped && received && sent &&
           loop.coroutine_statistics().live == 0;
}

auto pending_receive(event_loop&, udp_socket& socket, bool& cancelled)
    -> task<void>
{
    std::array<std::byte, 8> buffer {};
    const auto result = co_await socket.async_receive_from(buffer);
    cancelled = !result && result.error().value() == ECANCELED;
}

auto duplicate_receive(event_loop&, udp_socket& socket, bool& rejected)
    -> task<void>
{
    std::array<std::byte, 8> buffer {};
    const auto result = co_await socket.async_receive_from(buffer);
    rejected = !result && result.error().value() == EAGAIN;
}

auto send_when_cancelled(event_loop& loop, udp_socket& socket,
                         udp_endpoint destination, bool& cancelled)
    -> task<void>
{
    (void)co_await sleep_for(loop, 1h);
    const std::array<std::byte, 1> payload {std::byte {'x'}};
    const auto result = co_await socket.async_send_to(payload, destination);
    cancelled = !result && result.error().value() == ECANCELED;
}

auto duplicate_and_close() -> bool
{
    event_loop loop;
    auto* socket = add_socket(loop);
    const int descriptor = socket->descriptor();
    bool cancelled = false;
    bool rejected = false;
    if (loop.spawn(pending_receive(loop, *socket, cancelled)) !=
            task_spawn_result::accepted ||
        loop.spawn(duplicate_receive(loop, *socket, rejected)) !=
            task_spawn_result::accepted) {
        socket->close();
        return false;
    }
    socket->close();
    loop.stop();
    (void)loop.run();
    return cancelled && rejected && ::fcntl(descriptor, F_GETFD) == -1 &&
           errno == EBADF && loop.coroutine_statistics().live == 0;
}

auto shutdown_cancels_receive() -> bool
{
    event_loop loop;
    auto* socket = add_socket(loop);
    const int descriptor = socket->descriptor();
    bool receive_cancelled = false;
    bool send_cancelled = false;
    const auto destination = socket->local_endpoint();
    if (loop.spawn(pending_receive(loop, *socket, receive_cancelled)) !=
            task_spawn_result::accepted ||
        loop.spawn(send_when_cancelled(loop, *socket, destination,
                                       send_cancelled)) !=
            task_spawn_result::accepted) {
        loop.shutdown(event_loop::clock::duration::zero());
        (void)loop.run();
        return false;
    }
    loop.shutdown(event_loop::clock::duration::zero());
    const auto result = loop.run();
    return result == event_loop_result::stopped && receive_cancelled &&
           send_cancelled &&
           ::fcntl(descriptor, F_GETFD) == -1 && errno == EBADF &&
           loop.coroutine_statistics().live == 0;
}

auto send_errors(event_loop&, udp_socket& socket, udp_endpoint destination,
                 std::span<const std::byte> oversized, bool& passed)
    -> task<void>
{
    const auto too_large = co_await socket.async_send_to(oversized, destination);
    const auto invalid = co_await socket.async_send_to(
        std::array<std::byte, 1> {std::byte {'x'}},
        udp_endpoint {{127, 0, 0, 1}, 0});
    passed = !too_large && too_large.error().value() == EMSGSIZE &&
             !invalid && invalid.error().value() == EINVAL;
}

auto send_error_cases() -> bool
{
    event_loop loop;
    auto* socket = add_socket(loop);
    std::vector<std::byte> oversized(65508);
    bool passed = false;
    if (loop.spawn(send_errors(loop, *socket, socket->local_endpoint(), oversized,
                               passed)) != task_spawn_result::accepted) {
        return false;
    }
    return passed && loop.coroutine_statistics().live == 0;
}

auto constructor_rejects_invalid_address() -> bool
{
    event_loop loop;
    try {
        udp_socket socket(loop, 0, "not-an-ipv4-address");
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}

} // namespace

int main()
{
    try {
        const bool passed = roundtrip_and_rearm() && truncated_receive() &&
                            duplicate_and_close() &&
                            shutdown_cancels_receive() && send_error_cases() &&
                            constructor_rejects_invalid_address();
        if (!passed) std::cerr << "UDP coroutine test failed\n";
        return passed ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "UDP coroutine test exception: " << error.what() << '\n';
        return 1;
    }
}
