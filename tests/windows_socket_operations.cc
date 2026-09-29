#include "eventloop/task.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/udp_socket.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <system_error>

namespace {
using namespace eventloop;
using namespace std::chrono_literals;

auto check(bool condition, const char* message) -> void
{
    if (!condition) throw std::runtime_error(message);
}

[[nodiscard]] auto listener_endpoint(const tcp_acceptor& listener)
    -> ip_endpoint
{
    sockaddr_in address {};
    int length = sizeof(address);
    if (::getsockname(static_cast<SOCKET>(listener.descriptor()),
                      reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        throw std::system_error(::WSAGetLastError(), std::system_category(),
                                "getsockname(TCP listener)");
    }
    return ip_endpoint::loopback_v4(ntohs(address.sin_port));
}

auto stop_on_timeout(event_loop& loop, bool& timed_out) -> task<void>
{
    if (co_await sleep_for(loop, 3s) == timer_wait_result::expired) {
        timed_out = true;
        loop.shutdown(0ms);
    }
}

auto finish_tcp_side(event_loop& loop, int& finished, bool passed) -> void
{
    if (!passed) loop.shutdown(0ms);
    if (++finished == 2) loop.stop();
}

auto tcp_server(event_loop& loop, tcp_acceptor& listener, int& finished,
                bool& passed) -> task<void>
{
    auto accepted = co_await listener.async_accept();
    if (!accepted) {
        finish_tcp_side(loop, finished, false);
        co_return;
    }
    listener.close();
    auto stream = std::make_unique<tcp_stream>(loop, std::move(*accepted));
    auto* peer = stream.get();
    loop.add(std::move(stream));

    const auto empty_read = co_await peer->async_read_some(
        std::span<std::byte> {});
    const auto empty_write = co_await peer->async_write_some(
        std::span<const std::byte> {});
    std::array<std::byte, 1> input {};
    const auto received = co_await peer->async_read_some(input);
    constexpr std::array<std::byte, 1> response {std::byte {'o'}};
    const auto sent = co_await peer->async_write_some(response);
    passed = empty_read && *empty_read == 0 && empty_write && *empty_write == 0 &&
             received && *received == 1 && input[0] == std::byte {'i'} &&
             sent && *sent == 1;
    peer->close();
    finish_tcp_side(loop, finished, passed);
}

auto tcp_client(event_loop& loop, ip_endpoint endpoint, int& finished,
                bool& passed) -> task<void>
{
    auto stream = std::make_unique<tcp_stream>(loop, endpoint);
    auto* peer = stream.get();
    loop.add(std::move(stream));
    const auto connected = co_await peer->async_connect();
    if (!connected) {
        peer->close();
        finish_tcp_side(loop, finished, false);
        co_return;
    }

    constexpr std::array<std::byte, 1> request {std::byte {'i'}};
    const auto sent = co_await peer->async_write_some(request);
    std::array<std::byte, 1> response {};
    const auto received = co_await peer->async_read_some(response);
    passed = sent && *sent == 1 && received && *received == 1 &&
             response[0] == std::byte {'o'};
    peer->close();
    finish_tcp_side(loop, finished, passed);
}

[[nodiscard]] auto test_tcp() -> bool
{
    event_loop loop;
    auto listener = std::make_unique<tcp_acceptor>(
        loop, ip_endpoint::loopback_v4());
    auto* accepting = listener.get();
    const auto endpoint = listener_endpoint(*accepting);
    loop.add(std::move(listener));

    int finished = 0;
    bool server_passed = false;
    bool client_passed = false;
    bool timed_out = false;
    check(loop.spawn(tcp_server(loop, *accepting, finished, server_passed)) ==
              task_spawn_result::accepted,
          "failed to spawn TCP server task");
    check(loop.spawn(tcp_client(loop, endpoint, finished, client_passed)) ==
              task_spawn_result::accepted,
          "failed to spawn TCP client task");
    task_handle<void> watchdog;
    check(loop.spawn(stop_on_timeout(loop, timed_out), watchdog) ==
              task_spawn_result::accepted,
          "failed to spawn TCP watchdog");

    (void)loop.run();
    if (!watchdog.done()) (void)watchdog.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    return !timed_out && finished == 2 && server_passed && client_passed &&
           loop.coroutine_statistics().live == 0;
}

auto finish_udp_side(event_loop& loop, int& finished, bool passed) -> void
{
    if (!passed) loop.shutdown(0ms);
    if (++finished == 2) loop.stop();
}

auto udp_receiver(event_loop& loop, udp_socket& receiver,
                  ip_endpoint expected_source, int& finished,
                  bool& passed) -> task<void>
{
    std::array<std::byte, 3> buffer {};
    const auto first = co_await receiver.async_receive_from(buffer);
    const bool first_ok = first && first->size == 3 &&
                          first->source.port == expected_source.port &&
                          buffer == std::array<std::byte, 3> {
                              std::byte {'i'}, std::byte {'o'}, std::byte {'c'}};
    const auto second = co_await receiver.async_receive_from(buffer);
    passed = first_ok && second && second->size == 0 &&
             second->source.port == expected_source.port;
    receiver.close();
    finish_udp_side(loop, finished, passed);
}

auto udp_sender(event_loop& loop, udp_socket& sender,
                ip_endpoint destination, int& finished,
                bool& passed) -> task<void>
{
    constexpr std::array<std::byte, 3> message {
        std::byte {'i'}, std::byte {'o'}, std::byte {'c'}};
    const auto first = co_await sender.async_send_to(message, destination);
    const auto second = co_await sender.async_send_to(
        std::span<const std::byte> {}, destination);
    passed = first && *first == message.size() && second && *second == 0;
    sender.close();
    finish_udp_side(loop, finished, passed);
}

[[nodiscard]] auto test_udp() -> bool
{
    event_loop loop;
    auto receiver = std::make_unique<udp_socket>(
        loop, ip_endpoint::loopback_v4());
    auto sender = std::make_unique<udp_socket>(
        loop, ip_endpoint::loopback_v4());
    auto* receiving = receiver.get();
    auto* sending = sender.get();
    const auto source = sending->local_endpoint();
    const auto destination = receiving->local_endpoint();
    loop.add(std::move(receiver));
    loop.add(std::move(sender));

    int finished = 0;
    bool receiver_passed = false;
    bool sender_passed = false;
    bool timed_out = false;
    check(loop.spawn(udp_receiver(loop, *receiving, source, finished,
                                  receiver_passed)) ==
              task_spawn_result::accepted,
          "failed to spawn UDP receive task");
    check(loop.spawn(udp_sender(loop, *sending, destination, finished,
                                sender_passed)) ==
              task_spawn_result::accepted,
          "failed to spawn UDP send task");
    task_handle<void> watchdog;
    check(loop.spawn(stop_on_timeout(loop, timed_out), watchdog) ==
              task_spawn_result::accepted,
          "failed to spawn UDP watchdog");

    (void)loop.run();
    if (!watchdog.done()) (void)watchdog.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    return !timed_out && finished == 2 && receiver_passed && sender_passed &&
           loop.coroutine_statistics().live == 0;
}

auto shutdown_on_datagram(event_loop& loop, udp_socket& socket,
                          bool& received) -> task<void>
{
    std::array<std::byte, 1> buffer {};
    const auto result = co_await socket.async_receive_from(buffer);
    received = result && result->size == 1 && buffer[0] == std::byte {'x'};
    loop.shutdown(0ms);
}

auto observe_datagram(event_loop& loop, udp_socket& socket,
                      bool& completed) -> task<void>
{
    (void)loop;
    std::array<std::byte, 1> buffer {};
    (void)co_await socket.async_receive_from(buffer);
    completed = true;
}

[[nodiscard]] auto send_test_datagram(SOCKET sender,
                                      ip_endpoint destination) noexcept -> bool
{
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(destination.port);
    const char payload = 'x';
    return ::sendto(sender, &payload, sizeof(payload), 0,
                    reinterpret_cast<const sockaddr*>(&address),
                    sizeof(address)) == static_cast<int>(sizeof(payload));
}

[[nodiscard]] auto test_completion_batch_shutdown() -> bool
{
    event_loop loop;
    auto first = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto second = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto* first_socket = first.get();
    auto* second_socket = second.get();
    const auto first_endpoint = first_socket->local_endpoint();
    const auto second_endpoint = second_socket->local_endpoint();
    loop.add(std::move(first));
    loop.add(std::move(second));

    bool first_received = false;
    bool second_completed = false;
    if (loop.spawn(shutdown_on_datagram(loop, *first_socket, first_received)) !=
            task_spawn_result::accepted ||
        loop.spawn(observe_datagram(loop, *second_socket, second_completed)) !=
            task_spawn_result::accepted) {
        loop.shutdown(0ms);
        (void)loop.run();
        return false;
    }

    const SOCKET sender = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sender == INVALID_SOCKET) {
        loop.shutdown(0ms);
        (void)loop.run();
        return false;
    }
    const bool first_sent = send_test_datagram(sender, first_endpoint);
    const bool second_sent = send_test_datagram(sender, second_endpoint);
    (void)::closesocket(sender);
    if (!first_sent || !second_sent) {
        loop.shutdown(0ms);
        (void)loop.run();
        return false;
    }

    const auto result = loop.run();
    return result == event_loop_result::stopped && first_received &&
           second_completed && loop.coroutine_statistics().live == 0;
}

auto cancelled_receive(event_loop& loop, udp_socket& socket,
                       bool& cancelled) -> task<void>
{
    std::array<std::byte, 1> buffer {};
    const auto result = co_await socket.async_receive_from(buffer);
    cancelled = !result &&
                result.error() == std::make_error_code(
                    std::errc::operation_canceled);
}

[[nodiscard]] auto test_cancellation() -> bool
{
    event_loop loop;
    auto socket = std::make_unique<udp_socket>(
        loop, ip_endpoint::loopback_v4());
    auto* receiving = socket.get();
    loop.add(std::move(socket));
    bool cancelled = false;
    check(loop.spawn(cancelled_receive(loop, *receiving, cancelled)) ==
              task_spawn_result::accepted,
          "failed to spawn cancellation task");
    loop.shutdown(0ms);
    return loop.run() == event_loop_result::stopped && cancelled &&
           loop.coroutine_statistics().live == 0;
}
} // namespace

auto main() -> int
{
    try {
        check(test_tcp(), "TCP IOCP socket operations failed");
        check(test_udp(), "UDP IOCP socket operations failed");
        check(test_cancellation(), "IOCP cancellation did not retire safely");
        check(test_completion_batch_shutdown(),
              "shutdown dropped a dequeued IOCP completion");
        std::cout << "IOCP TCP, UDP, empty I/O, cancellation, and batched shutdown passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
