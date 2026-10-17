#include "eventloop/task.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/udp_socket.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

#ifdef EVENTLOOP_TEST_TLS
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "tls_test_certificate.h"
#endif

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#endif

using namespace eventloop;
using namespace std::chrono_literals;

namespace {

auto check(bool condition, const char* message) -> void
{
    if (!condition) throw std::runtime_error(message);
}

[[nodiscard]] auto listener_endpoint(const tcp_acceptor& listener)
    -> ip_endpoint
{
    sockaddr_in address {};
#ifdef _WIN32
    int length = sizeof(address);
    const auto status = ::getsockname(static_cast<SOCKET>(listener.descriptor()),
                                     reinterpret_cast<sockaddr*>(&address), &length);
    if (status != 0)
        throw std::system_error(::WSAGetLastError(), std::system_category(),
                                "getsockname");
#else
    socklen_t length = sizeof(address);
    const auto status = ::getsockname(listener.descriptor(),
                                     reinterpret_cast<sockaddr*>(&address), &length);
    if (status != 0)
        throw std::system_error(errno, std::system_category(), "getsockname");
#endif
    return ip_endpoint::loopback_v4(ntohs(address.sin_port));
}

auto watchdog(event_loop& loop, bool& timed_out) -> task<void>
{
    if (co_await sleep_for(loop, 3s) == timer_wait_result::expired) {
        timed_out = true;
        loop.shutdown(0ms);
    }
}

auto finish(event_loop& loop, int& completed, bool passed) -> void
{
    if (!passed) loop.shutdown(0ms);
    if (++completed == 2) loop.stop();
}

[[nodiscard]] auto no_delay(native_socket descriptor) -> bool
{
#ifdef _WIN32
    BOOL enabled = FALSE;
    int length = sizeof(enabled);
    return ::getsockopt(static_cast<SOCKET>(descriptor), IPPROTO_TCP, TCP_NODELAY,
                        reinterpret_cast<char*>(&enabled), &length) == 0 && enabled;
#else
    int enabled = 0;
    socklen_t length = sizeof(enabled);
    return ::getsockopt(descriptor, IPPROTO_TCP, TCP_NODELAY,
                        &enabled, &length) == 0 && enabled != 0;
#endif
}

auto tcp_server(event_loop& loop, tcp_acceptor& listener, int& completed,
                bool& passed) -> task<void>
{
    auto accepted = co_await listener.async_accept();
    if (!accepted) {
        finish(loop, completed, false);
        co_return;
    }
    listener.close();
#ifdef _WIN32
    const bool accepted_no_delay = true;
#else
    const bool accepted_no_delay = no_delay(accepted->get());
#endif
    auto stream = std::make_unique<tcp_stream>(loop, std::move(*accepted));
    auto* peer = stream.get();
    loop.add(std::move(stream));
    std::array<std::byte, 1> input {};
    const auto read = co_await peer->async_read_some(input);
    constexpr std::array<std::byte, 1> reply {std::byte {'b'}};
    const auto write = co_await peer->async_write_some(reply);
    passed = accepted_no_delay && read && *read == 1 && input[0] == std::byte {'a'} &&
             write && *write == 1;
    peer->close();
    finish(loop, completed, passed);
}

auto tcp_client(event_loop& loop, tcp_stream& peer, int& completed,
                bool& passed) -> task<void>
{
    const auto connected = co_await peer.async_connect();
    if (!connected) {
        peer.close();
        finish(loop, completed, false);
        co_return;
    }
    constexpr std::array<std::byte, 1> request {std::byte {'a'}};
    const auto write = co_await peer.async_write_some(request);
    std::array<std::byte, 1> reply {};
    const auto read = co_await peer.async_read_some(reply);
    passed = no_delay(peer.descriptor()) && write && *write == 1 && read && *read == 1 &&
             reply[0] == std::byte {'b'};
    peer.close();
    finish(loop, completed, passed);
}

[[nodiscard]] auto test_tcp() -> bool
{
    event_loop loop;
    auto listener = std::make_unique<tcp_acceptor>(loop, ip_endpoint::loopback_v4());
    auto* accepting = listener.get();
    auto client = std::make_unique<tcp_stream>(loop, listener_endpoint(*accepting));
    auto* connecting = client.get();
    loop.add(std::move(listener));
    loop.add(std::move(client));
    int completed = 0;
    bool server_ok = false;
    bool client_ok = false;
    bool timed_out = false;
    check(loop.spawn(tcp_server(loop, *accepting, completed, server_ok)) ==
              task_spawn_result::accepted, "spawn TCP server");
    check(loop.spawn(tcp_client(loop, *connecting, completed, client_ok)) ==
              task_spawn_result::accepted, "spawn TCP client");
    task_handle<void> timer;
    check(loop.spawn(watchdog(loop, timed_out), timer) ==
              task_spawn_result::accepted, "spawn TCP watchdog");
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    return !timed_out && completed == 2 && server_ok && client_ok &&
           loop.coroutine_statistics().live == 0;
}

#ifndef _WIN32
// Closes from a read completion, inside the loop's dispatch of that socket,
// and checks that the peer sees end of stream before the dispatch returns.
auto fin_server(event_loop& loop, tcp_acceptor& listener, native_socket client,
                bool& fin_seen) -> task<void>
{
    auto accepted = co_await listener.async_accept();
    listener.close();
    if (!accepted) {
        loop.shutdown(0ms);
        co_return;
    }
    auto stream = std::make_unique<tcp_stream>(loop, std::move(*accepted));
    auto* peer = stream.get();
    loop.add(std::move(stream));
    std::array<std::byte, 1> input {};
    const auto read = co_await peer->async_read_some(input);
    peer->close();
    pollfd ready {.fd = client, .events = POLLIN, .revents = 0};
    std::byte peeked {};
    fin_seen = read && *read == 1 && ::poll(&ready, 1, 1000) == 1 &&
               ::recv(client, &peeked, 1, MSG_PEEK | MSG_DONTWAIT) == 0;
    loop.shutdown(0ms);
}

auto fin_client(event_loop& loop, tcp_stream& peer) -> task<void>
{
    if (!co_await peer.async_connect()) co_return;
    // Lets the server's read suspend, so it completes from the poller.
    (void)co_await sleep_for(loop, 20ms);
    constexpr std::array<std::byte, 1> request {std::byte {'a'}};
    (void)co_await peer.async_write_some(request);
}

[[nodiscard]] auto test_close_sends_fin() -> bool
{
    event_loop loop;
    auto listener = std::make_unique<tcp_acceptor>(loop, ip_endpoint::loopback_v4());
    auto* accepting = listener.get();
    auto client = std::make_unique<tcp_stream>(loop, listener_endpoint(*accepting));
    auto* connecting = client.get();
    loop.add(std::move(listener));
    loop.add(std::move(client));
    bool fin_seen = false;
    bool timed_out = false;
    check(loop.spawn(fin_server(loop, *accepting, connecting->descriptor(), fin_seen)) ==
              task_spawn_result::accepted, "spawn FIN server");
    check(loop.spawn(fin_client(loop, *connecting)) ==
              task_spawn_result::accepted, "spawn FIN client");
    check(loop.spawn(watchdog(loop, timed_out)) ==
              task_spawn_result::accepted, "spawn FIN watchdog");
    return loop.run() == event_loop_result::stopped && !timed_out && fin_seen &&
           loop.coroutine_statistics().live == 0;
}
#endif

auto cancelled_read(event_loop& loop, tcp_stream& stream, bool& started,
                    bool& cancelled) -> task<void>
{
    (void)loop;
    std::array<std::byte, 1> buffer {};
    started = true;
    const auto result = co_await stream.async_read_some(buffer);
    cancelled = !result && result.error() ==
                               std::make_error_code(std::errc::operation_canceled);
}

auto cancelled_write(event_loop& loop, tcp_stream& stream, bool& started,
                     bool& cancelled) -> task<void>
{
    (void)loop;
    const std::array<std::byte, 256> buffer {};
    started = true;
    for (;;) {
        const auto result = co_await stream.async_write_some(buffer);
        if (!result) {
            cancelled = result.error() ==
                        std::make_error_code(std::errc::operation_canceled);
            co_return;
        }
        if (*result == 0) co_return;
    }
}

auto tcp_cancel_server(event_loop& loop, tcp_acceptor& listener,
                       bool& both_pending, bool& read_started,
                       bool& write_started, bool& read_cancelled,
                       bool& write_cancelled) -> task<void>
{
    auto accepted = co_await listener.async_accept();
    if (!accepted) {
        loop.shutdown(0ms);
        co_return;
    }
    listener.close();
    auto stream = std::make_unique<tcp_stream>(loop, std::move(*accepted));
    auto* peer = stream.get();
    loop.add(std::move(stream));
    const bool read_spawned =
        loop.spawn(cancelled_read(loop, *peer, read_started, read_cancelled)) ==
        task_spawn_result::accepted;
    const bool write_spawned =
        loop.spawn(cancelled_write(loop, *peer, write_started,
                                   write_cancelled)) ==
        task_spawn_result::accepted;
    both_pending = read_spawned && write_spawned && read_started &&
                   write_started && !read_cancelled && !write_cancelled;
    loop.shutdown(0ms);
}

auto tcp_cancel_client(event_loop& loop, tcp_stream& stream) -> task<void>
{
    (void)loop;
    (void)co_await stream.async_connect();
}

[[nodiscard]] auto test_concurrent_tcp_cancel() -> bool
{
    event_loop loop;
    auto listener = std::make_unique<tcp_acceptor>(
        loop, ip_endpoint::loopback_v4());
    auto* accepting = listener.get();
    auto client = std::make_unique<tcp_stream>(
        loop, listener_endpoint(*accepting));
    auto* connecting = client.get();
    loop.add(std::move(listener));
    loop.add(std::move(client));
    bool both_pending = false;
    bool read_started = false;
    bool write_started = false;
    bool read_cancelled = false;
    bool write_cancelled = false;
    bool timed_out = false;
    check(loop.spawn(tcp_cancel_server(
              loop, *accepting, both_pending, read_started, write_started,
              read_cancelled, write_cancelled)) == task_spawn_result::accepted,
          "spawn TCP cancellation server");
    check(loop.spawn(tcp_cancel_client(loop, *connecting)) ==
              task_spawn_result::accepted, "spawn TCP cancellation client");
    check(loop.spawn(watchdog(loop, timed_out)) ==
              task_spawn_result::accepted, "spawn TCP cancellation watchdog");
    return loop.run() == event_loop_result::stopped && !timed_out &&
           both_pending && read_cancelled && write_cancelled &&
           loop.coroutine_statistics().live == 0;
}

auto cancelled_accept(event_loop& loop, tcp_acceptor& listener,
                      bool& cancelled) -> task<void>
{
    (void)loop;
    const auto result = co_await listener.async_accept();
    cancelled = !result && result.error() ==
                               std::make_error_code(std::errc::operation_canceled);
}

[[nodiscard]] auto test_pending_accept_cancel() -> bool
{
    event_loop loop;
    auto listener = std::make_unique<tcp_acceptor>(
        loop, ip_endpoint::loopback_v4());
    auto* accepting = listener.get();
    loop.add(std::move(listener));
    bool cancelled = false;
    check(loop.spawn(cancelled_accept(loop, *accepting, cancelled)) ==
              task_spawn_result::accepted, "spawn pending accept");
    loop.shutdown(0ms);
    return loop.run() == event_loop_result::stopped && cancelled &&
           loop.coroutine_statistics().live == 0;
}

auto udp_receive(event_loop& loop, udp_socket& socket, ip_endpoint source,
                 int& completed, bool& passed) -> task<void>
{
    std::array<std::byte, 3> buffer {};
    const auto first = co_await socket.async_receive_from(buffer);
    const bool first_ok = first && first->size == buffer.size() &&
                          first->source.port == source.port &&
                          buffer == std::array<std::byte, 3> {
                              std::byte {'u'}, std::byte {'d'}, std::byte {'p'}};
    const auto second = co_await socket.async_receive_from(buffer);
    passed = first_ok && second && second->size == 0 &&
             second->source.port == source.port;
    socket.close();
    finish(loop, completed, passed);
}

auto udp_send(event_loop& loop, udp_socket& socket, ip_endpoint destination,
              int& completed, bool& passed) -> task<void>
{
    constexpr std::array<std::byte, 3> payload {
        std::byte {'u'}, std::byte {'d'}, std::byte {'p'}};
    const auto first = co_await socket.async_send_to(payload, destination);
    const auto second = co_await socket.async_send_to(
        std::span<const std::byte> {}, destination);
    passed = first && *first == payload.size() && second && *second == 0;
    socket.close();
    finish(loop, completed, passed);
}

[[nodiscard]] auto test_udp() -> bool
{
    event_loop loop;
    auto receiver = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto sender = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto* receiving = receiver.get();
    auto* sending = sender.get();
    const auto source = sending->local_endpoint();
    const auto destination = receiving->local_endpoint();
    loop.add(std::move(receiver));
    loop.add(std::move(sender));
    int completed = 0;
    bool received = false;
    bool sent = false;
    bool timed_out = false;
    check(loop.spawn(udp_receive(loop, *receiving, source, completed, received)) ==
              task_spawn_result::accepted, "spawn UDP receiver");
    check(loop.spawn(udp_send(loop, *sending, destination, completed, sent)) ==
              task_spawn_result::accepted, "spawn UDP sender");
    task_handle<void> timer;
    check(loop.spawn(watchdog(loop, timed_out), timer) ==
              task_spawn_result::accepted, "spawn UDP watchdog");
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    return !timed_out && completed == 2 && received && sent &&
           loop.coroutine_statistics().live == 0;
}

#ifdef EVENTLOOP_TEST_TLS
struct temporary_certificate {
    std::filesystem::path directory;
    std::filesystem::path certificate;
    std::filesystem::path key;

    temporary_certificate()
    {
        const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
        directory = std::filesystem::temp_directory_path() /
                    ("eventloop-tls-test-" + std::to_string(suffix));
        std::filesystem::create_directory(directory);
        certificate = directory / "cert.pem";
        key = directory / "key.pem";
        eventloop::test::make_localhost_certificate(certificate, key);
    }

    ~temporary_certificate()
    {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
    }
};

auto tls_server(event_loop& loop, tcp_acceptor& listener,
                std::shared_ptr<tls_context> context, int& completed,
                bool& passed) -> task<void>
{
    auto accepted = co_await listener.async_accept();
    if (!accepted) {
        finish(loop, completed, false);
        co_return;
    }
    listener.close();
    auto stream = std::make_unique<tls_stream>(loop, std::move(*accepted),
                                               std::move(context));
    auto* peer = stream.get();
    loop.add(std::move(stream));
    const auto handshake = flatten_result(co_await peer->async_handshake());
    if (!handshake) {
        peer->close();
        finish(loop, completed, false);
        co_return;
    }
    std::array<std::byte, 1> input {};
    const auto read = flatten_result(co_await peer->async_read_some(input));
    constexpr std::array<std::byte, 1> reply {std::byte {'t'}};
    const auto write = flatten_result(co_await peer->async_write_some(reply));
    passed = read && *read == 1 && input[0] == std::byte {'s'} &&
             write && *write == 1;
    peer->close();
    finish(loop, completed, passed);
}

auto tls_client(event_loop& loop, tls_stream& peer, int& completed,
                bool& passed) -> task<void>
{
    const auto connected = co_await peer.async_connect();
    if (!connected) {
        peer.close();
        finish(loop, completed, false);
        co_return;
    }
    const auto handshake = flatten_result(co_await peer.async_handshake());
    if (!handshake) {
        peer.close();
        finish(loop, completed, false);
        co_return;
    }
    constexpr std::array<std::byte, 1> request {std::byte {'s'}};
    const auto write = flatten_result(co_await peer.async_write_some(request));
    std::array<std::byte, 1> reply {};
    const auto read = flatten_result(co_await peer.async_read_some(reply));
    passed = write && *write == 1 && read && *read == 1 &&
             reply[0] == std::byte {'t'};
    peer.close();
    finish(loop, completed, passed);
}

[[nodiscard]] auto test_tls() -> bool
{
    temporary_certificate files;
    auto server_context = tls_context::make_server(files.certificate, files.key);
    auto client_context = tls_context::make_client(files.certificate);
    event_loop loop;
    auto listener = std::make_unique<tcp_acceptor>(loop, ip_endpoint::loopback_v4());
    auto* accepting = listener.get();
    auto client = std::make_unique<tls_stream>(
        loop, listener_endpoint(*accepting), client_context,
        tls_client_options {.hostname = "localhost"});
    auto* connecting = client.get();
    loop.add(std::move(listener));
    loop.add(std::move(client));
    int completed = 0;
    bool server_ok = false;
    bool client_ok = false;
    bool timed_out = false;
    check(loop.spawn(tls_server(loop, *accepting, server_context,
                                completed, server_ok)) == task_spawn_result::accepted,
          "spawn TLS server");
    check(loop.spawn(tls_client(loop, *connecting, completed, client_ok)) ==
              task_spawn_result::accepted, "spawn TLS client");
    task_handle<void> timer;
    check(loop.spawn(watchdog(loop, timed_out), timer) ==
              task_spawn_result::accepted, "spawn TLS watchdog");
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    return !timed_out && completed == 2 && server_ok && client_ok &&
           loop.coroutine_statistics().live == 0;
}
#endif

} // namespace

auto main() -> int
{
    try {
        check(test_tcp(), "TCP public API roundtrip failed");
        check(test_concurrent_tcp_cancel(),
              "concurrent TCP cancellation failed");
        check(test_pending_accept_cancel(), "pending accept cancellation failed");
#ifndef _WIN32
        check(test_close_sends_fin(), "TCP close did not send FIN promptly");
#endif
        check(test_udp(), "UDP public API roundtrip failed");
#ifdef EVENTLOOP_TEST_TLS
        check(test_tls(), "TLS public API roundtrip failed");
#endif
        std::cout << "TCP and UDP public API roundtrips passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
