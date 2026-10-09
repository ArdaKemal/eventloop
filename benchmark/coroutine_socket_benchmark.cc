#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/udp_socket.h"

#include <array>
#include <charconv>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

using namespace eventloop;

namespace {

constexpr std::size_t message_size = 64;
constexpr std::size_t default_transactions = 10'000;
constexpr std::size_t default_clients = 16;
using message = std::array<std::byte, message_size>;

struct benchmark_state {
    event_loop& loop;
    std::size_t target;
    std::size_t completed {0};
    std::size_t round_trips {0};
    bool valid {true};

    auto finish() noexcept -> void
    {
        if (++completed == target) loop.stop();
    }
};

auto stop_after(event_loop& loop) -> task<void>
{
    if (co_await sleep_for(loop, std::chrono::seconds(30)) ==
        timer_wait_result::expired) {
        loop.shutdown(event_loop::clock::duration::zero());
    }
}

auto tcp_echo_session(event_loop&, tcp_stream& socket,
                      std::size_t transactions,
                      benchmark_state& state) -> task<void>
{
    for (std::size_t index = 0; index < transactions; ++index) {
        message data {};
        std::size_t offset = 0;
        while (offset < data.size()) {
            const auto result = co_await socket.async_read_some(
                std::span<std::byte>(data).subspan(offset));
            if (!result || *result == 0) {
                state.valid = false;
                state.finish();
                co_return;
            }
            offset += *result;
        }

        offset = 0;
        while (offset < data.size()) {
            const auto result = co_await socket.async_write_some(
                std::span<const std::byte>(data).subspan(offset));
            if (!result || *result == 0) {
                state.valid = false;
                state.finish();
                co_return;
            }
            offset += *result;
        }
    }
    state.finish();
}

auto tcp_accept_sessions(event_loop& loop, tcp_acceptor& listener,
                         std::size_t clients, std::size_t transactions,
                         benchmark_state& state) -> task<void>
{
    for (std::size_t index = 0; index < clients; ++index) {
        auto accepted = co_await listener.async_accept();
        if (!accepted) {
            state.valid = false;
            state.finish();
            co_return;
        }
        auto connection = std::make_unique<tcp_stream>(
            loop, std::move(*accepted));
        auto* socket = connection.get();
        loop.add(std::move(connection));
        if (loop.spawn(tcp_echo_session(loop, *socket, transactions, state)) !=
            task_spawn_result::accepted) {
            state.valid = false;
            state.finish();
            co_return;
        }
    }
    state.finish();
}

auto tcp_client(event_loop&, tcp_stream& socket,
                std::size_t transactions, benchmark_state& state) -> task<void>
{
    const auto connected = co_await socket.async_connect();
    if (!connected) {
        state.valid = false;
        state.finish();
        co_return;
    }

    message sent {};
    for (std::size_t index = 0; index < sent.size(); ++index) {
        sent[index] = static_cast<std::byte>(index & 0xffU);
    }
    for (std::size_t index = 0; index < transactions; ++index) {
        std::size_t offset = 0;
        while (offset < sent.size()) {
            const auto result = co_await socket.async_write_some(
                std::span<const std::byte>(sent).subspan(offset));
            if (!result || *result == 0) {
                state.valid = false;
                state.finish();
                co_return;
            }
            offset += *result;
        }

        message received {};
        offset = 0;
        while (offset < received.size()) {
            const auto result = co_await socket.async_read_some(
                std::span<std::byte>(received).subspan(offset));
            if (!result || *result == 0) {
                state.valid = false;
                state.finish();
                co_return;
            }
            offset += *result;
        }
        if (received != sent) {
            state.valid = false;
        } else {
            ++state.round_trips;
        }
    }
    state.finish();
}

auto bound_port(native_socket descriptor) -> std::uint16_t
{
    sockaddr_in endpoint {};
#ifdef _WIN32
    int length = sizeof(endpoint);
    if (::getsockname(static_cast<SOCKET>(descriptor),
                      reinterpret_cast<sockaddr*>(&endpoint), &length) ==
        SOCKET_ERROR) {
        throw std::system_error(::WSAGetLastError(), std::system_category(),
                                "getsockname");
    }
#else
    socklen_t length = sizeof(endpoint);
    if (::getsockname(descriptor, reinterpret_cast<sockaddr*>(&endpoint),
                      &length) == -1) {
        throw std::system_error(errno, std::system_category(), "getsockname");
    }
#endif
    return ntohs(endpoint.sin_port);
}

auto run_tcp(std::size_t transactions, std::size_t clients) -> bool
{
    // Accept task, one session and one client per connection, and the watchdog.
    event_loop_options options;
    options.coroutine_frame_capacities.fill(2 * clients + 2);
    event_loop loop(options);
    auto listener = std::make_unique<tcp_acceptor>(loop, ip_endpoint::loopback_v4());
    auto* listener_ptr = listener.get();
    const auto port = bound_port(listener_ptr->descriptor());
    loop.add(std::move(listener));

    std::vector<tcp_stream*> sockets;
    sockets.reserve(clients);
    for (std::size_t index = 0; index < clients; ++index) {
        auto socket = std::make_unique<tcp_stream>(
            loop, ip_endpoint::loopback_v4(port));
        sockets.push_back(socket.get());
        loop.add(std::move(socket));
    }

    benchmark_state state {loop, 2 * clients + 1};
    if (loop.spawn(tcp_accept_sessions(loop, *listener_ptr, clients,
                                       transactions, state)) !=
        task_spawn_result::accepted) return false;
    for (auto* socket : sockets) {
        if (loop.spawn(tcp_client(loop, *socket, transactions, state)) !=
            task_spawn_result::accepted) {
            state.valid = false;
            loop.shutdown(event_loop::clock::duration::zero());
            (void)loop.run();
            return false;
        }
    }

    task_handle<void> watchdog;
    if (loop.spawn(stop_after(loop), watchdog) != task_spawn_result::accepted)
        return false;
    const auto started = std::chrono::steady_clock::now();
    const auto result = loop.run();
    const auto elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started);
    const bool timed_out = watchdog.done();
    if (!watchdog.done()) (void)watchdog.cancel();
    // Cancellation completes the observed task synchronously, but its frame
    // is retired when the loop drains completed roots.
    loop.stop();
    (void)loop.run();
    const auto total = transactions * clients;
    std::cout << "TCP: " << clients << " clients, " << state.round_trips
              << " of " << total << " 64-byte echo round trips in "
              << elapsed.count() << " s ("
              << static_cast<double>(state.round_trips) / elapsed.count()
              << " round trips/s)" << (timed_out ? " [timeout]" : "") << '\n';
    return result == event_loop_result::stopped && state.valid &&
           state.completed == state.target && state.round_trips == total;
}

auto udp_echo_server(event_loop&, udp_socket& socket, std::size_t datagrams,
                     benchmark_state& state) -> task<void>
{
    message data {};
    for (std::size_t index = 0; index < datagrams; ++index) {
        const auto received = co_await socket.async_receive_from(data);
        if (!received || received->size != data.size()) {
            state.valid = false;
            state.finish();
            co_return;
        }
        const auto sent = co_await socket.async_send_to(
            std::span<const std::byte>(data).first(received->size),
            received->source);
        if (!sent || *sent != received->size) {
            state.valid = false;
            state.finish();
            co_return;
        }
    }
    state.finish();
}

auto udp_client(event_loop&, udp_socket& socket, ip_endpoint destination,
                std::size_t transactions, benchmark_state& state) -> task<void>
{
    message sent {};
    for (std::size_t index = 0; index < sent.size(); ++index) {
        sent[index] = static_cast<std::byte>((index * 17U) & 0xffU);
    }
    for (std::size_t index = 0; index < transactions; ++index) {
        const auto sent_size = co_await socket.async_send_to(sent, destination);
        if (!sent_size || *sent_size != sent.size()) {
            state.valid = false;
            state.finish();
            co_return;
        }
        message received {};
        const auto result = co_await socket.async_receive_from(received);
        if (!result || result->size != received.size() || received != sent) {
            state.valid = false;
            state.finish();
            co_return;
        }
        ++state.round_trips;
    }
    state.finish();
}

auto run_udp(std::size_t transactions, std::size_t clients) -> bool
{
    // Server task, one task per client, and the watchdog.
    event_loop_options options;
    options.coroutine_frame_capacities.fill(clients + 2);
    event_loop loop(options);
    auto server = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto* server_ptr = server.get();
    const auto endpoint = server_ptr->local_endpoint();
    loop.add(std::move(server));

    std::vector<udp_socket*> sockets;
    sockets.reserve(clients);
    for (std::size_t index = 0; index < clients; ++index) {
        auto socket = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
        sockets.push_back(socket.get());
        loop.add(std::move(socket));
    }

    benchmark_state state {loop, clients + 1};
    const auto datagrams = transactions * clients;
    if (loop.spawn(udp_echo_server(loop, *server_ptr, datagrams, state)) !=
        task_spawn_result::accepted) return false;
    for (auto* socket : sockets) {
        if (loop.spawn(udp_client(loop, *socket, endpoint, transactions,
                                  state)) != task_spawn_result::accepted) {
            state.valid = false;
            loop.shutdown(event_loop::clock::duration::zero());
            (void)loop.run();
            return false;
        }
    }

    task_handle<void> watchdog;
    if (loop.spawn(stop_after(loop), watchdog) != task_spawn_result::accepted)
        return false;
    const auto started = std::chrono::steady_clock::now();
    const auto result = loop.run();
    const auto elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started);
    const bool timed_out = watchdog.done();
    if (!watchdog.done()) (void)watchdog.cancel();
    loop.stop();
    (void)loop.run();
    std::cout << "UDP: " << clients << " clients, " << state.round_trips
              << " of " << datagrams << " 64-byte echo round trips in "
              << elapsed.count() << " s ("
              << static_cast<double>(state.round_trips) / elapsed.count()
              << " round trips/s)" << (timed_out ? " [timeout]" : "") << '\n';
    return result == event_loop_result::stopped && state.valid &&
           state.completed == state.target && state.round_trips == datagrams;
}

auto parse_count(std::string_view text, const char* description) -> std::size_t
{
    std::size_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(),
                                              value);
    if (error != std::errc {} || end != text.data() + text.size() || value == 0) {
        throw std::invalid_argument(description);
    }
    return value;
}

} // namespace

auto main(int argc, char* argv[]) -> int
{
    try {
        const std::string_view mode = argc > 1 ? argv[1] : "both";
        const auto transactions = argc > 2
            ? parse_count(argv[2], "transaction count must be positive")
            : default_transactions;
        const auto clients = argc > 3
            ? parse_count(argv[3], "client count must be positive")
            : default_clients;
        if (mode != "tcp" && mode != "udp" && mode != "both") {
            throw std::invalid_argument("mode must be tcp, udp, or both");
        }
        if ((mode == "tcp" || mode == "both") &&
            !run_tcp(transactions, clients)) {
            std::cerr << "TCP benchmark workload failed\n";
            return 1;
        }
        if ((mode == "udp" || mode == "both") &&
            !run_udp(transactions, clients)) {
            std::cerr << "UDP benchmark workload failed\n";
            return 1;
        }
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
