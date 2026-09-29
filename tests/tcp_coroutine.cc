#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/task.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

using namespace eventloop;

using namespace std::chrono_literals;

namespace {

#ifdef _WIN32
struct winsock_scope {
    winsock_scope()
    {
        WSADATA data {};
        const int error = ::WSAStartup(MAKEWORD(2, 2), &data);
        if (error != 0)
            throw std::system_error(error, std::system_category(), "WSAStartup");
    }
    ~winsock_scope() { (void)::WSACleanup(); }
};
#endif

[[nodiscard]] auto raw_socket(int family) -> native_socket
{
#ifdef _WIN32
    return static_cast<native_socket>(::socket(family, SOCK_STREAM, 0));
#else
    return ::socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
#endif
}

[[nodiscard]] auto local_port(native_socket descriptor) -> std::uint16_t
{
    sockaddr_storage address {};
#ifdef _WIN32
    int length = sizeof(address);
#else
    socklen_t length = sizeof(address);
#endif
    if (::getsockname(descriptor, reinterpret_cast<sockaddr*>(&address),
                      &length) == -1) return 0;
    if (address.ss_family == AF_INET6) {
        return ntohs(reinterpret_cast<const sockaddr_in6&>(address).sin6_port);
    }
    return ntohs(reinterpret_cast<const sockaddr_in&>(address).sin_port);
}

[[nodiscard]] auto closed_descriptor(native_socket descriptor) -> bool
{
#ifdef _WIN32
    int kind = 0;
    int length = sizeof(kind);
    return ::getsockopt(static_cast<SOCKET>(descriptor), SOL_SOCKET, SO_TYPE,
                        reinterpret_cast<char*>(&kind), &length) == SOCKET_ERROR &&
           ::WSAGetLastError() == WSAENOTSOCK;
#else
    errno = 0;
    return ::fcntl(descriptor, F_GETFD) == -1 && errno == EBADF;
#endif
}

[[nodiscard]] auto ipv6_loopback_available() -> bool
{
    unique_fd descriptor(raw_socket(AF_INET6));
    if (!descriptor) {
#ifdef _WIN32
        const int error = ::WSAGetLastError();
        if (error == WSAEAFNOSUPPORT || error == WSAEPROTONOSUPPORT) return false;
        throw std::system_error(error, std::system_category(), "IPv6 socket probe");
#else
        if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) return false;
        throw std::system_error(errno, std::system_category(), "IPv6 socket probe");
#endif
    }
    sockaddr_in6 address {};
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_loopback;
    if (::bind(descriptor.get(), reinterpret_cast<sockaddr*>(&address),
               sizeof(address)) == 0) return true;
#ifdef _WIN32
    if (::WSAGetLastError() == WSAEADDRNOTAVAIL) return false;
    throw std::system_error(::WSAGetLastError(), std::system_category(),
                            "IPv6 loopback probe");
#else
    if (errno == EADDRNOTAVAIL || errno == ENODEV) return false;
    throw std::system_error(errno, std::system_category(), "IPv6 loopback probe");
#endif
}

[[nodiscard]] auto ipv6_only(native_socket descriptor) -> bool
{
    int value = 0;
#ifdef _WIN32
    int size = sizeof(value);
    return ::getsockopt(static_cast<SOCKET>(descriptor), IPPROTO_IPV6,
                        IPV6_V6ONLY, reinterpret_cast<char*>(&value), &size) == 0 &&
           value == 1;
#else
    socklen_t size = sizeof(value);
    return ::getsockopt(descriptor, IPPROTO_IPV6, IPV6_V6ONLY, &value, &size) == 0 &&
           value == 1;
#endif
}

[[nodiscard]] auto unused_port() -> std::uint16_t
{
    unique_fd descriptor(raw_socket(AF_INET));
    if (!descriptor) return 0;
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(descriptor.get(), reinterpret_cast<sockaddr*>(&address),
               sizeof(address)) == -1) return 0;
    return local_port(descriptor.get());
}

auto stop_after_two(event_loop& loop, int& completed) -> void
{
    if (++completed == 2) loop.stop();
}

auto stop_after(event_loop& loop, std::chrono::seconds delay) -> task<void>
{
    if (co_await sleep_for(loop, delay) == timer_wait_result::expired) {
        loop.stop();
    }
}

auto shutdown_after(event_loop& loop, std::chrono::seconds delay) -> task<void>
{
    if (co_await sleep_for(loop, delay) == timer_wait_result::expired) {
        loop.shutdown(0s);
    }
}

auto server(event_loop& loop, tcp_acceptor& listener,
            int& completed, bool& passed, native_socket& accepted_descriptor)
    -> task<void>
{
    auto accepted = co_await listener.async_accept();
    if (!accepted) {
        stop_after_two(loop, completed);
        co_return;
    }
    accepted_descriptor = accepted->get();
    auto socket = std::make_unique<tcp_stream>(
        loop, std::move(*accepted));
    auto* peer = socket.get();
    loop.add(std::move(socket));

    std::array<std::byte, 4> input {};
    const auto first = co_await peer->async_read_some(input);
    if (!first || *first != 1 || input[0] != std::byte {'a'}) {
        peer->close();
        stop_after_two(loop, completed);
        co_return;
    }
    constexpr std::array<std::byte, 1> acknowledgement {std::byte {'!'}};
    const auto acknowledged = co_await peer->async_write_some(acknowledgement);
    if (!acknowledged || *acknowledged != 1) {
        peer->close();
        stop_after_two(loop, completed);
        co_return;
    }

    // The client waits for the acknowledgement before sending the next byte.
    // This read therefore needs a second readiness registration.
    const auto second = co_await peer->async_read_some(input);
    if (second && *second == 1 && input[0] == std::byte {'b'}) {
        passed = true;
    }
    peer->close();
    stop_after_two(loop, completed);
}

auto client(event_loop& loop, ip_endpoint endpoint, int& completed,
            bool& passed, native_socket& descriptor) -> task<void>
{
    auto socket = std::make_unique<tcp_stream>(loop, endpoint);
    auto* peer = socket.get();
    descriptor = peer->descriptor();
    loop.add(std::move(socket));
    const auto connected = co_await peer->async_connect();
    if (!connected) {
        stop_after_two(loop, completed);
        co_return;
    }
    constexpr std::array<std::byte, 1> first {std::byte {'a'}};
    const auto first_write = co_await peer->async_write_some(first);
    std::array<std::byte, 1> acknowledgement {};
    const auto acknowledged = co_await peer->async_read_some(acknowledgement);
    if (!first_write || *first_write != 1 || !acknowledged ||
        *acknowledged != 1 || acknowledgement[0] != std::byte {'!'}) {
        peer->close();
        stop_after_two(loop, completed);
        co_return;
    }
    constexpr std::array<std::byte, 1> second {std::byte {'b'}};
    const auto second_write = co_await peer->async_write_some(second);
    if (second_write && *second_write == 1) {
        std::array<std::byte, 1> eof_buffer {};
        const auto eof = co_await peer->async_read_some(eof_buffer);
        passed = eof && *eof == 0;
    }
    peer->close();
    stop_after_two(loop, completed);
}

auto roundtrip(ip_endpoint endpoint = ip_endpoint::loopback_v4()) -> bool
{
    event_loop loop;
    auto listener = std::make_unique<tcp_acceptor>(loop, endpoint);
    auto* accepting = listener.get();
    const native_socket listener_descriptor = accepting->descriptor();
    if (endpoint.address_family == ip_endpoint::family::ipv6 &&
        !ipv6_only(listener_descriptor)) return false;
    const auto port = local_port(accepting->descriptor());
    if (port == 0) return false;
    loop.add(std::move(listener));
    int completed = 0;
    native_socket accepted_descriptor = static_cast<native_socket>(-1);
    native_socket client_descriptor = static_cast<native_socket>(-1);
    bool server_passed = false;
    bool client_passed = false;
    if (loop.spawn(server(loop, *accepting, completed, server_passed,
                          accepted_descriptor)) != task_spawn_result::accepted ||
        loop.spawn(client(loop, endpoint.address_family == ip_endpoint::family::ipv6
                                    ? ip_endpoint::loopback_v6(port)
                                    : ip_endpoint::loopback_v4(port),
                          completed, client_passed,
                          client_descriptor)) != task_spawn_result::accepted) {
        loop.shutdown(0s);
        (void)loop.run();
        return false;
    }
    task_handle<void> watchdog;
    if (loop.spawn(stop_after(loop, 2s), watchdog) !=
        task_spawn_result::accepted) return false;
    const auto result = loop.run();
    if (!watchdog.done()) (void)watchdog.cancel();
    if (completed != 2) {
        loop.shutdown(0s);
        (void)loop.run();
        return false;
    }
    accepting->close();
    loop.shutdown(0s);
    (void)loop.run();
    return result == event_loop_result::stopped && completed == 2 &&
           server_passed && client_passed &&
           closed_descriptor(listener_descriptor) &&
           closed_descriptor(accepted_descriptor) &&
           closed_descriptor(client_descriptor) &&
           loop.coroutine_statistics().live == 0;
}

struct tcp_pair {
    unique_fd client;
    unique_fd server;
};

[[nodiscard]] auto connected_pair() -> tcp_pair
{
    unique_fd listener(raw_socket(AF_INET));
    if (!listener) return {};
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(listener.get(), reinterpret_cast<sockaddr*>(&address),
               sizeof(address)) == -1 || ::listen(listener.get(), 1) == -1) {
        return {};
    }
    address.sin_port = htons(local_port(listener.get()));
    tcp_pair result;
    result.client.reset(raw_socket(AF_INET));
    if (!result.client ||
        ::connect(result.client.get(), reinterpret_cast<sockaddr*>(&address),
                  sizeof(address)) == -1) return {};
#ifdef _WIN32
    result.server.reset(::accept(static_cast<SOCKET>(listener.get()),
                                 nullptr, nullptr));
#else
    result.server.reset(::accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC));
#endif
    return result;
}

auto accept_result(event_loop&, tcp_acceptor& listener, int& error)
    -> task<void>
{
    auto result = co_await listener.async_accept();
    error = result ? 0 : result.error().value();
}

auto read_result(event_loop&, tcp_stream& socket, int& error) -> task<void>
{
    std::array<std::byte, 1> buffer {};
    const auto result = co_await socket.async_read_some(buffer);
    error = result ? 0 : result.error().value();
}

auto write_result(event_loop&, tcp_stream& socket, int& error) -> task<void>
{
    constexpr std::array<std::byte, 1> buffer {std::byte {'x'}};
    const auto result = co_await socket.async_write_some(buffer);
    error = result ? 0 : result.error().value();
}

auto connect_result(event_loop& loop, tcp_stream& socket,
                    int& error) -> task<void>
{
    const auto result = co_await socket.async_connect();
    error = result ? 0 : result.error().value();
    loop.stop();
}

auto duplicate_accept_and_close() -> bool
{
    event_loop loop;
    auto listener = std::make_unique<tcp_acceptor>(loop, ip_endpoint::loopback_v4());
    auto* owner = listener.get();
    const native_socket descriptor = owner->descriptor();
    loop.add(std::move(listener));
    int pending = -1;
    int duplicate = -1;
    if (loop.spawn(accept_result(loop, *owner, pending)) != task_spawn_result::accepted ||
        loop.spawn(accept_result(loop, *owner, duplicate)) != task_spawn_result::accepted) {
        owner->close();
        return false;
    }
    owner->close();
    // Root frames completed by close() are retired when the loop next drains
    // completed roots.
    loop.stop();
    (void)loop.run();
    return pending == ECANCELED && duplicate == EBUSY &&
           closed_descriptor(descriptor) &&
           loop.coroutine_statistics().live == 0;
}

auto fill_send_queue(native_socket descriptor) -> bool
{
    std::array<std::byte, 4096> buffer {};
#ifdef _WIN32
    u_long nonblocking = 1;
    if (::ioctlsocket(static_cast<SOCKET>(descriptor), FIONBIO, &nonblocking) != 0)
        return false;
#endif
    for (int attempts = 0; attempts < 1024; ++attempts) {
#ifdef _WIN32
        const auto written = ::send(static_cast<SOCKET>(descriptor),
                                    reinterpret_cast<const char*>(buffer.data()),
                                    static_cast<int>(buffer.size()), 0);
        if (written >= 0) continue;
        return ::WSAGetLastError() == WSAEWOULDBLOCK;
#else
        const auto written = ::send(descriptor, buffer.data(), buffer.size(),
                                    MSG_DONTWAIT | MSG_NOSIGNAL);
        if (written >= 0) continue;
        if (errno == EINTR) continue;
        return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
    }
    return false;
}

auto duplicate_io_and_close() -> bool
{
    auto pair = connected_pair();
    if (!pair.client || !pair.server) return false;
    event_loop loop;
    auto socket = std::make_unique<tcp_stream>(
        loop, std::move(pair.client));
    auto* owner = socket.get();
    const native_socket descriptor = owner->descriptor();
    if (!fill_send_queue(descriptor)) return false;
    loop.add(std::move(socket));
    int pending_read = -1;
    int duplicate_read = -1;
    int pending_write = -1;
    int duplicate_write = -1;
    if (loop.spawn(read_result(loop, *owner, pending_read)) != task_spawn_result::accepted ||
        loop.spawn(read_result(loop, *owner, duplicate_read)) != task_spawn_result::accepted ||
        loop.spawn(write_result(loop, *owner, pending_write)) != task_spawn_result::accepted ||
        loop.spawn(write_result(loop, *owner, duplicate_write)) != task_spawn_result::accepted) {
        owner->close();
        return false;
    }
    owner->close();
    loop.stop();
    (void)loop.run();
    return pending_read == ECANCELED && duplicate_read == EBUSY &&
           pending_write == ECANCELED && duplicate_write == EBUSY &&
           closed_descriptor(descriptor) &&
           loop.coroutine_statistics().live == 0;
}

auto immediate_errors(event_loop& loop, tcp_stream& connected,
                      tcp_stream& disconnected, bool& passed)
    -> task<void>
{
    const auto already_connected = co_await connected.async_connect();
    std::array<std::byte, 1> buffer {};
    const auto not_connected = co_await disconnected.async_read_some(buffer);
    const auto empty = co_await connected.async_write_some(
        std::span<const std::byte> {});
    passed = !already_connected && already_connected.error().value() == EISCONN &&
             !not_connected && not_connected.error().value() == ENOTCONN &&
             empty && *empty == 0;
    loop.stop();
}

auto immediate_error_cases() -> bool
{
    auto pair = connected_pair();
    if (!pair.client || !pair.server) return false;
    event_loop loop;
    auto connected = std::make_unique<tcp_stream>(
        loop, std::move(pair.client));
    auto disconnected = std::make_unique<tcp_stream>(
        loop, ip_endpoint::loopback_v4(1));
    auto* ready = connected.get();
    auto* idle = disconnected.get();
    loop.add(std::move(connected));
    bool passed = false;
    if (loop.spawn(immediate_errors(loop, *ready, *idle, passed)) !=
        task_spawn_result::accepted) return false;
    (void)loop.run();
    ready->close();
    disconnected.reset();
    return passed && loop.coroutine_statistics().live == 0;
}

auto refused_connect() -> bool
{
    const auto port = unused_port();
    if (port == 0) return false;
    event_loop loop;
    auto socket = std::make_unique<tcp_stream>(
        loop, ip_endpoint::loopback_v4(port));
    auto* owner = socket.get();
    const native_socket descriptor = owner->descriptor();
    loop.add(std::move(socket));
    int error = -1;
    if (loop.spawn(connect_result(loop, *owner, error)) !=
        task_spawn_result::accepted) {
        owner->close();
        return false;
    }
#ifdef _WIN32
    constexpr auto timeout = 5s;
#else
    constexpr auto timeout = 1s;
#endif
    if (loop.spawn(shutdown_after(loop, timeout)) !=
        task_spawn_result::accepted) return false;
    const auto result = loop.run();
    // Pending connect errors remove themselves; synchronous errors leave the
    // registered socket available for explicit removal.
    if (!closed_descriptor(descriptor)) owner->close();
    loop.shutdown(0s);
    (void)loop.run();
    const bool passed = result == event_loop_result::stopped &&
#ifdef _WIN32
           error == WSAECONNREFUSED &&
#else
           error == ECONNREFUSED &&
#endif
           closed_descriptor(descriptor) &&
           loop.coroutine_statistics().live == 0;
    if (!passed) {
        std::cerr << "refused connect result=" << static_cast<int>(result)
                  << " error=" << error
                  << " closed=" << closed_descriptor(descriptor)
                  << " live=" << loop.coroutine_statistics().live << '\n';
    }
    return passed;
}

auto shutdown_pending() -> bool
{
    auto pair = connected_pair();
    if (!pair.client || !pair.server) return false;
    event_loop loop;
    auto listener = std::make_unique<tcp_acceptor>(loop, ip_endpoint::loopback_v4());
    auto socket = std::make_unique<tcp_stream>(
        loop, std::move(pair.client));
    auto* accepting = listener.get();
    auto* reading = socket.get();
    const native_socket listener_descriptor = accepting->descriptor();
    const native_socket socket_descriptor = reading->descriptor();
    loop.add(std::move(listener));
    loop.add(std::move(socket));
    int accept_error = -1;
    int read_error = -1;
    if (loop.spawn(accept_result(loop, *accepting, accept_error)) !=
            task_spawn_result::accepted ||
        loop.spawn(read_result(loop, *reading, read_error)) !=
            task_spawn_result::accepted) {
        loop.shutdown(0s);
        (void)loop.run();
        return false;
    }
    loop.shutdown(0s);
    return loop.run() == event_loop_result::stopped &&
           accept_error == ECANCELED && read_error == ECANCELED &&
           closed_descriptor(listener_descriptor) &&
           closed_descriptor(socket_descriptor) &&
           loop.coroutine_statistics().live == 0;
}

} // namespace

int main()
{
#ifdef _WIN32
    winsock_scope winsock;
#endif
    const auto check = [](bool passed, const char* name) {
        if (!passed) std::cerr << "coroutine TCP test failed: " << name << '\n';
        return passed;
    };
    if (!check(roundtrip(), "IPv4 roundtrip") ||
        (ipv6_loopback_available() &&
         !check(roundtrip(ip_endpoint::loopback_v6()), "IPv6 roundtrip")) ||
        !check(duplicate_accept_and_close(), "duplicate accept and close") ||
        !check(duplicate_io_and_close(), "duplicate I/O and close") ||
        !check(immediate_error_cases(), "immediate errors") ||
        !check(refused_connect(), "refused connect") ||
        !check(shutdown_pending(), "shutdown pending")) return 1;
}
