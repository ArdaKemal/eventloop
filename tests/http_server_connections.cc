// Connection deadlines from server_options: silent and slow new clients are
// closed after header_timeout, idle keep-alive connections after
// idle_timeout, and a handler slower than both still answers. Redirect
// listeners apply header_timeout and can share a port. One listener can hand
// its connections to other loops (serving_loops).
#include "eventloop/event_loop.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "tls_test_certificate.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <latch>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace eventloop;
using namespace std::chrono_literals;
using namespace std::string_view_literals;
using clock_type = event_loop::clock;

namespace {

constexpr auto header_timeout = 300ms;
constexpr auto idle_timeout = 600ms;
// Generous for loaded and sanitizer runs; the lower bounds are exact.
constexpr auto slack = 1500ms;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP server connections: " << message << '\n';
    std::exit(1);
}

auto check_closed_after(clock_type::duration elapsed, clock_type::duration timeout,
                        std::string_view name) -> void
{
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    std::cerr << name << ": closed after " << ms << " ms\n";
    check(elapsed >= timeout, std::string(name) + ": closed before its deadline");
    check(elapsed < timeout + slack, std::string(name) + ": not closed at its deadline");
}

auto bytes(std::string_view value) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(value));
}

auto fast(event_loop&, http::request&, http::response& response) -> task<void>
{
    (void)co_await response.async_send(200, {}, bytes("ok"));
}

// Outlasts both deadlines; the connection must wait for it.
auto slow(event_loop& loop, http::request&, http::response& response) -> task<void>
{
    (void)co_await sleep_for(loop, idle_timeout + 200ms);
    (void)co_await response.async_send(200, {}, bytes("ok"));
}

// Outlasts the idle timeouts used in this test.
auto hang(event_loop& loop, http::request&, http::response& response) -> task<void>
{
    (void)co_await sleep_for(loop, 5s);
    (void)co_await response.async_send(200, {}, bytes("late"));
}

auto routes() -> std::shared_ptr<http::router>
{
    auto table = std::make_shared<http::router>();
    check(table->add(http::method_type::get, "/fast", fast).has_value(), "route");
    check(table->add(http::method_type::get, "/slow", slow).has_value(), "route");
    check(table->add(http::method_type::get, "/hang", hang).has_value(), "route");
    return table;
}

auto options() -> http::server_options
{
    return {.routes = routes(), .header_timeout = header_timeout, .idle_timeout = idle_timeout};
}

// Unwraps tcp_stream's direct result and tls_stream's task result.
auto transferred(std::expected<std::size_t, std::error_code> result) -> std::size_t
{
    return result ? *result : 0;
}
auto transferred(std::expected<std::expected<std::size_t, std::error_code>, task_result> result)
    -> std::size_t
{
    return result && *result ? **result : 0;
}

template<typename Stream>
auto write_all(event_loop& loop, Stream& stream, std::string_view data) -> task<bool>
{
    (void)loop;
    auto pending = bytes(data);
    while (!pending.empty()) {
        const auto written = transferred(co_await stream.async_write_some(pending));
        if (written == 0) co_return false;
        pending = pending.subspan(written);
    }
    co_return true;
}

// Reads until text arrives; false if the connection closes first.
template<typename Stream>
auto read_until(event_loop& loop, Stream& stream, std::string_view text,
                std::string* received = nullptr) -> task<bool>
{
    (void)loop;
    std::string local;
    auto& data = received != nullptr ? *received : local;
    std::array<std::byte, 1024> buffer {};
    while (data.find(text) == std::string::npos) {
        const auto size = transferred(co_await stream.async_read_some(buffer));
        if (size == 0) co_return false;
        data.append(reinterpret_cast<const char*>(buffer.data()), size);
    }
    co_return true;
}

// Waits for the server to close the connection; returns when it did. A
// failed read may already have removed the stream from the loop, so clients
// leave closed streams to the loop's shutdown.
template<typename Stream>
auto read_until_closed(event_loop& loop, Stream& stream) -> task<clock_type::time_point>
{
    (void)loop;
    std::array<std::byte, 1024> buffer {};
    while (transferred(co_await stream.async_read_some(buffer)) != 0) {}
    co_return clock_type::now();
}

auto connect(event_loop& loop, std::uint16_t port) -> task<tcp_stream*>
{
    auto owned = std::make_unique<tcp_stream>(loop, ip_endpoint::loopback_v4(port));
    auto* peer = owned.get();
    loop.add(std::move(owned));
    check(static_cast<bool>(co_await peer->async_connect()), "connect");
    co_return peer;
}

auto connect_tls(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
                 std::string protocol) -> task<tls_stream*>
{
    auto owned = std::make_unique<tls_stream>(loop, ip_endpoint::loopback_v4(port),
        std::move(context), tls_client_options {.hostname = "localhost",
                                                .application_protocols = {protocol}});
    auto* peer = owned.get();
    loop.add(std::move(owned));
    check(static_cast<bool>(co_await peer->async_connect()), "TLS connect");
    const auto handshake = co_await peer->async_handshake();
    check(handshake && *handshake, "TLS handshake");
    check(peer->application_protocol() == protocol, "ALPN");
    co_return peer;
}

// A client that never sends a byte, on a plain or TLS listener.
auto silent(event_loop& loop, std::uint16_t port, std::string_view name) -> task<void>
{
    const auto start = clock_type::now();
    auto* peer = (co_await connect(loop, port)).value();
    const auto closed = (co_await read_until_closed(loop, *peer)).value();
    check_closed_after(closed - start, header_timeout, name);
}

// Trickling a request head does not extend its deadline. A raw socket keeps
// the client independent of the loop removing a failed stream.
auto trickle(event_loop& loop, std::uint16_t port, std::string_view name) -> task<void>
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    check(fd != -1, "socket");
    sockaddr_in address {.sin_family = AF_INET, .sin_port = htons(port),
                         .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}, .sin_zero = {}};
    check(::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0,
          "connect");
    const auto start = clock_type::now();
    constexpr auto head = "GET /fast HTTP/1.1\r\n"sv;
    check(::send(fd, head.data(), head.size(), MSG_NOSIGNAL) ==
          static_cast<ssize_t>(head.size()), "send");
    for (int i = 0; i < 100; ++i) {
        (void)co_await sleep_for(loop, 20ms);
        char byte = 0;
        if (::recv(fd, &byte, 1, MSG_DONTWAIT) == 0 || ::send(fd, "x", 1, MSG_NOSIGNAL) != 1) {
            check_closed_after(clock_type::now() - start, header_timeout, name);
            ::close(fd);
            co_return;
        }
    }
    check(false, std::string(name) + ": never closed");
}

// A slow handler answers; keep-alive survives a pause shorter than the idle
// timeout, then the idle connection closes.
template<typename Stream>
auto keep_alive(event_loop& loop, Stream& peer, std::string_view name) -> task<void>
{
    constexpr auto request = "GET /slow HTTP/1.1\r\nHost: a\r\n\r\n"sv;
    const auto sent = co_await write_all(loop, peer, request);
    check(sent && *sent, "send slow request");
    const auto answered = co_await read_until(loop, peer, "\r\n\r\nok");
    check(answered && *answered, "slow response");
    (void)co_await sleep_for(loop, idle_timeout / 2);
    const auto resent = co_await write_all(loop, peer, "GET /fast HTTP/1.1\r\nHost: a\r\n\r\n");
    check(resent && *resent, "send keep-alive request");
    const auto reanswered = co_await read_until(loop, peer, "\r\n\r\nok");
    check(reanswered && *reanswered, "keep-alive response");
    const auto start = clock_type::now();
    const auto closed = co_await read_until_closed(loop, peer);
    check(closed.has_value(), "read until closed");
    check_closed_after(*closed - start, idle_timeout, name);
}

auto plain_keep_alive(event_loop& loop, std::uint16_t port) -> task<void>
{
    auto* peer = (co_await connect(loop, port)).value();
    (void)co_await keep_alive(loop, *peer, "HTTP/1.1 idle");
}

auto tls_keep_alive(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context)
    -> task<void>
{
    auto* peer = (co_await connect_tls(loop, port, std::move(context), "http/1.1")).value();
    (void)co_await keep_alive(loop, *peer, "HTTPS HTTP/1.1 idle");
}

// HPACK for GET https://a/slow: indexed :method and :scheme, literal :path
// and :authority with indexed names.
constexpr std::string_view http2_request =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    "\x00\x00\x00\x04\x00\x00\x00\x00\x00"                       // SETTINGS
    "\x00\x00\x0c\x01\x05\x00\x00\x00\x01"                       // HEADERS, stream 1
    "\x82\x87\x04\x05/slow\x01\x01" "a"sv;

// Slow handler, then the idle HTTP/2 connection closes.
auto http2_idle(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context)
    -> task<void>
{
    auto* peer = (co_await connect_tls(loop, port, std::move(context), "h2")).value();
    check((co_await write_all(loop, *peer, http2_request)).value(), "send h2 request");
    // The DATA frame carrying the body.
    check((co_await read_until(loop, *peer, "ok")).value(), "h2 response");
    const auto start = clock_type::now();
    const auto closed = (co_await read_until_closed(loop, *peer)).value();
    check_closed_after(closed - start, idle_timeout, "HTTP/2 idle");
}

// An HTTP/2 client that never opens a stream.
auto http2_silent(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context)
    -> task<void>
{
    const auto start = clock_type::now();
    auto* peer = (co_await connect_tls(loop, port, std::move(context), "h2")).value();
    check((co_await write_all(loop, *peer, http2_request.substr(0, 33))).value(),
          "send h2 preface");
    const auto closed = (co_await read_until_closed(loop, *peer)).value();
    check_closed_after(closed - start, header_timeout, "HTTP/2 without a request");
}

auto port_of(const tcp_acceptor& listener) -> std::uint16_t
{
    sockaddr_in address {};
    socklen_t length = sizeof(address);
    check(::getsockname(listener.descriptor(), reinterpret_cast<sockaddr*>(&address), &length) == 0,
          "getsockname");
    return ntohs(address.sin_port);
}

auto watchdog(event_loop& loop) -> task<void>
{
    if (co_await sleep_for(loop, 10s) == timer_wait_result::expired) check(false, "timed out");
}

auto stop_after(event_loop& loop, task<void> client) -> task<void>
{
    check(co_await std::move(client) == task_result::success, "client completed");
    loop.stop();
}

template<typename Server, typename Client>
auto run_case(event_loop& loop, std::unique_ptr<Server> listener, Client client) -> void
{
    auto* server = listener.get();
    loop.add(std::move(listener));
    check(loop.spawn(server->run()) == task_spawn_result::accepted, "spawn server");
    check(loop.spawn(stop_after(loop, client(*server, port_of(*server)))) ==
              task_spawn_result::accepted,
          "spawn client");
    task_handle<void> timer;
    check(loop.spawn(watchdog(loop), timer) == task_spawn_result::accepted, "spawn watchdog");
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
}

// serving_loops: listeners on one loop hand connections to it and two other
// loops in turn; the route records which thread served each request.
struct served_threads {
    std::mutex mutex;
    std::set<std::thread::id> ids;
};

auto where(event_loop&, http::request& request, http::response& response) -> task<void>
{
    auto& seen = *static_cast<served_threads*>(request.route_context());
    {
        const std::lock_guard lock {seen.mutex};
        seen.ids.insert(std::this_thread::get_id());
    }
    (void)co_await response.async_send(200, {}, bytes("here"));
}

template<typename Stream>
auto handoff_requests(event_loop& loop, std::size_t count, std::uint16_t port,
                      std::shared_ptr<tls_context> context, std::string_view request,
                      std::string_view expected, std::string_view name) -> task<void>
{
    for (std::size_t index = 0; index < count; ++index) {
        // Awaited results are named first: GCC rejects (co_await ...).value()
        // inside this template.
        Stream* peer = nullptr;
        if constexpr (std::is_same_v<Stream, tls_stream>) {
            auto connected = co_await connect_tls(loop, port, context, "http/1.1");
            peer = connected.value();
        } else {
            auto connected = co_await connect(loop, port);
            peer = connected.value();
        }
        const auto sent = co_await write_all(loop, *peer, request);
        check(sent && *sent, std::string(name) + ": send");
        std::string received;
        const auto answered = co_await read_until(loop, *peer, expected, &received);
        check(answered && *answered, std::string(name) + ": response " + received);
        (void)co_await read_until_closed(loop, *peer);
    }
}

auto handoff_client(event_loop& loop, std::uint16_t plain, std::uint16_t secure,
                    std::uint16_t redirect, std::shared_ptr<tls_context> context) -> task<void>
{
    constexpr auto request = "GET /where HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"sv;
    co_await handoff_requests<tcp_stream>(loop, 9, plain, {}, request, "here",
                                          "hand-off HTTP/1.1");
    co_await handoff_requests<tls_stream>(loop, 6, secure, context, request, "here",
                                          "hand-off HTTPS");
    co_await handoff_requests<tcp_stream>(loop, 2, redirect, {},
                                          "GET /x HTTP/1.1\r\nHost: a\r\n\r\n"sv,
                                          "Location: https://localhost/x", "hand-off redirect");
}

auto handoff_case(const std::filesystem::path& certificate, const std::filesystem::path& key)
    -> void
{
    std::array<event_loop*, 2> others {};
    std::latch ready {2};
    std::vector<std::jthread> threads;
    for (std::size_t index = 0; index < others.size(); ++index) {
        threads.emplace_back([&, index] {
            event_loop serving;
            others[index] = &serving;
            ready.count_down();
            (void)serving.run(); // until the listener loop is done with it
            serving.shutdown(0ms);
            (void)serving.run();
        });
    }
    ready.wait();

    served_threads plain_seen, secure_seen;
    {
        event_loop loop;
        const auto table = [](served_threads& seen) {
            auto result = std::make_shared<http::router>();
            check(result->add(http::method_type::get, "/where", where, &seen).has_value(),
                  "route");
            return result;
        };
        const auto options = [&](served_threads& seen) {
            return http::server_options {.routes = table(seen),
                                         .serving_loops = {&loop, others[0], others[1]}};
        };
        auto plain = std::make_unique<http::server>(loop, ip_endpoint::loopback_v4(0),
                                                    options(plain_seen));
        auto secure = std::make_unique<http::https_server>(loop, ip_endpoint::loopback_v4(0),
            tls_context::make_server(certificate, key), options(secure_seen));
        auto redirect = std::make_unique<http::redirect_server>(loop,
            ip_endpoint::loopback_v4(0), "localhost", 443,
            http::server_options {.serving_loops = {others[1]}});
        const auto ports = std::array {port_of(*plain), port_of(*secure), port_of(*redirect)};
        auto* plain_server = plain.get();
        auto* secure_server = secure.get();
        auto* redirect_server = redirect.get();
        loop.add(std::move(plain));
        loop.add(std::move(secure));
        loop.add(std::move(redirect));
        check(loop.spawn(plain_server->run()) == task_spawn_result::accepted, "spawn plain");
        check(loop.spawn(secure_server->run()) == task_spawn_result::accepted, "spawn TLS");
        check(loop.spawn(redirect_server->run()) == task_spawn_result::accepted,
              "spawn redirect");
        check(loop.spawn(stop_after(loop, handoff_client(loop, ports[0], ports[1], ports[2],
                  tls_context::make_client(certificate)))) == task_spawn_result::accepted,
              "spawn hand-off client");
        task_handle<void> timer;
        check(loop.spawn(watchdog(loop), timer) == task_spawn_result::accepted,
              "spawn watchdog");
        (void)loop.run();
        if (!timer.done()) (void)timer.cancel();
        loop.shutdown(0ms);
        (void)loop.run();
    }
    // The listeners are gone, so nothing posts to the serving loops any more.
    for (auto* other : others) other->stop();
    threads.clear();
    check(plain_seen.ids.size() == 3, "HTTP/1.1 connections served on all three loops");
    check(secure_seen.ids.size() == 3, "HTTPS connections served on all three loops");
    std::cerr << "hand-off: HTTP/1.1, HTTPS, and redirect served across loops\n";
}

// Sends two keep-alive GETs for /file.bin, the second closing; counts the
// response bytes until the server closes, then stops this client loop.
auto fetch_file(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
                std::size_t& received) -> task<void>
{
    auto* peer = (co_await connect_tls(loop, port, std::move(context), "http/1.1")).value();
    const auto sent = co_await write_all(loop, *peer,
        "GET /file.bin HTTP/1.1\r\nHost: a\r\n\r\n"
        "GET /file.bin HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    check(sent && *sent, "send file requests");
    std::array<std::byte, 1024> buffer {};
    while (const auto size = transferred(co_await peer->async_read_some(buffer)))
        received += size;
    loop.stop();
}

// An HTTPS connection holds its connection frame for its lifetime, so the
// frame must fit the 1 KiB class, whose default 40,960 slots size a loop for
// 10k connections; larger classes have only a few. This server loop has none
// above 1 KiB. A client on its own loop fetches a static file twice over one
// connection, which also exercises the userspace TLS file path.
auto https_frame_class_case(const std::filesystem::path& directory,
                            const std::filesystem::path& certificate,
                            const std::filesystem::path& key) -> void
{
    const auto root = directory / "root";
    std::filesystem::create_directories(root);
    constexpr std::size_t file_size = 100 * 1024;
    {
        std::ofstream file(root / "file.bin", std::ios::binary);
        file << std::string(file_size, 'x');
    }
    event_loop_options loop_options;
    loop_options.coroutine_frame_capacities[4] = 0;
    loop_options.coroutine_frame_capacities[5] = 0;
    event_loop loop(loop_options);
    auto server_options = options();
    server_options.document_root = root;
    auto listener = std::make_unique<http::https_server>(loop, ip_endpoint::loopback_v4(0),
        tls_context::make_server(certificate, key), server_options);
    const auto port = port_of(*listener);
    std::size_t received = 0;
    std::jthread client_thread([&] {
        event_loop client;
        check(client.spawn(fetch_file(client, port, tls_context::make_client(certificate),
                                 received)) == task_spawn_result::accepted, "spawn file client");
        (void)client.run();
        client.shutdown(0ms);
        (void)client.run();
        loop.stop();
    });
    auto* server = listener.get();
    loop.add(std::move(listener));
    check(loop.spawn(server->run()) == task_spawn_result::accepted, "spawn server");
    task_handle<void> timer;
    check(loop.spawn(watchdog(loop), timer) == task_spawn_result::accepted, "spawn watchdog");
    (void)loop.run();
    client_thread.join();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    check(received > 2 * file_size, "HTTPS keep-alive file responses within 1 KiB frames");
    std::cerr << "HTTPS keep-alive file responses within 1 KiB frames\n";
}

} // namespace

auto main() -> int
{
    const auto plain = [](auto client) {
        event_loop loop;
        run_case(loop, std::make_unique<http::server>(loop, ip_endpoint::loopback_v4(0), options()),
                 [&](http::server& server, std::uint16_t port) {
                     if constexpr (std::is_invocable_v<decltype(client), event_loop&,
                                                       http::server&, std::uint16_t>)
                         return client(loop, server, port);
                     else
                         return client(loop, port);
                 });
    };
    plain([](event_loop& loop, std::uint16_t port) { return silent(loop, port, "HTTP/1.1 silent"); });
    plain([](event_loop& loop, std::uint16_t port) {
        return trickle(loop, port, "HTTP/1.1 trickled head");
    });
    plain(plain_keep_alive);

    const auto redirect = [](auto client) {
        event_loop loop;
        auto options = ::options();
        options.reuse_port = true;
        auto listener = std::make_unique<http::redirect_server>(
            loop, ip_endpoint::loopback_v4(0), "localhost", 443, options);
        // A second listener with the same options binds the same port. It is
        // closed before serving, since the kernel would hand it connections.
        (void)http::redirect_server(
            loop, ip_endpoint::loopback_v4(port_of(*listener)), "localhost", 443, options);
        run_case(loop, std::move(listener),
                 [&](http::redirect_server&, std::uint16_t port) { return client(loop, port); });
    };
    redirect([](event_loop& loop, std::uint16_t port) {
        return silent(loop, port, "redirect silent");
    });
    redirect([](event_loop& loop, std::uint16_t port) {
        return trickle(loop, port, "redirect trickled head");
    });

    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-connections-" + std::to_string(::getpid()));
    std::filesystem::create_directories(directory);
    const auto certificate = directory / "cert.pem";
    const auto key = directory / "key.pem";
    test::make_localhost_certificate(certificate, key);
    const auto secure = [&](auto client) {
        event_loop loop;
        run_case(loop, std::make_unique<http::https_server>(loop, ip_endpoint::loopback_v4(0),
                     tls_context::make_server(certificate, key), options()),
                 [&](http::https_server& server, std::uint16_t port) {
                     auto context = tls_context::make_client(certificate);
                     if constexpr (std::is_invocable_v<decltype(client), event_loop&,
                                       http::https_server&, std::uint16_t,
                                       std::shared_ptr<tls_context>>)
                         return client(loop, server, port, std::move(context));
                     else
                         return client(loop, port, std::move(context));
                 });
    };
    secure([](event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context>) {
        return silent(loop, port, "HTTPS without a ClientHello");
    });
    secure(tls_keep_alive);
    secure(http2_silent);
    secure(http2_idle);
    handoff_case(certificate, key);
    https_frame_class_case(directory, certificate, key);
    std::filesystem::remove_all(directory);
}
