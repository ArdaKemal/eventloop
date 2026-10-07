// A routed handler that waits across loop iterations, then responds after
// its client has reset the connection. The reset removes the stream from the
// loop; the connection task and the handler's response must still be safe to
// use, and the late writes must fail instead of touching freed memory.
#include "eventloop/event_loop.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "tls_test_certificate.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace eventloop;
using namespace std::chrono_literals;
using namespace std::string_view_literals;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP connection lifetime: " << message << '\n';
    std::exit(1);
}

auto bytes(std::string_view value) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(value));
}

struct handler_state {
    bool started {false};
    bool done {false};
    bool write_failed {false};
};

// Waits past the client's reset, then streams a response.
auto late(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& state = *static_cast<handler_state*>(request.route_context());
    state.started = true;
    (void)co_await sleep_for(loop, 150ms);
    const auto started = co_await response.async_start(200, {});
    const auto written = co_await response.async_write(bytes("late"));
    const auto finished = co_await response.async_finish();
    state.write_failed = !(started && *started) || !(written && *written) ||
                         !(finished && *finished);
    state.done = true;
}

// Reuses freed heap chunks of every small size class, so a stale stream
// pointer reads garbage rather than the freed object's old contents.
auto scribble() -> std::vector<std::unique_ptr<std::byte[]>>
{
    std::vector<std::unique_ptr<std::byte[]>> blocks;
    for (std::size_t round = 0; round < 4; ++round) {
        for (std::size_t size = 16; size <= 8192; size += 16) {
            auto block = std::make_unique<std::byte[]>(size);
            std::memset(block.get(), 0xa5, size);
            blocks.push_back(std::move(block));
        }
    }
    return blocks;
}

auto write_all(event_loop& loop, tcp_stream& stream, std::string_view data) -> task<bool>
{
    (void)loop;
    auto pending = bytes(data);
    while (!pending.empty()) {
        const auto written = co_await stream.async_write_some(pending);
        if (!written || *written == 0) co_return false;
        pending = pending.subspan(*written);
    }
    co_return true;
}

auto write_all(event_loop& loop, tls_stream& stream, std::string_view data) -> task<bool>
{
    (void)loop;
    auto pending = bytes(data);
    while (!pending.empty()) {
        const auto written = co_await stream.async_write_some(pending);
        if (!written || !*written || **written == 0) co_return false;
        pending = pending.subspan(**written);
    }
    co_return true;
}

// Sends a request, resets the connection while the handler waits, and lets
// the handler finish against the removed stream.
template<typename Client>
auto reset_while_waiting(event_loop& loop, Client& peer, const handler_state& state)
    -> task<void>
{
    while (!state.started) (void)co_await sleep_for(loop, 1ms);
    const linger abort {.l_onoff = 1, .l_linger = 0};
    check(::setsockopt(peer.descriptor(), SOL_SOCKET, SO_LINGER, &abort, sizeof(abort)) == 0,
          "SO_LINGER");
    peer.close();
    (void)co_await sleep_for(loop, 30ms); // the server sees the reset
    const auto reused = scribble();
    while (!state.done) (void)co_await sleep_for(loop, 5ms);
}

auto plain_client(event_loop& loop, std::uint16_t port, const handler_state& state)
    -> task<void>
{
    auto owned = std::make_unique<tcp_stream>(loop, ip_endpoint::loopback_v4(port));
    auto& peer = *owned;
    loop.add(std::move(owned));
    check(static_cast<bool>(co_await peer.async_connect()), "connect");
    check((co_await write_all(loop, peer, "GET /late HTTP/1.1\r\nHost: a\r\n\r\n")).value_or(false),
          "send request");
    co_await reset_while_waiting(loop, peer, state);
    loop.stop();
}

// HPACK for GET https://a/late: indexed :method and :scheme, literal :path
// and :authority with indexed names.
constexpr std::string_view http2_request =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    "\x00\x00\x00\x04\x00\x00\x00\x00\x00"                       // SETTINGS
    "\x00\x00\x0c\x01\x05\x00\x00\x00\x01"                       // HEADERS, stream 1
    "\x82\x87\x04\x05/late\x01\x01" "a"sv;

auto tls_client(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
                std::string protocol, const handler_state& state) -> task<void>
{
    auto owned = std::make_unique<tls_stream>(loop, ip_endpoint::loopback_v4(port),
        std::move(context), tls_client_options {.hostname = "localhost",
                                                .application_protocols = {protocol}});
    auto& peer = *owned;
    loop.add(std::move(owned));
    check(static_cast<bool>(co_await peer.async_connect()), "TLS connect");
    const auto handshake = co_await peer.async_handshake();
    check(handshake && *handshake, "TLS handshake");
    const auto request = protocol == "h2" ? http2_request
                                          : "GET /late HTTP/1.1\r\nHost: a\r\n\r\n"sv;
    check((co_await write_all(loop, peer, request)).value_or(false), "send TLS request");
    co_await reset_while_waiting(loop, peer, state);
    loop.stop();
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
    if (co_await sleep_for(loop, 5s) == timer_wait_result::expired) check(false, "timed out");
}

template<typename Server, typename Client>
auto run_case(std::string_view name, std::unique_ptr<Server> listener, Client client,
              event_loop& loop, handler_state& state) -> void
{
    auto* server = listener.get();
    loop.add(std::move(listener));
    check(loop.spawn(server->run()) == task_spawn_result::accepted, "spawn server");
    check(loop.spawn(client(port_of(*server))) == task_spawn_result::accepted, "spawn client");
    task_handle<void> timer;
    check(loop.spawn(watchdog(loop), timer) == task_spawn_result::accepted, "spawn watchdog");
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    check(state.done, std::string(name) + ": handler finished");
    check(state.write_failed, std::string(name) + ": writes after the reset fail");
}

auto routes_for(handler_state& state) -> std::shared_ptr<http::router>
{
    auto routes = std::make_shared<http::router>();
    check(routes->add(http::method_type::get, "/late", late, &state).has_value(), "route");
    return routes;
}

} // namespace

auto main() -> int
{
    {
        handler_state state;
        event_loop loop;
        run_case("HTTP/1.1",
            std::make_unique<http::server>(loop, ip_endpoint::loopback_v4(0),
                http::server_options {.routes = routes_for(state)}),
            [&](std::uint16_t port) { return plain_client(loop, port, state); }, loop, state);
    }

    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-lifetime-" + std::to_string(::getpid()));
    std::filesystem::create_directories(directory);
    const auto certificate = directory / "cert.pem";
    const auto key = directory / "key.pem";
    test::make_localhost_certificate(certificate, key);
    for (const std::string protocol : {"http/1.1", "h2"}) {
        handler_state state;
        event_loop loop;
        run_case(protocol,
            std::make_unique<http::https_server>(loop, ip_endpoint::loopback_v4(0),
                tls_context::make_server(certificate, key),
                http::server_options {.routes = routes_for(state)}),
            [&](std::uint16_t port) {
                return tls_client(loop, port, tls_context::make_client(certificate), protocol, state);
            }, loop, state);
    }
    std::filesystem::remove_all(directory);
}
