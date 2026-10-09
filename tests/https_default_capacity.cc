// An HTTPS server on a loop with default options holds many concurrent
// HTTP/1.1 and HTTP/2 connections. Each TLS connection keeps a frame above
// 1 KiB, so the default 2 KiB class must cover more than a handful of peers.
// Clients run on their own loop so only the server's frames are counted.
#include "eventloop/event_loop.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "tls_test_certificate.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace eventloop;
using namespace std::chrono_literals;
using namespace std::string_view_literals;

namespace {

constexpr std::size_t connections = 64;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTPS default capacity: " << message << '\n';
    std::exit(1);
}

auto hello(event_loop&, http::request&, http::response& response) -> task<void>
{
    (void)co_await response.async_send(200, {}, std::as_bytes(std::span("hi"sv)));
}

struct client_state {
    std::size_t answered {0};
    std::size_t finished {0};
    bool release {false};
};

// Gets a first response, then holds the connection until every client has one.
auto client(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
            bool http2, client_state& state) -> task<void>
{
    auto owned = std::make_unique<tls_stream>(loop, ip_endpoint::loopback_v4(port),
        std::move(context), tls_client_options {.hostname = "localhost",
            .application_protocols = {http2 ? "h2" : "http/1.1"}});
    auto& peer = *owned;
    loop.add(std::move(owned));
    check(static_cast<bool>(co_await peer.async_connect()), "TLS connect");
    const auto handshake = co_await peer.async_handshake();
    check(handshake && *handshake, "TLS handshake");
    const auto request = http2
        ? "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00"sv
        : "GET /hello HTTP/1.1\r\nHost: a\r\n\r\n"sv;
    auto pending = std::as_bytes(std::span(request));
    while (!pending.empty()) {
        const auto written = co_await peer.async_write_some(pending);
        check(written && *written && **written != 0, "send request");
        pending = pending.subspan(**written);
    }
    std::array<std::byte, 64> response {};
    const auto received = co_await peer.async_read_some(response);
    check(received && *received && **received >= 9, "server answered");
    // HTTP/2 servers open with SETTINGS (frame type 4); HTTP/1.1 with a status line.
    const std::string_view text {reinterpret_cast<const char*>(response.data()), **received};
    check(http2 ? response[3] == std::byte {4} : text.starts_with("HTTP/1.1 200"),
          "expected response");
    ++state.answered;
    while (!state.release) (void)co_await sleep_for(loop, 1ms);
    peer.close();
    if (++state.finished == connections) loop.stop();
}

auto release_when_answered(event_loop& loop, client_state& state) -> task<void>
{
    for (int waited = 0; state.answered != connections; ++waited) {
        check(waited < 5000, "timed out with " + std::to_string(state.answered) +
                             " connections answered");
        (void)co_await sleep_for(loop, 1ms);
    }
    state.release = true;
}

auto port_of(const tcp_acceptor& listener) -> std::uint16_t
{
    sockaddr_in address {};
    socklen_t length = sizeof(address);
    check(::getsockname(listener.descriptor(), reinterpret_cast<sockaddr*>(&address),
                        &length) == 0, "getsockname");
    return ntohs(address.sin_port);
}

} // namespace

auto main() -> int
{
    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-https-capacity-" + std::to_string(::getpid()));
    std::filesystem::create_directories(directory);
    const auto certificate = directory / "cert.pem";
    const auto key = directory / "key.pem";
    test::make_localhost_certificate(certificate, key);

    // The server loop is built, run and destroyed on its own thread; it
    // publishes its port and itself, and the main thread may only stop() it.
    std::atomic<std::uint16_t> port {0};
    std::atomic<event_loop*> server_loop {nullptr};
    std::thread serving([&] {
        auto routes = std::make_shared<http::router>();
        check(routes->add(http::method_type::get, "/hello", hello).has_value(), "route");
        event_loop loop;
        auto listener = std::make_unique<http::https_server>(loop,
            ip_endpoint::loopback_v4(0), tls_context::make_server(certificate, key),
            http::server_options {.routes = routes});
        auto* server = listener.get();
        const auto bound = port_of(*server);
        loop.add(std::move(listener));
        check(loop.spawn(server->run()) == task_spawn_result::accepted, "spawn server");
        server_loop = &loop;
        port = bound;
        (void)loop.run();
        loop.shutdown(0ms);
        (void)loop.run();
    });
    while (port == 0) std::this_thread::yield();

    {
        event_loop_options options;
        options.coroutine_frame_capacities.fill(4 * connections);
        event_loop loop(options);
        client_state state;
        const auto context = tls_context::make_client(certificate);
        for (std::size_t index = 0; index < connections; ++index) {
            check(loop.spawn(client(loop, port, context, index % 2 == 1, state)) ==
                  task_spawn_result::accepted, "spawn client");
        }
        check(loop.spawn(release_when_answered(loop, state)) == task_spawn_result::accepted,
              "spawn release");
        (void)loop.run();
        loop.shutdown(0ms);
        (void)loop.run();
    }

    server_loop.load()->stop();
    serving.join();
    std::filesystem::remove_all(directory);
}
