// Counts general-heap allocations made while a kept-alive HTTP/1.1
// connection serves routed GET, POST and chunked POST requests. Connection setup and the
// first requests may allocate (sockets, session, pool slabs); steady-state
// routed requests must not.
#include "eventloop/event_loop.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/tcp_stream.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <new>
#include <span>
#include <string_view>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace {
std::atomic<std::size_t> allocations {0};
} // namespace

auto operator new(std::size_t size) -> void*
{
    allocations.fetch_add(1, std::memory_order_relaxed);
    if (void* pointer = std::malloc(size == 0 ? 1 : size)) return pointer;
    throw std::bad_alloc();
}
auto operator new[](std::size_t size) -> void* { return operator new(size); }
auto operator new(std::size_t size, const std::nothrow_t&) noexcept -> void*
{
    allocations.fetch_add(1, std::memory_order_relaxed);
    return std::malloc(size == 0 ? 1 : size);
}
auto operator new[](std::size_t size, const std::nothrow_t& tag) noexcept -> void*
{
    return operator new(size, tag);
}
auto operator delete(void* pointer) noexcept -> void { std::free(pointer); }
auto operator delete[](void* pointer) noexcept -> void { std::free(pointer); }
auto operator delete(void* pointer, std::size_t) noexcept -> void { std::free(pointer); }
auto operator delete[](void* pointer, std::size_t) noexcept -> void { std::free(pointer); }

using namespace eventloop;
using namespace std::chrono_literals;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP routing allocations: " << message << '\n';
    std::exit(1);
}

auto hello(event_loop&, http::request&, http::response& response) -> task<void>
{
    const std::array<http::header, 1> fields {{{"content-type", "text/plain"}}};
    constexpr std::string_view body = "hello";
    (void)co_await response.async_send(200, fields, std::as_bytes(std::span(body)));
}

auto upload(event_loop&, http::request& request, http::response& response) -> task<void>
{
    std::array<std::byte, 64> chunk {};
    for (;;) {
        auto read = co_await request.async_read_body(chunk);
        if (!read || !*read || **read == 0) break;
    }
    if (!co_await response.async_start(200, {})) co_return;
    constexpr std::string_view body = "stored";
    (void)co_await response.async_write(std::as_bytes(std::span(body)));
    (void)co_await response.async_finish();
}

struct measurement {
    std::size_t setup_allocations {0};
    std::size_t steady_allocations {0};
    std::size_t requests {0};
    bool done {false};
};

// Sends one request and reads exactly one response. Returns false on error.
auto round_trip(event_loop& loop, tcp_stream& peer, std::string_view request,
                std::array<std::byte, 1024>& buffer) -> task<bool>
{
    (void)loop;
    auto pending = std::as_bytes(std::span(request));
    while (!pending.empty()) {
        const auto written = co_await peer.async_write_some(pending);
        if (!written || *written == 0) co_return false;
        pending = pending.subspan(*written);
    }
    // Responses end either at content-length or at the final empty chunk.
    std::size_t size = 0;
    for (;;) {
        const auto received = co_await peer.async_read_some(std::span(buffer).subspan(size));
        if (!received || *received == 0) co_return false;
        size += *received;
        const std::string_view view(reinterpret_cast<const char*>(buffer.data()), size);
        const auto head_end = view.find("\r\n\r\n");
        if (head_end == std::string_view::npos) continue;
        if (view.find("transfer-encoding: chunked") < head_end) {
            if (view.ends_with("0\r\n\r\n")) co_return true;
            continue;
        }
        const auto length_at = view.find("content-length: ");
        if (length_at == std::string_view::npos || length_at > head_end) co_return false;
        const auto length = std::strtoul(view.data() + length_at + 16, nullptr, 10);
        if (size >= head_end + 4 + length) co_return true;
    }
}

auto client(event_loop& loop, std::uint16_t port, measurement& result) -> task<void>
{
    auto owned = std::make_unique<tcp_stream>(loop, ip_endpoint::loopback_v4(port));
    auto* peer = owned.get();
    loop.add(std::move(owned));
    constexpr std::string_view get = "GET /hello HTTP/1.1\r\nHost: a\r\n\r\n";
    constexpr std::string_view post =
        "POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\n"
        "0123456789012345678901234567890123456789012345678901234567890123456789"
        "012345678901234567890123456789";
    constexpr std::string_view chunked_post =
        "POST /upload HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
        "1e;part=1\r\n012345678901234567890123456789\r\n"
        "46\r\n0123456789012345678901234567890123456789012345678901234567890123456789\r\n"
        "0\r\nX-Sum: 100\r\n\r\n";
    const std::array<std::string_view, 3> rotation {get, post, chunked_post};
    std::array<std::byte, 1024> buffer {};
    if (co_await peer->async_connect()) {
        constexpr std::size_t warmup = 4;
        constexpr std::size_t measured = 42;
        std::size_t before = 0;
        bool ok = true;
        for (std::size_t index = 0; ok && index < warmup + measured; ++index) {
            if (index == warmup) before = allocations.load();
            ok = (co_await round_trip(loop, *peer, rotation[index % rotation.size()], buffer))
                     .value_or(false);
        }
        if (ok) {
            result.setup_allocations = before;
            result.steady_allocations = allocations.load() - before;
            result.requests = measured;
            result.done = true;
        }
    }
    peer->close();
    loop.stop();
}

auto watchdog(event_loop& loop, bool& timed_out) -> task<void>
{
    if (co_await sleep_for(loop, 5s) == timer_wait_result::expired) {
        timed_out = true;
        loop.shutdown(0ms);
    }
}

} // namespace

auto main() -> int
{
    auto routes = std::make_shared<http::router>();
    check(routes->add(http::method_type::get, "/hello", hello).has_value() &&
          routes->add(http::method_type::post, "/upload", upload).has_value(), "routes");
    event_loop loop;
    auto listener = std::make_unique<http::server>(loop, ip_endpoint::loopback_v4(0),
        http::server_options {.routes = routes});
    sockaddr_in address {};
    socklen_t length = sizeof(address);
    check(::getsockname(listener->descriptor(), reinterpret_cast<sockaddr*>(&address),
                        &length) == 0, "getsockname");
    auto* server = listener.get();
    loop.add(std::move(listener));
    check(loop.spawn(server->run()) == task_spawn_result::accepted, "spawn server");
    measurement result;
    check(loop.spawn(client(loop, ntohs(address.sin_port), result)) ==
          task_spawn_result::accepted, "spawn client");
    bool timed_out = false;
    task_handle<void> timer;
    check(loop.spawn(watchdog(loop, timed_out), timer) == task_spawn_result::accepted,
          "spawn watchdog");
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    check(!timed_out && result.done, "requests did not complete");
    // Setup allocates (sockets, session, routing state), proving the hook counts.
    check(result.setup_allocations > 0, "allocation counter is not active");
    if (result.steady_allocations != 0) {
        std::cerr << "HTTP routing allocations: " << result.steady_allocations
                  << " allocations over " << result.requests << " routed requests\n";
        return 1;
    }
}
