// Counts general-heap allocations while one HTTP/3 connection serves routed
// GET and POST requests, and, for comparison, static file GETs. Requests are
// encoded before measuring and the client reads into fixed buffers, so the
// count covers the server, the QUIC stack on both sides, and the loop.
#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"
#include "eventloop/quic.h"
#include "http3/frames.h"
#include "http3/qpack.h"
#include "tls_test_certificate.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <new>
#include <random>
#include <span>
#include <string_view>
#include <vector>

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
namespace h3 = eventloop::http3::detail;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP/3 routing allocations: " << message << '\n';
    std::exit(1);
}

auto hello(event_loop&, http::request&, http::response& response) -> task<void>
{
    constexpr std::string_view body = "hello";
    (void)co_await response.async_send(200, {}, std::as_bytes(std::span(body)));
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

auto encode(std::string_view method, std::string_view path, std::string_view body)
    -> std::vector<std::byte>
{
    const std::array<h3::field, 4> fields {{{":method", method}, {":scheme", "https"},
        {":authority", "localhost"}, {":path", path}}};
    std::vector<std::byte> block(512);
    const auto size = h3::qpack_encode(fields, block);
    check(size.has_value(), "encode request");
    std::vector<std::byte> request(*size + 16 + body.size() + 16);
    const auto framed = h3::encode_frame(h3::headers_frame,
        std::span(block).first(*size), request);
    check(framed.has_value(), "frame request");
    std::size_t used = *framed;
    if (!body.empty()) {
        const auto data = h3::encode_frame(h3::data_frame, std::as_bytes(std::span(body)),
                                           std::span(request).subspan(used));
        check(data.has_value(), "frame body");
        used += *data;
    }
    request.resize(used);
    return request;
}

struct measurement {
    std::size_t routed {0};
    std::size_t static_files {0};
    std::size_t requests {0};
    bool done {false};
};

// One request on a new stream; reads the response to FIN into buffer.
auto round_trip(event_loop&, quic_connection& connection, std::span<const std::byte> request,
                std::array<std::byte, 1024>& buffer) -> task<bool>
{
    const auto id = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!id) co_return false;
    while (!request.empty()) {
        const auto sent = flatten_result(co_await connection.async_write(*id, request, false));
        if (!sent || *sent == 0) co_return false;
        request = request.subspan(*sent);
    }
    if (!flatten_result(co_await connection.async_write(*id, {}, true))) co_return false;
    std::size_t total = 0;
    for (;;) {
        const auto got = flatten_result(co_await connection.async_read(*id, buffer));
        if (!got) co_return false;
        if (*got == 0) co_return total != 0;
        total += *got;
    }
}

auto client(event_loop& loop, quic_endpoint& endpoint, ip_endpoint server,
            const std::array<std::vector<std::byte>, 3>& requests, measurement& result)
    -> task<void>
{
    auto connected = flatten_result(co_await endpoint.async_connect(server, "localhost"));
    check(connected.has_value(), "connect");
    auto connection = std::move(*connected);
    const auto control = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::unidirectional));
    const std::array<std::byte, 3> settings {std::byte {0}, std::byte {4}, std::byte {0}};
    check(control && flatten_result(co_await connection.async_write(*control, settings, false)),
          "client control stream");
    std::array<std::byte, 1024> buffer {};
    constexpr std::size_t warmup = 6;
    constexpr std::size_t measured = 40;
    // Phase 0 alternates routed GET and POST; phase 1 repeats a static GET.
    for (int phase = 0; phase < 2; ++phase) {
        std::size_t before = 0;
        for (std::size_t index = 0; index < warmup + measured; ++index) {
            if (index == warmup) before = allocations.load();
            const auto& request = phase == 1 ? requests[2] : requests[index % 2];
            if (!(co_await round_trip(loop, connection, request, buffer)).value_or(false)) {
                check(false, "request failed");
            }
        }
        (phase == 0 ? result.routed : result.static_files) = allocations.load() - before;
    }
    result.requests = measured;
    result.done = true;
}

auto watch(event_loop& loop, http::http3_server& server, quic_endpoint& endpoint,
           measurement& result) -> task<void>
{
    for (int i = 0; i < 2000 && !result.done; ++i) (void)co_await sleep_for(loop, 5ms);
    co_await server.async_close();
    co_await endpoint.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

} // namespace

auto main() -> int
{
    std::random_device random;
    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-h3-allocations-" + std::to_string(random()));
    std::filesystem::create_directories(directory / "www");
    test::make_localhost_certificate(directory / "cert.pem", directory / "key.pem");
    std::ofstream(directory / "www" / "file.txt") << "static";

    auto routes = std::make_shared<http::router>();
    check(routes->add(http::method_type::get, "/hello", hello).has_value() &&
          routes->add(http::method_type::post, "/upload", upload).has_value(), "routes");
    const std::array<std::vector<std::byte>, 3> requests {
        encode("GET", "/hello", {}),
        encode("POST", "/upload", std::string_view(
            "0123456789012345678901234567890123456789012345678901234567890123456789")),
        encode("GET", "/file.txt", {}),
    };

    measurement result;
    {
        event_loop loop;
        http::http3_server server(loop, ip_endpoint::loopback_v4(0),
            directory / "cert.pem", directory / "key.pem",
            http::server_options {.routes = routes, .document_root = directory / "www",
                                  .connection_capacity = 1});
        quic_client_options options;
        constexpr std::array<std::uint8_t, 2> alpn {'h', '3'};
        options.alpn = alpn;
        options.trusted_ca = directory / "cert.pem";
        quic_endpoint endpoint(loop, ip_endpoint::loopback_v4(0), std::move(options));
        task_handle<void> serving;
        check(loop.spawn(server.run(), serving) == task_spawn_result::accepted, "spawn server");
        check(loop.spawn(client(loop, endpoint, server.local_endpoint(), requests, result)) ==
              task_spawn_result::accepted, "spawn client");
        check(loop.spawn(watch(loop, server, endpoint, result)) == task_spawn_result::accepted,
              "spawn watch");
        (void)loop.run();
    }
    std::filesystem::remove_all(directory);
    check(result.done, "requests did not complete");
    std::cout << "HTTP/3 allocations over " << result.requests << " requests: routed "
              << result.routed << ", static " << result.static_files << '\n';
    if (result.routed != 0) return 1;
}
