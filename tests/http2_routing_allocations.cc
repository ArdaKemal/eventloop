// Counts general-heap allocations per request on one HTTP/2 connection for
// routed GET and POST requests and for static file GETs. The raw client
// reuses pre-encoded frames and fixed buffers, so the counts cover the server,
// TLS, and the loop. Requests carry header values longer than the small-string
// buffer, as browsers do, so HPACK decoding must reuse string capacity.
// OpenSSL's own allocations are counted separately through its allocator
// hook. Steady-state requests must not allocate in either; OpenSSL is held to
// that only with transmit kTLS.
#include "eventloop/event_loop.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "http2/hpack.h"
#include "openssl_allocation_counter.h"
#include "tls_test_certificate.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <new>
#include <random>
#include <span>
#include <string_view>
#include <vector>

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
    std::cerr << "HTTP/2 routing allocations: " << message << '\n';
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

auto append_frame(std::vector<std::byte>& out, unsigned type, unsigned flags,
                  std::span<const std::byte> payload) -> void
{
    const auto size = payload.size();
    for (auto byte : {static_cast<unsigned>(size >> 16) & 255u, static_cast<unsigned>(size >> 8) & 255u,
                      static_cast<unsigned>(size) & 255u, type, flags, 0u, 0u, 0u, 0u})
        out.push_back(static_cast<std::byte>(byte));
    out.insert(out.end(), payload.begin(), payload.end());
}

// Request frames with stream ID zero; the client patches the ID per request.
auto encode(std::string_view method, std::string_view path, std::string_view body)
    -> std::vector<std::byte>
{
    const std::array<http2::detail::field, 6> fields {{{":method", std::string(method)},
        {":scheme", "https"}, {":authority", "localhost"}, {":path", std::string(path)},
        {"user-agent", "Mozilla/5.0 (X11; Linux x86_64) eventloop-allocation-test/1.0"},
        {"cookie", "session=0123456789abcdef0123456789abcdef; theme=dark; locale=en-GB"}}};
    std::vector<std::byte> block;
    check(http2::detail::hpack_encode(fields, block) == http2::detail::hpack_error::none,
          "encode request");
    std::vector<std::byte> out;
    append_frame(out, 1, body.empty() ? 5u : 4u, block);
    if (!body.empty()) append_frame(out, 0, 1, std::as_bytes(std::span(body)));
    return out;
}

auto write_all(event_loop&, tls_stream& peer, std::span<const std::byte> bytes) -> task<bool>
{
    while (!bytes.empty()) {
        const auto written = co_await peer.async_write_some(bytes);
        if (!written || !*written || **written == 0) co_return false;
        bytes = bytes.subspan(**written);
    }
    co_return true;
}

struct measurement {
    std::size_t routed {0};
    std::size_t static_files {0};
    std::size_t routed_openssl {0};
    std::size_t static_openssl {0};
    std::size_t requests {0};
    bool kernel_tls {false};
    bool done {false};
};

struct client_buffers {
    std::array<std::byte, 4096> request {};
    std::array<std::byte, 4096> input {};
    std::size_t input_size {0};
};

// Sends one request on stream_id and reads frames until its END_STREAM,
// answering PING and SETTINGS so the connection stays healthy.
auto round_trip(event_loop& loop, tls_stream& peer, std::span<const std::byte> frames,
                std::uint32_t stream_id, client_buffers& buffers) -> task<bool>
{
    std::memcpy(buffers.request.data(), frames.data(), frames.size());
    for (std::size_t at = 0; at + 9 <= frames.size();) {
        const auto size = (std::to_integer<std::size_t>(frames[at]) << 16) |
            (std::to_integer<std::size_t>(frames[at + 1]) << 8) |
            std::to_integer<std::size_t>(frames[at + 2]);
        buffers.request[at + 5] = static_cast<std::byte>(stream_id >> 24);
        buffers.request[at + 6] = static_cast<std::byte>(stream_id >> 16);
        buffers.request[at + 7] = static_cast<std::byte>(stream_id >> 8);
        buffers.request[at + 8] = static_cast<std::byte>(stream_id);
        at += 9 + size;
    }
    if (!(co_await write_all(loop, peer, std::span(buffers.request).first(frames.size())))
             .value_or(false)) co_return false;
    for (;;) {
        while (buffers.input_size >= 9) {
            const auto size = (std::to_integer<std::size_t>(buffers.input[0]) << 16) |
                (std::to_integer<std::size_t>(buffers.input[1]) << 8) |
                std::to_integer<std::size_t>(buffers.input[2]);
            if (buffers.input_size < 9 + size) break;
            const auto type = std::to_integer<unsigned>(buffers.input[3]);
            const auto flags = std::to_integer<unsigned>(buffers.input[4]);
            const auto id = (std::to_integer<std::uint32_t>(buffers.input[5]) << 24 |
                             std::to_integer<std::uint32_t>(buffers.input[6]) << 16 |
                             std::to_integer<std::uint32_t>(buffers.input[7]) << 8 |
                             std::to_integer<std::uint32_t>(buffers.input[8])) & 0x7fffffffu;
            const bool ended = id == stream_id && (flags & 1u) != 0 && (type == 0 || type == 1);
            if (type == 4 && (flags & 1u) == 0) {
                constexpr std::array<std::byte, 9> ack {std::byte {0}, std::byte {0}, std::byte {0},
                    std::byte {4}, std::byte {1}, std::byte {0}, std::byte {0}, std::byte {0},
                    std::byte {0}};
                if (!(co_await write_all(loop, peer, ack)).value_or(false)) co_return false;
            }
            std::memmove(buffers.input.data(), buffers.input.data() + 9 + size,
                         buffers.input_size - 9 - size);
            buffers.input_size -= 9 + size;
            if (ended) co_return true;
        }
        const auto received = co_await peer.async_read_some(
            std::span(buffers.input).subspan(buffers.input_size));
        if (!received || !*received || **received == 0) co_return false;
        buffers.input_size += **received;
    }
}

auto client(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
            const std::array<std::vector<std::byte>, 3>& requests, measurement& result)
    -> task<void>
{
    auto owned = std::make_unique<tls_stream>(loop, ip_endpoint::loopback_v4(port),
        std::move(context), tls_client_options {.hostname = "localhost",
                                                .application_protocols = {"h2"}});
    auto* peer = owned.get();
    loop.add(std::move(owned));
    auto buffers = std::make_unique<client_buffers>();
    bool secured = false;
    if (co_await peer->async_connect()) {
        const auto handshake = co_await peer->async_handshake();
        secured = handshake && *handshake;
    }
    check(secured, "TLS handshake");
    result.kernel_tls = peer->kernel_sendfile_available();
    constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    std::vector<std::byte> opening(std::as_bytes(std::span(preface)).begin(),
                                   std::as_bytes(std::span(preface)).end());
    append_frame(opening, 4, 0, {});
    check((co_await write_all(loop, *peer, opening)).value_or(false), "client preface");
    std::uint32_t stream_id = 1;
    constexpr std::size_t warmup = 6;
    constexpr std::size_t measured = 40;
    for (int phase = 0; phase < 2; ++phase) {
        std::size_t before = 0;
        std::size_t openssl_before = 0;
        for (std::size_t index = 0; index < warmup + measured; ++index) {
            if (index == warmup) {
                before = allocations.load();
                openssl_before = test::openssl_allocations.load();
            }
            const auto& request = phase == 1 ? requests[2] : requests[index % 2];
            check((co_await round_trip(loop, *peer, request, stream_id, *buffers)).value_or(false),
                  "request failed");
            stream_id += 2;
        }
        (phase == 0 ? result.routed : result.static_files) = allocations.load() - before;
        (phase == 0 ? result.routed_openssl : result.static_openssl) =
            test::openssl_allocations.load() - openssl_before;
    }
    result.requests = measured;
    result.done = true;
    peer->close();
    loop.stop();
}

auto watchdog(event_loop& loop, bool& timed_out) -> task<void>
{
    if (co_await sleep_for(loop, 10s) == timer_wait_result::expired) {
        timed_out = true;
        loop.shutdown(0ms);
    }
}

} // namespace

auto main() -> int
{
    check(test::install_openssl_allocation_counter(), "install OpenSSL allocation counter");
    std::random_device random;
    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-h2-allocations-" + std::to_string(random()));
    std::filesystem::create_directories(directory / "www");
    test::make_localhost_certificate(directory / "cert.pem", directory / "key.pem");
    // Paths longer than std::string's inline buffer, as real assets are.
    std::ofstream(directory / "www" / "static-asset-bundle.min.txt") << "static";

    auto routes = std::make_shared<http::router>();
    check(routes->add(http::method_type::get, "/api/v1/catalog/items/hello", hello).has_value() &&
          routes->add(http::method_type::post, "/upload", upload).has_value(), "routes");
    const std::array<std::vector<std::byte>, 3> requests {
        encode("GET", "/api/v1/catalog/items/hello", {}),
        encode("POST", "/upload",
               "0123456789012345678901234567890123456789012345678901234567890123456789"),
        encode("GET", "/static-asset-bundle.min.txt", {}),
    };

    // Static requests are measured without and with the open-file cache.
    auto run = [&](std::size_t cache_capacity) {
        measurement result;
        event_loop loop;
        auto listener = std::make_unique<http::https_server>(loop, ip_endpoint::loopback_v4(0),
            tls_context::make_server(directory / "cert.pem", directory / "key.pem"),
            http::server_options {.routes = routes, .document_root = directory / "www",
                                  .open_file_cache_capacity = cache_capacity});
        sockaddr_in address {};
        socklen_t length = sizeof(address);
        check(::getsockname(listener->descriptor(), reinterpret_cast<sockaddr*>(&address),
                            &length) == 0, "getsockname");
        auto* server = listener.get();
        loop.add(std::move(listener));
        check(loop.spawn(server->run()) == task_spawn_result::accepted, "spawn server");
        check(loop.spawn(client(loop, ntohs(address.sin_port),
                  tls_context::make_client(directory / "cert.pem"), requests, result)) ==
              task_spawn_result::accepted, "spawn client");
        bool timed_out = false;
        task_handle<void> timer;
        check(loop.spawn(watchdog(loop, timed_out), timer) == task_spawn_result::accepted,
              "spawn watchdog");
        (void)loop.run();
        if (!timer.done()) (void)timer.cancel();
        loop.shutdown(0ms);
        (void)loop.run();
        check(!timed_out, "timed out");
        return result;
    };
    const auto uncached = run(0);
    const auto cached = run(16);
    std::filesystem::remove_all(directory);
    // Setup (keys, handshake, certificate) allocates, proving the hook counts.
    check(test::openssl_allocations.load() > 0, "OpenSSL allocation counter is not active");
    std::cout << "OpenSSL allocations in total, including setup: "
              << test::openssl_allocations.load() << '\n';
    for (const auto* result : {&uncached, &cached}) {
        check(result->done, "requests did not complete");
        std::cout << "HTTP/2 allocations over " << result->requests << " requests"
                  << (result == &cached ? " with the open-file cache" : "") << ": routed "
                  << result->routed << ", static " << result->static_files << "; OpenSSL routed "
                  << result->routed_openssl << ", static " << result->static_openssl << '\n';
    }
    // Without transmit kTLS, OpenSSL builds each record itself and allocates
    // small WPACKET metadata per record (as tls_openssl shows); only the
    // kTLS path can be held to zero OpenSSL allocations.
    if (!uncached.kernel_tls)
        std::cout << "No transmit kTLS: OpenSSL record allocations are not checked\n";
    for (const auto* result : {&uncached, &cached})
        check(result->routed == 0 && result->static_files == 0 &&
              (!result->kernel_tls ||
               (result->routed_openssl == 0 && result->static_openssl == 0)),
              "steady-state requests allocate");
}
