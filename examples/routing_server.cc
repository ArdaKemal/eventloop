// A routed HTTP/1.1 server built only with the public API.
//
//   routing_server [port] [document-root]
//
//   curl http://127.0.0.1:8080/hello
//   curl http://127.0.0.1:8080/api/users?id=7
//   curl --data-binary @file http://127.0.0.1:8080/upload
//   curl http://127.0.0.1:8080/count
//
// Paths without a route are served from document-root when one is given.
#include "eventloop/event_loop.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/util/arg_parser.h"

#include <array>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <span>
#include <string_view>

using namespace eventloop;

namespace {

constexpr std::array<http::header, 1> plain_text {{{"content-type", "text/plain"}}};

auto bytes(std::string_view text) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(text));
}

auto hello(event_loop&, http::request&, http::response& response) -> task<void>
{
    (void)co_await response.async_send(200, plain_text, bytes("hello\n"));
}

// Every path under /api/: echoes the path and query it received.
auto api(event_loop&, http::request& request, http::response& response) -> task<void>
{
    std::array<char, 512> body {};
    const int size = std::snprintf(body.data(), body.size(), "path=%.*s query=%.*s\n",
        static_cast<int>(request.path().size()), request.path().data(),
        static_cast<int>(request.query().size()), request.query().data());
    if (size < 0 || static_cast<std::size_t>(size) >= body.size()) {
        (void)co_await response.async_send(414, plain_text, bytes("target too long\n"));
        co_return;
    }
    (void)co_await response.async_send(200, plain_text,
        std::as_bytes(std::span(body.data(), static_cast<std::size_t>(size))));
}

// Streams the request body through a fixed buffer and reports its size. The
// buffer lives in the handler's coroutine frame, which must fit the loop's
// 1024-byte size class to use its default capacity.
auto upload(event_loop&, http::request& request, http::response& response) -> task<void>
{
    std::array<std::byte, 512> chunk {};
    std::uint64_t total = 0;
    for (;;) {
        auto read = co_await request.async_read_body(chunk);
        if (!read || !*read) co_return;  // Cancelled or the peer went away.
        if (**read == 0) break;
        total += **read;
    }
    std::array<char, 32> body {};
    const auto end = std::to_chars(body.data(), body.data() + body.size() - 1, total).ptr;
    *end = '\n';
    (void)co_await response.async_send(200, plain_text,
        std::as_bytes(std::span(body.data(), end + 1)));
}

// A streamed response without a length: chunked on HTTP/1.1.
auto count(event_loop&, http::request&, http::response& response) -> task<void>
{
    if (!co_await response.async_start(200, plain_text)) co_return;
    std::array<char, 8> line {};
    for (int value = 1; value <= 5; ++value) {
        const auto end = std::to_chars(line.data(), line.data() + line.size() - 1, value).ptr;
        *end = '\n';
        const auto written = co_await response.async_write(
            std::as_bytes(std::span(line.data(), end + 1)));
        if (!written || !*written) co_return;
    }
    (void)co_await response.async_finish();
}

auto serve(event_loop& loop, http::server& server) -> task<void>
{
    (void)loop;
    (void)co_await server.run();
}

} // namespace

auto main(int argc, char** argv) -> int
{
    try {
        int port_number = 8080;
        std::string document_root;
        const std::array positionals {
            arg_parser::positional {"PORT", &port_number, false},
            arg_parser::positional {"DOCUMENT-ROOT", &document_root, false},
        };
        arg_parser arguments({}, positionals);
        arguments.set_usage("usage: routing_server [port] [document-root]  (default port 8080)\n");
        arguments.parse(argc, argv);
        const auto port = static_cast<std::uint16_t>(port_number);
        auto routes = std::make_shared<http::router>();
        if (!routes->add(http::method_type::get, "/hello", hello) ||
            !routes->add_prefix(http::method_type::get, "/api/", api) ||
            !routes->add(http::method_type::post, "/upload", upload) ||
            !routes->add(http::method_type::get, "/count", count)) {
            std::cerr << "route registration failed\n";
            return 1;
        }
        http::server_options options {.routes = routes};
        if (!document_root.empty()) options.document_root = document_root;

        event_loop loop;
        auto listener = std::make_unique<http::server>(
            loop, ip_endpoint::loopback_v4(port), std::move(options));
        auto* server = listener.get();
        loop.add(std::move(listener));
        if (loop.spawn(serve(loop, *server)) != task_spawn_result::accepted) {
            std::cerr << "listener task capacity exhausted\n";
            return 1;
        }
        std::cout << "Routing on http://127.0.0.1:" << port << '\n';
        (void)loop.run();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "routing_server: " << error.what() << '\n';
        return 1;
    }
}
