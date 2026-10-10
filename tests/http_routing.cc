// Routed HTTP/1.1 requests through the public server, router, request and
// response API, checked on the wire with a raw TCP client.
#include "eventloop/event_loop.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "tls_test_certificate.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace eventloop;
using namespace std::chrono_literals;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP routing: " << message << '\n';
    std::exit(1);
}

auto text(std::string_view value) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(value));
}

auto hello(event_loop&, http::request&, http::response& response) -> task<void>
{
    const std::array<http::header, 1> fields {{{"content-type", "text/plain"}}};
    (void)co_await response.async_send(200, fields, text("hello"));
}

// Echoes what the handler saw about the request.
auto info(event_loop&, http::request& request, http::response& response) -> task<void>
{
    std::array<char, 256> body {};
    const auto custom = request.header_value("X-Test").value_or("-");
    const int size = std::snprintf(body.data(), body.size(), "%.*s|%.*s|%.*s|%.*s",
        static_cast<int>(request.path().size()), request.path().data(),
        static_cast<int>(request.query().size()), request.query().data(),
        static_cast<int>(custom.size()), custom.data(),
        static_cast<int>(request.authority().size()), request.authority().data());
    (void)co_await response.async_send(200, {},
        std::as_bytes(std::span(body.data(), static_cast<std::size_t>(size))));
}

// Reads the whole body in small chunks and answers with its size and sum.
auto upload(event_loop&, http::request& request, http::response& response) -> task<void>
{
    std::array<std::byte, 700> chunk {};
    std::uint64_t count = 0;
    std::uint64_t sum = 0;
    for (;;) {
        auto read = co_await request.async_read_body(chunk);
        if (!read || !*read) co_return;
        if (**read == 0) break;
        count += **read;
        for (std::size_t index = 0; index < **read; ++index)
            sum += std::to_integer<unsigned>(chunk[index]);
    }
    std::array<char, 64> body {};
    const int size = std::snprintf(body.data(), body.size(), "%llu %llu",
        static_cast<unsigned long long>(count), static_cast<unsigned long long>(sum));
    (void)co_await response.async_send(200, {},
        std::as_bytes(std::span(body.data(), static_cast<std::size_t>(size))));
}

// Reads ten bytes and answers; the server discards the rest of the body.
auto partial(event_loop&, http::request& request, http::response& response) -> task<void>
{
    std::array<std::byte, 10> chunk {};
    (void)co_await request.async_read_body(chunk);
    (void)co_await response.async_send(200, {}, text("partial"));
}

auto stream(event_loop&, http::request&, http::response& response) -> task<void>
{
    const std::array<http::header, 1> fields {{{"content-type", "text/plain"}}};
    if (!co_await response.async_start(200, fields)) co_return;
    (void)co_await response.async_write(text("abc"));
    (void)co_await response.async_write(text("defgh"));
    const std::array<http::header, 1> trailers {{{"x-done", "yes"}}};
    (void)co_await response.async_finish(trailers);
}

auto silent(event_loop&, http::request&, http::response&) -> task<void>
{
    co_return;
}

auto fail(event_loop&) -> task<int> { throw std::runtime_error("handler failure"); }

// Throws from a task it awaits, before starting a response.
auto throwing(event_loop& loop, http::request&, http::response&) -> task<void>
{
    (void)co_await fail(loop);
}

struct short_state {
    bool finish_failed {false};
};

auto short_body(event_loop&, http::request& request, http::response& response) -> task<void>
{
    auto* state = static_cast<short_state*>(request.route_context());
    const std::array<http::header, 1> fields {{{"content-length", "5"}}};
    if (!co_await response.async_start(200, fields)) co_return;
    (void)co_await response.async_write(text("abc"));
    auto finished = co_await response.async_finish();
    state->finish_failed = finished && !*finished &&
        finished->error() == std::make_error_code(std::errc::invalid_argument);
}

auto misuse(event_loop&, http::request&, http::response& response) -> task<void>
{
    // Rejected before anything is written, then a valid response.
    const std::array<http::header, 1> bad {{{"Connection", "close"}}};
    auto rejected = co_await response.async_start(200, bad);
    const bool refused = rejected && !*rejected;
    auto informational = co_await response.async_start(101, {});
    const bool status_refused = informational && !*informational;
    (void)co_await response.async_send(200, {},
        text(refused && status_refused ? "refused" : "accepted"));
}

auto file(event_loop&, http::request& request, http::response& response) -> task<void>
{
    const auto* path = static_cast<const std::string*>(request.route_context());
    unique_fd descriptor(::open(path->c_str(), O_RDONLY | O_CLOEXEC));
    (void)co_await response.async_send_file(200, {}, std::move(descriptor), 2, 5);
}

struct exchange_result {
    std::string response;
    bool done {false};
};

// Writes request on a new connection and reads until the server closes it.
auto exchange(event_loop& loop, std::uint16_t port, std::string request,
              exchange_result& result) -> task<void>
{
    auto owned = std::make_unique<tcp_stream>(loop, ip_endpoint::loopback_v4(port));
    auto* peer = owned.get();
    loop.add(std::move(owned));
    if (co_await peer->async_connect()) {
        auto pending = text(request);
        while (!pending.empty()) {
            const auto written = co_await peer->async_write_some(pending);
            if (!written || *written == 0) break;
            pending = pending.subspan(*written);
        }
        std::array<std::byte, 1024> buffer {};
        for (;;) {
            const auto received = co_await peer->async_read_some(buffer);
            if (!received || *received == 0) break;
            result.response.append(reinterpret_cast<const char*>(buffer.data()), *received);
        }
        result.done = true;
    }
    peer->close();
}

// Sends the head, waits for 100 Continue, then sends the body. A server that
// does not answer the expectation leaves the client waiting until the
// watchdog fires.
auto continue_exchange(event_loop& loop, std::uint16_t port, exchange_result& result)
    -> task<void>
{
    auto owned = std::make_unique<tcp_stream>(loop, ip_endpoint::loopback_v4(port));
    auto* peer = owned.get();
    loop.add(std::move(owned));
    constexpr std::string_view head = "POST /upload HTTP/1.1\r\nHost: a\r\n"
        "Content-Length: 3\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n";
    std::array<std::byte, 1024> buffer {};
    if (co_await peer->async_connect() && co_await peer->async_write_some(text(head))) {
        while (result.response.find("\r\n\r\n") == std::string::npos) {
            const auto received = co_await peer->async_read_some(buffer);
            if (!received || *received == 0) break;
            result.response.append(reinterpret_cast<const char*>(buffer.data()), *received);
        }
        if (co_await peer->async_write_some(text("xyz"))) {
            for (;;) {
                const auto received = co_await peer->async_read_some(buffer);
                if (!received || *received == 0) break;
                result.response.append(reinterpret_cast<const char*>(buffer.data()), *received);
            }
            result.done = true;
        }
    }
    peer->close();
    loop.stop();
}

// One request over TLS HTTP/1.1, read until the server closes.
auto tls_exchange(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
                  std::string request, exchange_result& result) -> task<void>
{
    auto owned = std::make_unique<tls_stream>(loop, ip_endpoint::loopback_v4(port),
        std::move(context), tls_client_options {.hostname = "localhost",
                                                .application_protocols = {"http/1.1"}});
    auto* peer = owned.get();
    loop.add(std::move(owned));
    bool secured = false;
    if (co_await peer->async_connect()) {
        const auto handshake = co_await peer->async_handshake();
        secured = handshake && *handshake;
    }
    if (secured) {
        auto pending = text(request);
        while (!pending.empty()) {
            const auto written = co_await peer->async_write_some(pending);
            if (!written || !*written || **written == 0) break;
            pending = pending.subspan(**written);
        }
        std::array<std::byte, 1024> buffer {};
        for (;;) {
            const auto received = co_await peer->async_read_some(buffer);
            if (!received || !*received || **received == 0) break;
            result.response.append(reinterpret_cast<const char*>(buffer.data()), **received);
        }
        result.done = true;
    }
    peer->close();
    loop.stop();
}

auto run_all(event_loop& loop, std::uint16_t port, std::vector<std::string>& requests,
             std::vector<exchange_result>& results) -> task<void>
{
    for (std::size_t index = 0; index < requests.size(); ++index)
        (void)co_await exchange(loop, port, std::move(requests[index]), results[index]);
    loop.stop();
}

auto watchdog(event_loop& loop, bool& timed_out) -> task<void>
{
    if (co_await sleep_for(loop, 5s) == timer_wait_result::expired) {
        timed_out = true;
        loop.shutdown(0ms);
    }
}

// Removes date lines so responses compare exactly.
auto without_date(std::string value) -> std::string
{
    for (auto at = value.find("date: "); at != std::string::npos; at = value.find("date: ")) {
        const auto end = value.find("\r\n", at);
        value.erase(at, end + 2 - at);
    }
    return value;
}

auto serve(http::server_options options, std::vector<std::string> requests)
    -> std::vector<std::string>
{
    event_loop loop;
    auto listener = std::make_unique<http::server>(loop, ip_endpoint::loopback_v4(0),
                                                   std::move(options));
    sockaddr_in address {};
    socklen_t length = sizeof(address);
    check(::getsockname(listener->descriptor(), reinterpret_cast<sockaddr*>(&address),
                        &length) == 0, "getsockname");
    auto* server = listener.get();
    loop.add(std::move(listener));
    check(loop.spawn(server->run()) == task_spawn_result::accepted, "spawn server");
    std::vector<exchange_result> results(requests.size());
    check(loop.spawn(run_all(loop, ntohs(address.sin_port), requests, results)) ==
          task_spawn_result::accepted, "spawn client");
    bool timed_out = false;
    task_handle<void> timer;
    check(loop.spawn(watchdog(loop, timed_out), timer) == task_spawn_result::accepted,
          "spawn watchdog");
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    check(!timed_out, "requests timed out");
    std::vector<std::string> responses;
    for (auto& result : results) {
        check(result.done, "exchange did not complete");
        responses.push_back(without_date(std::move(result.response)));
    }
    return responses;
}

auto request(std::string_view head, std::string_view body = {}) -> std::string
{
    std::string value(head);
    value += "Host: example.test\r\n";
    if (!body.empty()) value += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    value += "Connection: close\r\n\r\n";
    value += body;
    return value;
}

// A chunked body in pieces of at most piece bytes, with an extension on the
// first chunk and an optional trailer section.
auto chunked(std::string_view body, std::size_t piece, std::string_view trailers = {})
    -> std::string
{
    std::string value;
    bool first = true;
    while (!body.empty()) {
        const auto count = std::min(piece, body.size());
        std::array<char, 20> size {};
        const auto end = std::to_chars(size.data(), size.data() + size.size(), count, 16).ptr;
        value.append(size.data(), end);
        if (first) value += ";note=first";
        first = false;
        value += "\r\n";
        value += body.substr(0, count);
        value += "\r\n";
        body.remove_prefix(count);
    }
    value += "0\r\n";
    value += trailers;
    value += "\r\n";
    return value;
}

auto chunked_request(std::string_view head, std::string_view body, std::size_t piece,
                     bool close = true, std::string_view trailers = {}) -> std::string
{
    std::string value(head);
    value += "Host: example.test\r\nTransfer-Encoding: chunked\r\n";
    if (close) value += "Connection: close\r\n";
    value += "\r\n";
    value += chunked(body, piece, trailers);
    return value;
}

class temporary_directory {
public:
    temporary_directory()
    {
        std::random_device random;
        path_ = std::filesystem::temp_directory_path() /
            ("eventloop-routing-" + std::to_string(random()));
        std::filesystem::create_directory(path_);
    }
    ~temporary_directory()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;
    [[nodiscard]] auto path() const -> const std::filesystem::path& { return path_; }

private:
    std::filesystem::path path_;
};

auto router_rules() -> void
{
    http::router routes;
    check(routes.add(http::method_type::get, "/a", hello).has_value(), "add route");
    check(routes.add(http::method_type::get, "/a", hello).error() ==
          std::make_error_code(std::errc::file_exists), "duplicate route");
    check(routes.add(http::method_type::get, "a", hello).error() ==
          std::make_error_code(std::errc::invalid_argument), "relative path");
    check(routes.add(http::method_type::get, "/a?b", hello).error() ==
          std::make_error_code(std::errc::invalid_argument), "query in path");
    check(routes.add(http::method_type::get, "/b", nullptr).error() ==
          std::make_error_code(std::errc::invalid_argument), "null handler");
    check(routes.add_prefix(http::method_type::get, "/a", hello).has_value(),
          "prefix and exact routes share a path");
    for (std::size_t index = 2; index < http::router::max_routes; ++index)
        check(routes.add(http::method_type::get, "/r" + std::to_string(index), hello)
                  .has_value(), "fill router");
    check(routes.add(http::method_type::get, "/full", hello).error() ==
          std::make_error_code(std::errc::no_buffer_space), "router capacity");
}

} // namespace

auto main() -> int
{
    router_rules();

    temporary_directory directory;
    {
        std::ofstream(directory.path() / "index.html") << "static";
        std::ofstream(directory.path() / "data.txt") << "0123456789";
    }
    const auto file_path = (directory.path() / "data.txt").string();
    short_state truncated;

    auto routes = std::make_shared<http::router>();
    check(routes->add(http::method_type::get, "/hello", hello).has_value() &&
          routes->add_prefix(http::method_type::get, "/api/", info).has_value() &&
          routes->add(http::method_type::post, "/upload", upload).has_value() &&
          routes->add(http::method_type::post, "/partial", partial).has_value() &&
          routes->add(http::method_type::get, "/stream", stream).has_value() &&
          routes->add(http::method_type::get, "/silent", silent).has_value() &&
          routes->add(http::method_type::get, "/throw", throwing).has_value() &&
          routes->add(http::method_type::get, "/short", short_body, &truncated).has_value() &&
          routes->add(http::method_type::get, "/misuse", misuse).has_value() &&
          routes->add(http::method_type::get, "/file", file,
                      const_cast<std::string*>(&file_path)).has_value(),
          "register routes");

    std::string large(10000, '\0');
    std::uint64_t large_sum = 0;
    for (std::size_t index = 0; index < large.size(); ++index) {
        large[index] = static_cast<char>('a' + index % 26);
        large_sum += static_cast<unsigned char>(large[index]);
    }

    const auto responses = serve(
        {.routes = routes, .document_root = directory.path(), .max_request_body = 20000},
        {
            request("GET /hello HTTP/1.1\r\n"),
            request("HEAD /hello HTTP/1.1\r\n"),
            request("OPTIONS /hello HTTP/1.1\r\n"),
            request("POST /hello HTTP/1.1\r\n"),
            request("GET /api/items?id=7 HTTP/1.1\r\nX-Test: seen\r\n"),
            request("POST /upload HTTP/1.1\r\n", large),
            request("GET /stream HTTP/1.1\r\nTE: trailers\r\n"),
            request("GET /stream HTTP/1.1\r\n"),
            request("GET /silent HTTP/1.1\r\n"),
            request("GET /short HTTP/1.1\r\n"),
            request("GET /misuse HTTP/1.1\r\n"),
            request("GET /file HTTP/1.1\r\n"),
            request("GET / HTTP/1.1\r\n"),
            // Rejected from the declared length, before any body is read.
            "POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 20001\r\n\r\n",
            // Keep-alive: the unread body is discarded before the next request.
            "POST /partial HTTP/1.1\r\nHost: a\r\nContent-Length: 5000\r\n\r\n" +
                std::string(5000, 'p') + request("GET /hello HTTP/1.1\r\n"),
            "GET /hello HTTP/1.1\r\nHost: a\r\n\r\n" + request("GET /api/x HTTP/1.1\r\n"),
            // Chunked request bodies.
            chunked_request("POST /upload HTTP/1.1\r\n", large, 3000, true, "X-Sum: 1\r\n"),
            chunked_request("POST /upload HTTP/1.1\r\n", "abc", 1, false) +
                request("GET /hello HTTP/1.1\r\n"),
            chunked_request("POST /partial HTTP/1.1\r\n", large, 700, false) +
                request("GET /hello HTTP/1.1\r\n"),
            "POST /upload HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n"
                "Connection: close\r\n\r\n3\r\nabc\r\nzz\r\n",
            chunked_request("POST /upload HTTP/1.1\r\n", std::string(20001, 'x'), 4000),
            "POST /upload HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n"
                "Content-Length: 3\r\nConnection: close\r\n\r\n0\r\n\r\n",
            chunked_request("POST /index.html HTTP/1.1\r\n", "abc", 3),
            chunked_request("POST /hello HTTP/1.1\r\n", "abc", 3),
            // Keep-alive continues after a handler throws.
            "GET /throw HTTP/1.1\r\nHost: a\r\n\r\n" + request("GET /hello HTTP/1.1\r\n"),
        });

    const std::string hello_head =
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n";
    check(responses[0] == hello_head + "connection: close\r\n\r\nhello", "exact route");
    check(responses[1] == hello_head + "connection: close\r\n\r\n", "HEAD runs GET without body");
    check(responses[2] == "HTTP/1.1 204 No Content\r\nAllow: GET, HEAD, OPTIONS\r\n"
          "Content-Length: 0\r\nConnection: close\r\n\r\n", "OPTIONS lists methods");
    check(responses[3] == "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD, OPTIONS\r\n"
          "Content-Length: 0\r\nConnection: close\r\n\r\n", "wrong method");
    check(responses[4].ends_with("\r\n\r\n/api/items|id=7|seen|example.test"), "prefix route");
    check(responses[5].ends_with("\r\n\r\n10000 " + std::to_string(large_sum)),
          "streamed request body");
    check(responses[6] == "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n"
          "transfer-encoding: chunked\r\nconnection: close\r\n\r\n"
          "3\r\nabc\r\n5\r\ndefgh\r\n0\r\nx-done: yes\r\n\r\n", "chunked with trailers");
    check(responses[7].ends_with("3\r\nabc\r\n5\r\ndefgh\r\n0\r\n\r\n"),
          "trailers dropped without TE");
    check(responses[8] == "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n"
          "connection: close\r\n\r\n", "handler without response");
    check(responses[9] == "HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n"
          "\r\nabc" && truncated.finish_failed, "short body abandons the response");
    check(responses[10].ends_with("\r\n\r\nrefused"), "invalid fields and status");
    check(responses[11].ends_with("content-length: 5\r\nconnection: close\r\n\r\n23456"),
          "file range");
    check(responses[12].starts_with("HTTP/1.1 200 OK") && responses[12].ends_with("static"),
          "static fallback");
    check(responses[13].starts_with("HTTP/1.1 413 "), "body above max_request_body");
    check(responses[14].starts_with("HTTP/1.1 200 OK\r\ncontent-length: 7\r\n\r\npartial") &&
          responses[14].ends_with("\r\n\r\nhello"), "unread body discarded");
    check(responses[15].find("hello") != std::string::npos &&
          responses[15].ends_with("\r\n\r\n/api/x||-|example.test"), "pipelined requests");
    check(responses[16].ends_with("\r\n\r\n10000 " + std::to_string(large_sum)),
          "chunked body with extension and trailers");
    check(responses[17].find("\r\n\r\n3 " + std::to_string('a' + 'b' + 'c')) !=
              std::string::npos && responses[17].ends_with("\r\n\r\nhello"),
          "pipelined request after a chunked body");
    check(responses[18].find("partial") != std::string::npos &&
          responses[18].ends_with("\r\n\r\nhello"), "unread chunked body discarded");
    check(responses[19].starts_with("HTTP/1.1 400 "), "malformed chunked body");
    check(responses[20].starts_with("HTTP/1.1 413 "), "chunked body above max_request_body");
    check(responses[21].starts_with("HTTP/1.1 400 "), "chunked with Content-Length");
    check(responses[22].starts_with("HTTP/1.1 501 "), "static request with chunked body");
    check(responses[23].starts_with("HTTP/1.1 405 ") &&
          responses[23].find("Connection: close") != std::string::npos,
          "chunked body on a path without a handler for the method");
    check(responses[24].starts_with("HTTP/1.1 500 Internal Server Error\r\n") &&
          responses[24].ends_with("\r\n\r\nhello"), "throwing handler answers 500");

    const auto cached = serve({.document_root = directory.path()},
        {
            request("GET / HTTP/1.1\r\nIf-None-Match: *\r\n"),
            request("HEAD /index.html HTTP/1.1\r\nIf-None-Match: *\r\n"),
        });
    for (const auto& response : cached)
        check(response.starts_with("HTTP/1.1 304 Not Modified\r\n") &&
              response.find("Content-Length: 6\r\n") != std::string::npos &&
              response.ends_with("\r\n\r\n"),
              "304 keeps representation length without a body");

    // Expect: 100-continue is answered when the handler reads the body.
    {
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
        exchange_result result;
        check(loop.spawn(continue_exchange(loop, ntohs(address.sin_port), result)) ==
              task_spawn_result::accepted, "spawn client");
        bool timed_out = false;
        task_handle<void> timer;
        check(loop.spawn(watchdog(loop, timed_out), timer) == task_spawn_result::accepted,
              "spawn watchdog");
        (void)loop.run();
        if (!timer.done()) (void)timer.cancel();
        loop.shutdown(0ms);
        (void)loop.run();
        const auto sum = std::to_string('x' + 'y' + 'z');
        check(!timed_out && result.done &&
              result.response.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK") &&
              result.response.ends_with("\r\n\r\n3 " + sum), "100 Continue");
    }

    // TLS HTTP/1.1 runs the same handlers.
    {
        const auto certificate = directory.path() / "cert.pem";
        const auto key = directory.path() / "key.pem";
        test::make_localhost_certificate(certificate, key);
        event_loop loop;
        auto listener = std::make_unique<http::https_server>(loop, ip_endpoint::loopback_v4(0),
            tls_context::make_server(certificate, key),
            http::server_options {.routes = routes, .enable_http2 = false});
        sockaddr_in address {};
        socklen_t length = sizeof(address);
        check(::getsockname(listener->descriptor(), reinterpret_cast<sockaddr*>(&address),
                            &length) == 0, "getsockname");
        auto* server = listener.get();
        loop.add(std::move(listener));
        check(loop.spawn(server->run()) == task_spawn_result::accepted, "spawn TLS server");
        exchange_result result;
        check(loop.spawn(tls_exchange(loop, ntohs(address.sin_port),
                  tls_context::make_client(certificate),
                  request("POST /upload HTTP/1.1\r\n", large), result)) ==
              task_spawn_result::accepted, "spawn TLS client");
        bool timed_out = false;
        task_handle<void> timer;
        check(loop.spawn(watchdog(loop, timed_out), timer) == task_spawn_result::accepted,
              "spawn watchdog");
        (void)loop.run();
        if (!timer.done()) (void)timer.cancel();
        loop.shutdown(0ms);
        (void)loop.run();
        check(!timed_out && result.done &&
              result.response.ends_with("\r\n\r\n10000 " + std::to_string(large_sum)),
              "TLS routed upload");
    }

    // Routes only: unmatched paths answer 404.
    const auto routed_only = serve({.routes = routes},
                                   {request("GET /index.html HTTP/1.1\r\n")});
    check(routed_only[0].starts_with("HTTP/1.1 404 "), "routes without document root");
}
