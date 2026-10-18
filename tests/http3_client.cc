// Public HTTP/3 client against the public HTTP/3 server: sequential requests
// on one connection, owned and streamed bodies, sinks, trailers, early
// responses, argument validation, and failure/close behavior.
#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"
#include "eventloop/http3/client.h"
#include "tls_test_certificate.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

using namespace eventloop;
using namespace std::chrono_literals;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP/3 client: " << message << '\n';
    std::exit(1);
}

auto text(std::string_view value) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(value));
}

auto body_text(const std::vector<std::byte>& body) -> std::string
{
    return {reinterpret_cast<const char*>(body.data()), body.size()};
}

auto field(const http3::client_response& response, std::string_view name) -> std::string
{
    for (const auto& item : response.headers) if (item.name == name) return item.value;
    return "<none>";
}

auto fails_with(const std::expected<http3::client_response, std::error_code>& result,
                std::errc code) -> bool
{
    return !result && result.error() == std::make_error_code(code);
}

auto hello(event_loop&, http::request& request, http::response& response) -> task<void>
{
    const auto echoed = request.header_value("x-echo").value_or("");
    const std::array<http::header, 2> fields {{{"content-type", "text/plain"}, {"x-echo", echoed}}};
    (void)co_await response.async_send(200, fields, text("hello"));
}

auto streamed(event_loop&, http::request&, http::response& response) -> task<void>
{
    if (!co_await response.async_start(200, {})) co_return;
    (void)co_await response.async_write(text("abc"));
    (void)co_await response.async_write(text("defgh"));
    const std::array<http::header, 1> trailers {{{"x-done", "yes"}}};
    (void)co_await response.async_finish(trailers);
}

// Answers with the byte count and byte sum of the request body.
auto upload(event_loop&, http::request& request, http::response& response) -> task<void>
{
    std::array<std::byte, 700> chunk {};
    std::uint64_t count = 0, sum = 0;
    for (;;) {
        auto read = co_await request.async_read_body(chunk);
        if (!read || !*read) co_return;
        if (**read == 0) break;
        count += **read;
        for (std::size_t i = 0; i < **read; ++i) sum += std::to_integer<unsigned>(chunk[i]);
    }
    const auto body = std::to_string(count) + " " + std::to_string(sum);
    (void)co_await response.async_send(200, {}, text(body));
}

// Responds before reading the rest of a large upload.
auto early(event_loop&, http::request& request, http::response& response) -> task<void>
{
    std::array<std::byte, 10> chunk {};
    (void)co_await request.async_read_body(chunk);
    (void)co_await response.async_send(200, {}, text("early"));
}

auto short_body(event_loop&, http::request&, http::response& response) -> task<void>
{
    const std::array<http::header, 1> fields {{{"content-length", "5"}}};
    if (!co_await response.async_start(200, fields)) co_return;
    (void)co_await response.async_write(text("abc"));
    (void)co_await response.async_finish();
}

auto get(std::string target) -> http3::client_request
{
    http3::client_request request;
    request.target = std::move(target);
    return request;
}

// Produces size bytes of the repeating pattern 0..250.
auto pattern_source(std::uint64_t size) -> http3::request_body_source
{
    return [size, sent = std::uint64_t {0}](std::span<std::byte> buffer) mutable
        -> std::expected<std::size_t, std::error_code> {
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), size - sent));
        for (std::size_t i = 0; i < count; ++i)
            buffer[i] = static_cast<std::byte>((sent + i) % 251);
        sent += count;
        return count;
    };
}

auto pattern_sum(std::uint64_t size) -> std::uint64_t
{
    std::uint64_t sum = 0;
    for (std::uint64_t i = 0; i < size; ++i) sum += i % 251;
    return sum;
}

// Coroutine frames come from bounded size classes, so the checks are split
// into several small coroutines that share one connection.
auto responses(event_loop&, http3::client_connection& connection) -> task<void>
{
    auto request = get("/hello");
    request.headers.push_back({"x-echo", "ping"});
    const auto hello_response = flatten_result(co_await connection.async_request(std::move(request)));
    check(hello_response && hello_response->status == 200 &&
          body_text(hello_response->body) == "hello" &&
          field(*hello_response, "content-type") == "text/plain" &&
          field(*hello_response, "x-echo") == "ping", "GET with request header");

    std::vector<unsigned> statuses;
    const auto trailed = flatten_result(co_await connection.async_request(get("/stream"), {},
        [&statuses](unsigned status, std::span<const http3::header>) -> std::error_code {
            statuses.push_back(status);
            return {};
        }));
    check(trailed && body_text(trailed->body) == "abcdefgh" && field(*trailed, "x-done") == "yes" &&
          statuses == std::vector<unsigned> {200, 0}, "streamed response with trailers");

    std::string sunk;
    const auto sinked = flatten_result(co_await connection.async_request(get("/hello"),
        [&sunk](std::span<const std::byte> chunk) -> std::error_code {
            sunk.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return {};
        }));
    check(sinked && sinked->body.empty() && sunk == "hello", "response sink");
}

auto uploads(event_loop&, http3::client_connection& connection) -> task<void>
{
    auto request = get("/upload");
    request.method = "POST";
    request.body.assign(3000, std::byte {7});
    const auto owned = flatten_result(co_await connection.async_request(std::move(request)));
    check(owned && body_text(owned->body) == "3000 21000", "owned request body");

    constexpr std::uint64_t streamed_size = 300 * 1024;
    request = get("/upload");
    request.method = "POST";
    request.headers.push_back({"content-length", std::to_string(streamed_size)});
    request.body_source = pattern_source(streamed_size);
    const auto sourced = flatten_result(co_await connection.async_request(std::move(request)));
    check(sourced && body_text(sourced->body) ==
          std::to_string(streamed_size) + " " + std::to_string(pattern_sum(streamed_size)),
          "streamed request body");

    request = get("/early");
    request.method = "POST";
    request.body_source = pattern_source(4 * 1024 * 1024);
    const auto early_response = flatten_result(co_await connection.async_request(std::move(request)));
    check(early_response && body_text(early_response->body) == "early",
          "response before the upload ends");
}

auto invalid(event_loop&, http3::client_connection& connection, http3::client_request request) -> task<bool>
{
    co_return fails_with(flatten_result(co_await connection.async_request(std::move(request))),
                         std::errc::invalid_argument);
}

auto validation(event_loop& connection_loop, http3::client_connection& connection) -> task<void>
{
    check(co_await invalid(connection_loop, connection, get("relative")) == true, "relative target");
    auto request = get("/upload");
    request.method = "POST";
    request.headers.push_back({"content-length", "4"});
    request.body.assign(3, std::byte {1});
    check(co_await invalid(connection_loop, connection, std::move(request)) == true, "mismatched Content-Length");
    request = get("/hello");
    request.headers.push_back({"connection", "close"});
    check(co_await invalid(connection_loop, connection, std::move(request)) == true, "connection-specific field");
    check(flatten_result(co_await connection.async_request(get("/hello"))).has_value(),
          "validation failures keep the connection");

    const auto aborted = flatten_result(co_await connection.async_request(get("/hello"),
        [](std::span<const std::byte>) { return std::make_error_code(std::errc::io_error); }));
    check(!aborted && aborted.error() == std::make_error_code(std::errc::io_error),
          "sink error is returned");
    check(fails_with(flatten_result(co_await connection.async_request(get("/hello"))),
                     std::errc::not_connected), "request after failure");
}

auto exercise(event_loop& loop, ip_endpoint server, std::filesystem::path ca, bool& done)
    -> task<void>
{
    const http3::client_options options {.trusted_ca = ca};
    {
        http3::client_connection connection(loop, server, "localhost", options);
        check(fails_with(flatten_result(co_await connection.async_request(get("/hello"))),
                         std::errc::not_connected), "request before connect");
        check(flatten_result(co_await connection.async_connect()).has_value(), "connect");
        const auto again = flatten_result(co_await connection.async_connect());
        check(!again && again.error() == std::make_error_code(std::errc::already_connected),
              "second connect");
        check(co_await responses(loop, connection) == task_result::success, "responses task");
        check(co_await uploads(loop, connection) == task_result::success, "uploads task");
        check(co_await validation(loop, connection) == task_result::success, "validation task");
        check(flatten_result(co_await connection.async_close()).has_value(), "close");
    }
    {
        http3::client_connection connection(loop, server, "localhost", options);
        check(flatten_result(co_await connection.async_connect()).has_value(), "reconnect");
        auto head = get("/hello");
        head.method = "HEAD";
        const auto headed = flatten_result(co_await connection.async_request(std::move(head)));
        check(headed && headed->status == 200 && headed->body.empty() &&
              field(*headed, "content-length") == "5", "HEAD keeps Content-Length without DATA");
        // The server resets a response stream that ends short of Content-Length.
        check(fails_with(flatten_result(co_await connection.async_request(get("/short"))),
                         std::errc::connection_reset), "reset response stream");
        check(flatten_result(co_await connection.async_close()).has_value(), "close after failure");
    }
    {
        // The certificate is not trusted by the system store.
        http3::client_connection connection(loop, server, "localhost");
        check(!flatten_result(co_await connection.async_connect()).has_value(), "untrusted server");
        check(flatten_result(co_await connection.async_close()).has_value(), "close failed connect");
    }
    done = true;
}

auto watch(event_loop& loop, http::http3_server& server, std::filesystem::path ca, bool& done)
    -> task<void>
{
    task_handle<void> client;
    check(loop.spawn(exercise(loop, server.local_endpoint(), std::move(ca), done), client) ==
          task_spawn_result::accepted, "spawn client");
    for (int i = 0; i < 4000 && !client.done(); ++i) (void)co_await sleep_for(loop, 5ms);
    check(client.done(), "client did not finish");
    (void)co_await client;
    co_await server.async_close();
    loop.stop();
}

class temporary_directory {
public:
    temporary_directory()
    {
        std::random_device random;
        path_ = std::filesystem::temp_directory_path() /
            ("eventloop-h3-client-" + std::to_string(random()));
        std::filesystem::create_directories(path_);
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

} // namespace

auto main() -> int
{
    temporary_directory directory;
    test::make_localhost_certificate(directory.path() / "cert.pem", directory.path() / "key.pem");
    auto routes = std::make_shared<http::router>();
    check(routes->add(http::method_type::get, "/hello", hello).has_value() &&
          routes->add(http::method_type::get, "/stream", streamed).has_value() &&
          routes->add(http::method_type::post, "/upload", upload).has_value() &&
          routes->add(http::method_type::post, "/early", early).has_value() &&
          routes->add(http::method_type::get, "/short", short_body).has_value(),
          "add routes");
    bool done = false;
    {
        event_loop loop;
        http::http3_server server(loop, ip_endpoint::loopback_v4(0), directory.path() / "cert.pem",
            directory.path() / "key.pem",
            http::server_options {.routes = routes,
                                  .max_request_body = std::uint64_t {8} * 1024 * 1024});
        task_handle<void> serving;
        check(loop.spawn(server.run(), serving) == task_spawn_result::accepted, "spawn server");
        check(loop.spawn(watch(loop, server, directory.path() / "cert.pem", done)) ==
              task_spawn_result::accepted, "spawn watch");
        (void)loop.run();
        if (!serving.done()) {
            loop.shutdown(event_loop::clock::duration::zero());
            (void)loop.run();
        }
    }
    check(done, "requests did not complete");
    std::cout << "HTTP/3 client: ok\n";
}
