// Routed HTTP/2 requests on a public https_server. Most cases use the public
// http2::async_request client; a raw frame client checks that handlers on one
// connection run concurrently.
#include "eventloop/event_loop.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/http2/client.h"
#include "eventloop/task_composition.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "http2/hpack.h"
#include "tls_test_certificate.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
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
    std::cerr << "HTTP/2 routing: " << message << '\n';
    std::exit(1);
}

auto text(std::string_view value) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(value));
}

auto hello(event_loop&, http::request& request, http::response& response) -> task<void>
{
    check(request.protocol() == http::protocol::http2, "protocol is HTTP/2");
    const std::array<http::header, 1> fields {{{"content-type", "text/plain"}}};
    (void)co_await response.async_send(200, fields, text("hello"));
}

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

auto upload(event_loop&, http::request& request, http::response& response) -> task<void>
{
    std::array<std::byte, 600> chunk {};
    std::uint64_t count = 0;
    std::uint64_t sum = 0;
    for (;;) {
        auto read = co_await request.async_read_body(chunk);
        if (!read) co_return;
        if (!*read) {
            (void)co_await response.async_send(400, {}, text(
                read->error() == std::make_error_code(std::errc::message_size)
                    ? "too large" : "bad body"));
            co_return;
        }
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

// Reads only after a delay, so an early upload fills its stream buffer and
// the connection pauses its input until this handler drains it.
auto late_upload(event_loop& loop, http::request& request, http::response& response)
    -> task<void>
{
    (void)co_await sleep_for(loop, 200ms);
    co_await upload(loop, request, response);
}

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

// A large streamed response, larger than one frame and the stream window.
auto big(event_loop&, http::request&, http::response& response) -> task<void>
{
    static const std::string block(50000, 'b');
    if (!co_await response.async_start(200, {})) co_return;
    for (int round = 0; round < 3; ++round) {
        auto written = co_await response.async_write(text(block));
        if (!written || !*written) co_return;
    }
    (void)co_await response.async_finish();
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

auto short_body(event_loop&, http::request&, http::response& response) -> task<void>
{
    const std::array<http::header, 1> fields {{{"content-length", "5"}}};
    if (!co_await response.async_start(200, fields)) co_return;
    (void)co_await response.async_write(text("abc"));
    (void)co_await response.async_finish();
}

auto file(event_loop&, http::request& request, http::response& response) -> task<void>
{
    const auto* path = static_cast<const std::string*>(request.route_context());
    unique_fd descriptor(::open(path->c_str(), O_RDONLY | O_CLOEXEC));
    (void)co_await response.async_send_file(200, {}, std::move(descriptor), 2, 5);
}

auto slow(event_loop& loop, http::request&, http::response& response) -> task<void>
{
    (void)co_await sleep_for(loop, 300ms);
    (void)co_await response.async_send(200, {}, text("slow"));
}

// Waits at most 100 ms for a body, using the library's timeout composition.
auto timed(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    std::array<std::byte, 64> chunk {};
    const auto waited = co_await with_timeout(loop, request.async_read_body(chunk), 100ms);
    const bool timed_out = waited && waited->state == timeout_result<
        std::expected<std::size_t, std::error_code>>::outcome::timed_out;
    (void)co_await response.async_send(timed_out ? 408 : 200, {},
                                       text(timed_out ? "timed out" : "read"));
}

// --- public client ---------------------------------------------------------

struct result {
    std::optional<std::expected<http2::client_response, std::error_code>> response;
    std::vector<http2::header> trailers;
};

auto request_task(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
                  http2::client_request request, result& out) -> task<void>
{
    auto trailers = &out.trailers;
    auto value = co_await http2::async_request(loop, ip_endpoint::loopback_v4(port),
        std::move(context), "localhost", std::move(request), {},
        [trailers](unsigned status, std::span<const http2::header> fields) {
            if (status == 0) trailers->assign(fields.begin(), fields.end());
            return std::error_code {};
        });
    if (value) out.response = std::move(*value);
    else out.response = std::unexpected(std::make_error_code(std::errc::operation_canceled));
}

auto run_requests(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
                  std::vector<http2::client_request>& requests, std::vector<result>& results)
    -> task<void>
{
    for (std::size_t index = 0; index < requests.size(); ++index)
        (void)co_await request_task(loop, port, context, std::move(requests[index]),
                                    results[index]);
    loop.stop();
}

auto watchdog(event_loop& loop, bool& timed_out) -> task<void>
{
    if (co_await sleep_for(loop, 10s) == timer_wait_result::expired) {
        timed_out = true;
        loop.shutdown(0ms);
    }
}

struct certificates {
    std::filesystem::path certificate;
    std::filesystem::path key;
};

struct server_fixture {
    event_loop& loop;
    http::https_server* server {nullptr};
    std::uint16_t port {0};
};

auto start_server(event_loop& loop, const certificates& files, http::server_options options)
    -> server_fixture
{
    auto listener = std::make_unique<http::https_server>(loop, ip_endpoint::loopback_v4(0),
        tls_context::make_server(files.certificate, files.key), std::move(options));
    sockaddr_in address {};
    socklen_t length = sizeof(address);
    check(::getsockname(listener->descriptor(), reinterpret_cast<sockaddr*>(&address),
                        &length) == 0, "getsockname");
    server_fixture fixture {loop, listener.get(), ntohs(address.sin_port)};
    loop.add(std::move(listener));
    check(loop.spawn(fixture.server->run()) == task_spawn_result::accepted, "spawn server");
    return fixture;
}

auto finish(event_loop& loop, task_handle<void>& timer) -> void
{
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
}

auto serve(const certificates& files, http::server_options options,
           std::vector<http2::client_request> requests) -> std::vector<result>
{
    event_loop loop;
    const auto fixture = start_server(loop, files, std::move(options));
    std::vector<result> results(requests.size());
    check(loop.spawn(run_requests(loop, fixture.port, tls_context::make_client(files.certificate),
                                  requests, results)) == task_spawn_result::accepted,
          "spawn client");
    bool timed_out = false;
    task_handle<void> timer;
    check(loop.spawn(watchdog(loop, timed_out), timer) == task_spawn_result::accepted,
          "spawn watchdog");
    finish(loop, timer);
    check(!timed_out, "requests timed out");
    return results;
}

auto request(std::string method, std::string target) -> http2::client_request
{
    http2::client_request value;
    value.method = std::move(method);
    value.target = std::move(target);
    value.authority = "example.test";
    return value;
}

auto bytes(std::string_view value) -> std::vector<std::byte>
{
    const auto view = text(value);
    return {view.begin(), view.end()};
}

auto ok(const result& value) -> const http2::client_response&
{
    check(value.response && *value.response, "request failed");
    return **value.response;
}

auto field(const http2::client_response& response, std::string_view name) -> std::string
{
    for (const auto& entry : response.headers) if (entry.name == name) return entry.value;
    return "<none>";
}

// --- raw multiplexing client -----------------------------------------------

auto append_frame(std::vector<std::byte>& out, unsigned type, unsigned flags, unsigned stream,
                  std::span<const std::byte> payload) -> void
{
    const auto size = payload.size();
    for (auto byte : {static_cast<unsigned>(size >> 16) & 255u, static_cast<unsigned>(size >> 8) & 255u,
                      static_cast<unsigned>(size) & 255u, type, flags, 0u, 0u, 0u, stream})
        out.push_back(static_cast<std::byte>(byte));
    out.insert(out.end(), payload.begin(), payload.end());
}

auto get_frame(std::string_view path, unsigned stream) -> std::vector<std::byte>
{
    const std::array<http2::detail::field, 4> fields {{{":method", "GET"}, {":scheme", "https"},
        {":authority", "localhost"}, {":path", std::string(path)}}};
    std::vector<std::byte> block;
    check(http2::detail::hpack_encode(fields, block) == http2::detail::hpack_error::none,
          "encode request");
    std::vector<std::byte> out;
    append_frame(out, 1, 5, stream, block);
    return out;
}

auto open_h2(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context)
    -> task<tls_stream*>
{
    auto owned = std::make_unique<tls_stream>(loop, ip_endpoint::loopback_v4(port),
        std::move(context), tls_client_options {.hostname = "localhost",
                                                .application_protocols = {"h2"}});
    auto* peer = owned.get();
    loop.add(std::move(owned));
    if (!co_await peer->async_connect()) co_return nullptr;
    const auto handshake = co_await peer->async_handshake();
    if (!handshake || !*handshake) co_return nullptr;
    co_return peer;
}

auto send_bytes(event_loop&, tls_stream& peer, std::vector<std::byte> out) -> task<bool>
{
    auto pending = std::span<const std::byte>(out);
    while (!pending.empty()) {
        const auto written = co_await peer.async_write_some(pending);
        if (!written || !*written || **written == 0) co_return false;
        pending = pending.subspan(**written);
    }
    co_return true;
}

auto preface_bytes() -> std::vector<std::byte>
{
    constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    std::vector<std::byte> out(text(preface).begin(), text(preface).end());
    append_frame(out, 4, 0, 0, {});
    return out;
}

// Sends a POST with HEADERS but no body and returns the response DATA.
auto timed_client(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
                  std::string& body) -> task<void>
{
    auto* peer = (co_await open_h2(loop, port, std::move(context))).value_or(nullptr);
    if (peer != nullptr) {
        const std::array<http2::detail::field, 4> fields {{{":method", "POST"},
            {":scheme", "https"}, {":authority", "localhost"}, {":path", "/timed"}}};
        std::vector<std::byte> block;
        check(http2::detail::hpack_encode(fields, block) == http2::detail::hpack_error::none,
              "encode request");
        auto out = preface_bytes();
        append_frame(out, 1, 4, 1, block);
        if ((co_await send_bytes(loop, *peer, std::move(out))).value_or(false)) {
            std::vector<std::byte> input;
            std::array<std::byte, 1024> buffer {};
            bool ended = false;
            while (!ended) {
                const auto received = co_await peer->async_read_some(buffer);
                if (!received || !*received || **received == 0) break;
                input.insert(input.end(), buffer.begin(), buffer.begin() +
                             static_cast<std::ptrdiff_t>(**received));
                while (input.size() >= 9) {
                    const auto size = (std::to_integer<std::size_t>(input[0]) << 16) |
                        (std::to_integer<std::size_t>(input[1]) << 8) |
                        std::to_integer<std::size_t>(input[2]);
                    if (input.size() < 9 + size) break;
                    if (std::to_integer<unsigned>(input[3]) == 0 &&
                        std::to_integer<unsigned>(input[8]) == 1) {
                        body.append(reinterpret_cast<const char*>(input.data() + 9), size);
                        ended = (std::to_integer<unsigned>(input[4]) & 1u) != 0;
                    }
                    input.erase(input.begin(), input.begin() + static_cast<std::ptrdiff_t>(9 + size));
                }
            }
        }
        peer->close();
    }
    loop.stop();
}

// Requests a large streamed response and a large static file, reads one
// chunk, and disconnects while the server is still writing; the server must
// keep serving. Whether a write then raises SIGPIPE depends on timing, so
// tests/event_loop.cc checks the SIGPIPE handling itself.
auto abandon_client(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
                    bool& abandoned) -> task<void>
{
    auto* peer = (co_await open_h2(loop, port, std::move(context))).value_or(nullptr);
    if (peer == nullptr) co_return;
    // Open every window so the server keeps writing until the disconnect.
    constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    std::vector<std::byte> out(text(preface).begin(), text(preface).end());
    constexpr std::array<std::byte, 6> window_setting {std::byte {0}, std::byte {4},
        std::byte {0x7f}, std::byte {0xff}, std::byte {0xff}, std::byte {0xff}};
    append_frame(out, 4, 0, 0, window_setting);
    constexpr std::array<std::byte, 4> connection_credit {std::byte {0x7f}, std::byte {0xfe},
        std::byte {0}, std::byte {0}};
    append_frame(out, 8, 0, 0, connection_credit);
    for (auto frame : {get_frame("/big", 1), get_frame("/large.bin", 3)})
        out.insert(out.end(), frame.begin(), frame.end());
    if ((co_await send_bytes(loop, *peer, std::move(out))).value_or(false)) {
        std::array<std::byte, 1024> buffer {};
        abandoned = static_cast<bool>(co_await peer->async_read_some(buffer));
    }
    peer->close();
}

auto abandon_then_request(event_loop& loop, std::uint16_t port,
                          std::shared_ptr<tls_context> context, bool& abandoned,
                          result& after) -> task<void>
{
    (void)co_await abandon_client(loop, port, context, abandoned);
    (void)co_await sleep_for(loop, 200ms);
    (void)co_await request_task(loop, port, context, request("GET", "/hello"), after);
    loop.stop();
}

// Keeps an idle routed connection open with a pending read, which loop
// shutdown cancels; the stream is not touched afterwards.
auto idle_client(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
                 bool& connected) -> task<void>
{
    auto* peer = (co_await open_h2(loop, port, std::move(context))).value_or(nullptr);
    if (peer == nullptr || !(co_await send_bytes(loop, *peer, preface_bytes())).value_or(false))
        co_return;
    std::array<std::byte, 256> buffer {};
    connected = static_cast<bool>(co_await peer->async_read_some(buffer));
    (void)co_await peer->async_read_some(buffer);
}

auto shutdown_when_connected(event_loop& loop, const bool& connected) -> task<void>
{
    for (int attempt = 0; attempt < 200 && !connected; ++attempt)
        (void)co_await sleep_for(loop, 5ms);
    (void)co_await sleep_for(loop, 50ms);
    loop.shutdown(0ms);
}

// Opens /slow on stream 1 and /hello on stream 3 together, and records the
// order in which their response DATA arrives.
auto multiplex(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
               std::vector<unsigned>& order) -> task<void>
{
    auto owned = std::make_unique<tls_stream>(loop, ip_endpoint::loopback_v4(port),
        std::move(context), tls_client_options {.hostname = "localhost",
                                                .application_protocols = {"h2"}});
    auto* peer = owned.get();
    loop.add(std::move(owned));
    bool secured = false;
    if (co_await peer->async_connect()) {
        const auto handshake = co_await peer->async_handshake();
        secured = handshake && *handshake;
    }
    if (secured) {
        constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        std::vector<std::byte> out(text(preface).begin(), text(preface).end());
        append_frame(out, 4, 0, 0, {});
        for (auto frame : {get_frame("/slow", 1), get_frame("/hello", 3)})
            out.insert(out.end(), frame.begin(), frame.end());
        auto pending = std::span<const std::byte>(out);
        while (!pending.empty()) {
            const auto written = co_await peer->async_write_some(pending);
            if (!written || !*written || **written == 0) break;
            pending = pending.subspan(**written);
        }
        std::vector<std::byte> input;
        std::array<std::byte, 1024> buffer {};
        while (order.size() < 2) {
            const auto received = co_await peer->async_read_some(buffer);
            if (!received || !*received || **received == 0) break;
            input.insert(input.end(), buffer.begin(), buffer.begin() +
                         static_cast<std::ptrdiff_t>(**received));
            while (input.size() >= 9) {
                const auto size = (std::to_integer<std::size_t>(input[0]) << 16) |
                    (std::to_integer<std::size_t>(input[1]) << 8) | std::to_integer<std::size_t>(input[2]);
                if (input.size() < 9 + size) break;
                const auto type = std::to_integer<unsigned>(input[3]);
                const auto flags = std::to_integer<unsigned>(input[4]);
                const auto stream_id = std::to_integer<unsigned>(input[8]);
                if (type == 0 && (flags & 1u) != 0) order.push_back(stream_id);
                input.erase(input.begin(), input.begin() + static_cast<std::ptrdiff_t>(9 + size));
            }
        }
    }
    peer->close();
    loop.stop();
}

class temporary_directory {
public:
    temporary_directory()
    {
        std::random_device random;
        path_ = std::filesystem::temp_directory_path() /
            ("eventloop-h2-routing-" + std::to_string(random()));
        std::filesystem::create_directories(path_ / "www");
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
    const certificates files {directory.path() / "cert.pem", directory.path() / "key.pem"};
    test::make_localhost_certificate(files.certificate, files.key);
    std::ofstream(directory.path() / "www" / "index.html") << "static";
    std::ofstream(directory.path() / "www" / "data.txt") << "0123456789";
    const auto file_path = (directory.path() / "www" / "data.txt").string();

    auto routes = std::make_shared<http::router>();
    check(routes->add(http::method_type::get, "/hello", hello).has_value() &&
          routes->add_prefix(http::method_type::get, "/api/", info).has_value() &&
          routes->add(http::method_type::post, "/upload", upload).has_value() &&
          routes->add(http::method_type::post, "/partial", partial).has_value() &&
          routes->add(http::method_type::post, "/late", late_upload).has_value() &&
          routes->add(http::method_type::get, "/stream", stream).has_value() &&
          routes->add(http::method_type::get, "/big", big).has_value() &&
          routes->add(http::method_type::get, "/silent", silent).has_value() &&
          routes->add(http::method_type::get, "/throw", throwing).has_value() &&
          routes->add(http::method_type::get, "/short", short_body).has_value() &&
          routes->add(http::method_type::get, "/slow", slow).has_value() &&
          routes->add(http::method_type::post, "/timed", timed).has_value() &&
          routes->add(http::method_type::get, "/file", file,
                      const_cast<std::string*>(&file_path)).has_value(),
          "register routes");

    // 60000 bytes exceeds the 16 KiB stream buffer: the client sends it under
    // the default 64 KiB window before applying the server's SETTINGS.
    std::string large(60000, '\0');
    std::uint64_t large_sum = 0;
    for (std::size_t index = 0; index < large.size(); ++index) {
        large[index] = static_cast<char>('a' + index % 26);
        large_sum += static_cast<unsigned char>(large[index]);
    }

    std::vector<http2::client_request> requests;
    requests.push_back(request("GET", "/hello"));
    requests.push_back(request("HEAD", "/hello"));
    requests.push_back(request("OPTIONS", "/hello"));
    requests.push_back(request("POST", "/hello"));
    auto api = request("GET", "/api/items?id=7");
    api.headers.push_back({"x-test", "seen"});
    requests.push_back(std::move(api));
    auto owned_upload = request("POST", "/upload");
    owned_upload.body = bytes(large);
    requests.push_back(std::move(owned_upload));
    auto sourced_upload = request("POST", "/upload");
    sourced_upload.body_source = [remaining = std::size_t {40000}](std::span<std::byte> chunk) mutable
        -> std::expected<std::size_t, std::error_code> {
        const auto count = std::min(remaining, chunk.size());
        std::fill_n(chunk.begin(), count, std::byte {'z'});
        remaining -= count;
        return count;
    };
    requests.push_back(std::move(sourced_upload));
    requests.push_back(request("GET", "/stream"));
    requests.push_back(request("GET", "/big"));
    requests.push_back(request("GET", "/silent"));
    requests.push_back(request("GET", "/short"));
    requests.push_back(request("GET", "/file"));
    requests.push_back(request("GET", "/"));
    auto declared = request("POST", "/upload");
    declared.headers.push_back({"content-length", "200001"});
    declared.body = std::vector<std::byte>(200001, std::byte {'x'});
    requests.push_back(std::move(declared));
    auto streamed_too_large = request("POST", "/upload");
    streamed_too_large.body_source = [remaining = std::size_t {200001}](std::span<std::byte> chunk) mutable
        -> std::expected<std::size_t, std::error_code> {
        const auto count = std::min(remaining, chunk.size());
        std::fill_n(chunk.begin(), count, std::byte {'y'});
        remaining -= count;
        return count;
    };
    requests.push_back(std::move(streamed_too_large));
    auto late = request("POST", "/late");
    late.body = bytes(large);
    requests.push_back(std::move(late));
    auto partial_upload = request("POST", "/partial");
    partial_upload.body = std::vector<std::byte>(5000, std::byte {'p'});
    requests.push_back(std::move(partial_upload));
    requests.push_back(request("GET", "/throw"));

    const auto results = serve(files,
        {.routes = routes, .document_root = directory.path() / "www",
         .max_request_body = 100000},
        std::move(requests));

    const auto& hello_response = ok(results[0]);
    check(hello_response.status == 200 && hello_response.body == bytes("hello") &&
          field(hello_response, "content-type") == "text/plain" &&
          field(hello_response, "content-length") == "5" &&
          field(hello_response, "date") != "<none>", "exact route");
    check(ok(results[1]).status == 200 && ok(results[1]).body.empty() &&
          field(ok(results[1]), "content-length") == "5", "HEAD runs GET without body");
    check(ok(results[2]).status == 204 && field(ok(results[2]), "allow") == "GET, HEAD, OPTIONS",
          "OPTIONS lists methods");
    check(ok(results[3]).status == 405 && field(ok(results[3]), "allow") == "GET, HEAD, OPTIONS",
          "wrong method");
    check(ok(results[4]).body == bytes("/api/items|id=7|seen|example.test"), "prefix route");
    check(ok(results[5]).body == bytes("60000 " + std::to_string(large_sum)),
          "owned upload beyond the stream buffer");
    check(ok(results[6]).body == bytes("40000 " + std::to_string(40000ull * 'z')),
          "streamed upload without content-length");
    check(ok(results[7]).body == bytes("abcdefgh") && results[7].trailers.size() == 1 &&
          results[7].trailers[0].name == "x-done", "streamed response with trailers");
    check(ok(results[8]).body.size() == 150000, "large streamed response");
    check(ok(results[9]).status == 500, "handler without response");
    check(results[10].response && !*results[10].response &&
          results[10].response->error() == std::make_error_code(std::errc::connection_reset),
          "short body resets the stream");
    check(ok(results[11]).body == bytes("23456"), "file range");
    check(ok(results[12]).status == 200 && ok(results[12]).body == bytes("static"),
          "static fallback");
    check(ok(results[13]).status == 413, "declared body above max_request_body");
    check(ok(results[14]).status == 400 && ok(results[14]).body == bytes("too large"),
          "streamed body above max_request_body");
    check(ok(results[15]).body == bytes("60000 " + std::to_string(large_sum)),
          "paused input resumes when the handler reads");
    check(ok(results[16]).body == bytes("partial"), "unread body stopped");
    check(ok(results[17]).status == 500, "throwing handler answers 500");

    // Handlers on one connection run concurrently: /hello on stream 3 is
    // answered while /slow on stream 1 sleeps.
    {
        event_loop loop;
        const auto fixture = start_server(loop, files, {.routes = routes});
        std::vector<unsigned> order;
        check(loop.spawn(multiplex(loop, fixture.port, tls_context::make_client(files.certificate),
                                   order)) == task_spawn_result::accepted, "spawn multiplex");
        bool timed_out = false;
        task_handle<void> timer;
        check(loop.spawn(watchdog(loop, timed_out), timer) == task_spawn_result::accepted,
              "spawn watchdog");
        finish(loop, timer);
        check(!timed_out && order == std::vector<unsigned> {3, 1}, "concurrent handlers");
    }

    // A client that disconnects mid-response does not end the server process.
    {
        {
            std::ofstream large(directory.path() / "www" / "large.bin", std::ios::binary);
            const std::string block(64 * 1024, 'L');
            for (int index = 0; index < 64; ++index) large << block;
        }
        event_loop loop;
        const auto fixture = start_server(loop, files,
            {.routes = routes, .document_root = directory.path() / "www"});
        bool abandoned = false;
        result after;
        check(loop.spawn(abandon_then_request(loop, fixture.port,
                  tls_context::make_client(files.certificate), abandoned, after)) ==
              task_spawn_result::accepted, "spawn abandoning client");
        bool timed_out = false;
        task_handle<void> timer;
        check(loop.spawn(watchdog(loop, timed_out), timer) == task_spawn_result::accepted,
              "spawn watchdog");
        finish(loop, timer);
        check(!timed_out && abandoned && ok(after).body == bytes("hello"),
              "server survives a client that disconnects mid-response");
    }

    // A handler's body read is cancelled by with_timeout on HTTP/2.
    {
        event_loop loop;
        const auto fixture = start_server(loop, files, {.routes = routes});
        std::string body;
        check(loop.spawn(timed_client(loop, fixture.port, tls_context::make_client(files.certificate),
                                      body)) == task_spawn_result::accepted, "spawn timed client");
        bool timed_out = false;
        task_handle<void> timer;
        check(loop.spawn(watchdog(loop, timed_out), timer) == task_spawn_result::accepted,
              "spawn watchdog");
        finish(loop, timer);
        check(!timed_out && body == "timed out", "cancelled body read");
    }

    // loop.shutdown() ends an idle routed connection without peer activity.
    {
        event_loop loop;
        const auto fixture = start_server(loop, files, {.routes = routes});
        bool connected = false;
        check(loop.spawn(idle_client(loop, fixture.port, tls_context::make_client(files.certificate),
                                     connected)) == task_spawn_result::accepted, "spawn idle client");
        check(loop.spawn(shutdown_when_connected(loop, connected)) == task_spawn_result::accepted,
              "spawn shutdown");
        const auto started = std::chrono::steady_clock::now();
        while (loop.run() == event_loop_result::interrupted) {}
        check(connected && std::chrono::steady_clock::now() - started < 5s,
              "shutdown with an idle routed connection");
    }

    // Routes only: unmatched paths answer 404.
    std::vector<http2::client_request> routed_only;
    routed_only.push_back(request("GET", "/index.html"));
    routed_only.push_back(request("GET", "/hello"));
    const auto only = serve(files, {.routes = routes}, std::move(routed_only));
    check(ok(only[0]).status == 404 && ok(only[1]).body == bytes("hello"),
          "routes without document root");
}
