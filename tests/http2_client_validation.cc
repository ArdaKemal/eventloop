#include "eventloop/event_loop.h"
#include "eventloop/http2/client.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "tls_test_certificate.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

using namespace eventloop;
using namespace std::chrono_literals;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP/2 client validation: " << message << '\n';
    std::exit(1);
}

template<class T>
[[nodiscard]] auto flatten(T result)
{
    using inner = typename T::value_type;
    if (!result) return inner(std::unexpected(std::make_error_code(std::errc::operation_canceled)));
    return std::move(*result);
}

auto append_frame(std::string& out, unsigned type, unsigned flags, unsigned stream,
                  std::string_view payload) -> void
{
    out += static_cast<char>((payload.size() >> 16) & 255);
    out += static_cast<char>((payload.size() >> 8) & 255);
    out += static_cast<char>(payload.size() & 255);
    out += static_cast<char>(type);
    out += static_cast<char>(flags);
    out += std::string_view("\0\0\0", 3);
    out += static_cast<char>(stream);
    out += payload;
}

// HPACK literal field without indexing and with a literal name (RFC 7541 6.2.2).
[[nodiscard]] auto literal(std::string_view name, std::string_view value) -> std::string
{
    std::string out(1, '\0');
    out += static_cast<char>(name.size());
    out += name;
    out += static_cast<char>(value.size());
    out += value;
    return out;
}

constexpr unsigned end_stream = 1;
constexpr unsigned end_headers = 4;

// SETTINGS, then the response HEADERS on stream 1.
[[nodiscard]] auto response(std::string_view status,
                            std::vector<std::pair<std::string_view, std::string_view>> fields,
                            bool fin) -> std::string
{
    std::string block = literal(":status", status);
    for (const auto& [name, value] : fields) block += literal(name, value);
    std::string out;
    append_frame(out, 4, 0, 0, {});
    append_frame(out, 1, end_headers | (fin ? end_stream : 0), 1, block);
    return out;
}

auto scripted_server(event_loop& loop, tcp_acceptor& listener,
                     std::shared_ptr<tls_context> context, std::string script) -> task<void>
{
    auto accepted = co_await listener.async_accept();
    if (!accepted) co_return;
    auto owned = std::make_unique<tls_stream>(loop, std::move(*accepted), std::move(context),
        tls_server_options {.application_protocols = {"h2"}});
    auto* peer = owned.get();
    loop.add(std::move(owned));
    if (flatten(co_await peer->async_handshake())) {
        auto pending = std::as_bytes(std::span(script));
        while (!pending.empty()) {
            const auto written = flatten(co_await peer->async_write_some(pending));
            if (!written || *written == 0) break;
            pending = pending.subspan(*written);
        }
        // Drain the request until the client closes the connection.
        std::array<std::byte, 1024> buffer {};
        for (;;) {
            const auto received = flatten(co_await peer->async_read_some(buffer));
            if (!received || *received == 0) break;
        }
    }
    peer->close();
}

using outcome = std::expected<http2::client_response, std::error_code>;

auto client(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
            http2::client_request request, std::optional<outcome>& result) -> task<void>
{
    result = flatten(co_await http2::async_request(loop, ip_endpoint::loopback_v4(port),
        std::move(context), "localhost", std::move(request)));
    loop.stop();
}

auto watchdog(event_loop& loop, bool& timed_out) -> task<void>
{
    if (co_await sleep_for(loop, 3s) == timer_wait_result::expired) {
        timed_out = true;
        loop.shutdown(0ms);
    }
}

struct certificate_files {
    std::filesystem::path certificate;
    std::filesystem::path key;
};

// Runs one request against a peer that replies with script. Without a script,
// no peer is accepted, for requests rejected before connecting.
[[nodiscard]] auto exchange(const certificate_files& files, http2::client_request request,
                            std::optional<std::string> script) -> outcome
{
    event_loop loop;
    auto listener = std::make_unique<tcp_acceptor>(loop, ip_endpoint::loopback_v4(0));
    sockaddr_in address {};
    socklen_t length = sizeof(address);
    check(::getsockname(listener->descriptor(), reinterpret_cast<sockaddr*>(&address),
                        &length) == 0, "getsockname");
    auto* acceptor = listener.get();
    loop.add(std::move(listener));
    if (script)
        check(loop.spawn(scripted_server(loop, *acceptor,
                  tls_context::make_server(files.certificate, files.key), std::move(*script))) ==
              task_spawn_result::accepted, "spawn server");
    std::optional<outcome> result;
    check(loop.spawn(client(loop, ntohs(address.sin_port),
              tls_context::make_client(files.certificate), std::move(request), result)) ==
          task_spawn_result::accepted, "spawn client");
    bool timed_out = false;
    task_handle<void> timer;
    check(loop.spawn(watchdog(loop, timed_out), timer) == task_spawn_result::accepted,
          "spawn watchdog");
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    check(!timed_out && result.has_value(), "request did not complete");
    return std::move(*result);
}

[[nodiscard]] auto fails_with(const outcome& result, std::errc code) -> bool
{
    return !result && result.error() == std::make_error_code(code);
}

[[nodiscard]] auto get(std::string method = "GET") -> http2::client_request
{
    http2::client_request request;
    request.method = std::move(method);
    return request;
}

[[nodiscard]] auto bytes(std::string_view text) -> std::vector<std::byte>
{
    const auto view = std::as_bytes(std::span(text));
    return {view.begin(), view.end()};
}

auto responses(const certificate_files& files) -> void
{
    std::string ok = response("200", {{"content-length", "5"}, {"content-length", "5"}}, false);
    append_frame(ok, 0, 0, 1, "ab");
    append_frame(ok, 0, end_stream, 1, "cde");
    const auto accepted = exchange(files, get(), ok);
    check(accepted && accepted->status == 200 && accepted->body == bytes("abcde"),
          "DATA matching Content-Length");

    for (auto field : {std::pair {"connection", "close"}, {"keep-alive", "1"},
                       {"proxy-connection", "close"}, {"transfer-encoding", "chunked"},
                       {"upgrade", "h2c"}, {"te", "gzip"}})
        check(fails_with(exchange(files, get(), response("200", {field}, true)),
                         std::errc::protocol_error), "connection-specific response field");

    std::string short_body = response("200", {{"content-length", "5"}}, false);
    append_frame(short_body, 0, end_stream, 1, "abc");
    check(fails_with(exchange(files, get(), short_body), std::errc::protocol_error),
          "DATA shorter than Content-Length");
    check(fails_with(exchange(files, get(), response("200", {{"content-length", "5"}}, true)),
                     std::errc::protocol_error), "Content-Length without DATA");

    std::string long_body = response("200", {{"content-length", "2"}}, false);
    append_frame(long_body, 0, end_stream, 1, "abc");
    check(fails_with(exchange(files, get(), long_body), std::errc::protocol_error),
          "DATA longer than Content-Length");

    check(fails_with(exchange(files, get(), response("200",
              {{"content-length", "4"}, {"content-length", "5"}}, true)),
          std::errc::protocol_error), "conflicting Content-Length");
    check(fails_with(exchange(files, get(), response("200", {{"content-length", "+4"}}, true)),
                     std::errc::protocol_error), "non-numeric Content-Length");

    for (auto status : {"204", "304"}) {
        std::string with_data = response(status, {}, false);
        append_frame(with_data, 0, end_stream, 1, "x");
        check(fails_with(exchange(files, get(), with_data), std::errc::protocol_error),
              "DATA on a bodyless status");
    }
    std::string head_data = response("200", {}, false);
    append_frame(head_data, 0, end_stream, 1, "x");
    check(fails_with(exchange(files, get("HEAD"), head_data), std::errc::protocol_error),
          "DATA in a HEAD response");

    // Content-Length describes the omitted representation for HEAD and 304.
    const auto head = exchange(files, get("HEAD"),
        response("200", {{"content-length", "10"}}, true));
    check(head && head->status == 200 && head->body.empty(), "HEAD with Content-Length");
    std::string not_modified = response("304", {{"content-length", "10"}}, false);
    append_frame(not_modified, 0, end_stream, 1, {});
    const auto cached = exchange(files, get(), not_modified);
    check(cached && cached->status == 304, "304 with Content-Length and empty DATA");
}

auto requests(const certificate_files& files) -> void
{
    auto declared = [](std::string_view value) {
        auto request = get("POST");
        request.headers.push_back({"content-length", std::string(value)});
        return request;
    };
    auto owned = declared("4");
    owned.body = bytes("abc");
    check(fails_with(exchange(files, std::move(owned), {}), std::errc::invalid_argument),
          "owned body shorter than Content-Length");
    check(fails_with(exchange(files, declared("1"), {}), std::errc::invalid_argument),
          "Content-Length without a body");
    check(fails_with(exchange(files, declared("x"), {}), std::errc::invalid_argument),
          "non-numeric request Content-Length");
    auto te = get();
    te.headers.push_back({"te", "gzip"});
    check(fails_with(exchange(files, std::move(te), {}), std::errc::invalid_argument),
          "TE other than trailers");

    const auto sourced = [&](std::string_view value, std::size_t produce) {
        auto request = declared(value);
        request.body_source = [remaining = produce](std::span<std::byte> chunk) mutable
            -> std::expected<std::size_t, std::error_code> {
            const auto count = std::min(remaining, chunk.size());
            std::fill_n(chunk.begin(), count, std::byte {'a'});
            remaining -= count;
            return count;
        };
        return exchange(files, std::move(request), response("200", {}, true));
    };
    check(fails_with(sourced("4", 3), std::errc::invalid_argument),
          "source ends before Content-Length");
    check(fails_with(sourced("2", 3), std::errc::invalid_argument),
          "source exceeds Content-Length");
    check(sourced("3", 3).has_value(), "source matches Content-Length");
}

class temporary_directory {
public:
    temporary_directory()
    {
        std::random_device random;
        for (int attempt = 0; attempt < 32; ++attempt) {
            auto candidate = std::filesystem::temp_directory_path() /
                ("eventloop-h2-client-" + std::to_string(random()));
            if (std::filesystem::create_directory(candidate)) { path_ = candidate; return; }
        }
        check(false, "create temporary directory");
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
    const certificate_files files {directory.path() / "cert.pem", directory.path() / "key.pem"};
    test::make_localhost_certificate(files.certificate, files.key);
    responses(files);
    requests(files);
}
