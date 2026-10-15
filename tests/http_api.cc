#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/server.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/tcp_stream.h"

#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "tls_test_certificate.h"
#endif

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

using namespace eventloop;
using namespace std::chrono_literals;

namespace {

class temporary_root {
public:
    temporary_root()
    {
        std::random_device random;
        for (int attempt = 0; attempt < 32; ++attempt) {
            const auto candidate = std::filesystem::temp_directory_path() /
                ("eventloop-http-api-" + std::to_string(random()));
            if (std::filesystem::create_directory(candidate)) {
                path_ = candidate;
                return;
            }
        }
        throw std::runtime_error("could not create temporary HTTP root");
    }

    ~temporary_root()
    {
        if (!path_.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(path_, ignored);
        }
    }

    temporary_root(const temporary_root&) = delete;
    auto operator=(const temporary_root&) -> temporary_root& = delete;

    [[nodiscard]] auto path() const -> const std::filesystem::path&
    {
        return path_;
    }

private:
    std::filesystem::path path_;
};

auto require(bool condition, const char* message) -> void
{
    if (!condition) throw std::runtime_error(message);
}

auto write_file(const std::filesystem::path& path, std::string_view contents)
    -> void
{
    std::ofstream output(path, std::ios::binary);
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    require(static_cast<bool>(output), "write test file");
}

[[nodiscard]] auto listener_port(const tcp_acceptor& listener) -> std::uint16_t
{
    sockaddr_in address {};
#ifdef _WIN32
    int length = sizeof(address);
    const auto status = ::getsockname(static_cast<SOCKET>(listener.descriptor()),
                                     reinterpret_cast<sockaddr*>(&address), &length);
#else
    socklen_t length = sizeof(address);
    const auto status = ::getsockname(listener.descriptor(),
                                     reinterpret_cast<sockaddr*>(&address), &length);
#endif
    require(status == 0, "getsockname HTTP listener");
    return ntohs(address.sin_port);
}

auto request_client(event_loop& loop, tcp_stream& peer,
                    std::string_view request, std::string& response,
                    bool& completed) -> task<void>
{
    if (co_await peer.async_connect()) {
        auto pending = std::as_bytes(std::span {request.data(), request.size()});
        while (!pending.empty()) {
            const auto written = co_await peer.async_write_some(pending);
            if (!written || *written == 0) break;
            pending = pending.subspan(*written);
        }
        if (pending.empty()) {
            std::array<std::byte, 1024> buffer {};
            for (;;) {
                const auto received = co_await peer.async_read_some(buffer);
                if (!received) break;
                if (*received == 0) {
                    completed = true;
                    break;
                }
                response.append(reinterpret_cast<const char*>(buffer.data()),
                                *received);
            }
        }
    }
    peer.close();
    loop.stop();
}

auto watchdog(event_loop& loop, bool& timed_out) -> task<void>
{
    if (co_await sleep_for(loop, 3s) == timer_wait_result::expired) {
        timed_out = true;
        loop.shutdown(0ms);
    }
}

[[nodiscard]] auto send_request(const std::filesystem::path& root,
                                std::string_view request,
                                http::server_options options = {}) -> std::string
{
    event_loop loop;
    options.document_root = root;
    auto listener = std::make_unique<http::server>(
        loop, ip_endpoint::loopback_v4(0), options);
    auto* server = listener.get();
    const auto port = listener_port(*server);
    auto client = std::make_unique<tcp_stream>(loop, ip_endpoint::loopback_v4(port));
    auto* peer = client.get();
    loop.add(std::move(listener));
    loop.add(std::move(client));
    auto server_task = server->run();
    require(loop.spawn(std::move(server_task)) == task_spawn_result::accepted,
            "spawn HTTP server");
    std::string response;
    bool completed = false;
    bool timed_out = false;
    auto client_task = request_client(loop, *peer, request, response, completed);
    require(loop.spawn(std::move(client_task)) ==
                task_spawn_result::accepted, "spawn HTTP client");
    task_handle<void> timer;
    require(loop.spawn(watchdog(loop, timed_out), timer) ==
                task_spawn_result::accepted, "spawn HTTP watchdog");
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    require(!timed_out && completed, "HTTP request did not complete");
    require(loop.coroutine_statistics().live == 0, "HTTP tasks remain live");
    return response;
}

#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
auto make_localhost_certificate(const std::filesystem::path& certificate,
                                const std::filesystem::path& key) -> void
{
    eventloop::test::make_localhost_certificate(certificate, key);
}

auto secure_request_client(event_loop& loop, tls_stream& peer,
                           std::string_view request, std::string& response,
                           std::string& protocol, bool& completed,
                           std::string& failure) -> task<void>
{
    const auto connected = co_await peer.async_connect();
    if (!connected) failure = "HTTPS TCP connect failed";
    else {
        const auto handshake = flatten_result(co_await peer.async_handshake());
        if (!handshake) failure = "HTTPS handshake failed";
        else {
            protocol = peer.application_protocol();
            auto pending = std::as_bytes(std::span {request.data(), request.size()});
            while (!pending.empty()) {
                const auto written = flatten_result(
                    co_await peer.async_write_some(pending));
                if (!written || *written == 0) {
                    failure = "HTTPS request write failed";
                    break;
                }
                pending = pending.subspan(*written);
            }
            if (pending.empty()) {
                std::array<std::byte, 1024> buffer {};
                for (;;) {
                    const auto received = flatten_result(
                        co_await peer.async_read_some(buffer));
                    if (!received) {
                        failure = "HTTPS response read failed after " +
                            std::to_string(response.size()) + " bytes: " +
                            received.error().message();
                        break;
                    }
                    if (*received == 0) {
                        completed = true;
                        break;
                    }
                    response.append(reinterpret_cast<const char*>(buffer.data()),
                                    *received);
                }
            }
        }
    }
    peer.close();
    loop.stop();
}

auto append_h2_frame(std::string& output, std::uint8_t type,
                     std::uint8_t flags, std::uint32_t stream_id,
                     std::string_view payload) -> void
{
    const auto length = payload.size();
    require(length <= 0xffffff, "HTTP/2 test frame too large");
    output.push_back(static_cast<char>((length >> 16) & 0xff));
    output.push_back(static_cast<char>((length >> 8) & 0xff));
    output.push_back(static_cast<char>(length & 0xff));
    output.push_back(static_cast<char>(type));
    output.push_back(static_cast<char>(flags));
    for (int shift = 24; shift >= 0; shift -= 8) {
        output.push_back(static_cast<char>((stream_id >> shift) & 0xff));
    }
    output.append(payload);
}

[[nodiscard]] auto h2_response_complete(std::string_view response) -> bool
{
    std::size_t offset = 0;
    while (response.size() - offset >= 9) {
        const auto byte = [&](std::size_t index) {
            return static_cast<std::uint8_t>(response[offset + index]);
        };
        const auto length = (static_cast<std::size_t>(byte(0)) << 16) |
                            (static_cast<std::size_t>(byte(1)) << 8) | byte(2);
        if (response.size() - offset - 9 < length) return false;
        const auto type = byte(3);
        const auto flags = byte(4);
        const auto stream_id = (static_cast<std::uint32_t>(byte(5) & 0x7f) << 24) |
                               (static_cast<std::uint32_t>(byte(6)) << 16) |
                               (static_cast<std::uint32_t>(byte(7)) << 8) | byte(8);
        offset += 9 + length;
        if (stream_id == 1 && (type == 0 || type == 1) && (flags & 1) != 0) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] auto h2_stream_data_bytes(std::string_view response) -> std::size_t
{
    std::size_t offset = 0;
    std::size_t total = 0;
    while (response.size() - offset >= 9) {
        const auto byte = [&](std::size_t index) {
            return static_cast<std::uint8_t>(response[offset + index]);
        };
        const auto length = (static_cast<std::size_t>(byte(0)) << 16) |
                            (static_cast<std::size_t>(byte(1)) << 8) | byte(2);
        if (response.size() - offset - 9 < length) break;
        const auto type = byte(3);
        const auto stream_id = (static_cast<std::uint32_t>(byte(5) & 0x7f) << 24) |
                               (static_cast<std::uint32_t>(byte(6)) << 16) |
                               (static_cast<std::uint32_t>(byte(7)) << 8) | byte(8);
        if (type == 0 && stream_id == 1) total += length;
        offset += 9 + length;
    }
    return total;
}

auto h2_request_client(event_loop& loop, tls_stream& peer,
                       std::string& response, std::string& protocol,
                       bool& completed, std::string& failure) -> task<void>
{
    const auto connected = co_await peer.async_connect();
    if (!connected) failure = "HTTP/2 TCP connect failed";
    else {
        const auto handshake = flatten_result(co_await peer.async_handshake());
        if (!handshake) failure = "HTTP/2 TLS handshake failed";
        else {
            protocol = peer.application_protocol();
            std::string request = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            append_h2_frame(request, 4, 0, 0, {}); // SETTINGS
            const std::string_view headers =
                "\x82\x87\x44\x0a/large.bin\x41\x09localhost";
            append_h2_frame(request, 1, 0x5, 1, headers); // HEADERS, END_HEADERS | END_STREAM
            auto pending = std::as_bytes(std::span {request.data(), request.size()});
            while (!pending.empty()) {
                const auto written = flatten_result(co_await peer.async_write_some(pending));
                if (!written || *written == 0) {
                    failure = "HTTP/2 request write failed";
                    break;
                }
                pending = pending.subspan(*written);
            }
            if (pending.empty()) {
                std::array<std::byte, 1024> buffer {};
                bool window_updated = false;
                while (!h2_response_complete(response)) {
                    const auto received = flatten_result(
                        co_await peer.async_read_some(buffer));
                    if (!received || *received == 0) {
                        failure = "HTTP/2 response read failed";
                        break;
                    }
                    response.append(reinterpret_cast<const char*>(buffer.data()),
                                    *received);
                    if (!window_updated &&
                        h2_stream_data_bytes(response) >= 65535) {
                        constexpr char increment[] = "\0\x02\0\0";
                        std::string updates;
                        append_h2_frame(updates, 8, 0, 0,
                                        std::string_view(increment, 4));
                        append_h2_frame(updates, 8, 0, 1,
                                        std::string_view(increment, 4));
                        auto pending_update = std::as_bytes(
                            std::span {updates.data(), updates.size()});
                        while (!pending_update.empty()) {
                            const auto written = flatten_result(
                                co_await peer.async_write_some(pending_update));
                            if (!written || *written == 0) {
                                failure = "HTTP/2 WINDOW_UPDATE write failed";
                                break;
                            }
                            pending_update = pending_update.subspan(*written);
                        }
                        if (!failure.empty()) break;
                        window_updated = true;
                    }
                    if (response.size() > 128 * 1024) {
                        failure = "HTTP/2 response exceeded test limit";
                        break;
                    }
                }
                completed = h2_response_complete(response);
            }
        }
    }
    peer.close();
    loop.stop();
}

[[nodiscard]] auto send_h2_request(const std::filesystem::path& root,
                                   const std::filesystem::path& certificate,
                                   const std::filesystem::path& key,
                                   std::uint16_t http3_port = 0)
    -> std::pair<std::string, std::string>
{
    auto server_context = tls_context::make_server(certificate, key);
    auto client_context = tls_context::make_client(certificate);
    event_loop loop;
    auto listener = std::make_unique<http::https_server>(
        loop, ip_endpoint::loopback_v4(0), std::move(server_context),
        http::server_options {.document_root = root, .enable_http2 = true,
                              .advertise_http3_port = http3_port});
    auto* server = listener.get();
    const auto port = listener_port(*server);
    auto client = std::make_unique<tls_stream>(
        loop, ip_endpoint::loopback_v4(port), std::move(client_context),
        tls_client_options {.hostname = "localhost",
                            .application_protocols = {"h2"}});
    auto* peer = client.get();
    loop.add(std::move(listener));
    loop.add(std::move(client));
    require(loop.spawn(server->run()) == task_spawn_result::accepted,
            "spawn HTTP/2 server");
    std::string response;
    std::string protocol;
    std::string failure;
    bool completed = false;
    bool timed_out = false;
    require(loop.spawn(h2_request_client(loop, *peer, response, protocol,
                                         completed, failure)) == task_spawn_result::accepted,
            "spawn HTTP/2 client");
    task_handle<void> timer;
    require(loop.spawn(watchdog(loop, timed_out), timer) ==
                task_spawn_result::accepted, "spawn HTTP/2 watchdog");
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    require(!timed_out, "HTTP/2 request timed out");
    if (!failure.empty()) throw std::runtime_error(failure);
    require(completed, "HTTP/2 response did not complete");
    require(loop.coroutine_statistics().live == 0, "HTTP/2 tasks remain live");
    return {std::move(response), std::move(protocol)};
}

auto check_h2_response(std::string_view response, std::string_view expected_body)
    -> void
{
    std::size_t offset = 0;
    bool saw_headers = false;
    bool ended = false;
    std::string body;
    while (response.size() - offset >= 9) {
        const auto byte = [&](std::size_t index) {
            return static_cast<std::uint8_t>(response[offset + index]);
        };
        const auto length = (static_cast<std::size_t>(byte(0)) << 16) |
                            (static_cast<std::size_t>(byte(1)) << 8) | byte(2);
        require(response.size() - offset - 9 >= length, "truncated HTTP/2 frame");
        const auto type = byte(3);
        const auto flags = byte(4);
        const auto stream_id = (static_cast<std::uint32_t>(byte(5) & 0x7f) << 24) |
                               (static_cast<std::uint32_t>(byte(6)) << 16) |
                               (static_cast<std::uint32_t>(byte(7)) << 8) | byte(8);
        const auto payload = response.substr(offset + 9, length);
        if (type == 1 && stream_id == 1) {
            require(!saw_headers, "duplicate HTTP/2 response headers");
            require((flags & 0x4) != 0, "unfinished HTTP/2 response headers");
            require(payload.starts_with(std::string_view("\0\x07:status\x03", 10)),
                    "missing HTTP/2 response status");
            require(payload.substr(10, 3) == "200", "unexpected HTTP/2 status");
            saw_headers = true;
        } else if (type == 0 && stream_id == 1) {
            require(saw_headers, "HTTP/2 DATA before HEADERS");
            body.append(payload);
        } else if (type == 3 || type == 7) {
            throw std::runtime_error("HTTP/2 stream or connection reset");
        }
        if (stream_id == 1 && (type == 0 || type == 1) && (flags & 1) != 0) {
            ended = true;
        }
        offset += 9 + length;
    }
    require(saw_headers && ended, "incomplete HTTP/2 response");
    require(body == expected_body, "unexpected HTTP/2 body");
}

[[nodiscard]] auto send_secure_request(const std::filesystem::path& root,
                                       const std::filesystem::path& certificate,
                                       const std::filesystem::path& key,
                                       std::string_view request,
                                       std::uint16_t http3_port = 0)
    -> std::pair<std::string, std::string>
{
    auto server_context = tls_context::make_server(certificate, key);
    auto client_context = tls_context::make_client(certificate);
    event_loop loop;
    auto listener = std::make_unique<http::https_server>(
        loop, ip_endpoint::loopback_v4(0), std::move(server_context),
        http::server_options {.document_root = root, .enable_http2 = false,
                              .advertise_http3_port = http3_port});
    auto* server = listener.get();
    const auto port = listener_port(*server);
    auto client = std::make_unique<tls_stream>(
        loop, ip_endpoint::loopback_v4(port), std::move(client_context),
        tls_client_options {.hostname = "localhost",
                            .application_protocols = {"http/1.1"}});
    auto* peer = client.get();
    loop.add(std::move(listener));
    loop.add(std::move(client));
    auto server_task = server->run();
    require(loop.spawn(std::move(server_task)) == task_spawn_result::accepted,
            "spawn HTTPS server");
    std::string response;
    std::string protocol;
    std::string failure;
    bool completed = false;
    bool timed_out = false;
    auto client_task = secure_request_client(
        loop, *peer, request, response, protocol, completed, failure);
    require(loop.spawn(std::move(client_task)) == task_spawn_result::accepted,
            "spawn HTTPS client");
    task_handle<void> timer;
    require(loop.spawn(watchdog(loop, timed_out), timer) ==
                task_spawn_result::accepted, "spawn HTTPS watchdog");
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    require(!timed_out, "HTTPS request timed out");
    if (!failure.empty()) throw std::runtime_error(failure);
    require(completed, "HTTPS response did not complete");
    require(loop.coroutine_statistics().live == 0, "HTTPS tasks remain live");
    return {std::move(response), std::move(protocol)};
}
#endif

[[nodiscard]] auto body_of(const std::string& response) -> std::string_view
{
    const auto separator = response.find("\r\n\r\n");
    require(separator != std::string::npos, "missing HTTP header terminator");
    return std::string_view(response).substr(separator + 4);
}

auto check_response(const std::string& response, std::string_view status,
                    std::string_view body) -> void
{
    require(response.starts_with(status), "unexpected HTTP status");
    require(body_of(response) == body, "unexpected HTTP body");
}

} // namespace

auto main() -> int
{
    try {
        temporary_root root;
        constexpr std::string_view small_body = "small public API response";
        const std::string large(70 * 1024, 'x');
        write_file(root.path() / "small.txt", small_body);
        write_file(root.path() / "large.bin", large);
        const auto listing = root.path() / "listing";
        require(std::filesystem::create_directory(listing),
                "create listing directory");
        write_file(listing / "item.txt", "listed entry");
        require(std::filesystem::create_directory(listing / "nested"),
                "create nested directory");

        const auto small_response = send_request(root.path(),
            "GET /small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        check_response(small_response, "HTTP/1.1 200 OK", small_body);

        const auto large_response = send_request(root.path(),
            "GET /large.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        check_response(large_response, "HTTP/1.1 200 OK", large);
        require(large_response.find("Content-Length: 71680\r\n") !=
                    std::string::npos, "large response length");

        check_response(send_request(root.path(),
            "GET /missing.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
            "HTTP/1.1 404 Not Found", "");

        const auto head_response = send_request(root.path(),
            "HEAD /small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        check_response(head_response, "HTTP/1.1 200 OK", "");
        require(head_response.find("Content-Length: 25\r\n") !=
                    std::string::npos, "HEAD content length");

        check_response(send_request(root.path(),
            "GET /%2e%2e/secret.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
            "HTTP/1.1 400 Bad Request", "");

        const auto listing_response = send_request(root.path(),
            "GET /listing/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            http::server_options {.directory_listing = true});
        require(listing_response.starts_with("HTTP/1.1 200 OK"),
                "directory listing status");
        const auto listing_body = body_of(listing_response);
        require(listing_body.find("<a href=\"item.txt\">item.txt</a>") !=
                    std::string_view::npos, "directory listing file link");
        require(listing_body.find("<a href=\"nested/\">nested/</a>") !=
                    std::string_view::npos, "directory listing folder link");

#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
        temporary_root certificate_root;
        const auto certificate = certificate_root.path() / "cert.pem";
        const auto key = certificate_root.path() / "key.pem";
        make_localhost_certificate(certificate, key);
        const auto [secure_response, negotiated_protocol] = send_secure_request(
            root.path(), certificate, key,
            "GET /small.txt HTTP/1.1\r\nHost: localhost\r\n"
            "Connection: close\r\n\r\n");
        require(negotiated_protocol == "http/1.1", "HTTPS ALPN protocol");
        check_response(secure_response, "HTTP/1.1 200 OK", small_body);

        const auto [secure_large_response, large_protocol] = send_secure_request(
            root.path(), certificate, key,
            "GET /large.bin HTTP/1.1\r\nHost: localhost\r\n"
            "Connection: close\r\n\r\n");
        require(large_protocol == "http/1.1", "HTTPS large ALPN protocol");
        check_response(secure_large_response, "HTTP/1.1 200 OK", large);
        require(secure_large_response.find("Content-Length: 71680\r\n") !=
                    std::string::npos, "HTTPS large response length");
        require(secure_large_response.find("Alt-Svc") == std::string::npos,
                "HTTPS advertised HTTP/3 without a port");

        // Alt-Svc rides static file responses: buffered, sendfile, and 304.
        constexpr std::string_view alt_svc = "\r\nAlt-Svc: h3=\":8444\"; ma=86400\r\n";
        for (const std::string_view target : {"/small.txt", "/large.bin"}) {
            const auto [advertised, advertised_protocol] = send_secure_request(
                root.path(), certificate, key,
                "GET " + std::string(target) + " HTTP/1.1\r\nHost: localhost\r\n"
                "Connection: close\r\n\r\n", 8444);
            require(advertised_protocol == "http/1.1", "Alt-Svc ALPN protocol");
            require(advertised.find(alt_svc) < advertised.find("\r\n\r\n"),
                    "HTTPS static Alt-Svc");
        }
        const auto etag_start = secure_response.find("ETag: ") + 6;
        const auto etag = secure_response.substr(etag_start,
            secure_response.find("\r\n", etag_start) - etag_start);
        const auto [not_modified, not_modified_protocol] = send_secure_request(
            root.path(), certificate, key,
            "GET /small.txt HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: " + etag +
            "\r\nConnection: close\r\n\r\n", 8444);
        require(not_modified.starts_with("HTTP/1.1 304 "), "HTTPS conditional status");
        require(not_modified.find(alt_svc) != std::string::npos, "HTTPS 304 Alt-Svc");
        require(send_request(root.path(),
            "GET /small.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            http::server_options {.advertise_http3_port = 8444})
                .find("Alt-Svc") == std::string::npos, "plain HTTP advertised HTTP/3");

        const auto [h2_response, h2_protocol] = send_h2_request(
            root.path(), certificate, key);
        require(h2_protocol == "h2", "HTTP/2 ALPN protocol");
        check_h2_response(h2_response, large);
        require(h2_response.find("alt-svc") == std::string::npos,
                "HTTP/2 advertised HTTP/3 without a port");
        const auto [h2_advertised, h2_advertised_protocol] = send_h2_request(
            root.path(), certificate, key, 8444);
        require(h2_advertised_protocol == "h2", "HTTP/2 Alt-Svc ALPN protocol");
        check_h2_response(h2_advertised, large);
        require(h2_advertised.find("\x07" "alt-svc\x14h3=\":8444\"; ma=86400") !=
                    std::string::npos, "HTTP/2 static Alt-Svc");
#endif
        // WebTransport needs routes. The check runs before the certificate is
        // read, so placeholder paths are enough.
        {
            event_loop loop;
            http::server_options options;
            options.webtransport.enabled = true;
            bool refused = false;
            try {
                http::http3_server server(loop, ip_endpoint::loopback_v4(0),
                    "unused.pem", "unused.key", options);
            } catch (const std::invalid_argument&) {
                refused = true;
            }
            require(refused, "WebTransport without routes");
        }
    } catch (const std::exception& error) {
        std::cerr << "HTTP API test failed: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
