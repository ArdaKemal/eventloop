#include "eventloop/event_loop.h"
#include "eventloop/http/server.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/tcp_stream.h"

#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>
#include <botan/x509self.h>
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
    auto listener = std::make_unique<http::server>(
        loop, 0, root.string(), "127.0.0.1", options);
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
    Botan::AutoSeeded_RNG rng;
    Botan::RSA_PrivateKey private_key(rng, 2048);
    Botan::X509_Cert_Options options("localhost");
    options.more_dns.push_back("localhost");
    options.not_before("20260101000000Z");
    options.not_after("20300101000000Z");
    const auto generated = Botan::X509::create_self_signed_cert(
        options, private_key, "SHA-256", rng);
    std::ofstream certificate_file(certificate, std::ios::binary);
    certificate_file << generated.PEM_encode();
    require(static_cast<bool>(certificate_file), "write HTTPS certificate");
    std::ofstream key_file(key, std::ios::binary);
    key_file << Botan::PKCS8::PEM_encode(private_key);
    require(static_cast<bool>(key_file), "write HTTPS private key");
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

[[nodiscard]] auto send_secure_request(const std::filesystem::path& root,
                                       const std::filesystem::path& certificate,
                                       const std::filesystem::path& key,
                                       std::string_view request)
    -> std::pair<std::string, std::string>
{
    auto server_context = tls_context::make_server(certificate, key);
    auto client_context = tls_context::make_client(certificate);
    event_loop loop;
    auto listener = std::make_unique<http::https_server>(
        loop, 0, std::move(server_context), root.string(), "127.0.0.1",
        http::server_options {.enable_http2 = false});
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
#endif
    } catch (const std::exception& error) {
        std::cerr << "HTTP API test failed: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
