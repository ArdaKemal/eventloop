#include "posix_socket_helpers.h"

#include "eventloop/event_loop.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/task.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace eventloop;

namespace {

constexpr std::string_view message = "OpenSSL TLS loopback";

[[nodiscard]] auto system_error(const char* operation) -> std::system_error
{
    return {errno, std::system_category(), operation};
}

auto make_nonblocking(int descriptor) -> void
{
    const int flags = fcntl(descriptor, F_GETFL);
    if (flags == -1 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == -1) {
        throw system_error("fcntl");
    }
}

struct connected_pair {
    unique_fd client;
    unique_fd server;
};

[[nodiscard]] auto connect_loopback() -> connected_pair
{
    unique_fd listener(test_socket::socket(AF_INET, SOCK_STREAM));
    if (!listener) throw system_error("socket");

    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener.get(), reinterpret_cast<const sockaddr*>(&address),
             sizeof(address)) == -1 || listen(listener.get(), 1) == -1) {
        throw system_error("bind/listen");
    }
    socklen_t address_size = sizeof(address);
    if (getsockname(listener.get(), reinterpret_cast<sockaddr*>(&address),
                    &address_size) == -1) {
        throw system_error("getsockname");
    }
    unique_fd client(test_socket::socket(AF_INET, SOCK_STREAM));
    if (!client) throw system_error("socket");
    if (connect(client.get(), reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)) == -1) {
        throw system_error("connect");
    }
    unique_fd server(test_socket::accept(listener.get(), true));
    if (!server) throw system_error("accept4");
    make_nonblocking(client.get());
    return {std::move(client), std::move(server)};
}

struct result_state {
    event_loop& loop;
    int completed {0};
    bool server_ok {false};
    bool client_ok {false};
    bool server_ready {false};
    std::size_t write_count {0};

    auto finish() -> void
    {
        if (++completed == 2) loop.stop();
    }
};

struct stream_pair {
    tls_stream* server;
    tls_stream* client;
};

[[nodiscard]] auto add_streams(event_loop& loop,
                               const std::filesystem::path& certificate,
                               const std::filesystem::path& key,
                               const std::filesystem::path& trusted_ca,
                               std::string_view hostname = "localhost",
                               bool small_send_buffer = false,
                               bool mismatch_alpn = false) -> stream_pair
{
    auto sockets = connect_loopback();
    if (small_send_buffer) {
        const int size = 4096;
        if (setsockopt(sockets.client.get(), SOL_SOCKET, SO_SNDBUF,
                       &size, sizeof(size)) == -1) {
            throw system_error("setsockopt");
        }
    }
    auto server = std::make_unique<tls_stream>(
        loop, std::move(sockets.server),
        tls_context::make_server(certificate, key),
        tls_server_options {.application_protocols = {"echo"}});
    auto client = std::make_unique<tls_stream>(
        loop, std::move(sockets.client),
        tls_context::make_client(trusted_ca),
        tls_client_options {.hostname = std::string(hostname),
                            .application_protocols = {mismatch_alpn ? "other" : "echo"}});
    stream_pair pair {server.get(), client.get()};
    loop.add(std::move(server));
    loop.add(std::move(client));
    return pair;
}

[[nodiscard]] auto echo_server(event_loop& loop, tls_stream& stream,
                               result_state& result) -> task<void>
{
    (void)loop;
    auto handshake = co_await stream.async_handshake();
    std::array<std::byte, 64> buffer {};
    if (handshake && *handshake) {
        auto received = co_await stream.async_read_some(buffer);
        if (received && *received && **received == message.size() &&
            std::string_view(reinterpret_cast<const char*>(buffer.data()),
                             **received) == message) {
            auto written = co_await stream.async_write_some(
                std::span<const std::byte>(buffer).first(**received));
            if (written && *written && **written == **received) {
                auto closed = co_await stream.async_close();
                result.server_ok = closed && *closed;
            }
        }
    }
    stream.close();
    result.finish();
}

[[nodiscard]] auto echo_client(event_loop& loop, tls_stream& stream,
                               result_state& result) -> task<void>
{
    (void)loop;
    auto handshake = co_await stream.async_handshake();
    std::array<std::byte, 64> buffer {};
    if (handshake && *handshake && stream.application_protocol() == "echo") {
        auto written = co_await stream.async_write_some(
            std::as_bytes(std::span {message}));
        if (written && *written && **written == message.size()) {
            auto received = co_await stream.async_read_some(buffer);
            if (received && *received && **received == message.size() &&
                std::string_view(reinterpret_cast<const char*>(buffer.data()),
                                 **received) == message) {
                auto eof = co_await stream.async_read_some(buffer);
                result.client_ok = eof && *eof && **eof == 0;
            }
        }
    }
    stream.close();
    result.finish();
}

[[nodiscard]] auto rejection_server(event_loop& loop, tls_stream& stream,
                                    result_state& result) -> task<void>
{
    (void)loop;
    auto handshake = co_await stream.async_handshake();
    if (handshake && *handshake) {
        std::array<std::byte, 1> buffer {};
        auto received = co_await stream.async_read_some(buffer);
        result.server_ok = received && !*received;
    } else {
        result.server_ok = handshake && !*handshake;
    }
    stream.close();
    result.finish();
}

[[nodiscard]] auto rejection_client(event_loop& loop, tls_stream& stream,
                                    result_state& result) -> task<void>
{
    (void)loop;
    auto handshake = co_await stream.async_handshake();
    result.client_ok = handshake && !*handshake &&
                       handshake->error().category() == tls_error_category();
    stream.close();
    result.finish();
}

[[nodiscard]] auto truncation_server(event_loop& loop, tls_stream& stream,
                                     result_state& result) -> task<void>
{
    (void)loop;
    auto handshake = co_await stream.async_handshake();
    if (handshake && *handshake) {
        std::array<std::byte, 1> buffer {};
        auto received = co_await stream.async_read_some(buffer);
        result.server_ok = received && !*received &&
                           received->error() == make_error_code(tls_errc::truncated);
    }
    stream.close();
    result.finish();
}

[[nodiscard]] auto truncation_client(event_loop& loop, tls_stream& stream,
                                     result_state& result) -> task<void>
{
    (void)loop;
    auto handshake = co_await stream.async_handshake();
    result.client_ok = handshake && *handshake;
    stream.close(); // Abrupt transport close without TLS close_notify.
    result.finish();
}

[[nodiscard]] auto blocked_write_server(event_loop& loop, tls_stream& stream,
                                        tls_stream& client,
                                        result_state& result) -> task<void>
{
    auto handshake = co_await stream.async_handshake();
    if (handshake && *handshake) {
        (void)co_await sleep_for(loop, std::chrono::milliseconds {100});
        result.server_ok = result.write_count != 0;
    }
    client.close();
    result.finish();
}

[[nodiscard]] auto blocked_write_client(event_loop& loop, tls_stream& stream,
                                        result_state& result) -> task<void>
{
    (void)loop;
    auto handshake = co_await stream.async_handshake();
    if (handshake && *handshake) {
        static constexpr std::array<std::byte, 4096> bytes {};
        for (;;) {
            auto written = co_await stream.async_write_some(bytes);
            if (!written) break;
            if (!*written) {
                result.client_ok = result.write_count != 0 &&
                                   written->error().value() == ECANCELED;
                break;
            }
            ++result.write_count;
        }
    }
    stream.close();
    result.finish();
}

[[nodiscard]] auto busy_server(event_loop& loop, tls_stream& stream,
                               result_state& result) -> task<void>
{
    (void)loop;
    auto handshake = co_await stream.async_handshake();
    result.server_ready = true;
    if (handshake && *handshake) {
        std::array<std::byte, 1> buffer {};
        auto received = co_await stream.async_read_some(buffer);
        result.server_ok = received && *received && **received == 1;
    }
    stream.close();
    result.finish();
}

[[nodiscard]] auto busy_client(event_loop& loop, tls_stream& stream,
                               tls_stream& server, result_state& result)
    -> task<void>
{
    auto handshake = co_await stream.async_handshake();
    if (handshake && *handshake) {
        while (!result.server_ready) (void)co_await yield(loop);
        (void)co_await yield(loop);
        constexpr std::array<std::byte, 1> byte {};
        std::array<std::byte, 1> duplicate_buffer {};
        auto busy = co_await server.async_read_some(duplicate_buffer);
        auto close_busy = co_await server.async_close();
        auto sent = co_await server.async_write_some(byte);
        std::array<std::byte, 1> response {};
        auto received = co_await stream.async_read_some(response);
        auto replied = co_await stream.async_write_some(byte);
        result.client_ok = busy && !*busy && busy->error().value() == EBUSY &&
                           close_busy && !*close_busy &&
                           close_busy->error().value() == EBUSY &&
                           sent && *sent && **sent == 1 &&
                           received && *received && **received == 1 &&
                           replied && *replied && **replied == 1;
    }
    stream.close();
    result.finish();
}

[[nodiscard]] auto run_case(const std::filesystem::path& certificate,
                            const std::filesystem::path& key,
                            const std::filesystem::path& trusted_ca,
                            int which) -> bool
{
    event_loop loop;
    result_state result {loop};
    auto streams = add_streams(loop, certificate, key, trusted_ca,
                               which == 1 ? "wrong.example" : "localhost",
                               which == 3, which == 6);
    task<void> server;
    task<void> client;
    switch (which) {
    case 0:
        server = echo_server(loop, *streams.server, result);
        client = echo_client(loop, *streams.client, result);
        break;
    case 1:
    case 5:
    case 6:
        server = rejection_server(loop, *streams.server, result);
        client = rejection_client(loop, *streams.client, result);
        break;
    case 3:
        server = blocked_write_server(loop, *streams.server, *streams.client,
                                      result);
        client = blocked_write_client(loop, *streams.client, result);
        break;
    case 4:
        server = busy_server(loop, *streams.server, result);
        client = busy_client(loop, *streams.client, *streams.server, result);
        break;
    default:
        server = truncation_server(loop, *streams.server, result);
        client = truncation_client(loop, *streams.client, result);
        break;
    }
    if (server.state() == task_state::frame_allocation_failure ||
        client.state() == task_state::frame_allocation_failure) {
        throw std::runtime_error("cannot allocate TLS loopback tasks");
    }
    if (loop.spawn(std::move(server)) != task_spawn_result::accepted ||
        loop.spawn(std::move(client)) != task_spawn_result::accepted) {
        throw std::runtime_error("cannot start TLS loopback tasks");
    }
    loop.run();
    if (!result.server_ok || !result.client_ok) {
        std::cerr << "TLS case " << which << " failed: server=" << result.server_ok
                  << " client=" << result.client_ok << '\n';
    }
    return result.server_ok && result.client_ok;
}

[[nodiscard]] auto outbound_server(event_loop& loop, tcp_acceptor& acceptor,
                                   const std::filesystem::path& certificate,
                                   const std::filesystem::path& key,
                                   result_state& result, bool reject)
    -> task<void>
{
    auto accepted = co_await acceptor.async_accept();
    if (!accepted) {
        result.finish();
        co_return;
    }
    acceptor.close();
    auto stream = std::make_unique<tls_stream>(
        loop, std::move(*accepted),
        tls_context::make_server(certificate, key),
        tls_server_options {.application_protocols = {"echo"}});
    auto* server = stream.get();
    loop.add(std::move(stream));
    if (reject) (void)co_await rejection_server(loop, *server, result);
    else (void)co_await echo_server(loop, *server, result);
}

[[nodiscard]] auto outbound_client(event_loop& loop, tls_stream& stream,
                                   result_state& result, bool reject)
    -> task<void>
{
    auto early = co_await stream.async_handshake();
    const bool early_rejected = early && !*early &&
        early->error().value() == ENOTCONN;
    auto connected = co_await stream.async_connect();
    if (!early_rejected || !connected) {
        stream.close();
        result.finish();
        co_return;
    }
    if (reject) (void)co_await rejection_client(loop, stream, result);
    else (void)co_await echo_client(loop, stream, result);
}

[[nodiscard]] auto run_outbound_case(const std::filesystem::path& certificate,
                                     const std::filesystem::path& key,
                                     const std::filesystem::path& trusted_ca,
                                     bool ipv6, bool reject) -> bool
{
    event_loop loop;
    result_state result {loop};
    auto listener = std::make_unique<tcp_acceptor>(
        loop, ipv6 ? ip_endpoint::loopback_v6(0)
                   : ip_endpoint::loopback_v4(0));
    auto* acceptor = listener.get();
    sockaddr_storage local {};
    socklen_t local_size = sizeof(local);
    if (getsockname(acceptor->descriptor(),
                    reinterpret_cast<sockaddr*>(&local), &local_size) == -1) {
        throw system_error("getsockname");
    }
    const auto port = ipv6
        ? ntohs(reinterpret_cast<const sockaddr_in6*>(&local)->sin6_port)
        : ntohs(reinterpret_cast<const sockaddr_in*>(&local)->sin_port);
    loop.add(std::move(listener));
    auto client = std::make_unique<tls_stream>(
        loop, ipv6 ? ip_endpoint::loopback_v6(port)
                   : ip_endpoint::loopback_v4(port),
        tls_context::make_client(trusted_ca),
        tls_client_options {.hostname = reject ? "wrong.example" : "localhost",
                            .application_protocols = {"echo"}});
    auto* client_stream = client.get();
    loop.add(std::move(client));
    auto server_task = outbound_server(loop, *acceptor, certificate, key,
                                       result, reject);
    auto client_task = outbound_client(loop, *client_stream, result, reject);
    if (server_task.state() == task_state::frame_allocation_failure ||
        client_task.state() == task_state::frame_allocation_failure) {
        throw std::runtime_error("cannot allocate outbound TLS tasks");
    }
    if (loop.spawn(std::move(server_task)) != task_spawn_result::accepted ||
        loop.spawn(std::move(client_task)) != task_spawn_result::accepted) {
        throw std::runtime_error("cannot start outbound TLS tasks");
    }
    loop.run();
    if (!result.server_ok || !result.client_ok) {
        std::cerr << "outbound TLS " << (ipv6 ? "IPv6" : "IPv4")
                  << (reject ? " verification" : " echo")
                  << " failed: server=" << result.server_ok
                  << " client=" << result.client_ok << '\n';
    }
    return result.server_ok && result.client_ok;
}
[[nodiscard]] auto plaintext_handshake(event_loop& loop, tls_stream& stream,
                                       bool& failed) -> task<void>
{
    (void)loop;
    auto handshake = co_await stream.async_handshake();
    // The failed handshake closed and released the loop-owned stream.
    failed = handshake && !*handshake;
}

// A handshake that fails before suspending closes a loop-owned stream outside
// any handler call, which removes it at once; the operation must not touch or
// destroy it while still marked active.
[[nodiscard]] auto run_plaintext_peer_case(const std::filesystem::path& trusted_ca)
    -> bool
{
    auto sockets = connect_loopback();
    constexpr std::string_view plaintext = "HTTP/1.1 200 OK\r\n\r\n";
    if (send(sockets.server.get(), plaintext.data(), plaintext.size(),
             MSG_NOSIGNAL) != static_cast<ssize_t>(plaintext.size())) {
        throw system_error("send");
    }
    pollfd readable {.fd = sockets.client.get(), .events = POLLIN, .revents = 0};
    if (poll(&readable, 1, 5000) != 1) throw system_error("poll");
    event_loop loop;
    auto client = std::make_unique<tls_stream>(
        loop, std::move(sockets.client), tls_context::make_client(trusted_ca),
        tls_client_options {.hostname = "localhost", .application_protocols = {}});
    auto* stream = client.get();
    loop.add(std::move(client));
    bool failed = false;
    if (loop.spawn(plaintext_handshake(loop, *stream, failed)) !=
        task_spawn_result::accepted) {
        throw std::runtime_error("cannot start plaintext peer task");
    }
    if (!failed) std::cerr << "TLS plaintext peer handshake did not fail\n";
    return failed;
}
} // namespace

auto main(int argc, char* argv[]) -> int
{
    if (argc != 4 && argc != 5) return 2;
    try {
        const std::filesystem::path certificate = argv[1];
        const std::filesystem::path key = argv[2];
        const std::filesystem::path trusted_ca = argv[3];
        if (argc == 5) {
            return run_case(certificate, key, trusted_ca, 5) ? 0 : 1;
        }
        const bool passed = run_case(certificate, key, trusted_ca, 0) &&
                            run_case(certificate, key, trusted_ca, 1) &&
                            run_case(certificate, key, trusted_ca, 2) &&
                            run_case(certificate, key, trusted_ca, 3) &&
                            run_case(certificate, key, trusted_ca, 4) &&
                            run_case(certificate, key, trusted_ca, 6) &&
                            run_plaintext_peer_case(trusted_ca) &&
                            run_outbound_case(certificate, key, trusted_ca,
                                              false, false) &&
                            run_outbound_case(certificate, key, trusted_ca,
                                              false, true);
        if (!passed) return 1;
        try {
            if (!run_outbound_case(certificate, key, trusted_ca, true, false) ||
                !run_outbound_case(certificate, key, trusted_ca, true, true)) {
                return 1;
            }
        } catch (const std::system_error& error) {
            if (error.code().value() != EAFNOSUPPORT &&
                error.code().value() != EADDRNOTAVAIL) throw;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
