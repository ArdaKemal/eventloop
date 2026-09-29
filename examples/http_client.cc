#include "http_client_resolve.h"
#include "http_client_url.h"

#include "eventloop/event_loop.h"
#include "eventloop/task.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <unistd.h>
#endif

#include <array>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <expected>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

namespace {

using http_client_example::parse_url;
using http_client_example::resolve_addresses;
using http_client_example::url_parts;

[[nodiscard]] auto normalize_io(
    std::expected<std::size_t, std::error_code> result) noexcept
    -> std::expected<std::size_t, std::error_code>
{
    return result;
}

[[nodiscard]] auto normalize_io(
    std::expected<std::expected<std::size_t, std::error_code>,
                  eventloop::task_result> result) noexcept
    -> std::expected<std::size_t, std::error_code>
{
    if (result) return std::move(*result);
    return std::unexpected(std::make_error_code(
        result.error() == eventloop::task_result::frame_allocation_failure
            ? std::errc::not_enough_memory
            : std::errc::operation_canceled));
}

[[nodiscard]] auto write_stdout(std::span<const std::byte> bytes) -> bool
{
    while (!bytes.empty()) {
#ifdef _WIN32
        const auto length = static_cast<unsigned int>(std::min(
            bytes.size(), static_cast<std::size_t>(
                              std::numeric_limits<int>::max())));
        const auto count = ::_write(::_fileno(stdout), bytes.data(), length);
#else
        const auto count = ::write(STDOUT_FILENO, bytes.data(), bytes.size());
#endif
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
    return true;
}

template<typename Stream>
[[nodiscard]] auto exchange_http(eventloop::event_loop& loop, Stream& stream,
                                 const std::string& request)
    -> eventloop::task<bool>
{
    (void)loop;
    auto bytes = std::as_bytes(std::span(request.data(), request.size()));
    while (!bytes.empty()) {
        const auto sent = normalize_io(co_await stream.async_write_some(bytes));
        if (!sent || *sent == 0) {
            std::cerr << "HTTP write failed: "
                      << (sent ? "zero bytes written" : sent.error().message())
                      << '\n';
            co_return false;
        }
        bytes = bytes.subspan(*sent);
    }

    std::array<std::byte, 1024> buffer {};
    for (;;) {
        const auto received = normalize_io(co_await stream.async_read_some(buffer));
        if (!received) {
            std::cerr << "HTTP read failed: " << received.error().message()
                      << '\n';
            co_return false;
        }
        if (*received == 0) co_return true;
        if (!write_stdout(std::span<const std::byte>(buffer).first(*received))) {
            std::cerr << "stdout write failed: " << std::strerror(errno) << '\n';
            co_return false;
        }
    }
}

[[nodiscard]] auto fetch(eventloop::event_loop& loop, url_parts url,
                         bool& success) -> eventloop::task<void>
{
    try {
        auto resolved = co_await eventloop::run_blocking(
            loop, [host = url.hostname, port = url.port]() noexcept {
                return resolve_addresses(host, port);
            });
        if (!resolved) {
            std::cerr << "DNS worker unavailable or cancelled\n";
            loop.stop();
            co_return;
        }
        if (resolved->error != 0 || resolved->count == 0) {
            std::cerr << "DNS lookup failed: "
                      << (resolved->error != 0 ? ::gai_strerror(resolved->error)
                                              : "no supported addresses")
                      << '\n';
            loop.stop();
            co_return;
        }

        std::string request = "GET " + url.target + " HTTP/1.1\r\nHost: " +
                              url.host_header + "\r\nConnection: close\r\n\r\n";
        std::shared_ptr<eventloop::tls_context> context;
        if (url.secure) context = eventloop::tls_context::make_system_client();

        for (std::size_t index = 0; index < resolved->count; ++index) {
            const auto endpoint = resolved->endpoints[index];
            if (url.secure) {
                auto socket = std::make_unique<eventloop::tls_stream>(
                    loop, endpoint, context,
                    eventloop::tls_client_options {
                        .hostname = url.hostname,
                        .application_protocols = {"http/1.1"},
                    });
                auto* stream = socket.get();
                loop.add(std::move(socket));
                const auto connected = co_await stream->async_connect();
                if (!connected) {
                    std::cerr << "connect failed: " << connected.error().message()
                              << '\n';
                    stream->close();
                    continue;
                }
                const auto handshake = co_await stream->async_handshake();
                if (!handshake || !*handshake) {
                    std::cerr << "TLS handshake failed: "
                              << (handshake
                                      ? handshake->error().message()
                                      : "coroutine frame unavailable or cancelled")
                              << '\n';
                    stream->close();
                    break;
                }
                const auto exchanged = co_await exchange_http(loop, *stream, request);
                success = exchanged && *exchanged;
                stream->close();
                break;
            }

            auto socket = std::make_unique<eventloop::tcp_stream>(loop, endpoint);
            auto* stream = socket.get();
            loop.add(std::move(socket));
            const auto connected = co_await stream->async_connect();
            if (!connected) {
                std::cerr << "connect failed: " << connected.error().message()
                          << '\n';
                stream->close();
                continue;
            }
            const auto exchanged = co_await exchange_http(loop, *stream, request);
            success = exchanged && *exchanged;
            stream->close();
            break;
        }
        loop.stop();
    } catch (const std::exception& error) {
        std::cerr << "HTTP client failed: " << error.what() << '\n';
        loop.stop();
    }
}

} // namespace

auto main(int argc, char* argv[]) -> int
{
    if (argc != 2) {
        std::cerr << "usage: http_client <http:// or https:// URL>\n";
        return 2;
    }
    try {
#ifdef _WIN32
        if (::_setmode(::_fileno(stdout), _O_BINARY) == -1) {
            throw std::system_error(errno, std::generic_category(),
                                    "set stdout binary mode");
        }
#endif
        auto url = parse_url(argv[1]);
        eventloop::event_loop_options options;
        options.worker_count = 1;
        eventloop::event_loop loop(options);
        bool success = false;
        if (loop.spawn(fetch(loop, std::move(url), success)) !=
            eventloop::task_spawn_result::accepted) {
            throw std::runtime_error("cannot start HTTP client task");
        }
        if (loop.run() == eventloop::event_loop_result::interrupted) {
            loop.shutdown(std::chrono::seconds {0});
            (void)loop.run();
        }
        return success ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
