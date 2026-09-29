#include "eventloop/http/server.h"

#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
#include "../http2/connection.h"
#endif
#include "file_operations.h"
#include "eventloop/http/session.h"
#include "eventloop/tcp_stream.h"
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
#include "eventloop/tls_stream.h"
#endif

#include <array>
#include <cstdio>
#include <cstring>
#include <expected>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace eventloop::http {
namespace {

auto validate_hostname(std::string_view hostname) -> void
{
    if (hostname.empty()) {
        throw std::invalid_argument("redirect hostname cannot be empty");
    }
    for (const unsigned char value : hostname) {
        if (value <= 0x20 || value == 0x7f || value == '/' || value == '\\' ||
            value == '?' || value == '#' || value == '@') {
            throw std::invalid_argument("redirect hostname is invalid");
        }
    }
}

template<typename T>
[[nodiscard]] auto operation_result(
    std::expected<T, std::error_code> result) noexcept
    -> std::expected<T, std::error_code>
{
    return result;
}

template<typename T>
[[nodiscard]] auto operation_result(
    std::expected<std::expected<T, std::error_code>, task_result> result) noexcept
    -> std::expected<T, std::error_code>
{
    if (!result) {
        return std::unexpected(std::make_error_code(
            std::errc::resource_unavailable_try_again));
    }
    return std::move(*result);
}

[[nodiscard]] auto operation_succeeded(
    const std::expected<std::expected<void, std::error_code>, task_result>& result)
    noexcept -> bool
{
    return result && *result;
}

template<typename Stream>
[[nodiscard]] auto serve_connection(event_loop& loop, unique_fd descriptor,
                                    std::shared_ptr<unique_fd> root,
                                    server_options options,
                                    std::shared_ptr<tls_context> context)
    -> task<void>
{
    std::unique_ptr<Stream> socket;
    Stream* peer = nullptr;
    bool registered = false;
    try {
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
        if constexpr (std::is_same_v<Stream, tls_stream>) {
            socket = std::make_unique<tls_stream>(
                loop, std::move(descriptor), std::move(context),
                tls_server_options {.application_protocols =
                    options.enable_http2
                    ? std::vector<std::string> {"h2", "http/1.1"}
                    : std::vector<std::string> {"http/1.1"}
                });
        } else {
#endif
            socket = std::make_unique<tcp_stream>(loop, std::move(descriptor));
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
        }
#endif
        peer = socket.get();
        loop.add(std::move(socket));
        registered = true;
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
        if constexpr (std::is_same_v<Stream, tls_stream>) {
            const auto handshake = co_await peer->async_handshake();
            if (!operation_succeeded(handshake)) {
                peer->close();
                co_return;
            }
            if (options.enable_http2 && peer->application_protocol() == "h2") {
                const auto served = co_await http2::detail::serve(
                    loop, *peer, root, options.directory_listing);
                if (served && *served) {
                    const auto closed = co_await peer->async_close();
                    (void)closed;
                }
                peer->close();
                co_return;
            }
        }
#endif

        // The parser and I/O buffers live outside the bounded coroutine frame.
        auto state = std::make_unique<session>(root->get(), options.directory_listing);
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
        std::unique_ptr<std::byte[]> tls_file_buffer;
#endif
        while (!state->closed()) {
            while (!state->has_response() && !state->closed()) {
                auto buffer = state->read_space();
                if (buffer.empty()) {
                    constexpr std::byte excess {0};
                    state->receive(std::span {&excess, std::size_t {1}});
                    break;
                }
                auto received = operation_result(co_await peer->async_read_some(buffer));
                if (!received || *received == 0) {
                    peer->close();
                    co_return;
                }
                state->commit_read(*received);
            }
            if (state->closed()) break;
            if (!state->has_response()) continue;

            auto response = std::as_bytes(state->response());
            while (!response.empty()) {
                auto written = operation_result(
                    co_await peer->async_write_some(response));
                if (!written || *written == 0) {
                    peer->close();
                    co_return;
                }
                response = response.subspan(*written);
            }

            const auto file_size = state->file_size();
            auto file = state->take_file();
            if (file) {
                if constexpr (std::is_same_v<Stream, tcp_stream>) {
                    auto sent = co_await peer->async_send_file({}, std::move(file),
                                                               file_size);
                    if (!operation_succeeded(sent)) {
                        peer->close();
                        co_return;
                    }
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
                } else {
                    if (!tls_file_buffer) {
                        tls_file_buffer.reset(
                            new (std::nothrow) std::byte[4096]);
                        if (!tls_file_buffer) {
                            peer->close();
                            co_return;
                        }
                    }
                    const std::span<std::byte> file_buffer {
                        tls_file_buffer.get(), 4096};
                    std::size_t remaining = file_size;
                    while (remaining != 0) {
                        const auto bytes = std::min(remaining, file_buffer.size());
                        if (!detail::read_file(file.get(), file_buffer.first(bytes))) {
                            peer->close();
                            co_return;
                        }
                        auto chunk = file_buffer.first(bytes);
                        while (!chunk.empty()) {
                            auto written = operation_result(
                                co_await peer->async_write_some(chunk));
                            if (!written || *written == 0) {
                                peer->close();
                                co_return;
                            }
                            chunk = chunk.subspan(*written);
                        }
                        remaining -= bytes;
                    }
                    tls_file_buffer.reset();
#endif
                }
            }
            state->finish_response();
        }
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
        if constexpr (std::is_same_v<Stream, tls_stream>) {
            const auto closed = co_await peer->async_close();
            (void)closed;
            peer->close();
        } else {
#endif
            peer->close();
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
        }
#endif
    } catch (...) {
        // Construction and response allocation failures retire the connection.
        if (registered) peer->close();
    }
}

struct redirect_state {
    std::array<char, max_message_size> input {};
    std::array<char, 4096> response {};
    std::size_t input_size {0};
};

[[nodiscard]] auto serve_redirect(event_loop& loop, unique_fd descriptor,
                                  std::shared_ptr<const std::string> hostname,
                                  std::uint16_t https_port) -> task<void>
{
    std::unique_ptr<tcp_stream> socket;
    tcp_stream* peer = nullptr;
    bool registered = false;
    try {
        socket = std::make_unique<tcp_stream>(loop, std::move(descriptor));
        peer = socket.get();
        loop.add(std::move(socket));
        registered = true;
        auto state = std::make_unique<redirect_state>();
        constexpr std::string_view bad =
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        std::span<const std::byte> response;
        for (;;) {
            {
                request request;
                const auto parsed = parse_request(
                    std::string_view {state->input.data(), state->input_size}, request);
                if (parsed.status == parse_status::complete) {
                    const int size = https_port == 443
                        ? std::snprintf(state->response.data(), state->response.size(),
                              "HTTP/1.1 308 Permanent Redirect\r\n"
                              "Location: https://%.*s%.*s\r\n"
                              "Content-Length: 0\r\nConnection: close\r\n\r\n",
                              static_cast<int>(hostname->size()), hostname->data(),
                              static_cast<int>(request.target.size()),
                              request.target.data())
                        : std::snprintf(state->response.data(), state->response.size(),
                              "HTTP/1.1 308 Permanent Redirect\r\n"
                              "Location: https://%.*s:%u%.*s\r\n"
                              "Content-Length: 0\r\nConnection: close\r\n\r\n",
                              static_cast<int>(hostname->size()), hostname->data(),
                              static_cast<unsigned int>(https_port),
                              static_cast<int>(request.target.size()),
                              request.target.data());
                    if (size >= 0 && static_cast<std::size_t>(size) <
                                         state->response.size()) {
                        response = std::as_bytes(std::span {state->response}.first(
                            static_cast<std::size_t>(size)));
                    } else {
                        response = std::as_bytes(std::span {bad.data(), bad.size()});
                    }
                    break;
                }
                if (parsed.status != parse_status::incomplete ||
                    state->input_size == state->input.size()) {
                    response = std::as_bytes(std::span {bad.data(), bad.size()});
                    break;
                }
            }
            auto space = std::as_writable_bytes(std::span {state->input})
                .subspan(state->input_size);
            auto received = co_await peer->async_read_some(space);
            if (!received || *received == 0) {
                peer->close();
                co_return;
            }
            state->input_size += *received;
        }
        while (!response.empty()) {
            auto written = co_await peer->async_write_some(response);
            if (!written || *written == 0) break;
            response = response.subspan(*written);
        }
        peer->close();
    } catch (...) {
        if (registered) peer->close();
    }
}

} // namespace

server::server(event_loop& loop, std::uint16_t port, std::string_view root,
               std::string_view address, server_options options)
    : tcp_acceptor(loop, ip_endpoint::parse(address, port), options.reuse_port), options_(options)
{
    root_descriptor_ = std::make_shared<unique_fd>(detail::open_root(root));
}

server::~server() = default;

auto server::run() -> task<void>
{
    return accept_loop(owner(), *this, root_descriptor_, options_);
}

auto server::accept_loop(event_loop& loop, server& listener,
                         std::shared_ptr<unique_fd> root,
                         server_options options) -> task<void>
{
    while (auto accepted = co_await listener.async_accept()) {
        const auto result = loop.spawn(serve_connection<tcp_stream>(
            loop, std::move(*accepted), root, options, {}));
        if (result != task_spawn_result::accepted) {
            // Frame allocation can fail before the descriptor is moved into
            // the task. Close it here in that case (and for any other
            // rejected spawn).
            accepted->reset();
        }
    }
}

#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
https_server::https_server(event_loop& loop, std::uint16_t port,
                           std::shared_ptr<tls_context> context,
                           std::string_view root, std::string_view address,
                           server_options options)
    : tcp_acceptor(loop, ip_endpoint::parse(address, port), options.reuse_port),
      root_descriptor_(std::make_shared<unique_fd>(detail::open_root(root))),
      context_(std::move(context)), options_(options)
{
    if (!context_) throw std::invalid_argument("HTTPS context is required");
}

https_server::~https_server() = default;

auto https_server::run() -> task<void>
{
    return accept_loop(owner(), *this, root_descriptor_, context_, options_);
}

auto https_server::accept_loop(event_loop& loop, https_server& listener,
                               std::shared_ptr<unique_fd> root,
                               std::shared_ptr<tls_context> context,
                               server_options options) -> task<void>
{
    while (auto accepted = co_await listener.async_accept()) {
        const auto result = loop.spawn(serve_connection<tls_stream>(
            loop, std::move(*accepted), root, options, context));
        if (result != task_spawn_result::accepted) accepted->reset();
    }
}
#endif

redirect_server::redirect_server(event_loop& loop, std::uint16_t port,
                                 std::string_view hostname,
                                 std::uint16_t https_port,
                                 std::string_view address)
    : tcp_acceptor(loop, ip_endpoint::parse(address, port)), https_port_(https_port)
{
    validate_hostname(hostname);
    hostname_ = std::make_shared<const std::string>(hostname);
}

auto redirect_server::run() -> task<void>
{
    return accept_loop(owner(), *this, hostname_, https_port_);
}

auto redirect_server::accept_loop(event_loop& loop, redirect_server& listener,
                                   std::shared_ptr<const std::string> hostname,
                                   std::uint16_t https_port) -> task<void>
{
    while (auto accepted = co_await listener.async_accept()) {
        const auto result = loop.spawn(serve_redirect(
            loop, std::move(*accepted), hostname, https_port));
        if (result != task_spawn_result::accepted) accepted->reset();
    }
}

} // namespace eventloop::http
