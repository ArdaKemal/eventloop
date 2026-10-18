#include "eventloop/http/server.h"

#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
#include "../http2/connection.h"
#endif
#include "connection_deadline.h"
#include "file_operations.h"
#include "http1_exchange.h"
#include "parser.h"
#include "open_file_cache.h"
#include "session.h"
#include "../socket_operations.h"
#include "eventloop/tcp_stream.h"
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
#include "eventloop/tls_stream.h"
#endif

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <expected>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace eventloop::http {
namespace {

using detail::max_message_size;
using detail::parse_request;
using detail::parse_status;

// The options a connection task needs, kept small because they live in its
// coroutine frame for the whole connection.
struct connection_options {
    std::shared_ptr<const router> routes;
    std::uint64_t max_request_body {0};
    std::chrono::milliseconds header_timeout {};
    std::chrono::milliseconds idle_timeout {};
    bool directory_listing {false};
    bool enable_http2 {false};
    std::string alt_svc; // field value for static file responses over TLS
};

[[nodiscard]] auto for_connection(const server_options& options) -> connection_options
{
    connection_options result {options.routes, options.max_request_body, options.header_timeout,
        options.idle_timeout, options.directory_listing, options.enable_http2, {}};
    if (options.advertise_http3_port != 0)
        result.alt_svc = "h3=\":" + std::to_string(options.advertise_http3_port) + "\"; ma=86400";
    return result;
}

// An empty document root means routes only; static requests answer 404.
[[nodiscard]] auto open_document_root(const server_options& options)
    -> std::shared_ptr<detail::document_root>
{
    if (!options.routes && options.document_root.empty())
        throw std::invalid_argument("server needs routes or a document root");
    auto root = std::make_shared<detail::document_root>();
    if (options.document_root.empty()) return root;
    root->descriptor = detail::open_root(options.document_root.string());
    if (options.open_file_cache_capacity != 0)
        root->cache = std::make_unique<detail::open_file_cache>(options.open_file_cache_capacity);
    return root;
}

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

// A peer reset, failed TLS operation, or cancellation removes a stream from
// the loop, possibly while a routed handler waits on something else. The
// connection task keeps using it afterwards, so it pins the stream.
class stream_pin {
public:
    stream_pin() = default;
    stream_pin(const stream_pin&) = delete;
    auto operator=(const stream_pin&) -> stream_pin& = delete;
    ~stream_pin()
    {
        if (stream_ != nullptr) eventloop::detail::socket_operations::stream_unpin(*stream_);
    }
    auto hold(tcp_stream& stream) noexcept -> void
    {
        eventloop::detail::socket_operations::stream_pin(stream);
        stream_ = &stream;
    }

private:
    tcp_stream* stream_ {nullptr};
};

#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
// Sends a file body over TLS: kernel sendfile with kTLS, otherwise full-size
// records from a buffer that lives only while the body is sent. A separate
// task keeps this state out of the connection frame, which must stay within
// the 1 KiB size class that holds one frame per connection.
[[nodiscard]] auto send_file_over_tls(event_loop& loop, tls_stream& peer, unique_fd file,
                                      std::uint64_t offset, std::size_t size) -> task<bool>
{
    (void)loop;
    if (peer.kernel_sendfile_available())
        co_return operation_succeeded(
            co_await peer.async_send_file(std::move(file), offset, size));
    constexpr std::size_t buffer_size = 16 * 1024; // one maximum TLS record
    const std::unique_ptr<std::byte[]> buffer(new (std::nothrow) std::byte[buffer_size]);
    if (!buffer) co_return false;
    while (size != 0) {
        const auto count = std::min(size, buffer_size);
        auto chunk = std::span(buffer.get(), count);
        if (!detail::read_file_at(file.get(), offset, chunk)) co_return false;
        while (!chunk.empty()) {
            auto written = operation_result(co_await peer.async_write_some(chunk));
            if (!written || *written == 0) co_return false;
            chunk = chunk.subspan(*written);
        }
        size -= count;
        offset += count;
    }
    co_return true;
}
#endif

template<typename Stream>
[[nodiscard]] auto serve_connection(event_loop& loop, unique_fd descriptor,
                                    std::shared_ptr<detail::document_root> root,
                                    std::shared_ptr<const connection_options> options,
                                    std::shared_ptr<tls_context> context)
    -> task<void>
{
    stream_pin pin;
    std::unique_ptr<Stream> socket;
    Stream* peer = nullptr;
    bool registered = false;
    try {
        // Expiry cancels this task, so the pending read or handshake fails.
        // Named first: GCC 15 types co_await in a template as an rvalue here.
        auto& cancellation = co_await detail::current_cancellation {};
        auto deadline = std::make_unique<detail::connection_deadline>(loop, cancellation);
        deadline->start(options->header_timeout);
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
        if constexpr (std::is_same_v<Stream, tls_stream>) {
            socket = std::make_unique<tls_stream>(
                loop, std::move(descriptor), std::move(context),
                tls_server_options {.application_protocols =
                    options->enable_http2
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
        pin.hold(*peer);
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
        if constexpr (std::is_same_v<Stream, tls_stream>) {
            const auto handshake = co_await peer->async_handshake();
            if (!operation_succeeded(handshake)) {
                peer->close();
                co_return;
            }
            if (options->enable_http2 && peer->application_protocol() == "h2") {
                const auto served = co_await http2::detail::serve(
                    loop, *peer, root, options->directory_listing, options->routes,
                    options->max_request_body, *deadline, options->idle_timeout,
                    options->alt_svc);
                if (served && *served) {
                    const auto closed = co_await peer->async_close();
                    (void)closed;
                }
                peer->close();
                co_return;
            }
        }
#endif

        // The parser, routing state and I/O buffers live outside the bounded
        // coroutine frame, allocated once per connection.
        std::unique_ptr<detail::route_state> routing;
        if (options->routes) {
            routing = std::make_unique<detail::route_state>();
            routing->routes = options->routes.get();
            routing->max_request_body = options->max_request_body;
        }
        auto state = std::make_unique<detail::session>(root->descriptor.get(),
            options->directory_listing, routing.get(), static_cast<bool>(root->descriptor),
            root->cache.get(),
            std::is_same_v<Stream, tcp_stream> ? std::string_view {} : options->alt_svc);
        std::unique_ptr<detail::http1_exchange<Stream>> exchange;
        if (routing) {
            exchange = std::make_unique<detail::http1_exchange<Stream>>(
                loop, *peer, *state, *routing);
        }
        while (!state->closed()) {
            while (!state->has_response() && !state->routed() && !state->closed()) {
                auto buffer = state->read_space();
                if (buffer.empty()) {
                    constexpr std::byte excess {0};
                    state->receive(std::span {&excess, std::size_t {1}});
                    break;
                }
                // The deadline runs from accept, or restarts after a response.
                if (!deadline->running()) deadline->start(options->idle_timeout);
                auto received = operation_result(co_await peer->async_read_some(buffer));
                if (!received || *received == 0) {
                    peer->close();
                    co_return;
                }
                state->commit_read(*received);
            }
            deadline->stop();
            if (state->closed()) break;
            if (state->routed()) {
                const auto kept = co_await detail::http1_exchange<Stream>::serve(loop, *exchange);
                state->finish_routed(kept && *kept);
                continue;
            }
            if (!state->has_response()) continue;

            auto response = std::as_bytes(state->response());
            const auto file_size = state->file_size();
            const auto file_offset = state->file_offset();
            auto file = state->take_file();
            // Plain TCP sends the head with the file in one operation.
            constexpr bool plain = std::is_same_v<Stream, tcp_stream>;
            while (!(plain && file) && !response.empty()) {
                auto written = operation_result(
                    co_await peer->async_write_some(response));
                if (!written || *written == 0) {
                    peer->close();
                    co_return;
                }
                response = response.subspan(*written);
            }

            if (file) {
                bool sent = false;
                if constexpr (plain)
                    sent = operation_succeeded(co_await peer->async_send_file(
                        response, std::move(file), file_offset, file_size));
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
                if constexpr (std::is_same_v<Stream, tls_stream>) {
                    const auto copied = co_await send_file_over_tls(
                        loop, *peer, std::move(file), file_offset, file_size);
                    sent = copied && *copied;
                }
#endif
                if (!sent) {
                    peer->close();
                    co_return;
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
                                  std::uint16_t https_port,
                                  std::chrono::milliseconds header_timeout) -> task<void>
{
    stream_pin pin;
    std::unique_ptr<tcp_stream> socket;
    tcp_stream* peer = nullptr;
    bool registered = false;
    try {
        // Expiry cancels this task, so the pending read fails.
        auto& cancellation = co_await detail::current_cancellation {};
        auto deadline = std::make_unique<detail::connection_deadline>(loop, cancellation);
        deadline->start(header_timeout);
        socket = std::make_unique<tcp_stream>(loop, std::move(descriptor));
        peer = socket.get();
        loop.add(std::move(socket));
        registered = true;
        pin.hold(*peer);
        auto state = std::make_unique<redirect_state>();
        constexpr std::string_view bad =
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        std::span<const std::byte> response;
        for (;;) {
            {
                detail::parsed_request request;
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
        deadline->stop();
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

namespace detail {

// What a connection task needs on the loop that serves it. The document root
// is per loop because its open-file cache is loop-affine.
struct serving_loop {
    event_loop* loop {nullptr};
    std::shared_ptr<document_root> root;
    std::shared_ptr<const connection_options> options;
    std::shared_ptr<tls_context> context;            // https_server
    std::shared_ptr<const std::string> hostname;     // redirect_server
    std::uint16_t https_port {0};
    std::chrono::milliseconds header_timeout {};
};

} // namespace detail

namespace {

// One serving_loop per entry of options.serving_loops, or for owner alone;
// fill() completes each entry.
template<typename Fill>
[[nodiscard]] auto make_serving(event_loop& owner, const server_options& options, Fill fill)
    -> detail::serving_set
{
    detail::serving_set serving;
    const auto add = [&](event_loop* loop) {
        if (loop == nullptr) throw std::invalid_argument("serving loop is null");
        auto entry = std::make_shared<detail::serving_loop>();
        entry->loop = loop;
        fill(*entry);
        serving.push_back(std::move(entry));
    };
    if (options.serving_loops.empty()) add(&owner);
    for (auto* loop : options.serving_loops) add(loop);
    return serving;
}

using serve_function = task<void> (*)(event_loop&, unique_fd, const detail::serving_loop&);

// Accepts until the listener closes, handing connections to the serving loops
// in turn. Another loop serves its connection from a posted task.
[[nodiscard]] auto accept_connections(event_loop& loop, tcp_acceptor& listener,
                                      detail::serving_set serving, serve_function serve)
    -> task<void>
{
    std::size_t next = 0;
    while (auto accepted = co_await listener.async_accept()) {
        auto target = serving[next++ % serving.size()];
        if (target->loop == &loop) {
            // Frame allocation can fail before the descriptor is moved into
            // the task. Close it here in that case (and for any other
            // rejected spawn).
            if (loop.spawn(serve(loop, std::move(*accepted), *target)) !=
                task_spawn_result::accepted)
                accepted->reset();
            continue;
        }
        // A full queue destroys the task, closing the connection; a rejected
        // spawn there leaves the descriptor in the task, which closes it.
        auto* destination = target->loop;
        (void)destination->post([target = std::move(target), serve,
                                 descriptor = std::move(*accepted)]() mutable noexcept {
            (void)target->loop->spawn(serve(*target->loop, std::move(descriptor), *target));
        });
    }
}

// Each copies what it needs out of the entry; the task does not borrow it.
auto serve_plain(event_loop& loop, unique_fd descriptor, const detail::serving_loop& entry)
    -> task<void>
{
    return serve_connection<tcp_stream>(loop, std::move(descriptor), entry.root,
                                        entry.options, {});
}

#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
auto serve_tls(event_loop& loop, unique_fd descriptor, const detail::serving_loop& entry)
    -> task<void>
{
    return serve_connection<tls_stream>(loop, std::move(descriptor), entry.root,
                                        entry.options, entry.context);
}
#endif

auto serve_redirect_entry(event_loop& loop, unique_fd descriptor,
                          const detail::serving_loop& entry) -> task<void>
{
    return serve_redirect(loop, std::move(descriptor), entry.hostname, entry.https_port,
                          entry.header_timeout);
}

} // namespace

server::server(event_loop& loop, ip_endpoint local, server_options options)
    : tcp_acceptor(loop, local, options.reuse_port)
{
    // Shared, not copied, so each connection frame stays in its size class.
    const auto connection = std::make_shared<const connection_options>(for_connection(options));
    serving_ = make_serving(loop, options, [&](detail::serving_loop& entry) {
        entry.root = open_document_root(options);
        entry.options = connection;
    });
}

server::~server() = default;

auto server::run() -> task<void>
{
    return accept_connections(owner(), *this, serving_, serve_plain);
}

#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
https_server::https_server(event_loop& loop, ip_endpoint local,
                           std::shared_ptr<tls_context> context, server_options options)
    : tcp_acceptor(loop, local, options.reuse_port)
{
    if (!context) throw std::invalid_argument("HTTPS context is required");
    const auto connection = std::make_shared<const connection_options>(for_connection(options));
    serving_ = make_serving(loop, options, [&](detail::serving_loop& entry) {
        entry.root = open_document_root(options);
        entry.options = connection;
        entry.context = context;
    });
}

https_server::~https_server() = default;

auto https_server::run() -> task<void>
{
    return accept_connections(owner(), *this, serving_, serve_tls);
}
#endif

redirect_server::redirect_server(event_loop& loop, ip_endpoint local,
                                 std::string_view hostname, std::uint16_t https_port,
                                 server_options options)
    : tcp_acceptor(loop, local, options.reuse_port)
{
    validate_hostname(hostname);
    const auto name = std::make_shared<const std::string>(hostname);
    serving_ = make_serving(loop, options, [&](detail::serving_loop& entry) {
        entry.hostname = name;
        entry.https_port = https_port;
        entry.header_timeout = options.header_timeout;
    });
}

redirect_server::~redirect_server() = default;

auto redirect_server::run() -> task<void>
{
    return accept_connections(owner(), *this, serving_, serve_redirect_entry);
}

} // namespace eventloop::http
