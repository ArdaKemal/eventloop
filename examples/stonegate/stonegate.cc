#include "configuration.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/tls_context.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {

using stonegate::server_config;

// GET /healthz answers 200 "ok" on every protocol; HEAD is implied.
auto healthz(eventloop::event_loop& loop, eventloop::http::request& request,
             eventloop::http::response& response) -> eventloop::task<void>
{
    (void)loop;
    (void)request;
    constexpr std::string_view body = "ok\n";
    const std::array<eventloop::http::header, 2> fields {{
        {"content-type", "text/plain; charset=utf-8"}, {"cache-control", "no-store"}}};
    (void)co_await response.async_send(200, fields, std::as_bytes(std::span(body)));
}

[[nodiscard]] auto make_routes() -> std::shared_ptr<const eventloop::http::router>
{
    auto routes = std::make_shared<eventloop::http::router>();
    if (!routes->add(eventloop::http::method_type::get, "/healthz", healthz))
        throw std::runtime_error("register /healthz");
    return routes;
}

template<typename Listener>
auto serve(eventloop::event_loop& loop, Listener& listener) -> eventloop::task<void>
{
    (void)loop;
    (void)co_await listener.run();
}

template<typename Listener, typename... Args>
auto start(eventloop::event_loop& loop, Args&&... args) -> void
{
    auto listener = std::make_unique<Listener>(loop, std::forward<Args>(args)...);
    auto* active = listener.get();
    loop.add(std::move(listener));
    if (loop.spawn(serve(loop, *active)) != eventloop::task_spawn_result::accepted) {
        active->close();
        throw std::runtime_error("listener task capacity exhausted");
    }
}

// HTTP/3 owners and observed handles cannot move while run() is pending.
struct http3_listener {
    std::unique_ptr<eventloop::http::http3_server> server;
    eventloop::task_handle<void> running;
};

auto stop(eventloop::event_loop& loop, int seconds,
          std::span<http3_listener> listeners) -> void
{
    for (auto& listener : listeners)
        if (listener.server) listener.server->close();
    loop.shutdown(std::chrono::seconds {seconds});
    while (loop.run() != eventloop::event_loop_result::stopped)
        loop.shutdown(eventloop::event_loop::clock::duration::zero());
    // A stopped, shutting-down loop has retired all roots, including endpoint
    // receivers and connection tasks. Owners/handles may now be destroyed.
}

} // namespace

auto main(int argc, char** argv) -> int
{
    try {
        const auto configuration = stonegate::parse_configuration(argc, argv);
        std::array<std::shared_ptr<eventloop::tls_context>, stonegate::max_servers> contexts;
        // Load every credential before starting any listener; --check follows
        // this same path without creating sockets or an event loop.
        for (std::size_t index = 0; index < configuration.servers.size(); ++index) {
            const auto& settings = configuration.servers[index];
            if (settings.certificate.empty()) continue;
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
            try {
                contexts[index] = eventloop::tls_context::make_server(
                    settings.certificate, settings.private_key, settings.key_password);
            } catch (const std::exception& error) {
                throw std::invalid_argument("server " + settings.name + ": " + error.what());
            }
#else
            throw std::runtime_error("this eventloop build has no Windows TLS support");
#endif
        }
        if (configuration.check) {
            std::cout << "Configuration OK (" << configuration.servers.size() << " server(s))\n";
            return 0;
        }
        // Preserve the original per-server frame budget even with HTTP/3
        // disabled, and sum it across servers for shared-loop capacity.
        std::size_t connections = 0, requests = 0;
        for (const auto& settings : configuration.servers) {
            connections += settings.http3_connections;
            requests += settings.http3_requests == 0 ? settings.http3_connections * 4
                                                   : settings.http3_requests;
        }
        eventloop::event_loop_options loop_options;
        for (auto& capacity : loop_options.coroutine_frame_capacities)
            capacity = std::max(capacity, connections * 8);
        loop_options.coroutine_frame_capacities[4] = std::max(
            loop_options.coroutine_frame_capacities[4], requests);
        eventloop::event_loop loop(loop_options);
        std::array<http3_listener, stonegate::max_servers> http3;
        try {
            const auto routes = make_routes();
            for (std::size_t index = 0; index < configuration.servers.size(); ++index) {
                const auto& settings = configuration.servers[index];
                const eventloop::http::server_options options {
                    .routes = routes,
                    .document_root = settings.root,
                    .directory_listing = settings.directory_listing,
                    .open_file_cache_capacity = settings.open_file_cache_capacity,
                    .reuse_port = settings.reuse_port,
                    .header_timeout = std::chrono::milliseconds {settings.header_timeout_ms},
                    .idle_timeout = std::chrono::milliseconds {settings.idle_timeout_ms},
                    .enable_http2 = settings.http2,
                    .connection_capacity = settings.http3_connections,
                    .request_capacity = settings.http3_requests,
                    .max_udp_payload_size = settings.http3_max_datagram,
                };
                if (settings.mode == server_config::http_mode::serve) {
                    start<eventloop::http::server>(loop,
                        eventloop::ip_endpoint::parse(settings.bind, settings.http_port), options);
                    std::cout << settings.name << ": HTTP/1.1 on " << settings.bind << ':'
                              << settings.http_port << '\n';
                }
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
                if (contexts[index] && settings.https_port != 0) {
                    if (settings.mode == server_config::http_mode::redirect) {
                        start<eventloop::http::redirect_server>(loop,
                            eventloop::ip_endpoint::parse(settings.bind, settings.http_port),
                            settings.redirect_host, settings.https_port);
                        std::cout << settings.name << ": HTTP redirect on " << settings.bind << ':'
                                  << settings.http_port << '\n';
                    }
                    start<eventloop::http::https_server>(loop,
                        eventloop::ip_endpoint::parse(settings.bind, settings.https_port),
                        contexts[index], options);
                    std::cout << settings.name << ": HTTPS (HTTP/1.1"
                              << (settings.http2 ? ", HTTP/2" : "") << ") on "
                              << settings.bind << ':' << settings.https_port << '\n';
                }
#endif
                if (settings.http3_port != 0) {
                    auto& listener = http3[index];
                    listener.server = std::make_unique<eventloop::http::http3_server>(
                        loop, eventloop::ip_endpoint::parse(settings.bind, settings.http3_port),
                        settings.certificate, settings.private_key, options);
                    if (loop.spawn(listener.server->run(), listener.running) !=
                        eventloop::task_spawn_result::accepted)
                        throw std::runtime_error("HTTP/3 listener task capacity exhausted");
                    std::cout << settings.name << ": HTTP/3 on UDP " << settings.bind << ':'
                              << settings.http3_port << '\n';
                }
            }
            std::cout.flush();
            (void)loop.run();
        } catch (...) {
            stop(loop, 0, http3);
            throw;
        }
        stop(loop, configuration.shutdown_seconds, http3);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "stonegate: " << error.what() << '\n';
        return 1;
    }
}
