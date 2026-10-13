#include "configuration.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/quic.h"
#include "eventloop/tls_context.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <latch>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>
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


using contexts_type =
    std::array<std::shared_ptr<eventloop::tls_context>, stonegate::max_servers>;
// One group per HTTP/3 server, shared by that server's endpoint on every worker.
using groups_type =
    std::array<std::shared_ptr<eventloop::quic_worker_group>, stonegate::max_servers>;

// Builds every configured listener on one worker's loop. In reuse_port mode
// several workers share each port with SO_REUSEPORT; HTTP/3 connection IDs
// carry the worker index and the server's group forwards packets to their
// owner. In handoff mode only worker 0 builds listeners, and its TCP servers
// hand connections to every loop in serving. Only worker 0 reports listeners.
auto start_listeners(eventloop::event_loop& loop, const stonegate::configuration& configuration,
                     const contexts_type& contexts, const groups_type& groups,
                     const std::shared_ptr<const eventloop::http::router>& routes,
                     std::size_t worker, std::span<eventloop::event_loop* const> serving,
                     std::span<http3_listener> http3) -> void
{
    const bool shared = configuration.workers > 1 &&
        configuration.mode == stonegate::worker_mode::reuse_port;
    const bool report = worker == 0;
    for (std::size_t index = 0; index < configuration.servers.size(); ++index) {
        const auto& settings = configuration.servers[index];
        const eventloop::http::server_options options {
            .routes = routes,
            .document_root = settings.root,
            .directory_listing = settings.directory_listing,
            .open_file_cache_capacity = settings.open_file_cache_capacity,
            .reuse_port = settings.reuse_port || shared,
            .serving_loops = {serving.begin(), serving.end()},
            .header_timeout = std::chrono::milliseconds {settings.header_timeout_ms},
            .idle_timeout = std::chrono::milliseconds {settings.idle_timeout_ms},
            .enable_http2 = settings.http2,
            .advertise_http3_port = settings.http3_port,
            .connection_capacity = settings.http3_connections,
            .request_capacity = settings.http3_requests,
            .max_udp_payload_size = settings.http3_max_datagram,
            .worker_index = shared
                ? std::optional<std::uint8_t> {static_cast<std::uint8_t>(worker)}
                : std::nullopt,
            .worker_group = groups[index],
        };
        if (settings.mode == server_config::http_mode::serve) {
            start<eventloop::http::server>(loop,
                eventloop::ip_endpoint::parse(settings.bind, settings.http_port), options);
            if (report)
                std::cout << settings.name << ": HTTP/1.1 on " << settings.bind << ':'
                          << settings.http_port << '\n';
        }
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
        if (contexts[index] && settings.https_port != 0) {
            if (settings.mode == server_config::http_mode::redirect) {
                start<eventloop::http::redirect_server>(loop,
                    eventloop::ip_endpoint::parse(settings.bind, settings.http_port),
                    settings.redirect_host, settings.https_port, options);
                if (report)
                    std::cout << settings.name << ": HTTP redirect on " << settings.bind
                              << ':' << settings.http_port << '\n';
            }
            start<eventloop::http::https_server>(loop,
                eventloop::ip_endpoint::parse(settings.bind, settings.https_port),
                contexts[index], options);
            if (report)
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
            if (report)
                std::cout << settings.name << ": HTTP/3 on UDP " << settings.bind << ':'
                          << settings.http3_port << '\n';
        }
    }
}

// One worker per event-loop thread. A loop that leaves run() (on a signal or
// a startup failure) asks every other loop to stop through post(); the posted
// task runs on its own loop and ignores a loop that is already stopping, so a
// stop never cuts another loop's shutdown short. No loop is destroyed until
// every worker has finished posting.
struct worker {
    eventloop::event_loop* loop {nullptr};
    bool stopping {false}; // owner loop thread only
};

struct worker_group {
    explicit worker_group(std::size_t count)
        : workers(count), created(static_cast<std::ptrdiff_t>(count)),
          built(static_cast<std::ptrdiff_t>(count)),
          finished(static_cast<std::ptrdiff_t>(count)) {}
    std::vector<worker> workers;
    std::latch created; // every loop exists, so handoff targets are known
    std::latch built;
    std::latch finished;
    std::atomic<bool> failed {false};
    std::mutex error_mutex;
    std::string error;

    auto fail(std::string message) -> void
    {
        const std::lock_guard lock {error_mutex};
        if (error.empty()) error = std::move(message);
        failed.store(true);
    }
    // Counts down for a worker that never runs a loop.
    auto absent(std::ptrdiff_t count) -> void
    {
        created.count_down(count);
        built.count_down(count);
        finished.count_down(count);
    }
    auto stop_others(std::size_t self) -> void
    {
        for (std::size_t index = 0; index < workers.size(); ++index) {
            auto& target = workers[index];
            if (index == self || target.loop == nullptr) continue;
            // A full queue falls back to a direct stop, which could end
            // that worker's shutdown early but cannot leave it running.
            if (!target.loop->post([&target]() noexcept {
                    if (!target.stopping) target.loop->stop();
                }))
                target.loop->stop();
        }
    }
};

struct worker_setup {
    const stonegate::configuration& configuration;
    const contexts_type& contexts;
    groups_type groups;
    std::shared_ptr<const eventloop::http::router> routes;
    eventloop::event_loop_options loop_options;
};

// started() runs once the loop exists; worker 0 uses it to start the other
// threads, which then inherit the signal mask that loop installed.
template<typename Started>
auto run_worker(worker_group& group, const worker_setup& setup, std::size_t index,
                Started started) -> void
{
    std::optional<eventloop::event_loop> loop;
    try {
        loop.emplace(setup.loop_options);
    } catch (const std::exception& error) {
        group.fail(error.what());
        started();
        group.absent(1);
        return;
    }
    auto& self = group.workers[index];
    self.loop = &*loop;
    started();
    group.created.arrive_and_wait();
    const bool handoff = setup.configuration.workers > 1 &&
        setup.configuration.mode == stonegate::worker_mode::handoff;
    std::array<http3_listener, stonegate::max_servers> http3;
    if (!group.failed.load() && (!handoff || index == 0)) {
        try {
            std::vector<eventloop::event_loop*> serving;
            if (handoff)
                for (const auto& other : group.workers) serving.push_back(other.loop);
            start_listeners(*loop, setup.configuration, setup.contexts, setup.groups,
                            setup.routes, index, serving, http3);
            if (index == 0) std::cout.flush();
        } catch (const std::exception& error) {
            group.fail(error.what());
        }
    }
    group.built.arrive_and_wait();
    if (!group.failed.load()) (void)loop->run();
    self.stopping = true;
    group.stop_others(index);
    stop(*loop, group.failed.load() ? 0 : setup.configuration.shutdown_seconds, http3);
    // Other workers may still post to this loop until they arrive here.
    group.finished.arrive_and_wait();
}

// Returns the first startup error, or an empty string after a clean stop.
auto run_workers(const stonegate::configuration& configuration,
                 const contexts_type& contexts) -> std::string
{
    // Preserve the original per-server frame budget even with HTTP/3
    // disabled, and sum it across servers for each loop's shared capacity.
    std::size_t connections = 0, requests = 0;
    for (const auto& settings : configuration.servers) {
        connections += settings.http3_connections;
        requests += settings.http3_requests == 0 ? settings.http3_connections * 10
                                               : settings.http3_requests;
    }
    worker_setup setup {configuration, contexts, {}, make_routes(), {}};
    // Endpoints sharing a port forward packets for connections another
    // worker owns, so a client whose address changes keeps its connection.
    if (configuration.workers > 1 && configuration.mode == stonegate::worker_mode::reuse_port)
        for (std::size_t index = 0; index < configuration.servers.size(); ++index)
            if (configuration.servers[index].http3_port != 0)
                setup.groups[index] =
                    std::make_shared<eventloop::quic_worker_group>(configuration.workers);
    for (auto& capacity : setup.loop_options.coroutine_frame_capacities)
        capacity = std::max(capacity, connections * 8);
    setup.loop_options.coroutine_frame_capacities[4] = std::max(
        setup.loop_options.coroutine_frame_capacities[4], requests);

    worker_group group(configuration.workers);
    std::vector<std::jthread> threads;
    threads.reserve(configuration.workers - 1);
    run_worker(group, setup, 0, [&] {
        for (std::size_t index = 1; index < configuration.workers; ++index) {
            try {
                threads.emplace_back([&group, &setup, index] {
                    run_worker(group, setup, index, [] {});
                });
            } catch (const std::exception& error) {
                group.fail(error.what());
                group.absent(static_cast<std::ptrdiff_t>(configuration.workers - index));
                return;
            }
        }
    });
    threads.clear();
    return group.error;
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
        if (configuration.workers > 1) {
            if (configuration.mode == stonegate::worker_mode::reuse_port)
                std::cout << configuration.workers << " workers share every listener\n";
            else
                std::cout << configuration.workers << " workers serve TCP connections "
                             "accepted by worker 0; HTTP/3 runs on worker 0\n";
            std::cout.flush();
        }
        const auto failure = run_workers(configuration, contexts);
        if (!failure.empty()) throw std::runtime_error(failure);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "stonegate: " << error.what() << '\n';
        return 1;
    }
}
