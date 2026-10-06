// Serves the same payload routed and static on HTTP/1.1, TLS HTTP/1.1 or
// HTTP/2, and HTTP/3, so a load generator can compare the two paths.
//
//   routing_benchmark_server <document-root> <certificate> <key> <base-port>
//                            [open-file-cache-capacity [blocking-workers
//                            [blocking-microseconds]]]
//
// HTTP/1.1 listens on base-port, HTTPS on base-port + 1, and HTTP/3 on UDP
// base-port + 2. GET /routed answers from memory with as many bytes as
// <document-root>/payload.bin, which static requests fetch as /payload.bin.
// GET /blocking first sleeps on a worker through run_blocking(), standing in
// for a database query (default 16 workers, 100 us), then sends the payload.
#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/tls_context.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace eventloop;

namespace {

std::vector<std::byte> payload;
std::chrono::microseconds query_time {100};

constexpr std::array<http::header, 1> fields {{
    {"content-type", "application/octet-stream"}}};

auto routed(event_loop&, http::request&, http::response& response) -> task<void>
{
    (void)co_await response.async_send(200, fields, payload);
}

auto blocking(event_loop& loop, http::request&, http::response& response) -> task<void>
{
    const auto queried = co_await run_blocking(loop, []() noexcept {
        std::this_thread::sleep_for(query_time);
    });
    if (!queried) {
        (void)co_await response.async_send(503, {}, {});
        co_return;
    }
    (void)co_await response.async_send(200, fields, payload);
}

[[nodiscard]] auto parse_count(std::string_view text, const char* name) -> std::size_t
{
    std::size_t value = 0;
    if (std::from_chars(text.data(), text.data() + text.size(), value).ec != std::errc {})
        throw std::invalid_argument(std::string(name) + " must be a number");
    return value;
}

template<typename Listener>
auto serve(event_loop& loop, Listener& listener) -> task<void>
{
    (void)loop;
    (void)co_await listener.run();
}

event_loop* running = nullptr;

} // namespace

auto main(int argc, char** argv) -> int
{
    if (argc < 5 || argc > 8) {
        std::cerr << "usage: routing_benchmark_server <document-root> <certificate> <key> "
                     "<base-port> [open-file-cache-capacity [blocking-workers "
                     "[blocking-microseconds]]]\n";
        return 1;
    }
    try {
        const std::filesystem::path root = argv[1];
        std::ifstream file(root / "payload.bin", std::ios::binary);
        const std::string bytes {std::istreambuf_iterator<char>(file), {}};
        if (bytes.empty()) throw std::runtime_error("payload.bin is missing or empty");
        const auto view = std::as_bytes(std::span(bytes));
        payload.assign(view.begin(), view.end());
        unsigned base = 0;
        const std::string_view port_text = argv[4];
        if (std::from_chars(port_text.data(), port_text.data() + port_text.size(), base).ec !=
                std::errc {} || base == 0 || base > 65533)
            throw std::invalid_argument("base port must be 1..65533");

        auto routes = std::make_shared<http::router>();
        if (!routes->add(http::method_type::get, "/routed", routed) ||
            !routes->add(http::method_type::get, "/blocking", blocking))
            throw std::runtime_error("register routes");
        const std::size_t cache_capacity =
            argc > 5 ? parse_count(argv[5], "open file cache capacity") : 0;
        const std::size_t workers = argc > 6 ? parse_count(argv[6], "blocking workers") : 16;
        if (workers == 0) throw std::invalid_argument("blocking workers must be positive");
        if (argc > 7) {
            query_time = std::chrono::microseconds(
                parse_count(argv[7], "blocking microseconds"));
        }
        const http::server_options options {.routes = routes, .document_root = root,
                                            .open_file_cache_capacity = cache_capacity};

        // Size the coroutine pools for many concurrent HTTP/3 requests.
        // Admit one blocking query per concurrent request.
        event_loop_options loop_options {.worker_count = workers,
                                         .coroutine_completion_capacity = 4096};
        for (auto& capacity : loop_options.coroutine_frame_capacities)
            capacity = std::max<std::size_t>(capacity, 1024);
        event_loop loop(loop_options);
        running = &loop;
        std::signal(SIGINT, [](int) { if (running != nullptr) running->stop(); });
        std::signal(SIGTERM, [](int) { if (running != nullptr) running->stop(); });

        auto plain = std::make_unique<http::server>(
            loop, ip_endpoint::loopback_v4(static_cast<std::uint16_t>(base)), options);
        auto secure = std::make_unique<http::https_server>(
            loop, ip_endpoint::loopback_v4(static_cast<std::uint16_t>(base + 1)),
            tls_context::make_server(argv[2], argv[3]), options);
        http::http3_server quic(loop, ip_endpoint::loopback_v4(static_cast<std::uint16_t>(base + 2)),
            argv[2], argv[3], http::server_options {
                .routes = routes, .document_root = root,
                .open_file_cache_capacity = cache_capacity,
                .connection_capacity = 64, .request_capacity = 1024});
        auto* plain_server = plain.get();
        auto* secure_server = secure.get();
        loop.add(std::move(plain));
        loop.add(std::move(secure));
        task_handle<void> quic_run;
        if (loop.spawn(serve(loop, *plain_server)) != task_spawn_result::accepted ||
            loop.spawn(serve(loop, *secure_server)) != task_spawn_result::accepted ||
            loop.spawn(quic.run(), quic_run) != task_spawn_result::accepted)
            throw std::runtime_error("could not start listeners");
        std::cout << "ready" << std::endl;
        (void)loop.run();
        quic.close();
        loop.shutdown(event_loop::clock::duration::zero());
        while (loop.run() == event_loop_result::interrupted)
            loop.shutdown(event_loop::clock::duration::zero());
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "routing_benchmark_server: " << error.what() << '\n';
        return 1;
    }
}
