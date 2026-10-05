// Serves the same payload routed and static on HTTP/1.1, TLS HTTP/1.1 or
// HTTP/2, and HTTP/3, so a load generator can compare the two paths.
//
//   routing_benchmark_server <document-root> <certificate> <key> <base-port>
//                            [open-file-cache-capacity]
//
// HTTP/1.1 listens on base-port, HTTPS on base-port + 1, and HTTP/3 on UDP
// base-port + 2. GET /routed answers from memory with as many bytes as
// <document-root>/payload.bin, which static requests fetch as /payload.bin.
#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/tls_context.h"

#include <algorithm>
#include <array>
#include <charconv>
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
#include <vector>

using namespace eventloop;

namespace {

std::vector<std::byte> payload;

auto routed(event_loop&, http::request&, http::response& response) -> task<void>
{
    static constexpr std::array<http::header, 1> fields {{
        {"content-type", "application/octet-stream"}}};
    (void)co_await response.async_send(200, fields, payload);
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
    if (argc != 5 && argc != 6) {
        std::cerr << "usage: routing_benchmark_server <document-root> <certificate> <key> "
                     "<base-port> [open-file-cache-capacity]\n";
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
        if (!routes->add(http::method_type::get, "/routed", routed))
            throw std::runtime_error("register /routed");
        std::size_t cache_capacity = 0;
        if (argc == 6) {
            const std::string_view text = argv[5];
            if (std::from_chars(text.data(), text.data() + text.size(), cache_capacity).ec !=
                    std::errc {})
                throw std::invalid_argument("open file cache capacity must be a number");
        }
        const http::server_options options {.routes = routes, .document_root = root,
                                            .open_file_cache_capacity = cache_capacity};

        // Size the coroutine pools for many concurrent HTTP/3 requests.
        event_loop_options loop_options;
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
