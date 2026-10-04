#include "eventloop/event_loop.h"
#include "eventloop/http/server.h"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

using namespace eventloop;

namespace {
[[nodiscard]] auto parse_port(std::string_view text) -> std::uint16_t
{
    unsigned int port = 0;
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), port);
    if (error != std::errc {} || end != text.data() + text.size() ||
        port == 0 || port > 65535) {
        throw std::invalid_argument("port must be between 1 and 65535");
    }
    return static_cast<std::uint16_t>(port);
}

[[nodiscard]] auto parse_threads(std::string_view text) -> std::size_t
{
    std::size_t threads = 0;
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), threads);
    if (error != std::errc {} || end != text.data() + text.size() ||
        threads == 0) {
        throw std::invalid_argument("threads must be a positive integer");
    }
    return threads;
}

auto serve(std::uint16_t port, const char* root, bool reuse_port) -> void
{
    event_loop loop;
    auto server = std::make_unique<http::server>(
        loop, ip_endpoint::loopback_v4(port),
        http::server_options {.document_root = root, .reuse_port = reuse_port});
    auto* active = server.get();
    loop.add(std::move(server));
    if (loop.spawn(active->run()) != task_spawn_result::accepted) {
        active->close();
        throw std::runtime_error("could not start HTTP listener task");
    }
    (void)loop.run();
    loop.shutdown(event_loop::clock::duration::zero());
    (void)loop.run();
}

} // namespace

auto main(int argc, char* argv[]) -> int
{
    if (argc < 3 || argc > 4) {
        std::cerr << "usage: http_benchmark_server <document-root> <port> [threads]\n";
        return 1;
    }

    try {
        const auto port = parse_port(argv[2]);
        const auto threads =
            argc == 4 ? parse_threads(argv[3]) : std::size_t {1};

#ifdef _WIN32
        if (threads != 1) {
            throw std::invalid_argument(
                "multiple listener threads require SO_REUSEPORT");
        }
#endif
        if (threads == 1) {
            serve(port, argv[1], false);
            return 0;
        }

        std::vector<std::thread> workers;
        workers.reserve(threads);
        for (std::size_t index = 0; index < threads; ++index) {
            workers.emplace_back([port, root = argv[1]] {
                serve(port, root, true);
            });
        }
        for (auto& worker : workers) {
            worker.join();
        }
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
