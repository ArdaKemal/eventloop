#include "eventloop/event_loop.h"
#include "eventloop/http/server.h"

#include <charconv>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace {
[[nodiscard]] auto parse_port(std::string_view text) -> std::uint16_t
{
    unsigned int port = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
    if (error != std::errc {} || end != text.data() + text.size() ||
        port == 0 || port > 65535) {
        throw std::invalid_argument("port must be between 1 and 65535");
    }
    return static_cast<std::uint16_t>(port);
}
} // namespace

auto main(int argc, char* argv[]) -> int
{
    if (argc < 2 || argc > 3) {
        std::cerr << "usage: http_server <document-root> [port]\n";
        return 1;
    }

    try {
        const auto port = argc == 3 ? parse_port(argv[2]) : std::uint16_t {8080};
        event_loop loop;
        loop.add(std::make_unique<http::server>(loop, port, argv[1]));
        std::cout << "HTTP server listening on http://127.0.0.1:" << port << '\n';
        loop.run();
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
