// WebTransport over HTTP/3 echo server. Usage:
//   webtransport_echo_server <port> <certificate.pem> <key.pem>
// Serves the CONNECT route /echo; see webtransport_echo.h for its behavior.
#include "webtransport_echo.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"

#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string_view>

namespace {

using namespace eventloop;

auto parse_port(const char* text) -> std::uint16_t
{
    unsigned value = 0;
    const auto* end = text + std::strlen(text);
    const auto result = std::from_chars(text, end, value);
    if (result.ec != std::errc {} || result.ptr != end || value == 0 || value > 65535) return 0;
    return static_cast<std::uint16_t>(value);
}

} // namespace

auto main(int argc, char** argv) -> int
{
    if (argc != 4) {
        std::fprintf(stderr, "usage: %s <port> <certificate.pem> <key.pem>\n", argv[0]);
        return 2;
    }
    const auto port = parse_port(argv[1]);
    if (port == 0) {
        std::fprintf(stderr, "error: port must be between 1 and 65535\n");
        return 2;
    }
    try {
        auto routes = std::make_shared<http::router>();
        if (!routes->add(http::method_type::connect, "/echo", webtransport_echo::echo_session).has_value())
            return 1;
        http::server_options options;
        options.routes = routes;
        options.webtransport.enabled = true;
        event_loop loop;
        http::http3_server server(loop, ip_endpoint::loopback_v4(port), argv[2], argv[3], options);
        if (loop.spawn(server.run()) != task_spawn_result::accepted) return 1;
        std::printf("WebTransport echo server listening on https://127.0.0.1:%u/echo\n",
                    static_cast<unsigned>(port));
        std::fflush(stdout);
        if (loop.run() == event_loop_result::interrupted) {
            loop.shutdown(std::chrono::seconds {0});
            (void)loop.run();
        }
    } catch (const std::exception& error) {
        std::fprintf(stderr, "error: %s\n", error.what());
        return 1;
    }
    return 0;
}
