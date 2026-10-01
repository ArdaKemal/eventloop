#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"

#include <charconv>
#include <cstdio>
#include <cstring>
#include <exception>

auto main(int argc, char** argv) -> int
{
    if (argc != 5) {
        std::fprintf(stderr, "usage: %s <port> <root> <cert.pem> <key.pem>\n", argv[0]);
        return 2;
    }
    unsigned port = 0;
    const auto* end = argv[1] + std::strlen(argv[1]);
    const auto parsed = std::from_chars(argv[1], end, port);
    if (parsed.ec != std::errc{} || parsed.ptr != end || port == 0 || port > 65535)
        return 2;
    try {
        eventloop::event_loop loop;
        eventloop::http::http3_server server(loop,
            eventloop::ip_endpoint::any_v4(static_cast<std::uint16_t>(port)),
            argv[2], argv[3], argv[4]);
        if (loop.spawn(server.run()) != eventloop::task_spawn_result::accepted)
            return 1;
        (void)loop.run();
        server.close();
        loop.shutdown(eventloop::event_loop::clock::duration::zero());
        while (loop.run() == eventloop::event_loop_result::interrupted)
            loop.shutdown(eventloop::event_loop::clock::duration::zero());
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
