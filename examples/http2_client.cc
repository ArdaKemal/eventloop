#include "eventloop/http2/client.h"

#include <chrono>
#include <exception>
#include <iostream>
#include <string>

namespace {

auto fetch(eventloop::event_loop& loop, eventloop::ip_endpoint endpoint,
           std::string hostname, std::string target, bool& success)
    -> eventloop::task<void>
{
    eventloop::http2::client_request request;
    request.target = std::move(target);
    auto result = co_await eventloop::http2::async_request(
        loop, endpoint, eventloop::tls_context::make_system_client(),
        std::move(hostname), std::move(request));
    if (!result) {
        std::cerr << "HTTP/2 task failed\n";
    } else if (!*result) {
        std::cerr << "HTTP/2 request failed: " << result->error().message() << '\n';
    } else {
        std::cout << "HTTP/2 " << (*result)->status << '\n';
        const auto& body = (*result)->body;
        std::cout.write(reinterpret_cast<const char*>(body.data()),
                        static_cast<std::streamsize>(body.size()));
        success = true;
    }
    loop.stop();
}

} // namespace

auto main(int argc, char* argv[]) -> int
{
    if (argc != 4) {
        std::cerr << "usage: http2_client NUMERIC_IP HOSTNAME /PATH\n";
        return 2;
    }
    try {
        auto endpoint = eventloop::ip_endpoint::parse(argv[1], 443);
        eventloop::event_loop loop;
        bool success = false;
        if (loop.spawn(fetch(loop, endpoint, argv[2], argv[3], success)) !=
            eventloop::task_spawn_result::accepted) {
            std::cerr << "cannot start HTTP/2 request\n";
            return 1;
        }
        if (loop.run() == eventloop::event_loop_result::interrupted) {
            loop.shutdown(std::chrono::seconds{0});
            (void)loop.run();
        }
        return success ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
