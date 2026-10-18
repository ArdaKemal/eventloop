#include "eventloop/event_loop.h"
#include "eventloop/task.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/util/arg_parser.h"

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>

using namespace eventloop;

namespace {
[[nodiscard]] auto echo_session(event_loop& loop, tcp_stream& stream) -> task<void>
{
    (void)loop;
    std::array<std::byte, 512> buffer {};
    for (;;) {
        const auto received = co_await stream.async_read_some(buffer);
        if (!received || *received == 0) break;

        std::size_t offset = 0;
        while (offset < *received) {
            const auto sent = co_await stream.async_write_some(
                std::span<const std::byte>(buffer).subspan(offset, *received - offset));
            if (!sent || *sent == 0) {
                stream.close();
                co_return;
            }
            offset += *sent;
        }
    }
    stream.close();
}

[[nodiscard]] auto serve(event_loop& loop, tcp_acceptor& listener) -> task<void>
{
    for (;;) {
        auto accepted = co_await listener.async_accept();
        if (!accepted) co_return;

        auto stream = std::make_unique<tcp_stream>(loop, std::move(*accepted));
        auto* session = stream.get();
        loop.add(std::move(stream));
        if (loop.spawn(echo_session(loop, *session)) != task_spawn_result::accepted) {
            session->close();
        }
    }
}

[[nodiscard]] auto parse_port(std::string_view text) -> std::uint16_t
{
    unsigned int port = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
    if (error != std::errc {} || end != text.data() + text.size() || port == 0 ||
        port > 65535) {
        throw std::invalid_argument("port must be between 1 and 65535");
    }
    return static_cast<std::uint16_t>(port);
}
} // namespace

auto main(int argc, char* argv[]) -> int
{
    try {
        std::uint16_t port = 7000;
        const std::array positionals {arg_parser::positional {"PORT",
            arg_parser::value_handler([&port](std::string_view value) { port = parse_port(value); }),
            false}};
        arg_parser arguments({}, positionals);
        arguments.set_usage("usage: tcp_echo [port]  (default 7000)\n");
        arguments.parse(argc, argv);
        event_loop loop;
        auto listener = std::make_unique<tcp_acceptor>(loop, ip_endpoint::loopback_v4(port));
        auto* accepting = listener.get();
        loop.add(std::move(listener));
        if (loop.spawn(serve(loop, *accepting)) != task_spawn_result::accepted) {
            accepting->close();
            throw std::runtime_error("cannot start TCP echo listener");
        }
        std::cout << "echo server listening on 127.0.0.1:" << port << '\n';
        if (loop.run() == event_loop_result::interrupted) {
            loop.shutdown(std::chrono::seconds {0});
            (void)loop.run();
        }
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
