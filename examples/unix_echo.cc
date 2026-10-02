#include "eventloop/event_loop.h"
#include "eventloop/task.h"
#include "eventloop/unix_socket.h"

#include <array>
#include <chrono>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>

using namespace eventloop;

namespace {
[[nodiscard]] auto echo_session(event_loop& loop, unix_stream& stream) -> task<void>
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

[[nodiscard]] auto serve(event_loop& loop, unix_acceptor& listener) -> task<void>
{
    for (;;) {
        auto accepted = co_await listener.async_accept();
        if (!accepted) co_return;

        auto stream = std::make_unique<unix_stream>(loop, std::move(*accepted));
        auto* session = stream.get();
        loop.add(std::move(stream));
        if (loop.spawn(echo_session(loop, *session)) != task_spawn_result::accepted) {
            session->close();
        }
    }
}

} // namespace

auto main(int argc, char* argv[]) -> int
{
    try {
        const std::string_view path = argc > 1 ? argv[1] : "/tmp/eventloop-echo.sock";
        event_loop loop;
        auto listener = std::make_unique<unix_acceptor>(loop, path);
        auto* accepting = listener.get();
        loop.add(std::move(listener));
        if (loop.spawn(serve(loop, *accepting)) != task_spawn_result::accepted) {
            accepting->close();
            throw std::runtime_error("cannot start Unix echo listener");
        }
        std::cout << "echo server listening on " << path << '\n';
        if (loop.run() == event_loop_result::interrupted) {
            loop.shutdown(std::chrono::seconds {0});
            (void)loop.run();
        }
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
