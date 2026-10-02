#include "eventloop/task.h"
#include "eventloop/unix_socket.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

using namespace eventloop;
using namespace std::chrono_literals;

namespace {
auto require(bool value, const char* message) -> void
{
    if (!value) throw std::runtime_error(message);
}

auto server(event_loop& loop, unix_acceptor& listener, int& completed,
            bool& passed) -> task<void>
{
    auto accepted = co_await listener.async_accept();
    if (!accepted) {
        ++completed;
        co_return;
    }
    listener.close();
    auto peer = std::make_unique<unix_stream>(loop, std::move(*accepted));
    auto* stream = peer.get();
    loop.add(std::move(peer));
    std::array<std::byte, 1> data {};
    auto read = co_await stream->async_read_some(data);
    constexpr std::array<std::byte, 1> reply {std::byte {'y'}};
    auto wrote = co_await stream->async_write_some(reply);
    passed = read && *read == 1 && data[0] == std::byte {'x'} &&
             wrote && *wrote == 1;
    stream->close();
    if (++completed == 2) loop.stop();
}

auto client(event_loop& loop, unix_stream& stream, int& completed,
            bool& passed) -> task<void>
{
    auto connected = co_await stream.async_connect();
    if (connected) {
        constexpr std::array<std::byte, 1> request {std::byte {'x'}};
        auto wrote = co_await stream.async_write_some(request);
        std::array<std::byte, 1> reply {};
        auto read = co_await stream.async_read_some(reply);
        passed = wrote && *wrote == 1 && read && *read == 1 &&
                 reply[0] == std::byte {'y'};
    }
    stream.close();
    if (++completed == 2) loop.stop();
}

auto watchdog(event_loop& loop, bool& timed_out) -> task<void>
{
    if (co_await sleep_for(loop, 3s) == timer_wait_result::expired) {
        timed_out = true;
        loop.shutdown(0ms);
    }
}
} // namespace

auto main() -> int
{
    try {
        const std::string path = "/tmp/eventloop-unix-test-" +
                                 std::to_string(::getpid()) + ".sock";
        event_loop loop;
        auto listener = std::make_unique<unix_acceptor>(loop, path);
        auto* accepting = listener.get();
        require(std::filesystem::exists(path), "listener path absent");
        try {
            unix_acceptor duplicate(loop, path);
            throw std::runtime_error("duplicate bind succeeded");
        } catch (const std::system_error& error) {
            require(error.code().value() == EADDRINUSE, "wrong duplicate bind error");
        }
        auto peer = std::make_unique<unix_stream>(loop, path);
        auto* connecting = peer.get();
        loop.add(std::move(listener));
        loop.add(std::move(peer));
        int completed = 0;
        bool server_ok = false;
        bool client_ok = false;
        bool timed_out = false;
        require(loop.spawn(server(loop, *accepting, completed, server_ok)) ==
                task_spawn_result::accepted, "server spawn");
        require(loop.spawn(client(loop, *connecting, completed, client_ok)) ==
                task_spawn_result::accepted, "client spawn");
        task_handle<void> timer;
        require(loop.spawn(watchdog(loop, timed_out), timer) ==
                task_spawn_result::accepted, "watchdog spawn");
        (void)loop.run();
        if (!timer.done()) (void)timer.cancel();
        loop.shutdown(0ms);
        (void)loop.run();
        require(!timed_out && completed == 2 && server_ok && client_ok,
                "Unix stream exchange failed");
        require(!std::filesystem::exists(path), "listener path not removed");
        require(loop.coroutine_statistics().live == 0, "live coroutine frames");

        {
            event_loop cleanup_loop;
            const std::string replacement_path = path + ".replacement";
            const std::string moved_path = path + ".moved";
            unix_acceptor replacement(cleanup_loop, replacement_path);
            std::filesystem::rename(replacement_path, moved_path);
            std::ofstream(replacement_path) << "replacement";
            replacement.close();
            require(std::filesystem::is_regular_file(replacement_path),
                    "listener removed replacement path");
            std::filesystem::remove(replacement_path);
            std::filesystem::remove(moved_path);
        }
        {
            event_loop shutdown_loop;
            const std::string shutdown_path = path + ".shutdown";
            auto shutdown_listener =
                std::make_unique<unix_acceptor>(shutdown_loop, shutdown_path);
            shutdown_loop.add(std::move(shutdown_listener));
            shutdown_loop.shutdown(0ms);
            (void)shutdown_loop.run();
            require(!std::filesystem::exists(shutdown_path),
                    "shutdown left listener path");
        }
        bool invalid = false;
        try { unix_stream bad(loop, std::string(200, 'a')); }
        catch (const std::invalid_argument&) { invalid = true; }
        require(invalid, "long path accepted");
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
