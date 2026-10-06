// Holds completion paths to a constant number of EPOLL_CTL_MOD calls when the
// continuation immediately starts the next operation of the same kind. The
// test interposes epoll_ctl to count modifications and reads the registered
// masks back from /proc/self/fdinfo.
#include "eventloop/event_loop.h"
#include "eventloop/task.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "eventloop/udp_socket.h"
#include "tls_test_certificate.h"

#include <algorithm>
#include <cerrno>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

using namespace eventloop;

namespace {

std::size_t modifications = 0;
int epoll_descriptor = -1;

} // namespace

extern "C" auto epoll_ctl(int descriptor, int operation, int target,
                          epoll_event* event) noexcept -> int
{
    epoll_descriptor = descriptor;
    if (operation == EPOLL_CTL_MOD) ++modifications;
    return static_cast<int>(
        ::syscall(SYS_epoll_ctl, descriptor, operation, target, event));
}

namespace {

constexpr std::size_t rounds = 1000;

// Each socket arms its interest once and drops it once after the last
// completion; updating before resumption cost two per completion.
constexpr std::size_t allowed_modifications = 4;

[[nodiscard]] auto registered_events(int target) -> std::optional<unsigned>
{
    std::ifstream info("/proc/self/fdinfo/" + std::to_string(epoll_descriptor));
    std::string line;
    while (std::getline(info, line)) {
        int descriptor = -1;
        unsigned events = 0;
        if (std::sscanf(line.c_str(), "tfd: %d events: %x", &descriptor,
                        &events) == 2 && descriptor == target)
            return events;
    }
    return std::nullopt;
}

[[nodiscard]] auto idle(int target) -> bool
{
    const auto events = registered_events(target);
    return events && (*events & (EPOLLIN | EPOLLOUT)) == 0;
}

[[nodiscard]] auto check(const char* name, bool completed, int first,
                         int second) -> bool
{
    const bool passed = completed && modifications <= allowed_modifications &&
                        idle(first) && (second == -1 || idle(second));
    if (!passed)
        std::cerr << name << ": completed " << completed << ", "
                  << modifications << " modifications\n";
    return passed;
}

auto require(bool condition, const char* step) -> void
{
    if (!condition) throw std::system_error(errno, std::generic_category(), step);
}

auto finish(event_loop& loop, std::size_t& finished) -> void
{
    if (++finished == 2) loop.stop();
}

// A small send buffer makes writes from the first socket wait for the reader.
[[nodiscard]] auto unix_pair() -> std::pair<unique_fd, unique_fd>
{
    std::array<int, 2> sockets {};
    require(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
                         sockets.data()) == 0, "socketpair");
    std::pair<unique_fd, unique_fd> pair {unique_fd(sockets[0]),
                                          unique_fd(sockets[1])};
    const int size = 4096;
    require(::setsockopt(pair.first.get(), SOL_SOCKET, SO_SNDBUF, &size,
                         sizeof(size)) == 0, "SO_SNDBUF");
    return pair;
}

// TLS needs TCP sockets.
[[nodiscard]] auto tcp_pair() -> std::pair<unique_fd, unique_fd>
{
    unique_fd listener(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    unique_fd first(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    require(listener && first, "socket");
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof(address);
    auto* generic = reinterpret_cast<sockaddr*>(&address);
    require(::bind(listener.get(), generic, length) == 0 &&
            ::listen(listener.get(), 1) == 0 &&
            ::getsockname(listener.get(), generic, &length) == 0 &&
            ::connect(first.get(), generic, length) == 0, "connect");
    unique_fd second(::accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC));
    require(static_cast<bool>(second), "accept");
    return {std::move(first), std::move(second)};
}

template<class Stream>
auto add(event_loop& loop, std::unique_ptr<Stream> stream) -> Stream&
{
    auto& added = *stream;
    loop.add(std::unique_ptr<tcp_stream>(std::move(stream)));
    return added;
}

constexpr std::size_t transfer_size = 4 * 1024 * 1024;
// Outside the coroutine frames, which must fit the loop's size classes.
std::array<std::byte, 64 * 1024> write_buffer {};
std::array<std::byte, 64 * 1024> read_buffer {};

auto write_all(event_loop& loop, tcp_stream& stream, bool& passed,
               std::size_t& finished) -> task<void>
{
    std::size_t sent = 0;
    while (sent < transfer_size) {
        const auto size = std::min(write_buffer.size(), transfer_size - sent);
        const auto written = co_await stream.async_write_some(
            std::span<const std::byte>(write_buffer).first(size));
        if (!written || *written == 0) break;
        sent += *written;
    }
    passed = sent == transfer_size;
    finish(loop, finished);
}

auto read_all(event_loop& loop, tcp_stream& stream, bool& passed,
              std::size_t& finished) -> task<void>
{
    std::size_t received = 0;
    while (received < transfer_size) {
        const auto read = co_await stream.async_read_some(read_buffer);
        if (!read || *read == 0) break;
        received += *read;
    }
    passed = received == transfer_size;
    finish(loop, finished);
}

// Each write completion's continuation starts the next write.
auto pending_writes() -> bool
{
    auto sockets = unix_pair();
    event_loop loop;
    auto& writer = add(loop, std::make_unique<tcp_stream>(
        loop, std::move(sockets.first)));
    auto& reader = add(loop, std::make_unique<tcp_stream>(
        loop, std::move(sockets.second)));
    modifications = 0;
    bool wrote = false;
    bool read = false;
    std::size_t finished = 0;
    require(loop.spawn(write_all(loop, writer, wrote, finished)) ==
                task_spawn_result::accepted &&
            loop.spawn(read_all(loop, reader, read, finished)) ==
                task_spawn_result::accepted, "spawn");
    (void)loop.run();
    return check("pending writes", wrote && read, writer.descriptor(),
                 reader.descriptor());
}

struct temporary_certificate {
    std::filesystem::path directory;
    std::filesystem::path certificate;
    std::filesystem::path key;

    temporary_certificate()
    {
        const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
        directory = std::filesystem::temp_directory_path() /
                    ("eventloop-interest-test-" + std::to_string(suffix));
        std::filesystem::create_directory(directory);
        certificate = directory / "cert.pem";
        key = directory / "key.pem";
        test::make_localhost_certificate(certificate, key);
    }

    ~temporary_certificate()
    {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
    }
};

// TLS reads wait for readability; the continuation reads and waits again.
auto tls_ping(event_loop& loop, tls_stream& stream, bool initiator,
              std::size_t& handshakes, bool& passed, std::size_t& finished)
    -> task<void>
{
    std::size_t round = 0;
    if (flatten_result(co_await stream.async_handshake())) {
        if (++handshakes == 2) modifications = 0;
        std::array<std::byte, 1> byte {};
        for (; round < rounds; ++round) {
            if (initiator && !flatten_result(
                    co_await stream.async_write_some(byte))) break;
            const auto read = flatten_result(co_await stream.async_read_some(byte));
            if (!read || *read != 1) break;
            if (!initiator && !flatten_result(
                    co_await stream.async_write_some(byte))) break;
        }
    }
    passed = round == rounds;
    finish(loop, finished);
}

auto readiness_waits() -> bool
{
    temporary_certificate files;
    auto sockets = tcp_pair();
    event_loop loop;
    auto& client = add(loop, std::make_unique<tls_stream>(
        loop, std::move(sockets.first), tls_context::make_client(files.certificate),
        tls_client_options {.hostname = "localhost", .application_protocols = {}}));
    auto& server = add(loop, std::make_unique<tls_stream>(
        loop, std::move(sockets.second),
        tls_context::make_server(files.certificate, files.key)));
    std::size_t handshakes = 0;
    bool client_passed = false;
    bool server_passed = false;
    std::size_t finished = 0;
    require(loop.spawn(tls_ping(loop, client, true, handshakes, client_passed,
                                finished)) == task_spawn_result::accepted &&
            loop.spawn(tls_ping(loop, server, false, handshakes, server_passed,
                                finished)) == task_spawn_result::accepted,
            "spawn");
    (void)loop.run();
    return check("readiness waits", client_passed && server_passed,
                 client.descriptor(), server.descriptor());
}

auto datagram_ping(event_loop& loop, udp_socket& socket, ip_endpoint peer,
                   bool initiator, bool& passed, std::size_t& finished)
    -> task<void>
{
    std::array<std::byte, 1> byte {};
    std::size_t round = 0;
    for (; round < rounds; ++round) {
        if (initiator && !co_await socket.async_send_to(byte, peer)) break;
        if (!co_await socket.async_receive_from(byte)) break;
        if (!initiator && !co_await socket.async_send_to(byte, peer)) break;
    }
    // Closing from inside the completion must not touch the removed socket.
    if (!initiator) socket.close();
    passed = round == rounds;
    finish(loop, finished);
}

auto datagram_waits() -> bool
{
    event_loop loop;
    auto first_socket = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto second_socket = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto& first = *first_socket;
    auto& second = *second_socket;
    loop.add(std::move(first_socket));
    loop.add(std::move(second_socket));
    modifications = 0;
    bool first_passed = false;
    bool second_passed = false;
    std::size_t finished = 0;
    require(loop.spawn(datagram_ping(loop, first, second.local_endpoint(),
                                     true, first_passed, finished)) ==
                task_spawn_result::accepted &&
            loop.spawn(datagram_ping(loop, second, first.local_endpoint(),
                                     false, second_passed, finished)) ==
                task_spawn_result::accepted, "spawn");
    (void)loop.run();
    return check("datagram waits", first_passed && second_passed,
                 first.descriptor(), -1);
}

} // namespace

auto main() -> int
{
    try {
        const bool writes = pending_writes();
        const bool readiness = readiness_waits();
        const bool datagrams = datagram_waits();
        return writes && readiness && datagrams ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
