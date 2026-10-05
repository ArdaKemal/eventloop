#include "posix_socket_helpers.h"

#include "eventloop/http/mime_types.h"
#include "http/parser.h"
#include "eventloop/http/server.h"
#include "http/session.h"
#include "eventloop/unique_fd.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/resource.h>
#endif

using namespace eventloop;

namespace {
std::size_t allocations = 0;
}

auto operator new(std::size_t size) -> void*
{
    ++allocations;
    if (void* memory = std::malloc(size)) return memory;
    throw std::bad_alloc {};
}

auto operator new[](std::size_t size) -> void*
{
    ++allocations;
    if (void* memory = std::malloc(size)) return memory;
    throw std::bad_alloc {};
}

auto operator delete(void* memory) noexcept -> void { std::free(memory); }
auto operator delete[](void* memory) noexcept -> void { std::free(memory); }
auto operator delete(void* memory, std::size_t) noexcept -> void { std::free(memory); }
auto operator delete[](void* memory, std::size_t) noexcept -> void { std::free(memory); }

namespace {

auto stop_after(event_loop& loop, std::chrono::milliseconds delay) -> task<void>
{
    if (co_await sleep_for(loop, delay) == timer_wait_result::expired) {
        loop.stop();
    }
}

struct capture {
    std::array<char, 128 * 1024> output {};
    std::size_t size {0};
    bool open {true};
};

[[nodiscard]] auto contains(const capture& stream, std::string_view value) -> bool
{
    return std::string_view {stream.output.data(), stream.size}.find(value) !=
           std::string_view::npos;
}

auto collect(http::detail::session& session, capture& stream) -> void
{
    while (session.has_response()) {
        const auto response = session.response();
        if (response.size() > stream.output.size() - stream.size) {
            stream.open = false;
            return;
        }
        std::memcpy(stream.output.data() + stream.size, response.data(),
                    response.size());
        stream.size += response.size();
        const auto file_size = session.file_size();
        auto file = session.take_file();
        if (file) {
            std::size_t remaining = file_size;
            while (remaining != 0) {
                const auto read_size = ::read(file.get(),
                    stream.output.data() + stream.size,
                    std::min(remaining, stream.output.size() - stream.size));
                if (read_size <= 0) {
                    stream.open = false;
                    return;
                }
                stream.size += static_cast<std::size_t>(read_size);
                remaining -= static_cast<std::size_t>(read_size);
            }
        }
        session.finish_response();
    }
    stream.open = !session.closed();
}

auto write_file(int directory, const char* name, std::string_view contents) -> bool
{
    const int descriptor = openat(directory, name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (descriptor == -1) return false;
    const auto written = ::write(descriptor, contents.data(), contents.size());
    ::close(descriptor);
    return written == static_cast<ssize_t>(contents.size());
}

auto parser_and_mime_tests() -> bool
{
    constexpr std::string_view raw =
        "GET /assets/site.CSS?version=1 HTTP/1.1\r\n"
        "host: localhost\r\nConnection: keep-alive\r\n\r\n";
    http::detail::parsed_request request;
    const auto before = allocations;
    const auto result = http::detail::parse_request(raw, request);
    const auto mime = http::mime_type_from_path(request.target);
    const auto after = allocations;

    if (result.status != http::detail::parse_status::complete || request.target != "/assets/site.CSS?version=1" ||
        mime != "text/css; charset=utf-8" || before != after) return false;
    if (http::mime_type_from_path("/image.png") != "image/png") return false;
    if (http::mime_type_from_path("/archive.bin") != "application/octet-stream") return false;

    http::detail::parsed_request incomplete;
    if (http::detail::parse_request("GET / HTTP/1.1\r\nHost: local", incomplete).status !=
        http::detail::parse_status::incomplete) return false;
    http::detail::parsed_request missing_host;
    if (http::detail::parse_request("GET / HTTP/1.1\r\n\r\n", missing_host).status !=
        http::detail::parse_status::bad_request) return false;
    http::detail::parsed_request chunked;
    if (http::detail::parse_request(
            "POST / HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n",
            chunked).status != http::detail::parse_status::unsupported_transfer_encoding) return false;
    http::detail::parsed_request control;
    if (http::detail::parse_request(
            "GET /listing?\nInjected:yes HTTP/1.1\r\nHost: local\r\n\r\n",
            control).status != http::detail::parse_status::bad_request ||
        http::detail::parse_request(
            "GET / HTTP/1.1\r\nHost: local\nInjected:yes\r\n\r\n",
            control).status != http::detail::parse_status::bad_request) return false;
    return true;
}

auto session_input_growth_tests() -> bool
{
    if (sizeof(http::detail::session) > 512) return false;

    const std::string long_request =
        "OPTIONS / HTTP/1.1\r\nHost: localhost\r\nX-Pad: " +
        std::string(500, 'x') + "\r\n\r\n";
    http::detail::session session(-1);
    std::size_t offset = 0;
    const auto before = allocations;
    while (offset < long_request.size()) {
        auto space = session.read_space();
        if (space.empty()) return false;
        const auto size = std::min({space.size(), std::size_t {73},
                                    long_request.size() - offset});
        std::memcpy(space.data(), long_request.data() + offset, size);
        session.commit_read(size);
        offset += size;
    }
    if (!session.has_response() || allocations != before + 1) return false;
    capture response;
    collect(session, response);
    if (!contains(response, "204 No Content") || !response.open ||
        session.read_space().size() != 256) return false;

    constexpr std::string_view short_request =
        "OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const auto idle_allocations = allocations;
    session.receive(std::as_bytes(std::span {short_request}));
    collect(session, response);
    if (!response.open || allocations != idle_allocations ||
        session.read_space().size() != 256) return false;

    http::detail::session direct(-1);
    const std::string pipelined = long_request + std::string(short_request);
    direct.receive(std::as_bytes(std::span {pipelined}));
    if (!direct.has_response()) return false;
    direct.finish_response();
    if (!direct.has_response()) return false;
    direct.finish_response();
    if (direct.closed() || direct.read_space().size() != 256) return false;

    http::detail::session oversized(-1);
    std::array<char, http::detail::max_message_size> unterminated_headers {};
    unterminated_headers.fill('x');
    oversized.receive(std::as_bytes(std::span {unterminated_headers}));
    return oversized.has_response() &&
        std::string_view {oversized.response().data(), oversized.response().size()}
            .find("431 Request Header Fields Too Large") != std::string_view::npos;
}

// With the open-file cache, a small file is served from its cached
// descriptor, so it survives removal within the revalidation window, and a
// large file is sent from a private descriptor whose position starts at 0.
auto session_cache_tests() -> bool
{
    char directory_name[] = "/tmp/eventloop-http-cache-XXXXXX";
    if (mkdtemp(directory_name) == nullptr) return false;
    const int directory = open(directory_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory == -1) return false;
    const std::string large(70 * 1024, 'y');
    bool valid = write_file(directory, "site.css", "body{}") &&
                 write_file(directory, "large.bin", large);
    constexpr std::string_view requests =
        "GET /site.css HTTP/1.1\r\nHost: localhost\r\n\r\n"
        "GET /large.bin HTTP/1.1\r\nHost: localhost\r\n\r\n";
    {
        http::detail::open_file_cache cache(8);
        http::detail::session session(directory, false, nullptr, true, &cache);
        for (int round = 0; valid && round < 2; ++round) {
            if (round == 1) valid = unlinkat(directory, "site.css", 0) == 0;
            auto stream = std::make_unique<capture>();
            session.receive(std::as_bytes(std::span {requests}));
            collect(session, *stream);
            valid = valid && stream->open && contains(*stream, "body{}") &&
                    contains(*stream, "Content-Length: 71680") && contains(*stream, large);
        }
    }
    (void)unlinkat(directory, "site.css", 0);
    (void)unlinkat(directory, "large.bin", 0);
    ::close(directory);
    (void)rmdir(directory_name);
    return valid;
}

auto session_tests() -> bool
{
    char directory_name[] = "/tmp/eventloop-http-XXXXXX";
    if (mkdtemp(directory_name) == nullptr) return false;
    const int directory = open(directory_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory == -1) return false;
    std::array<char, 70 * 1024> large_contents {};
    large_contents.fill('x');
    if (!write_file(directory, "index.html", "<h1>home</h1>") ||
        !write_file(directory, "site.css", "body{}") ||
        !write_file(directory, "large.bin",
                    std::string_view {large_contents.data(), large_contents.size()}) ||
        mkdirat(directory, "listing", 0700) == -1 ||
        symlinkat("/etc", directory, "escape") == -1) {
        ::close(directory);
        return false;
    }
    const int listing = openat(directory, "listing", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (listing == -1 || !write_file(listing, "a&b.txt", "listed")) {
        if (listing != -1) ::close(listing);
        ::close(directory);
        return false;
    }
    ::close(listing);

    capture stream;
    http::detail::session session(directory);
    constexpr std::string_view requests =
        "GET /site.css HTTP/1.1\r\nHost: localhost\r\n\r\n"
        "HEAD /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const auto split = requests.size() / 2;
    const auto before = allocations;
    session.receive({});
    session.receive(std::as_bytes(std::span {requests.data(), split}));
    session.receive(std::as_bytes(std::span {
        requests.data() + split, requests.size() - split}));
    collect(session, stream);
    collect(session, stream);
    const auto after = allocations;

    // Response storage is allocated only while each response is in flight;
    // the session no longer keeps a small-response buffer while idle.
    const bool valid = after - before == 2 &&
        contains(stream, "Content-Type: text/css; charset=utf-8") &&
        contains(stream, "body{}") &&
        contains(stream, "Content-Type: text/html; charset=utf-8") &&
        !stream.open;

    capture forbidden_stream;
    http::detail::session forbidden_session(directory);
    constexpr std::string_view forbidden_request =
        "GET /listing/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    forbidden_session.receive(std::as_bytes(std::span {forbidden_request}));
    collect(forbidden_session, forbidden_stream);

    capture redirect_stream;
    http::detail::session redirect_session(directory, true);
    constexpr std::string_view redirect_request =
        "GET /listing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    redirect_session.receive(std::as_bytes(std::span {redirect_request}));
    collect(redirect_session, redirect_stream);

    capture injected_redirect_stream;
    http::detail::session injected_redirect(directory, true);
    constexpr std::string_view injected_redirect_request =
        "GET /listing?\nInjected:yes HTTP/1.1\r\nHost: localhost\r\n\r\n";
    injected_redirect.receive(std::as_bytes(std::span {injected_redirect_request}));
    collect(injected_redirect, injected_redirect_stream);

    capture listing_stream;
    http::detail::session listing_session(directory, true);
    constexpr std::string_view listing_request =
        "GET /listing/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    listing_session.receive(std::as_bytes(std::span {listing_request}));
    for (int index = 0; index < 8 && listing_stream.open; ++index) {
        collect(listing_session, listing_stream);
    }

    capture escape_stream;
    http::detail::session escape_session(directory);
    constexpr std::string_view escape_request =
        "GET /escape/passwd HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    escape_session.receive(std::as_bytes(std::span {escape_request}));
    collect(escape_session, escape_stream);

    const bool directories_valid =
        contains(forbidden_stream, "403 Forbidden") &&
        contains(redirect_stream, "308 Permanent Redirect") &&
        contains(redirect_stream, "Location: /listing/") &&
        contains(injected_redirect_stream, "400 Bad Request") &&
        !contains(injected_redirect_stream, "Injected:yes") &&
        contains(listing_stream, "Content-Length:") &&
        contains(listing_stream, "href=\"a%26b.txt\"") &&
        contains(listing_stream, "a&amp;b.txt") && !listing_stream.open;
    const bool root_confined = contains(escape_stream, "404 Not Found");

    capture large_stream;
    http::detail::session large_session(directory);
    constexpr std::string_view large_request =
        "GET /large.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    large_session.receive(std::as_bytes(std::span {large_request}));
    for (int index = 0; index < 8 && large_stream.open; ++index) {
        collect(large_session, large_stream);
    }
    const bool large_file_valid =
        contains(large_stream, "Content-Length: 71680") &&
        large_stream.size > large_contents.size() && !large_stream.open;

    capture draining_stream;
    http::detail::session draining_session(directory);
    constexpr std::string_view draining_request =
        "GET /site.css HTTP/1.1\r\nHost: localhost\r\n\r\n";
    draining_session.receive(std::as_bytes(std::span {draining_request}));
    draining_session.shutdown();
    const bool response_was_allowed_to_drain = draining_stream.open;
    collect(draining_session, draining_stream);

    capture idle_stream;
    http::detail::session idle_session(directory);
    idle_session.shutdown();
    idle_stream.open = !idle_session.closed();
    const bool graceful_shutdown_valid = response_was_allowed_to_drain &&
                                         !draining_stream.open &&
                                         !idle_stream.open;

    unlinkat(directory, "escape", 0);
    unlinkat(directory, "listing/a&b.txt", 0);
    unlinkat(directory, "listing", AT_REMOVEDIR);
    unlinkat(directory, "index.html", 0);
    unlinkat(directory, "site.css", 0);
    unlinkat(directory, "large.bin", 0);
    ::close(directory);
    unlinkat(AT_FDCWD, directory_name, AT_REMOVEDIR);
    return valid && directories_valid && root_confined && large_file_valid &&
           graceful_shutdown_valid;
}

template<typename Listener>
auto request_after_listener_removal(event_loop& loop,
                                    std::unique_ptr<Listener> listener,
                                    std::string_view request,
                                    std::string_view expected) -> bool
{
    auto* owner = listener.get();
    const int listener_descriptor = owner->descriptor();
    sockaddr_in endpoint {};
    socklen_t endpoint_size = sizeof(endpoint);
    if (getsockname(listener_descriptor, reinterpret_cast<sockaddr*>(&endpoint),
                    &endpoint_size) == -1) return false;
    loop.add(std::move(listener));

    unique_fd client(test_socket::socket(AF_INET, SOCK_STREAM));
    if (!client || connect(client.get(), reinterpret_cast<sockaddr*>(&endpoint),
                           endpoint_size) == -1) return false;

    if (loop.spawn(owner->run()) != task_spawn_result::accepted) return false;
    bool sent = false;
    if (!loop.post(execution_task([&]() noexcept {
            owner->close();
            sent = send(client.get(), request.data(), request.size(), test_socket::no_signal) ==
                   static_cast<ssize_t>(request.size());
        }))) return false;
    task_handle<void> stop_task;
    if (loop.spawn(stop_after(loop, std::chrono::milliseconds(100)), stop_task) !=
        task_spawn_result::accepted) return false;
    (void)loop.run();
    if (!stop_task.done()) {
        (void)stop_task.cancel();
        loop.stop();
        (void)loop.run();
    }

    std::array<char, 2048> response {};
    const auto received = recv(client.get(), response.data(), response.size(),
                               MSG_DONTWAIT);
    const bool valid = sent && received > 0 &&
        std::string_view {response.data(), static_cast<std::size_t>(received)}
            .find(expected) != std::string_view::npos;
    return valid;
}

auto listener_removal_test() -> bool
{
    char directory_name[] = "/tmp/eventloop-http-root-XXXXXX";
    if (mkdtemp(directory_name) == nullptr) return false;
    unique_fd directory(open(directory_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (!directory || !write_file(directory.get(), "index.html", "root survives")) {
        return false;
    }

    event_loop loop;
    const bool valid = request_after_listener_removal(
        loop, std::make_unique<http::server>(loop, ip_endpoint::loopback_v4(0),
            http::server_options {.document_root = directory_name}),
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "root survives");
    unlinkat(directory.get(), "index.html", 0);
    directory.reset();
    unlinkat(AT_FDCWD, directory_name, AT_REMOVEDIR);
    return valid;
}

auto redirect_listener_removal_test() -> bool
{
    event_loop loop;
    return request_after_listener_removal(
        loop, std::make_unique<http::redirect_server>(loop, ip_endpoint::loopback_v4(0),
                                                     "localhost", 443),
        "GET /next HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "Location: https://localhost/next");
}

auto pipelined_sendfile_test() -> bool
{
    char directory_name[] = "/tmp/eventloop-http-pipeline-XXXXXX";
    if (mkdtemp(directory_name) == nullptr) return false;
    unique_fd directory(open(directory_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    std::array<char, 70 * 1024> contents {};
    contents.fill('x');
    if (!directory || !write_file(directory.get(), "large.bin",
                                  {contents.data(), contents.size()}) ||
        !write_file(directory.get(), "small.txt", "last response")) {
        return false;
    }

    event_loop loop;
    auto listener = std::make_unique<http::server>(loop, ip_endpoint::loopback_v4(0),
        http::server_options {.document_root = directory_name});
    auto* active = listener.get();
    sockaddr_in endpoint {};
    socklen_t endpoint_size = sizeof(endpoint);
    if (getsockname(active->descriptor(), reinterpret_cast<sockaddr*>(&endpoint),
                    &endpoint_size) == -1) return false;
    loop.add(std::move(listener));

    unique_fd client(test_socket::socket(AF_INET, SOCK_STREAM));
    if (!client || connect(client.get(), reinterpret_cast<sockaddr*>(&endpoint),
                           endpoint_size) == -1) return false;
    constexpr std::string_view requests =
        "GET /large.bin HTTP/1.1\r\nHost: localhost\r\n\r\n"
        "GET /small.txt HTTP/1.1\r\nHost: localhost\r\n"
        "Connection: close\r\n\r\n";
    if (send(client.get(), requests.data(), requests.size(), test_socket::no_signal) !=
        static_cast<ssize_t>(requests.size())) return false;
    if (loop.spawn(active->run()) != task_spawn_result::accepted) return false;
    std::array<char, 80 * 1024> response {};
    std::size_t size = 0;
    std::thread reader([&]() {
        while (size < response.size()) {
            const auto received = recv(client.get(), response.data() + size,
                                       response.size() - size, 0);
            if (received <= 0) break;
            size += static_cast<std::size_t>(received);
        }
        loop.stop();
    });
    task_handle<void> stop_task;
    if (loop.spawn(stop_after(loop, std::chrono::seconds(2)), stop_task) !=
        task_spawn_result::accepted) {
        (void)::shutdown(client.get(), SHUT_RD);
        reader.join();
        active->close();
        return false;
    }
    (void)loop.run();
    if (!stop_task.done()) {
        (void)stop_task.cancel();
        loop.stop();
        (void)loop.run();
    }
    (void)::shutdown(client.get(), SHUT_RD);
    reader.join();
    active->close();
    loop.shutdown(event_loop::clock::duration::zero());
    loop.run();
    const std::string_view result {response.data(), size};
    const auto header_end = result.find("\r\n\r\n");
    const bool body_valid = header_end != std::string_view::npos &&
        header_end + 4 + contents.size() <= result.size() &&
        std::all_of(result.begin() + static_cast<std::ptrdiff_t>(header_end + 4),
                    result.begin() + static_cast<std::ptrdiff_t>(
                        header_end + 4 + contents.size()),
                    [](char value) { return value == 'x'; });
    const bool valid = result.find("Content-Length: 71680") !=
            std::string_view::npos &&
        result.find("last response") != std::string_view::npos &&
        body_valid;
    unlinkat(directory.get(), "large.bin", 0);
    unlinkat(directory.get(), "small.txt", 0);
    directory.reset();
    unlinkat(AT_FDCWD, directory_name, AT_REMOVEDIR);
    return valid;
}

auto concurrent_connection_capacity_test() -> bool
{
#ifdef __APPLE__
    // Each connection needs a client and a server descriptor. macOS commonly
    // starts with a soft limit of 256, too small for this 128-connection test.
    struct descriptor_limit_scope {
        rlimit original {};
        bool changed {false};
        ~descriptor_limit_scope()
        {
            if (changed) (void)setrlimit(RLIMIT_NOFILE, &original);
        }
    } descriptor_limit;
    if (getrlimit(RLIMIT_NOFILE, &descriptor_limit.original) == -1) return false;
    if (descriptor_limit.original.rlim_cur < 512) {
        auto limit = descriptor_limit.original;
        limit.rlim_cur = 512;
        if (setrlimit(RLIMIT_NOFILE, &limit) == -1) return false;
        descriptor_limit.changed = true;
    }
#endif
    char directory_name[] = "/tmp/eventloop-http-capacity-XXXXXX";
    if (mkdtemp(directory_name) == nullptr) return false;
    unique_fd directory(open(directory_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (!directory || !write_file(directory.get(), "index.html", "capacity")) {
        return false;
    }

    event_loop loop;
    auto listener = std::make_unique<http::server>(loop, ip_endpoint::loopback_v4(0),
        http::server_options {.document_root = directory_name});
    auto* active = listener.get();
    sockaddr_in endpoint {};
    socklen_t endpoint_size = sizeof(endpoint);
    if (getsockname(active->descriptor(), reinterpret_cast<sockaddr*>(&endpoint),
                    &endpoint_size) == -1) return false;
    loop.add(std::move(listener));
    if (loop.spawn(active->run()) != task_spawn_result::accepted) return false;

    constexpr std::size_t connection_count = 128;
    constexpr std::string_view request =
        "HEAD /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n";
    std::vector<unique_fd> clients;
    clients.reserve(connection_count);
    bool connected = true;
    for (std::size_t index = 0; index < connection_count; ++index) {
        unique_fd client(test_socket::socket(AF_INET, SOCK_STREAM));
        if (!client ||
            connect(client.get(), reinterpret_cast<sockaddr*>(&endpoint),
                    endpoint_size) == -1 ||
            send(client.get(), request.data(), request.size(), test_socket::no_signal) !=
                static_cast<ssize_t>(request.size())) {
            connected = false;
            break;
        }
        clients.push_back(std::move(client));
    }

    task_handle<void> stop_task;
    const bool timer_started =
        loop.spawn(stop_after(loop, std::chrono::milliseconds(500)), stop_task) ==
        task_spawn_result::accepted;
    if (timer_started) (void)loop.run();

    const auto statistics = loop.coroutine_statistics();
    bool responses_valid = connected && clients.size() == connection_count;
    for (const auto& client : clients) {
        std::array<char, 512> response {};
        const auto received = recv(client.get(), response.data(), response.size(),
                                   MSG_DONTWAIT);
        responses_valid = responses_valid && received > 0 &&
            std::string_view {response.data(),
                              static_cast<std::size_t>(received)}
                .find("HTTP/1.1 200 OK") != std::string_view::npos;
    }
    const bool valid = timer_started && responses_valid &&
        statistics.active_roots == connection_count + 1 &&
        statistics.allocation_failures == 0;

    clients.clear();
    active->close();
    loop.shutdown(event_loop::clock::duration::zero());
    (void)loop.run();
    unlinkat(directory.get(), "index.html", 0);
    directory.reset();
    unlinkat(AT_FDCWD, directory_name, AT_REMOVEDIR);
    return valid && loop.coroutine_statistics().live == 0;
}

auto invalid_configuration_test() -> bool
{
    event_loop loop;
    constexpr char root[] {'.', '\0', 'x'};
    constexpr char address[] {'1', '2', '7', '.', '0', '.', '0', '.', '1',
                              '\0', 'x'};
    bool root_rejected = false;
    bool address_rejected = false;
    bool empty_rejected = false;
    try {
        http::server server(loop, ip_endpoint::loopback_v4(0), http::server_options {
            .document_root = std::string(std::string_view {root, sizeof(root)})});
    } catch (const std::invalid_argument&) {
        root_rejected = true;
    }
    try {
        http::server server(loop,
            ip_endpoint::parse(std::string_view {address, sizeof(address)}, 0),
            http::server_options {.document_root = "."});
    } catch (const std::invalid_argument&) {
        address_rejected = true;
    }
    try {
        http::server server(loop, ip_endpoint::loopback_v4(0), http::server_options {});
    } catch (const std::invalid_argument&) {
        empty_rejected = true;
    }
    return root_rejected && address_rejected && empty_rejected;
}

} // namespace

auto chunked_head_tests() -> bool
{
    using http::detail::parse_status;
    http::detail::parsed_request head;
    const auto chunked = http::detail::parse_request_head(
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", head);
    http::detail::parsed_request both;
    const auto smuggled = http::detail::parse_request_head(
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n"
        "Content-Length: 3\r\n\r\n", both);
    http::detail::parsed_request gzip;
    const auto other = http::detail::parse_request_head(
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", gzip);
    http::detail::parsed_request full;
    const auto whole = http::detail::parse_request(
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", full);
    return chunked.status == parse_status::complete && head.chunked &&
           smuggled.status == parse_status::bad_request &&
           other.status == parse_status::unsupported_transfer_encoding &&
           whole.status == parse_status::unsupported_transfer_encoding;
}

struct chunked_result {
    std::string body;
    std::string rest;
    http::detail::chunked_decoder::status status {};
    auto operator==(const chunked_result&) const -> bool = default;
};

// Feeds input in pieces of step bytes, taking at most max_data per call.
auto decode_chunked(std::string_view input, std::size_t step, std::size_t max_data)
    -> chunked_result
{
    using status = http::detail::chunked_decoder::status;
    http::detail::chunked_decoder decoder;
    chunked_result result;
    auto bytes = std::as_bytes(std::span(input));
    while (!bytes.empty()) {
        auto piece = bytes.first(std::min(step, bytes.size()));
        const auto before = piece.size();
        for (;;) {
            std::span<const std::byte> data;
            result.status = decoder.feed(piece, max_data, data);
            result.body.append(reinterpret_cast<const char*>(data.data()), data.size());
            if (result.status != status::data) break;
        }
        bytes = bytes.subspan(before - piece.size());
        if (result.status == status::done || result.status == status::error) break;
    }
    result.rest.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return result;
}

auto chunked_decoder_tests() -> bool
{
    using status = http::detail::chunked_decoder::status;
    const auto both = [](std::string_view input, std::size_t max_data = 7) {
        const auto whole = decode_chunked(input, input.size() == 0 ? 1 : input.size(), max_data);
        const auto bytewise = decode_chunked(input, 1, max_data);
        return whole == bytewise ? std::optional(whole) : std::nullopt;
    };
    const auto decodes = [&](std::string_view input, std::string_view body,
                             std::string_view rest = {}) {
        const auto result = both(input);
        return result && result->status == status::done && result->body == body &&
               result->rest == rest;
    };
    const auto rejects = [&](std::string_view input) {
        const auto result = both(input);
        return result && result->status == status::error;
    };
    const std::string long_extension = "1;" + std::string(1100, 'x') + "\r\na\r\n0\r\n\r\n";
    return decodes("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", "hello world") &&
        decodes("A\r\n0123456789\r\n0\r\n\r\n", "0123456789") &&
        decodes("3;name=value\r\nabc\r\n0;last\r\n\r\n", "abc") &&
        decodes("3\r\nabc\r\n0\r\nX-Sum: 1\r\nX-Other: two\r\n\r\n", "abc") &&
        decodes("0\r\n\r\nGET / HTTP/1.1\r\n", "", "GET / HTTP/1.1\r\n") &&
        rejects("z\r\n") && rejects(";\r\n") && rejects("5\nhello") &&
        rejects("3\r\nabcd\r\n") && rejects("1000000000000000\r\n") &&
        rejects("0\r\n:bad\r\n\r\n") && rejects("0\r\n folded\r\n\r\n") &&
        rejects("0\r\nno-colon\r\n\r\n") && rejects(long_extension) &&
        rejects("0\r\n\r\r") && chunked_head_tests();
}

auto main() -> int
{
    const bool parser = parser_and_mime_tests();
    const bool session = session_tests();
    const bool input_growth = session_input_growth_tests();
    const bool cache = session_cache_tests();
    const bool listener = listener_removal_test();
    const bool redirect = redirect_listener_removal_test();
    const bool pipeline = pipelined_sendfile_test();
    const bool capacity = concurrent_connection_capacity_test();
    const bool configuration = invalid_configuration_test();
    const bool chunked = chunked_decoder_tests();
    if (!parser || !session || !input_growth || !cache || !listener || !redirect ||
        !pipeline || !capacity || !configuration || !chunked) {
        std::cerr << "HTTP tests failed: parser=" << parser
                  << " session=" << session << " listener=" << listener
                  << " input_growth=" << input_growth
                  << " cache=" << cache
                  << " redirect=" << redirect << " pipeline=" << pipeline
                  << " capacity=" << capacity
                  << " configuration=" << configuration << " chunked=" << chunked << '\n';
        return 1;
    }
    return 0;
}
