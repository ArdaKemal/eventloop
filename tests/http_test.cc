#include "eventloop/http/mime_types.h"
#include "eventloop/http/request.h"
#include "eventloop/http/server.h"
#include "eventloop/http/session.h"
#include "eventloop/unique_fd.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <new>
#include <span>
#include <string_view>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

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

class fixed_stream final : public byte_stream {
public:
    auto write(std::span<const std::byte> data) -> void override
    {
        if (data.size() > output.size() - size) throw std::bad_alloc {};
        std::memcpy(output.data() + size, data.data(), data.size());
        size += data.size();
    }

    auto close() -> void override { open = false; }
    [[nodiscard]] auto ready() const noexcept -> bool override { return open; }
    [[nodiscard]] auto write_pending() const noexcept -> bool override { return false; }

    std::array<char, 128 * 1024> output {};
    std::size_t size {0};
    bool open {true};

private:
    auto on_data(std::span<const std::byte>) -> void override {}
};

[[nodiscard]] auto contains(const fixed_stream& stream, std::string_view value) -> bool
{
    return std::string_view {stream.output.data(), stream.size}.find(value) !=
           std::string_view::npos;
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
    http::request request;
    const auto before = allocations;
    const auto result = http::parse_request(raw, request);
    const auto mime = http::mime_type_from_path(request.target);
    const auto after = allocations;

    if (result.status != http::parse_status::complete || request.target != "/assets/site.CSS?version=1" ||
        mime != "text/css; charset=utf-8" || before != after) return false;
    if (http::mime_type_from_path("/image.png") != "image/png") return false;
    if (http::mime_type_from_path("/archive.bin") != "application/octet-stream") return false;

    http::request incomplete;
    if (http::parse_request("GET / HTTP/1.1\r\nHost: local", incomplete).status !=
        http::parse_status::incomplete) return false;
    http::request missing_host;
    if (http::parse_request("GET / HTTP/1.1\r\n\r\n", missing_host).status !=
        http::parse_status::bad_request) return false;
    http::request chunked;
    if (http::parse_request(
            "POST / HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n",
            chunked).status != http::parse_status::unsupported_transfer_encoding) return false;
    return true;
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

    fixed_stream stream;
    http::session session(stream, directory);
    constexpr std::string_view requests =
        "GET /site.css HTTP/1.1\r\nHost: localhost\r\n\r\n"
        "HEAD /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const auto split = requests.size() / 2;
    const auto before = allocations;
    session.receive(std::as_bytes(std::span {requests.data(), split}));
    session.receive(std::as_bytes(std::span {
        requests.data() + split, requests.size() - split}));
    session.write_drained();
    session.write_drained();
    const auto after = allocations;

    const bool valid = before == after &&
        contains(stream, "Content-Type: text/css; charset=utf-8") &&
        contains(stream, "body{}") &&
        contains(stream, "Content-Type: text/html; charset=utf-8") &&
        !stream.open;

    fixed_stream forbidden_stream;
    http::session forbidden_session(forbidden_stream, directory);
    constexpr std::string_view forbidden_request =
        "GET /listing/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    forbidden_session.receive(std::as_bytes(std::span {forbidden_request}));
    forbidden_session.write_drained();

    fixed_stream redirect_stream;
    http::session redirect_session(redirect_stream, directory, true);
    constexpr std::string_view redirect_request =
        "GET /listing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    redirect_session.receive(std::as_bytes(std::span {redirect_request}));
    redirect_session.write_drained();

    fixed_stream listing_stream;
    http::session listing_session(listing_stream, directory, true);
    constexpr std::string_view listing_request =
        "GET /listing/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    listing_session.receive(std::as_bytes(std::span {listing_request}));
    for (int index = 0; index < 8 && listing_stream.open; ++index) {
        listing_session.write_drained();
    }

    fixed_stream escape_stream;
    http::session escape_session(escape_stream, directory);
    constexpr std::string_view escape_request =
        "GET /escape/passwd HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    escape_session.receive(std::as_bytes(std::span {escape_request}));
    escape_session.write_drained();

    const bool directories_valid =
        contains(forbidden_stream, "403 Forbidden") &&
        contains(redirect_stream, "308 Permanent Redirect") &&
        contains(redirect_stream, "Location: /listing/") &&
        contains(listing_stream, "Content-Length:") &&
        contains(listing_stream, "href=\"a%26b.txt\"") &&
        contains(listing_stream, "a&amp;b.txt") && !listing_stream.open;
    const bool root_confined = contains(escape_stream, "404 Not Found");

    fixed_stream large_stream;
    http::session large_session(large_stream, directory);
    constexpr std::string_view large_request =
        "GET /large.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    large_session.receive(std::as_bytes(std::span {large_request}));
    for (int index = 0; index < 8 && large_stream.open; ++index) {
        large_session.write_drained();
    }
    const bool large_file_valid =
        contains(large_stream, "Content-Length: 71680") &&
        large_stream.size > large_contents.size() && !large_stream.open;

    fixed_stream draining_stream;
    http::session draining_session(draining_stream, directory);
    constexpr std::string_view draining_request =
        "GET /site.css HTTP/1.1\r\nHost: localhost\r\n\r\n";
    draining_session.receive(std::as_bytes(std::span {draining_request}));
    draining_session.shutdown();
    const bool response_was_allowed_to_drain = draining_stream.open;
    draining_session.write_drained();

    fixed_stream idle_stream;
    http::session idle_session(idle_stream, directory);
    idle_session.shutdown();
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

auto request_after_listener_removal(event_loop& loop,
                                    std::unique_ptr<notifiable> listener,
                                    std::string_view request,
                                    std::string_view expected) -> bool
{
    const int listener_descriptor = listener->descriptor();
    sockaddr_in endpoint {};
    socklen_t endpoint_size = sizeof(endpoint);
    if (getsockname(listener_descriptor, reinterpret_cast<sockaddr*>(&endpoint),
                    &endpoint_size) == -1) return false;
    loop.add(std::move(listener));

    unique_fd client(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (!client || connect(client.get(), reinterpret_cast<sockaddr*>(&endpoint),
                           endpoint_size) == -1) return false;

    bool sent = false;
    if (!loop.post(execution_task([&]() noexcept {
            loop.remove(listener_descriptor);
            sent = send(client.get(), request.data(), request.size(), MSG_NOSIGNAL) ==
                   static_cast<ssize_t>(request.size());
        }))) return false;
    (void)loop.schedule_after(std::chrono::milliseconds(100),
                              execution_task([&loop]() noexcept { loop.stop(); }));
    loop.run();

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
        loop, std::make_unique<http::server>(loop, 0, directory_name),
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
        loop, std::make_unique<http::redirect_server>(loop, 0, "localhost", 443),
        "GET /next HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "Location: https://localhost/next");
}

} // namespace

auto main() -> int
{
    if (!parser_and_mime_tests() || !session_tests() ||
        !listener_removal_test() || !redirect_listener_removal_test()) {
        std::cerr << "HTTP tests failed\n";
        return 1;
    }
    return 0;
}
