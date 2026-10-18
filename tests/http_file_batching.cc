// Linux file responses: an HTTP/1.1 head joins its sendfile body (MSG_MORE),
// and HTTP/2 DATA over transmit kTLS is corked across frames. Checks bodies
// around the 11 KiB sendfile threshold, routed and static servers, pipelined
// and multiplexed requests, small windows, resets and connection errors, and
// that no head, tail or TCP_CORK stays held afterwards. Blocking clients run
// on the test thread; the servers run on their own loop thread.
#include "eventloop/event_loop.h"
#include "eventloop/http/request.h"
#include "eventloop/http/response.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/tls_context.h"
#include "http2/hpack.h"
#include "tls_test_certificate.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace eventloop;
using namespace std::chrono_literals;
using clock_type = std::chrono::steady_clock;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP file batching: " << message << '\n';
    std::exit(1);
}

// --- fixture files --------------------------------------------------------

struct fixture_file {
    std::string name;
    std::vector<std::byte> bytes;
};

class temporary_directory {
public:
    temporary_directory()
    {
        std::random_device random;
        path_ = std::filesystem::temp_directory_path() /
            ("eventloop-file-batching-" + std::to_string(random()));
        std::filesystem::create_directories(path_ / "www");
    }
    ~temporary_directory()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;
    [[nodiscard]] auto path() const -> const std::filesystem::path& { return path_; }

private:
    std::filesystem::path path_;
};

auto make_files(const std::filesystem::path& root) -> std::map<std::string, fixture_file>
{
    // Sizes straddle the 11 KiB sendfile threshold, a 64 KiB loopback segment
    // and several HTTP/2 write turns.
    const std::array<std::pair<const char*, std::size_t>, 9> sizes {{
        {"empty.bin", 0}, {"one.bin", 1}, {"below.bin", 11 * 1024 - 1},
        {"exact.bin", 11 * 1024}, {"above.bin", 11 * 1024 + 1},
        {"segment.bin", 64 * 1024 + 3}, {"medium.bin", 100 * 1000},
        {"large.bin", (1 << 20) + 7}, {"huge.bin", (12 << 20) + 1}}};
    std::map<std::string, fixture_file> files;
    std::uint32_t state = 0x9e3779b9;
    for (const auto& [name, size] : sizes) {
        fixture_file file {name, std::vector<std::byte>(size)};
        for (auto& byte : file.bytes) {
            state = state * 1664525 + 1013904223;
            byte = static_cast<std::byte>(state >> 24);
        }
        std::ofstream output(root / name, std::ios::binary);
        output.write(reinterpret_cast<const char*>(file.bytes.data()),
                     static_cast<std::streamsize>(file.bytes.size()));
        check(static_cast<bool>(output), "write fixture file");
        files.emplace(name, std::move(file));
    }
    return files;
}

// --- servers ----------------------------------------------------------------

auto send_named(event_loop&, http::request& request, http::response& response) -> task<void>
{
    const auto& root = *static_cast<const std::filesystem::path*>(request.route_context());
    const auto name = std::string(request.path().substr(3));
    unique_fd file(::open((root / name).c_str(), O_RDONLY | O_CLOEXEC));
    struct stat info {};
    if (!file || ::fstat(file.get(), &info) != 0) {
        (void)co_await response.async_send(404, {}, {});
        co_return;
    }
    (void)co_await response.async_send_file(200, {}, std::move(file), 0,
                                            static_cast<std::uint64_t>(info.st_size));
}

struct ports {
    std::uint16_t plain_routed {0};
    std::uint16_t plain_static {0};
    std::uint16_t tls_routed {0};
    std::uint16_t tls_static {0};
};

template<typename Listener>
auto start_listener(event_loop& loop, std::unique_ptr<Listener> listener) -> std::uint16_t
{
    sockaddr_in address {};
    socklen_t length = sizeof(address);
    check(::getsockname(listener->descriptor(), reinterpret_cast<sockaddr*>(&address),
                        &length) == 0, "getsockname");
    auto* raw = listener.get();
    loop.add(std::move(listener));
    check(loop.spawn(raw->run()) == task_spawn_result::accepted, "spawn listener");
    return ntohs(address.sin_port);
}

class server_thread {
public:
    server_thread(const std::filesystem::path& directory)
        : root_(directory / "www")
    {
        std::promise<ports> ready;
        auto started = ready.get_future();
        thread_ = std::thread([this, directory, &ready] {
            event_loop loop;
            auto routes = std::make_shared<http::router>();
            check(routes->add_prefix(http::method_type::get, "/r/", send_named, &root_)
                      .has_value(), "add route");
            const auto context = tls_context::make_server(directory / "cert.pem",
                                                          directory / "key.pem");
            const auto routed = http::server_options {.routes = routes};
            const auto files = http::server_options {.document_root = root_};
            ports bound;
            bound.plain_routed = start_listener(loop, std::make_unique<http::server>(
                loop, ip_endpoint::loopback_v4(0), routed));
            bound.plain_static = start_listener(loop, std::make_unique<http::server>(
                loop, ip_endpoint::loopback_v4(0), files));
            bound.tls_routed = start_listener(loop, std::make_unique<http::https_server>(
                loop, ip_endpoint::loopback_v4(0), context, routed));
            bound.tls_static = start_listener(loop, std::make_unique<http::https_server>(
                loop, ip_endpoint::loopback_v4(0), context, files));
            loop_ = &loop;
            ready.set_value(bound);
            (void)loop.run();
            loop.shutdown(0ms);
            (void)loop.run();
        });
        ports_ = started.get();
    }
    ~server_thread()
    {
        loop_->stop();
        thread_.join();
    }
    server_thread(const server_thread&) = delete;
    auto operator=(const server_thread&) -> server_thread& = delete;
    [[nodiscard]] auto bound() const noexcept -> const ports& { return ports_; }

private:
    std::filesystem::path root_;
    event_loop* loop_ {nullptr};
    ports ports_;
    std::thread thread_;
};

// --- socket state -------------------------------------------------------------

auto port_of(int descriptor, bool peer) -> std::uint16_t
{
    sockaddr_in address {};
    socklen_t length = sizeof(address);
    const int result = peer
        ? ::getpeername(descriptor, reinterpret_cast<sockaddr*>(&address), &length)
        : ::getsockname(descriptor, reinterpret_cast<sockaddr*>(&address), &length);
    if (result != 0 || address.sin_family != AF_INET) return 0;
    return ntohs(address.sin_port);
}

// The server's end of a client connection, found among this process's
// descriptors; -1 once the server has released it.
auto server_end(std::uint16_t server_port, int client) -> int
{
    const auto client_port = port_of(client, false);
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd", error)) {
        const int descriptor = std::atoi(entry.path().filename().c_str());
        if (descriptor == client) continue;
        if (port_of(descriptor, false) == server_port &&
            port_of(descriptor, true) == client_port) return descriptor;
    }
    return -1;
}

auto corked(int descriptor) -> int
{
    int value = -1;
    socklen_t length = sizeof(value);
    if (::getsockopt(descriptor, IPPROTO_TCP, TCP_CORK, &value, &length) != 0) return -1;
    return value;
}

// Waits up to a second for the server end's TCP_CORK to read want; a
// released server end counts as uncorked.
auto cork_becomes(std::uint16_t server_port, int client, int want) -> bool
{
    const auto deadline = clock_type::now() + 1s;
    for (;;) {
        const int server = server_end(server_port, client);
        const int value = server == -1 ? 0 : corked(server);
        if (value == want) return true;
        if (clock_type::now() > deadline) return false;
        std::this_thread::sleep_for(2ms);
    }
}

auto released(std::uint16_t server_port, int client) -> bool
{
    const auto deadline = clock_type::now() + 2s;
    while (server_end(server_port, client) != -1) {
        if (clock_type::now() > deadline) return false;
        std::this_thread::sleep_for(5ms);
    }
    return true;
}

// Transmit kTLS sockets currently open, or nullopt without kernel TLS.
auto ktls_transmitters() -> std::optional<long>
{
    std::ifstream stats("/proc/net/tls_stat");
    std::string name;
    long value = 0;
    while (stats >> name >> value)
        if (name == "TlsCurrTxSw") return value;
    return std::nullopt;
}

// --- clients ------------------------------------------------------------------

class client {
public:
    // alpn empty: plain TCP. receive_buffer > 0 shrinks SO_RCVBUF.
    client(std::uint16_t port, std::string_view alpn = {}, int receive_buffer = 0)
    {
        descriptor_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        check(descriptor_ != -1, "client socket");
        if (receive_buffer > 0)
            check(::setsockopt(descriptor_, SOL_SOCKET, SO_RCVBUF, &receive_buffer,
                               sizeof(receive_buffer)) == 0, "SO_RCVBUF");
        // Without TCP_NODELAY a small window update can wait for a delayed ACK.
        const int enabled = 1;
        check(::setsockopt(descriptor_, IPPROTO_TCP, TCP_NODELAY, &enabled,
                           sizeof(enabled)) == 0, "TCP_NODELAY");
        const timeval timeout {.tv_sec = 5, .tv_usec = 0};
        check(::setsockopt(descriptor_, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                           sizeof(timeout)) == 0, "SO_RCVTIMEO");
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        check(::connect(descriptor_, reinterpret_cast<sockaddr*>(&address),
                        sizeof(address)) == 0, "connect");
        if (alpn.empty()) return;
        context_.reset(SSL_CTX_new(TLS_client_method()));
        check(context_ != nullptr, "SSL_CTX_new");
        std::string protocols(1, static_cast<char>(alpn.size()));
        protocols += alpn;
        check(SSL_CTX_set_alpn_protos(context_.get(),
                  reinterpret_cast<const unsigned char*>(protocols.data()),
                  static_cast<unsigned>(protocols.size())) == 0, "ALPN");
        ssl_.reset(SSL_new(context_.get()));
        check(ssl_ && SSL_set_fd(ssl_.get(), descriptor_) == 1 &&
              SSL_set_tlsext_host_name(ssl_.get(), "localhost") == 1 &&
              SSL_connect(ssl_.get()) == 1, "TLS handshake");
        const unsigned char* selected = nullptr;
        unsigned selected_size = 0;
        SSL_get0_alpn_selected(ssl_.get(), &selected, &selected_size);
        check(std::string_view(reinterpret_cast<const char*>(selected), selected_size) == alpn,
              "ALPN selection");
    }
    ~client()
    {
        ssl_.reset();
        if (descriptor_ != -1) ::close(descriptor_);
    }
    client(const client&) = delete;
    auto operator=(const client&) -> client& = delete;

    [[nodiscard]] auto descriptor() const noexcept -> int { return descriptor_; }

    auto write(std::span<const std::byte> bytes) -> void
    {
        while (!bytes.empty()) {
            const auto sent = ssl_
                ? SSL_write(ssl_.get(), bytes.data(), static_cast<int>(bytes.size()))
                : static_cast<int>(::send(descriptor_, bytes.data(), bytes.size(), MSG_NOSIGNAL));
            check(sent > 0, "client write");
            bytes = bytes.subspan(static_cast<std::size_t>(sent));
        }
    }
    auto write(std::string_view text) -> void { write(std::as_bytes(std::span(text))); }

    // Reads at least one byte into the input buffer; false on EOF or error.
    auto fill() -> bool
    {
        std::array<std::byte, 64 * 1024> chunk {};
        const auto received = ssl_
            ? SSL_read(ssl_.get(), chunk.data(), static_cast<int>(chunk.size()))
            : static_cast<int>(::recv(descriptor_, chunk.data(), chunk.size(), 0));
        if (received <= 0) return false;
        input_.insert(input_.end(), chunk.begin(), chunk.begin() + received);
        return true;
    }
    auto exact(std::size_t size) -> std::vector<std::byte>
    {
        while (input_.size() < size) check(fill(), "connection ended mid-message");
        std::vector<std::byte> result(input_.begin(), input_.begin() + static_cast<long>(size));
        input_.erase(input_.begin(), input_.begin() + static_cast<long>(size));
        return result;
    }
    auto head() -> std::string
    {
        for (;;) {
            const std::string_view view(reinterpret_cast<const char*>(input_.data()), input_.size());
            if (const auto end = view.find("\r\n\r\n"); end != std::string_view::npos) {
                std::string result(view.substr(0, end + 4));
                input_.erase(input_.begin(), input_.begin() + static_cast<long>(end + 4));
                return result;
            }
            check(fill(), "connection ended mid-head");
        }
    }
    // Abortive close: the server sees a reset, not a FIN.
    auto reset() -> void
    {
        const linger hard {.l_onoff = 1, .l_linger = 0};
        (void)::setsockopt(descriptor_, SOL_SOCKET, SO_LINGER, &hard, sizeof(hard));
        ssl_.reset();
        ::close(descriptor_);
        descriptor_ = -1;
    }
    [[nodiscard]] auto buffered() const noexcept -> std::size_t { return input_.size(); }

private:
    struct context_free { auto operator()(SSL_CTX* value) const -> void { SSL_CTX_free(value); } };
    struct ssl_free { auto operator()(SSL* value) const -> void { SSL_free(value); } };
    int descriptor_ {-1};
    std::unique_ptr<SSL_CTX, context_free> context_;
    std::unique_ptr<SSL, ssl_free> ssl_;
    std::vector<std::byte> input_;
};

auto http1_request(std::string_view method, std::string_view path) -> std::string
{
    return std::string(method) + " " + std::string(path) +
        " HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: identity\r\n\r\n";
}

// Reads one HTTP/1.1 response and checks it carries file's bytes.
auto http1_expect(client& peer, const fixture_file& file, bool head, std::string_view label) -> void
{
    const auto text = peer.head();
    check(text.starts_with("HTTP/1.1 200"), std::string(label) + ": status line " + text);
    std::string lower(text);
    std::ranges::transform(lower, lower.begin(), [](unsigned char c) { return std::tolower(c); });
    const auto field = lower.find("\r\ncontent-length:");
    check(field != std::string::npos, std::string(label) + ": content-length");
    const auto length = std::strtoull(lower.c_str() + field + 17, nullptr, 10);
    check(length == file.bytes.size(), std::string(label) + ": content-length value");
    if (head) return;
    check(peer.exact(file.bytes.size()) == file.bytes, std::string(label) + ": body bytes");
}

auto path_for(bool routed, std::string_view name) -> std::string
{
    return (routed ? "/r/" : "/") + std::string(name);
}

auto http1_sequence(std::uint16_t port, bool routed, std::string_view alpn,
                    const std::map<std::string, fixture_file>& files, std::string_view label)
    -> void
{
    client peer(port, alpn);
    for (const auto& [name, file] : files) {
        peer.write(http1_request("GET", path_for(routed, name)));
        http1_expect(peer, file, false, std::string(label) + " GET " + name);
    }
    for (const auto* name : {"exact.bin", "large.bin"}) {
        peer.write(http1_request("HEAD", path_for(routed, name)));
        http1_expect(peer, files.at(name), true, std::string(label) + " HEAD " + name);
    }
    // Pipelined: each head must follow the previous body, not overtake it.
    std::string batch;
    const std::array<const char*, 4> order {"above.bin", "below.bin", "segment.bin", "exact.bin"};
    for (const auto* name : order) batch += http1_request("GET", path_for(routed, name));
    peer.write(batch);
    for (const auto* name : order)
        http1_expect(peer, files.at(name), false, std::string(label) + " pipelined " + name);
    check(peer.buffered() == 0, std::string(label) + ": bytes after the last response");
}

// --- HTTP/2 --------------------------------------------------------------------

auto frame(unsigned type, unsigned flags, std::uint32_t stream,
           std::span<const std::byte> payload = {}) -> std::vector<std::byte>
{
    std::vector<std::byte> out(9 + payload.size());
    out[0] = static_cast<std::byte>(payload.size() >> 16);
    out[1] = static_cast<std::byte>(payload.size() >> 8);
    out[2] = static_cast<std::byte>(payload.size());
    out[3] = static_cast<std::byte>(type);
    out[4] = static_cast<std::byte>(flags);
    for (int index = 0; index < 4; ++index)
        out[5 + static_cast<std::size_t>(index)] = static_cast<std::byte>(stream >> (24 - 8 * index));
    std::ranges::copy(payload, out.begin() + 9);
    return out;
}

auto be32(std::uint32_t value) -> std::array<std::byte, 4>
{
    return {static_cast<std::byte>(value >> 24), static_cast<std::byte>(value >> 16),
            static_cast<std::byte>(value >> 8), static_cast<std::byte>(value)};
}

struct h2_response {
    std::string status;
    std::vector<std::byte> body;
    bool ended {false};
};

class h2_client {
public:
    h2_client(std::uint16_t port, std::uint32_t stream_window, int receive_buffer = 0)
        : peer_(port, "h2", receive_buffer)
    {
        std::vector<std::byte> out;
        constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const auto preface_bytes = std::as_bytes(std::span(preface));
        out.insert(out.end(), preface_bytes.begin(), preface_bytes.end());
        std::array<std::byte, 6> settings {std::byte {0}, std::byte {4}};
        std::ranges::copy(be32(stream_window), settings.begin() + 2);
        append(out, frame(4, 0, 0, settings));
        append(out, frame(8, 0, 0, be32((1U << 30) - 65535)));
        peer_.write(out);
    }
    auto request(std::uint32_t stream, std::string_view path) -> void
    {
        const std::array<http2::detail::field, 4> fields {{{":method", "GET"},
            {":scheme", "https"}, {":path", std::string(path)}, {":authority", "localhost"}}};
        std::vector<std::byte> block;
        check(http2::detail::hpack_encode(fields, block) == http2::detail::hpack_error::none,
              "HPACK request");
        peer_.write(frame(1, 5, stream, block));
        responses_[stream];
    }
    auto send(std::span<const std::byte> bytes) -> void { peer_.write(bytes); }
    // Processes one frame; returns its type, or -1 at end of connection.
    auto pump() -> int
    {
        std::array<std::byte, 9> header {};
        while (peer_.buffered() < 9)
            if (!peer_.fill()) return -1;
        const auto bytes = peer_.exact(9);
        std::ranges::copy(bytes, header.begin());
        const auto size = (std::to_integer<std::size_t>(header[0]) << 16) |
            (std::to_integer<std::size_t>(header[1]) << 8) | std::to_integer<std::size_t>(header[2]);
        const auto type = std::to_integer<int>(header[3]);
        const auto flags = std::to_integer<unsigned>(header[4]);
        std::uint32_t stream = 0;
        for (int index = 5; index < 9; ++index)
            stream = (stream << 8) | std::to_integer<std::uint32_t>(header[static_cast<std::size_t>(index)]);
        stream &= 0x7fffffffU;
        check(size <= 16384, "oversized frame");
        const auto payload = peer_.exact(size);
        last_stream_ = stream;
        last_size_ = size;
        if (type == 4 && !(flags & 1)) peer_.write(frame(4, 1, 0));
        if (type == 7) goaway_ = true;
        if (type == 3) {
            check(responses_.contains(stream), "reset of unknown stream");
            reset_streams_.push_back(stream);
        }
        if (type == 1) {
            check(responses_.contains(stream) && (flags & 4), "HEADERS for unknown stream");
            std::vector<http2::detail::field> fields;
            check(decoder_.decode(payload, fields) == http2::detail::hpack_error::none,
                  "HPACK response");
            for (const auto& field : fields)
                if (field.name == ":status") responses_[stream].status = field.value;
            if (flags & 1) responses_[stream].ended = true;
        }
        if (type == 0) {
            check(responses_.contains(stream), "DATA for unknown stream");
            auto& response = responses_[stream];
            check(!response.ended, "DATA after END_STREAM");
            response.body.insert(response.body.end(), payload.begin(), payload.end());
            if (flags & 1) response.ended = true;
        }
        return type;
    }
    auto finish(std::uint32_t stream) -> h2_response&
    {
        while (!responses_[stream].ended) check(pump() != -1, "connection ended mid-response");
        return responses_[stream];
    }
    auto response(std::uint32_t stream) -> h2_response& { return responses_[stream]; }
    [[nodiscard]] auto last_stream() const noexcept -> std::uint32_t { return last_stream_; }
    [[nodiscard]] auto last_size() const noexcept -> std::size_t { return last_size_; }
    [[nodiscard]] auto goaway() const noexcept -> bool { return goaway_; }
    [[nodiscard]] auto descriptor() const noexcept -> int { return peer_.descriptor(); }
    auto transport() -> client& { return peer_; }

private:
    static auto append(std::vector<std::byte>& out, const std::vector<std::byte>& bytes) -> void
    {
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    client peer_;
    http2::detail::hpack_decoder decoder_;
    std::map<std::uint32_t, h2_response> responses_;
    std::vector<std::uint32_t> reset_streams_;
    std::uint32_t last_stream_ {0};
    std::size_t last_size_ {0};
    bool goaway_ {false};
};

auto expect_body(h2_response& response, const fixture_file& file, std::string_view label) -> void
{
    check(response.status == "200", std::string(label) + ": status " + response.status);
    check(response.body == file.bytes, std::string(label) + ": body bytes");
}

auto h2_multiplexed(std::uint16_t port, bool routed,
                    const std::map<std::string, fixture_file>& files, std::string_view label)
    -> void
{
    h2_client peer(port, 1U << 30);
    std::vector<std::pair<std::uint32_t, std::string>> streams;
    std::uint32_t id = 1;
    for (int round = 0; round < 2; ++round)
        for (const auto& [name, file] : files) {
            peer.request(id, path_for(routed, name));
            streams.emplace_back(id, name);
            id += 2;
        }
    for (const auto& [stream, name] : streams)
        expect_body(peer.finish(stream), files.at(name), std::string(label) + " " + name);
    check(cork_becomes(port, peer.descriptor(), 0), std::string(label) + ": cork left set");
}

// A slow reader fills the socket during a file send (the file exceeds the
// 4 MiB default tcp_wmem maximum): with kTLS the writer holds the cork while
// it waits, and releases it when the response ends.
auto h2_slow_reader(std::uint16_t port, bool routed, bool ktls,
                    const std::map<std::string, fixture_file>& files, std::string_view label)
    -> void
{
    h2_client peer(port, 1U << 30, 16 * 1024);
    peer.request(1, path_for(routed, "huge.bin"));
    if (ktls) check(cork_becomes(port, peer.descriptor(), 1),
                    std::string(label) + ": cork not held while the socket is full");
    expect_body(peer.finish(1), files.at("huge.bin"), std::string(label) + " huge.bin");
    check(cork_becomes(port, peer.descriptor(), 0), std::string(label) + ": cork left set");
}

// Each window update releases one frame; the writer must uncork before it
// parks for credit or the frame waits in the kernel.
auto h2_small_window(std::uint16_t port, bool routed,
                     const std::map<std::string, fixture_file>& files, std::string_view label)
    -> void
{
    constexpr std::uint32_t window = 4000;
    h2_client peer(port, window);
    peer.request(1, path_for(routed, "medium.bin"));
    auto& response = peer.response(1);
    std::size_t credit = window;
    auto slowest = clock_type::duration::zero();
    while (!response.ended) {
        const auto start = clock_type::now();
        while (credit != 0 && !response.ended) {
            const auto before = response.body.size();
            check(peer.pump() != -1, std::string(label) + ": connection ended");
            const auto received = response.body.size() - before;
            check(received <= credit, std::string(label) + ": stream window overrun");
            credit -= received;
        }
        slowest = std::max(slowest, clock_type::now() - start);
        if (response.ended) break;
        check(cork_becomes(port, peer.descriptor(), 0),
              std::string(label) + ": cork held while parked for credit");
        peer.send(frame(8, 0, 1, be32(window)));
        credit = window;
    }
    expect_body(response, files.at("medium.bin"), std::string(label) + " small window");
    std::cout << label << " small window: slowest credit round "
              << std::chrono::duration_cast<std::chrono::microseconds>(slowest).count()
              << " us\n";
}

// A reset stream stops mid-file; the connection keeps serving afterwards.
auto h2_reset_mid_transfer(std::uint16_t port, bool routed,
                           const std::map<std::string, fixture_file>& files,
                           std::string_view label) -> void
{
    h2_client peer(port, 1U << 30);
    peer.request(1, path_for(routed, "huge.bin"));
    while (peer.response(1).body.size() < 200 * 1000)
        check(peer.pump() != -1, std::string(label) + ": connection ended before reset");
    peer.send(frame(3, 0, 1, be32(8)));
    peer.request(3, path_for(routed, "above.bin"));
    expect_body(peer.finish(3), files.at("above.bin"), std::string(label) + " after reset");
    check(!peer.response(1).ended || peer.response(1).body == files.at("huge.bin").bytes,
          std::string(label) + ": reset stream bytes");
    peer.request(5, path_for(routed, "large.bin"));
    expect_body(peer.finish(5), files.at("large.bin"), std::string(label) + " after reset");
    check(cork_becomes(port, peer.descriptor(), 0), std::string(label) + ": cork left set");
}

// A connection error mid-file ends the connection promptly (GOAWAY, EOF),
// and an abortive client close releases the server's socket.
auto h2_connection_errors(std::uint16_t port, bool routed, std::string_view label) -> void
{
    {
        h2_client peer(port, 1U << 30, 16 * 1024);
        peer.request(1, path_for(routed, "huge.bin"));
        while (peer.response(1).body.size() < 100 * 1000)
            check(peer.pump() != -1, std::string(label) + ": connection ended early");
        // WINDOW_UPDATE with a zero increment on stream 0 is a connection error.
        peer.send(frame(8, 0, 0, be32(0)));
        while (peer.pump() != -1) {}
        check(peer.goaway(), std::string(label) + ": no GOAWAY after a connection error");
        check(released(port, peer.descriptor()), std::string(label) + ": socket kept after error");
    }
    {
        h2_client peer(port, 1U << 30, 16 * 1024);
        peer.request(1, path_for(routed, "huge.bin"));
        while (peer.response(1).body.size() < 100 * 1000)
            check(peer.pump() != -1, std::string(label) + ": connection ended early");
        const auto client_port = port_of(peer.descriptor(), false);
        const int server = server_end(port, peer.descriptor());
        check(server != -1, std::string(label) + ": server end not found");
        peer.transport().reset();
        const auto deadline = clock_type::now() + 2s;
        while (port_of(server, true) == client_port && clock_type::now() < deadline)
            std::this_thread::sleep_for(5ms);
        check(port_of(server, true) != client_port,
              std::string(label) + ": socket kept after client reset");
    }
}

auto plain_reset_mid_transfer(std::uint16_t port, bool routed, std::string_view label) -> void
{
    client peer(port, {}, 16 * 1024);
    peer.write(http1_request("GET", path_for(routed, "huge.bin")));
    (void)peer.head();
    (void)peer.exact(100 * 1000);
    const auto client_port = port_of(peer.descriptor(), false);
    const int server = server_end(port, peer.descriptor());
    check(server != -1, std::string(label) + ": server end not found");
    peer.reset();
    const auto deadline = clock_type::now() + 2s;
    while (port_of(server, true) == client_port && clock_type::now() < deadline)
        std::this_thread::sleep_for(5ms);
    check(port_of(server, true) != client_port, std::string(label) + ": socket kept after reset");
}

} // namespace

auto main() -> int
{
    temporary_directory directory;
    test::make_localhost_certificate(directory.path() / "cert.pem", directory.path() / "key.pem");
    const auto files = make_files(directory.path() / "www");
    server_thread server(directory.path());
    const auto& bound = server.bound();

    http1_sequence(bound.plain_routed, true, {}, files, "HTTP/1.1 routed");
    http1_sequence(bound.plain_static, false, {}, files, "HTTP/1.1 static");
    http1_sequence(bound.tls_routed, true, "http/1.1", files, "HTTPS/1.1 routed");
    http1_sequence(bound.tls_static, false, "http/1.1", files, "HTTPS/1.1 static");
    plain_reset_mid_transfer(bound.plain_routed, true, "HTTP/1.1 routed");
    plain_reset_mid_transfer(bound.plain_static, false, "HTTP/1.1 static");

    bool ktls = false;
    {
        h2_client probe(bound.tls_routed, 1U << 30);
        probe.request(1, "/r/one.bin");
        (void)probe.finish(1);
        const auto transmitters = ktls_transmitters();
        ktls = transmitters && *transmitters > 0;
    }
    std::cout << (ktls ? "transmit kTLS active: HTTP/2 file DATA uses SSL_sendfile\n"
                       : "transmit kTLS unavailable: cork checks skipped, buffered DATA path\n");
    for (const bool routed : {true, false}) {
        const auto port = routed ? bound.tls_routed : bound.tls_static;
        const std::string label = routed ? "HTTP/2 routed" : "HTTP/2 static";
        h2_multiplexed(port, routed, files, label);
        h2_slow_reader(port, routed, ktls, files, label);
        h2_small_window(port, routed, files, label);
        h2_reset_mid_transfer(port, routed, files, label);
        h2_connection_errors(port, routed, label);
    }
    std::cout << "HTTP file batching: passed\n";
    return 0;
}
