#include "eventloop/event_loop.h"
#include "eventloop/http2/client.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "tls_test_certificate.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

using namespace eventloop;
using namespace std::chrono_literals;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP/2 client validation: " << message << '\n';
    std::exit(1);
}

template<class T>
[[nodiscard]] auto flatten(T result)
{
    using inner = typename T::value_type;
    if (!result) return inner(std::unexpected(std::make_error_code(std::errc::operation_canceled)));
    return std::move(*result);
}

auto append_frame(std::string& out, unsigned type, unsigned flags, unsigned stream,
                  std::string_view payload) -> void
{
    out += static_cast<char>((payload.size() >> 16) & 255);
    out += static_cast<char>((payload.size() >> 8) & 255);
    out += static_cast<char>(payload.size() & 255);
    out += static_cast<char>(type);
    out += static_cast<char>(flags);
    out += std::string_view("\0\0\0", 3);
    out += static_cast<char>(stream);
    out += payload;
}

// HPACK literal field without indexing and with a literal name (RFC 7541 6.2.2).
[[nodiscard]] auto literal(std::string_view name, std::string_view value) -> std::string
{
    std::string out(1, '\0');
    out += static_cast<char>(name.size());
    out += name;
    out += static_cast<char>(value.size());
    out += value;
    return out;
}

constexpr unsigned end_stream = 1;
constexpr unsigned end_headers = 4;

// SETTINGS, then the response HEADERS on stream 1.
[[nodiscard]] auto response(std::string_view status,
                            std::vector<std::pair<std::string_view, std::string_view>> fields,
                            bool fin) -> std::string
{
    std::string block = literal(":status", status);
    for (const auto& [name, value] : fields) block += literal(name, value);
    std::string out;
    append_frame(out, 4, 0, 0, {});
    append_frame(out, 1, end_headers | (fin ? end_stream : 0), 1, block);
    return out;
}

// Bytes the scripted server read after its script, and whether it is done.
std::string server_received;
bool server_finished = false;

auto scripted_server(event_loop& loop, tcp_acceptor& listener,
                     std::shared_ptr<tls_context> context, std::string script) -> task<void>
{
    auto accepted = co_await listener.async_accept();
    if (!accepted) co_return;
    auto owned = std::make_unique<tls_stream>(loop, std::move(*accepted), std::move(context),
        tls_server_options {.application_protocols = {"h2"}});
    auto* peer = owned.get();
    loop.add(std::move(owned));
    if (flatten(co_await peer->async_handshake())) {
        auto pending = std::as_bytes(std::span(script));
        while (!pending.empty()) {
            const auto written = flatten(co_await peer->async_write_some(pending));
            if (!written || *written == 0) break;
            pending = pending.subspan(*written);
        }
        // Drain the request until the client closes the connection.
        std::array<std::byte, 1024> buffer {};
        for (;;) {
            const auto received = flatten(co_await peer->async_read_some(buffer));
            if (!received || *received == 0) break;
            server_received.append(reinterpret_cast<const char*>(buffer.data()), *received);
        }
    }
    peer->close();
    server_finished = true;
}

using outcome = std::expected<http2::client_response, std::error_code>;

auto client(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
            bool wait_for_server, http2::client_request request, std::optional<outcome>& result,
            http2::response_sink sink, http2::response_header_sink header_sink) -> task<void>
{
    result = flatten(co_await http2::async_request(loop, ip_endpoint::loopback_v4(port),
        std::move(context), "localhost", std::move(request), std::move(sink),
        std::move(header_sink)));
    // Let a scripted server read what the client sent before closing.
    for (int turn = 0; turn < 100 && wait_for_server && !server_finished; ++turn)
        (void)co_await sleep_for(loop, 1ms);
    loop.stop();
}

auto watchdog(event_loop& loop, bool& timed_out) -> task<void>
{
    if (co_await sleep_for(loop, 3s) == timer_wait_result::expired) {
        timed_out = true;
        loop.shutdown(0ms);
    }
}

struct certificate_files {
    std::filesystem::path certificate;
    std::filesystem::path key;
};

// Runs one request against a peer that replies with script. Without a script,
// no peer is accepted, for requests rejected before connecting.
[[nodiscard]] auto exchange(const certificate_files& files, http2::client_request request,
                            std::optional<std::string> script,
                            http2::response_sink sink = {},
                            http2::response_header_sink header_sink = {}) -> outcome
{
    event_loop loop;
    auto listener = std::make_unique<tcp_acceptor>(loop, ip_endpoint::loopback_v4(0));
    sockaddr_in address {};
    socklen_t length = sizeof(address);
    check(::getsockname(listener->descriptor(), reinterpret_cast<sockaddr*>(&address),
                        &length) == 0, "getsockname");
    auto* acceptor = listener.get();
    loop.add(std::move(listener));
    if (script)
        check(loop.spawn(scripted_server(loop, *acceptor,
                  tls_context::make_server(files.certificate, files.key), std::move(*script))) ==
              task_spawn_result::accepted, "spawn server");
    std::optional<outcome> result;
    server_received.clear();
    server_finished = false;
    check(loop.spawn(client(loop, ntohs(address.sin_port),
              tls_context::make_client(files.certificate), script.has_value(),
              std::move(request), result,
              std::move(sink), std::move(header_sink))) ==
          task_spawn_result::accepted, "spawn client");
    bool timed_out = false;
    task_handle<void> timer;
    check(loop.spawn(watchdog(loop, timed_out), timer) == task_spawn_result::accepted,
          "spawn watchdog");
    (void)loop.run();
    if (!timer.done()) (void)timer.cancel();
    loop.shutdown(0ms);
    (void)loop.run();
    check(!timed_out && result.has_value(), "request did not complete");
    return std::move(*result);
}

[[nodiscard]] auto fails_with(const outcome& result, std::errc code) -> bool
{
    return !result && result.error() == std::make_error_code(code);
}

[[nodiscard]] auto get(std::string method = "GET") -> http2::client_request
{
    http2::client_request request;
    request.method = std::move(method);
    return request;
}

[[nodiscard]] auto bytes(std::string_view text) -> std::vector<std::byte>
{
    const auto view = std::as_bytes(std::span(text));
    return {view.begin(), view.end()};
}

auto responses(const certificate_files& files) -> void
{
    std::string ok = response("200", {{"content-length", "5"}, {"content-length", "5"}}, false);
    append_frame(ok, 0, 0, 1, "ab");
    append_frame(ok, 0, end_stream, 1, "cde");
    const auto accepted = exchange(files, get(), ok);
    check(accepted && accepted->status == 200 && accepted->body == bytes("abcde"),
          "DATA matching Content-Length");

    // Each sink exclusively owns its state across suspension and task moves.
    std::string streamed;
    unsigned streamed_status = 0;
    const auto streamed_response = exchange(files, get(), ok,
        [state = std::make_unique<std::string>(), &streamed](
            std::span<const std::byte> chunk) -> std::error_code {
            state->append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            streamed = *state;
            return {};
        },
        [state = std::make_unique<unsigned>(), &streamed_status](
            unsigned status, std::span<const http2::header>) -> std::error_code {
            *state = status;
            streamed_status = *state;
            return {};
        });
    check(streamed_response && streamed_response->body.empty() &&
          streamed == "abcde" && streamed_status == 200,
          "move-only response sinks");

    for (auto field : {std::pair {"connection", "close"}, {"keep-alive", "1"},
                       {"proxy-connection", "close"}, {"transfer-encoding", "chunked"},
                       {"upgrade", "h2c"}, {"te", "gzip"}, {"te", "trailers"}})
        check(fails_with(exchange(files, get(), response("200", {field}, true)),
                         std::errc::protocol_error), "connection-specific response field");

    std::string short_body = response("200", {{"content-length", "5"}}, false);
    append_frame(short_body, 0, end_stream, 1, "abc");
    check(fails_with(exchange(files, get(), short_body), std::errc::protocol_error),
          "DATA shorter than Content-Length");
    check(fails_with(exchange(files, get(), response("200", {{"content-length", "5"}}, true)),
                     std::errc::protocol_error), "Content-Length without DATA");

    std::string long_body = response("200", {{"content-length", "2"}}, false);
    append_frame(long_body, 0, end_stream, 1, "abc");
    check(fails_with(exchange(files, get(), long_body), std::errc::protocol_error),
          "DATA longer than Content-Length");

    check(fails_with(exchange(files, get(), response("200",
              {{"content-length", "4"}, {"content-length", "5"}}, true)),
          std::errc::protocol_error), "conflicting Content-Length");
    check(fails_with(exchange(files, get(), response("200", {{"content-length", "+4"}}, true)),
                     std::errc::protocol_error), "non-numeric Content-Length");

    for (auto status : {"204", "304"}) {
        std::string with_data = response(status, {}, false);
        append_frame(with_data, 0, end_stream, 1, "x");
        check(fails_with(exchange(files, get(), with_data), std::errc::protocol_error),
              "DATA on a bodyless status");
    }
    std::string head_data = response("200", {}, false);
    append_frame(head_data, 0, end_stream, 1, "x");
    check(fails_with(exchange(files, get("HEAD"), head_data), std::errc::protocol_error),
          "DATA in a HEAD response");

    // Content-Length describes the omitted representation for HEAD and 304.
    const auto head = exchange(files, get("HEAD"),
        response("200", {{"content-length", "10"}}, true));
    check(head && head->status == 200 && head->body.empty(), "HEAD with Content-Length");
    std::string not_modified = response("304", {{"content-length", "10"}}, false);
    append_frame(not_modified, 0, end_stream, 1, {});
    const auto cached = exchange(files, get(), not_modified);
    check(cached && cached->status == 304, "304 with Content-Length and empty DATA");
}

[[nodiscard]] auto goaway(unsigned last_stream, std::size_t size = 8, unsigned stream = 0)
    -> std::string
{
    std::string payload(size, '\0');
    if (size >= 4) payload[3] = static_cast<char>(last_stream);
    std::string out;
    append_frame(out, 7, 0, stream, payload);
    return out;
}

[[nodiscard]] auto reset(unsigned stream, std::size_t size = 4) -> std::string
{
    std::string out;
    append_frame(out, 3, 0, stream, std::string(size, '\0'));
    return out;
}

auto shutdown_frames(const certificate_files& files) -> void
{
    // A GOAWAY that covers stream 1 lets the response finish.
    std::string settings;
    append_frame(settings, 4, 0, 0, {});
    std::string finishing = settings + goaway(1);
    std::string body = response("200", {}, false);
    finishing += body.substr(9); // HEADERS without a second SETTINGS.
    append_frame(finishing, 0, end_stream, 1, "ok");
    const auto completed = exchange(files, get(), finishing);
    check(completed && completed->status == 200 && completed->body == bytes("ok"),
          "GOAWAY covering the request");
    // The client answers with its own GOAWAY: last stream 0, NO_ERROR.
    check(server_received.size() >= 17 &&
          server_received.substr(server_received.size() - 17) ==
              std::string("\0\0\x08\x07\0\0\0\0\0", 9) + std::string(8, '\0'),
          "client closes with GOAWAY");

    check(fails_with(exchange(files, get(), settings + goaway(0)), std::errc::connection_reset),
          "GOAWAY before the request");
    check(fails_with(exchange(files, get(), settings + goaway(1, 8, 1)),
                     std::errc::protocol_error), "GOAWAY on a request stream");
    check(fails_with(exchange(files, get(), settings + goaway(1, 7)), std::errc::protocol_error),
          "short GOAWAY");

    check(fails_with(exchange(files, get(), settings + reset(1)), std::errc::connection_reset),
          "RST_STREAM on the request");
    for (unsigned stream : {0u, 3u, 2u})
        check(fails_with(exchange(files, get(), settings + reset(stream)),
                         std::errc::protocol_error), "RST_STREAM on another stream");
    check(fails_with(exchange(files, get(), settings + reset(1, 5)), std::errc::protocol_error),
          "RST_STREAM with a wrong length");
}

// RFC 9113 section 4.1: undefined flags and the reserved stream-id bit are
// ignored on receipt.
auto frame_header_bits(const certificate_files& files) -> void
{
    const auto reserved = [](std::string& out, unsigned type, unsigned flags,
                             std::string_view payload) {
        append_frame(out, type, flags, type == 0 || type == 1 ? 1 : 0, payload);
        out[out.size() - payload.size() - 4] |= static_cast<char>(0x80);
    };
    std::string script;
    reserved(script, 4, 0x02, {});
    reserved(script, 8, 0x80, std::string_view("\x80\0\0\1", 4));
    reserved(script, 1, end_headers | 0x40, literal(":status", "200"));
    reserved(script, 0, end_stream | 0x10, "ok");
    const auto ignored = exchange(files, get(), script);
    check(ignored && ignored->status == 200 && ignored->body == bytes("ok"),
          "undefined flags and reserved bits are ignored");
}

// RFC 9113 section 6.5.2: a server must not enable push.
auto server_push_setting(const certificate_files& files) -> void
{
    std::string push;
    append_frame(push, 4, 0, 0, std::string_view("\0\2\0\0\0\1", 6));
    check(fails_with(exchange(files, get(), push + response("200", {}, true)),
                     std::errc::protocol_error), "server SETTINGS_ENABLE_PUSH=1");
    std::string disabled;
    append_frame(disabled, 4, 0, 0, std::string_view("\0\2\0\0\0\0", 6));
    check(exchange(files, get(), disabled + response("200", {}, true)).has_value(),
          "server SETTINGS_ENABLE_PUSH=0");
}

auto requests(const certificate_files& files) -> void
{
    auto declared = [](std::string_view value) {
        auto request = get("POST");
        request.headers.push_back({"content-length", std::string(value)});
        return request;
    };
    auto owned = declared("4");
    owned.body = bytes("abc");
    check(fails_with(exchange(files, std::move(owned), {}), std::errc::invalid_argument),
          "owned body shorter than Content-Length");
    check(fails_with(exchange(files, declared("1"), {}), std::errc::invalid_argument),
          "Content-Length without a body");
    check(fails_with(exchange(files, declared("x"), {}), std::errc::invalid_argument),
          "non-numeric request Content-Length");
    auto te = get();
    te.headers.push_back({"te", "gzip"});
    check(fails_with(exchange(files, std::move(te), {}), std::errc::invalid_argument),
          "TE other than trailers");
    auto trailers = get();
    trailers.headers.push_back({"te", "trailers"});
    check(exchange(files, std::move(trailers), response("200", {}, true)).has_value(),
          "request TE: trailers");
    auto other_host = get();
    other_host.headers.push_back({"host", "example.com"});
    check(fails_with(exchange(files, std::move(other_host), {}), std::errc::invalid_argument),
          "Host differing from :authority");
    auto same_host = get();
    same_host.headers.push_back({"host", "localhost"});
    check(exchange(files, std::move(same_host), response("200", {}, true)).has_value(),
          "Host equal to :authority");
    check(fails_with(exchange(files, get("CONNECT"), {}), std::errc::operation_not_supported),
          "CONNECT is unsupported");

    const auto sourced = [&](std::string_view value, std::size_t produce) {
        auto request = declared(value);
        request.body_source = [remaining = std::make_unique<std::size_t>(produce)](
            std::span<std::byte> chunk)
            -> std::expected<std::size_t, std::error_code> {
            const auto count = std::min(*remaining, chunk.size());
            std::fill_n(chunk.begin(), count, std::byte {'a'});
            *remaining -= count;
            return count;
        };
        return exchange(files, std::move(request), response("200", {}, true));
    };
    check(fails_with(sourced("4", 3), std::errc::invalid_argument),
          "source ends before Content-Length");
    check(fails_with(sourced("2", 3), std::errc::invalid_argument),
          "source exceeds Content-Length");
    check(sourced("3", 3).has_value(), "source matches Content-Length");
}

class temporary_directory {
public:
    temporary_directory()
    {
        std::random_device random;
        for (int attempt = 0; attempt < 32; ++attempt) {
            auto candidate = std::filesystem::temp_directory_path() /
                ("eventloop-h2-client-" + std::to_string(random()));
            if (std::filesystem::create_directory(candidate)) { path_ = candidate; return; }
        }
        check(false, "create temporary directory");
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

} // namespace

auto main() -> int
{
    temporary_directory directory;
    const certificate_files files {directory.path() / "cert.pem", directory.path() / "key.pem"};
    test::make_localhost_certificate(files.certificate, files.key);
    responses(files);
    shutdown_frames(files);
    frame_header_bits(files);
    server_push_setting(files);
    requests(files);
}
