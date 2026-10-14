// Routed HTTP/3 requests: a public quic_endpoint client sends requests to a
// public http3_server with routes. Request and response framing use the
// private QPACK and frame codecs; handlers use only the public API.
#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"
#include "eventloop/quic.h"
#include "http3/frames.h"
#include "http3/qpack.h"
#include "tls_test_certificate.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

using namespace eventloop;
using namespace std::chrono_literals;
namespace h3 = eventloop::http3::detail;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP/3 routing: " << message << '\n';
    std::exit(1);
}

auto text(std::string_view value) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(value));
}

// Handlers, shared in spirit with the HTTP/1.1 routing test.
auto hello(event_loop&, http::request& request, http::response& response) -> task<void>
{
    check(request.protocol() == http::protocol::http3, "protocol is HTTP/3");
    const std::array<http::header, 1> fields {{{"content-type", "text/plain"}}};
    (void)co_await response.async_send(200, fields, text("hello"));
}

// A section the client's 300-byte SETTINGS_MAX_FIELD_SECTION_SIZE refuses.
auto big(event_loop&, http::request&, http::response& response) -> task<void>
{
    const std::string value(300, 'v');
    const std::array<http::header, 1> fields {{{"x-big", value}}};
    const auto sent = co_await response.async_send(200, fields, text("big"));
    check(sent && !*sent && sent->error() == std::make_error_code(std::errc::message_size),
          "oversized response section fails with message_size");
}

auto cookies(event_loop&, http::request& request, http::response& response) -> task<void>
{
    ++*static_cast<std::size_t*>(request.route_context());
    const auto value = request.header_value("cookie");
    std::size_t count = 0;
    for (const auto& field : request.headers())
        if (field.name == "cookie") ++count;
    check(count == (value ? 1u : 0u), "handler sees one normalized Cookie field");
    check(request.header_value("x-test") == "seen", "Cookie joining preserves other fields");
    (void)co_await response.async_send(200, {}, text(value.value_or("<none>")));
}

auto info(event_loop&, http::request& request, http::response& response) -> task<void>
{
    std::array<char, 256> body {};
    const auto custom = request.header_value("X-Test").value_or("-");
    const int size = std::snprintf(body.data(), body.size(), "%.*s|%.*s|%.*s|%.*s",
        static_cast<int>(request.path().size()), request.path().data(),
        static_cast<int>(request.query().size()), request.query().data(),
        static_cast<int>(custom.size()), custom.data(),
        static_cast<int>(request.authority().size()), request.authority().data());
    (void)co_await response.async_send(200, {},
        std::as_bytes(std::span(body.data(), static_cast<std::size_t>(size))));
}

auto upload(event_loop&, http::request& request, http::response& response) -> task<void>
{
    ++*static_cast<std::size_t*>(request.route_context());
    std::array<std::byte, 700> chunk {};
    std::uint64_t count = 0;
    std::uint64_t sum = 0;
    for (;;) {
        auto read = co_await request.async_read_body(chunk);
        if (!read) co_return;
        if (!*read) {
            // Report the read error as the body so the client can see it.
            const auto message = read->error() == std::make_error_code(std::errc::message_size)
                ? std::string_view("too large") : std::string_view("bad body");
            (void)co_await response.async_send(400, {}, text(message));
            co_return;
        }
        if (**read == 0) break;
        count += **read;
        for (std::size_t index = 0; index < **read; ++index)
            sum += std::to_integer<unsigned>(chunk[index]);
    }
    std::array<char, 64> body {};
    const int size = std::snprintf(body.data(), body.size(), "%llu %llu",
        static_cast<unsigned long long>(count), static_cast<unsigned long long>(sum));
    (void)co_await response.async_send(200, {},
        std::as_bytes(std::span(body.data(), static_cast<std::size_t>(size))));
}

auto partial(event_loop&, http::request& request, http::response& response) -> task<void>
{
    std::array<std::byte, 10> chunk {};
    (void)co_await request.async_read_body(chunk);
    (void)co_await response.async_send(200, {}, text("partial"));
}

auto stream(event_loop&, http::request&, http::response& response) -> task<void>
{
    const std::array<http::header, 1> fields {{{"content-type", "text/plain"}}};
    if (!co_await response.async_start(200, fields)) co_return;
    (void)co_await response.async_write(text("abc"));
    (void)co_await response.async_write(text("defgh"));
    const std::array<http::header, 1> trailers {{{"x-done", "yes"}}};
    (void)co_await response.async_finish(trailers);
}

auto silent(event_loop&, http::request&, http::response&) -> task<void>
{
    co_return;
}

auto short_body(event_loop&, http::request&, http::response& response) -> task<void>
{
    const std::array<http::header, 1> fields {{{"content-length", "5"}}};
    if (!co_await response.async_start(200, fields)) co_return;
    (void)co_await response.async_write(text("abc"));
    (void)co_await response.async_finish();
}

auto file(event_loop&, http::request& request, http::response& response) -> task<void>
{
    const auto* path = static_cast<const std::string*>(request.route_context());
    unique_fd descriptor(::open(path->c_str(), O_RDONLY | O_CLOEXEC));
    (void)co_await response.async_send_file(200, {}, std::move(descriptor), 2, 5);
}

// --- client side -----------------------------------------------------------

auto headers_frame(std::vector<h3::field> fields) -> std::vector<std::byte>
{
    std::vector<std::byte> block(16 * 1024);
    const auto size = h3::qpack_encode(fields, block);
    check(size.has_value(), "encode field section");
    block.resize(*size);
    std::vector<std::byte> frame(block.size() + 16);
    const auto framed = h3::encode_frame(h3::headers_frame, block, frame);
    check(framed.has_value(), "frame HEADERS");
    frame.resize(*framed);
    return frame;
}

auto data_frame(std::string_view payload) -> std::vector<std::byte>
{
    std::vector<std::byte> output(payload.size() + 16);
    const auto framed = h3::encode_frame(h3::data_frame, text(payload), output);
    check(framed.has_value(), "frame DATA");
    output.resize(*framed);
    return output;
}

struct request_spec {
    std::string method {"GET"};
    std::string path {"/"};
    std::vector<std::pair<std::string, std::string>> fields {};
    std::vector<std::string> body {};  // One DATA frame per entry.
    std::string scheme {"https"};
    bool wait_continue {false};
};

auto encode(const request_spec& spec) -> std::vector<std::byte>
{
    std::vector<h3::field> fields {{":method", spec.method}, {":scheme", spec.scheme},
                                   {":authority", "example.test"}, {":path", spec.path}};
    for (const auto& [name, value] : spec.fields) fields.push_back({name, value});
    auto bytes = headers_frame(fields);
    if (!spec.wait_continue) for (const auto& part : spec.body) {
        auto frame = data_frame(part);
        bytes.insert(bytes.end(), frame.begin(), frame.end());
    }
    return bytes;
}

struct response_view {
    unsigned status {0};
    std::vector<std::pair<std::string, std::string>> fields {};
    std::string body {};
    std::vector<std::pair<std::string, std::string>> trailers {};
    std::error_code error {};

    [[nodiscard]] auto field(std::string_view name) const -> std::string
    {
        for (const auto& [key, value] : fields) if (key == name) return value;
        return "<none>";
    }
};

auto parse_response(std::span<const std::byte> bytes, response_view& view) -> void
{
    bool seen_headers = false;
    while (!bytes.empty()) {
        const auto frame = h3::decode_frame(bytes, bytes.size());
        check(frame.has_value(), "decode response frame");
        if (frame->type == h3::headers_frame) {
            std::array<h3::field, 32> fields {};
            std::array<char, 2048> strings {};
            const auto count = h3::qpack_decode(frame->payload, fields, strings);
            check(count.has_value(), "decode response section");
            auto& target = seen_headers ? view.trailers : view.fields;
            for (std::size_t index = 0; index < *count; ++index) {
                if (fields[index].name == ":status")
                    view.status = static_cast<unsigned>(std::stoul(std::string(fields[index].value)));
                else
                    target.emplace_back(std::string(fields[index].name),
                                        std::string(fields[index].value));
            }
            seen_headers = true;
        } else if (frame->type == h3::data_frame) {
            view.body.append(reinterpret_cast<const char*>(frame->payload.data()),
                             frame->payload.size());
        }
        bytes = bytes.subspan(frame->encoded_size);
    }
}

auto send_all(event_loop&, quic_connection& connection, std::uint64_t id,
              std::span<const std::byte> bytes, bool fin) -> task<std::error_code>
{
    while (!bytes.empty()) {
        const auto sent = flatten_result(co_await connection.async_write(id, bytes, false));
        if (!sent) co_return sent.error();
        if (*sent == 0) co_return std::make_error_code(std::errc::io_error);
        bytes = bytes.subspan(*sent);
    }
    if (fin) {
        const auto finished = flatten_result(co_await connection.async_write(id, {}, true));
        if (!finished) co_return finished.error();
    }
    co_return std::error_code {};
}

auto sent(const std::expected<std::error_code, task_result>& result) -> bool
{ return result && !*result; }

auto exchange(event_loop& loop, quic_connection& connection, std::vector<std::byte> request,
              const request_spec& spec, response_view& view) -> task<void>
{
    const auto id = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    check(id.has_value(), "open request stream");
    // The server may answer and stop reading before the whole body is sent
    // (RFC 9114 4.1.1); the response still arrives.
    const auto request_sent = co_await send_all(loop, connection, *id, request, !spec.wait_continue);
    check(sent(request_sent) || (request_sent && *request_sent == quic_errc::stream_reset),
          "send request");
    std::vector<std::byte> bytes;
    std::array<std::byte, 1024> buffer {};
    if (spec.wait_continue) {
        // Send HEADERS only and leave the request stream open. DATA cannot
        // reach the handler until its interim response has been verified.
        for (;;) {
            const auto got = flatten_result(co_await connection.async_read(*id, buffer));
            check(got && *got != 0, "Continue arrives before response FIN");
            bytes.insert(bytes.end(), buffer.begin(),
                         buffer.begin() + static_cast<std::ptrdiff_t>(*got));
            const auto frame = h3::decode_frame(bytes, 1024);
            if (!frame) {
                check(frame.error() == h3::frame_error::incomplete_input,
                      "incremental Continue frame");
                continue;
            }
            check(frame->type == h3::headers_frame && frame->encoded_size == bytes.size(),
                  "Continue is a single HEADERS frame");
            std::array<h3::field, 4> fields {};
            std::array<char, 64> strings {};
            const auto count = h3::qpack_decode(frame->payload, fields, strings);
            check(count && *count == 1 && fields[0].name == ":status" &&
                  fields[0].value == "100", "Continue contains only :status 100");
            bytes.clear();
            break;
        }
        for (const auto& part : spec.body) {
            const auto frame = data_frame(part);
            check(sent(co_await send_all(loop, connection, *id, frame, false)),
                  "send body after Continue");
        }
        check(sent(co_await send_all(loop, connection, *id, {}, true)),
              "finish request after Continue");
    }
    for (;;) {
        const auto got = flatten_result(co_await connection.async_read(*id, buffer));
        if (!got) { view.error = got.error(); break; }
        if (*got == 0) break;
        bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*got));
    }
    if (!view.error) parse_response(bytes, view);
}

auto client(event_loop& loop, quic_endpoint& endpoint, ip_endpoint server,
            std::vector<std::vector<std::byte>>& requests, const std::vector<request_spec>& specs,
            std::vector<response_view>& responses,
            std::span<const std::byte> settings, bool& done) -> task<void>
{
    auto connected = flatten_result(co_await endpoint.async_connect(server, "localhost"));
    check(connected.has_value(), "connect");
    auto connection = std::move(*connected);
    const auto control = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::unidirectional));
    check(control && sent(co_await send_all(loop, connection, *control, settings, false)),
          "client control stream");
    for (std::size_t index = 0; index < requests.size(); ++index)
        (void)co_await exchange(loop, connection, std::move(requests[index]), specs[index],
                               responses[index]);
    done = true;
}

auto watch(event_loop& loop, http::http3_server& server, quic_endpoint& endpoint,
           bool& done) -> task<void>
{
    for (int i = 0; i < 2000 && !done; ++i) (void)co_await sleep_for(loop, 5ms);
    co_await server.async_close();
    co_await endpoint.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

// Client control stream: type 0 and an empty SETTINGS frame.
constexpr std::array<std::byte, 3> empty_settings {std::byte {0}, std::byte {4}, std::byte {0}};

auto serve(const std::filesystem::path& directory, http::server_options options,
           std::vector<request_spec> specs,
           std::span<const std::byte> settings = empty_settings) -> std::vector<response_view>
{
    std::vector<std::vector<std::byte>> requests;
    for (const auto& spec : specs) requests.push_back(encode(spec));
    std::vector<response_view> responses(requests.size());
    bool done = false;
    {
        event_loop loop;
        http::http3_server server(loop, ip_endpoint::loopback_v4(0),
            directory / "cert.pem", directory / "key.pem", std::move(options));
        quic_client_options client_options;
        constexpr std::array<std::uint8_t, 2> alpn {'h', '3'};
        client_options.alpn = alpn;
        client_options.trusted_ca = directory / "cert.pem";
        quic_endpoint endpoint(loop, ip_endpoint::loopback_v4(0), std::move(client_options));
        task_handle<void> serving;
        check(loop.spawn(server.run(), serving) == task_spawn_result::accepted, "spawn server");
        check(loop.spawn(client(loop, endpoint, server.local_endpoint(), requests, specs, responses,
                                settings, done)) == task_spawn_result::accepted, "spawn client");
        check(loop.spawn(watch(loop, server, endpoint, done)) == task_spawn_result::accepted,
              "spawn watch");
        (void)loop.run();
    }
    check(done, "requests did not complete");
    return responses;
}

class temporary_directory {
public:
    temporary_directory()
    {
        std::random_device random;
        path_ = std::filesystem::temp_directory_path() /
            ("eventloop-h3-routing-" + std::to_string(random()));
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

} // namespace

auto main() -> int
{
    temporary_directory directory;
    test::make_localhost_certificate(directory.path() / "cert.pem", directory.path() / "key.pem");
    std::ofstream(directory.path() / "www" / "index.html") << "static";
    std::ofstream(directory.path() / "www" / "data.txt") << "0123456789";
    std::filesystem::create_directories(directory.path() / "www" / "listing");
    std::ofstream(directory.path() / "www" / "listing" / "entry.txt") << "listed";
    const auto file_path = (directory.path() / "www" / "data.txt").string();

    std::size_t cookie_calls = 0;
    std::size_t upload_calls = 0;
    auto routes = std::make_shared<http::router>();
    check(routes->add(http::method_type::get, "/hello", hello).has_value() &&
          routes->add(http::method_type::get, "/cookies", cookies, &cookie_calls).has_value() &&
          routes->add_prefix(http::method_type::get, "/api/", info).has_value() &&
          routes->add(http::method_type::post, "/upload", upload, &upload_calls).has_value() &&
          routes->add(http::method_type::post, "/partial", partial).has_value() &&
          routes->add(http::method_type::get, "/stream", stream).has_value() &&
          routes->add(http::method_type::get, "/big", big).has_value() &&
          routes->add(http::method_type::get, "/silent", silent).has_value() &&
          routes->add(http::method_type::get, "/short", short_body).has_value() &&
          routes->add(http::method_type::get, "/file", file,
                      const_cast<std::string*>(&file_path)).has_value(),
          "register routes");

    std::string large(10000, '\0');
    std::uint64_t large_sum = 0;
    for (std::size_t index = 0; index < large.size(); ++index) {
        large[index] = static_cast<char>('a' + index % 26);
        large_sum += static_cast<unsigned char>(large[index]);
    }
    const auto length = [](std::size_t size) {
        return std::pair<std::string, std::string> {"content-length", std::to_string(size)};
    };

    const auto responses = serve(directory.path(),
        {.routes = routes, .document_root = directory.path() / "www",
         .max_request_body = 20000, .connection_capacity = 1, .request_capacity = 2},
        {
            {.path = "/hello"},
            {.method = "HEAD", .path = "/hello"},
            {.method = "OPTIONS", .path = "/hello"},
            {.method = "POST", .path = "/hello"},
            {.path = "/api/items?id=7", .fields = {{"x-test", "seen"}}},
            {.method = "POST", .path = "/upload", .fields = {length(large.size())},
             .body = {large.substr(0, 3000), large.substr(3000, 2), large.substr(3002)}},
            {.method = "POST", .path = "/upload", .body = {"no", "-length"}},
            {.path = "/stream"},
            {.path = "/silent"},
            {.path = "/short"},
            {.path = "/file"},
            {.path = "/"},
            {.method = "POST", .path = "/upload", .fields = {length(20001)}},
            {.method = "POST", .path = "/upload", .body = {std::string(20001, 'x')}},
            {.method = "POST", .path = "/partial", .fields = {length(5000)},
             .body = {std::string(5000, 'p')}},
            {.path = "/hello"},
            {.path = "/cookies", .fields = {{"cookie", "a=1"}, {"x-test", "seen"},
                                           {"cookie", "b=2; c=3"}, {"cookie", "d=4"}}},
            {.path = "/cookies", .fields = {{"cookie", "single=1"}, {"x-test", "seen"}}},
            {.path = "/cookies", .fields = {{"x-test", "seen"}}},
        });

    const auto& hello_response = responses[0];
    check(hello_response.status == 200 && hello_response.body == "hello" &&
          hello_response.field("content-type") == "text/plain" &&
          hello_response.field("content-length") == "5" &&
          hello_response.field("date") != "<none>", "exact route");
    check(responses[1].status == 200 && responses[1].body.empty() &&
          responses[1].field("content-length") == "5" &&
          responses[1].field("date") != "<none>", "HEAD runs GET without body");
    check(responses[2].status == 204 && responses[2].field("allow") == "GET, HEAD, OPTIONS" &&
          responses[2].field("date") != "<none>",
          "OPTIONS lists methods");
    check(responses[3].status == 405 && responses[3].field("allow") == "GET, HEAD, OPTIONS" &&
          responses[3].field("date") != "<none>",
          "wrong method");
    check(responses[4].body == "/api/items|id=7|seen|example.test", "prefix route");
    check(responses[5].body == "10000 " + std::to_string(large_sum), "streamed request body");
    std::uint64_t unframed_sum = 0;
    for (const char c : std::string_view("no-length")) unframed_sum += static_cast<unsigned char>(c);
    check(responses[6].body == "9 " + std::to_string(unframed_sum), "body without content-length");
    check(responses[7].status == 200 && responses[7].body == "abcdefgh" &&
          responses[7].field("content-length") == "<none>" &&
          responses[7].trailers.size() == 1 && responses[7].trailers[0].first == "x-done",
          "streamed response with trailers");
    check(responses[8].status == 500, "handler without response");
    check(responses[9].error == make_error_code(quic_errc::stream_reset),
          "short body resets the stream");
    check(responses[10].status == 200 && responses[10].body == "23456", "file range");
    check(responses[11].status == 200 && responses[11].body == "static" &&
          responses[11].field("date") != "<none>", "static fallback");
    check(responses[12].status == 413 && responses[12].field("date") != "<none>",
          "declared body above max_request_body");
    check(responses[13].status == 400 && responses[13].body == "too large",
          "streamed body above max_request_body");
    check(responses[14].body == "partial", "unread body stopped");
    check(responses[15].body == "hello", "connection survives");
    check(responses[16].body == "a=1; b=2; c=3; d=4", "split Cookies joined in wire order");
    check(responses[17].body == "single=1", "single Cookie preserved");
    check(responses[18].body == "<none>", "absent Cookie preserved");

    // SETTINGS_MAX_FIELD_SECTION_SIZE = 300 (RFC 9114 4.2.2). The fallback
    // 500 and /hello fit; /big's 300-byte header does not. /hello goes first
    // so the server has read the client's SETTINGS before /big.
    constexpr std::array<std::byte, 6> limited_settings {std::byte {0}, std::byte {4},
        std::byte {3}, std::byte {6}, std::byte {0x41}, std::byte {0x2c}};
    const auto limited = serve(directory.path(), {.routes = routes},
        {{.path = "/hello"}, {.path = "/big"}}, limited_settings);
    check(limited[0].status == 200 && limited[0].body == "hello",
          "responses within the peer field section limit are sent");
    check(limited[1].status == 500 && limited[1].field("x-big") == "<none>",
          "peer field section limit replaces the oversized response with 500");

    const auto uploads_before = upload_calls;
    const auto large_lengths = serve(directory.path(),
        {.routes = routes, .max_request_body = std::numeric_limits<std::uint64_t>::max()},
        {
            {.method = "POST", .path = "/upload",
             .fields = {{"content-length", "4611686018427387904"}}},
            {.method = "POST", .path = "/upload",
             .fields = {{"content-length", "18446744073709551615"}}},
            {.method = "POST", .path = "/upload",
             .fields = {{"content-length", "18446744073709551616"},
                        {"content-length", "00018446744073709551616"}}},
            {.method = "POST", .path = "/upload",
             .fields = {{"content-length", std::string(100, '9')}}},
            {.method = "POST", .path = "/upload",
             .fields = {{"content-length", "18446744073709551616"},
                        {"content-length", "18446744073709551617"}}},
            {.method = "POST", .path = "/upload",
             .fields = {{"content-length", "18446744073709551616x"}}},
            {.method = "POST", .path = "/upload",
             .fields = {{"content-length", "000000000000000000000003"},
                        {"content-length", "3"}}, .body = {"abc"}},
            {.path = "/hello"},
        });
    for (std::size_t i = 0; i < 4; ++i)
        check(large_lengths[i].status == 413 && large_lengths[i].field("date") != "<none>",
              "unmatchable declared length answers 413 even with unlimited body option");
    for (std::size_t i = 4; i < 6; ++i)
        check(large_lengths[i].status == 0 &&
              large_lengths[i].error == make_error_code(quic_errc::stream_reset),
              "invalid large Content-Length remains a malformed request");
    check(large_lengths[6].status == 200 && large_lengths[6].body == "3 294",
          "long zero-padded length retains exact body framing");
    check(upload_calls == uploads_before + 1, "unmatchable length never reaches a handler");
    check(large_lengths[7].status == 200 && large_lengths[7].body == "hello",
          "connection survives unmatchable and malformed lengths");

    const request_spec exhausted_cookie {.path = "/cookies",
        .fields = {{"cookie", std::string(5000, 'a')}, {"x-test", "seen"},
                   {"cookie", std::string(5000, 'b')}}};
    // This request fits both decode buffers; only Cookie joining exhausts
    // their unused string tail. Distinguish that path from header rejection.
    const auto encoded_cookie = encode(exhausted_cookie);
    const auto cookie_frame = h3::decode_frame(encoded_cookie, 16 * 1024);
    std::array<h3::field, h3::qpack_max_fields> decoded_fields {};
    std::array<char, 16 * 1024> decoded_strings {};
    check(cookie_frame && h3::qpack_decode(cookie_frame->payload, decoded_fields,
                                         decoded_strings).has_value(),
          "Cookie boundary request fits the existing decode limits");
    const auto calls_before = cookie_calls;
    const auto cookie_boundary = serve(directory.path(), {.routes = routes},
        {exhausted_cookie,
         {.path = "/cookies", .fields = {{"cookie", "ok=1"}, {"x-test", "seen"}}}});
    check(cookie_boundary[0].error == make_error_code(quic_errc::stream_reset) &&
          cookie_boundary[0].status == 0, "Cookie join exhaustion resets the request stream");
    check(cookie_boundary[1].status == 200 && cookie_boundary[1].body == "ok=1",
          "connection survives Cookie join exhaustion");
    check(cookie_calls == calls_before + 1, "exhausted Cookie request never invokes the handler");

    const auto cached = serve(directory.path(),
        {.document_root = directory.path() / "www"},
        {
            {.path = "/index.html", .fields = {{"if-none-match", responses[11].field("etag")}}},
            {.path = "/", .fields = {{"if-modified-since", responses[11].field("last-modified")}}},
            {.method = "HEAD", .path = "/index.html", .fields = {{"if-none-match", "*"}}},
        });
    for (const auto& response : cached)
        check(response.status == 304 && response.body.empty() &&
              response.field("content-length") == "6" && response.field("date") != "<none>",
              "304 keeps representation length without a body");

    const auto listings = serve(directory.path(),
        {.document_root = directory.path() / "www", .directory_listing = true},
        {{.path = "/listing/"}, {.method = "HEAD", .path = "/listing/"}});
    check(listings[0].status == 200 &&
          listings[0].body.find("entry.txt") != std::string::npos &&
          listings[0].field("date") != "<none>", "static directory listing");
    check(listings[1].status == 200 && listings[1].body.empty() &&
          listings[1].field("content-length") == std::to_string(listings[0].body.size()) &&
          listings[1].field("date") != "<none>",
          "HEAD directory listing preserves GET metadata without DATA");

    // Routes only: unmatched paths answer 404.
    const auto routed_only = serve(directory.path(), {.routes = routes},
                                   {{.path = "/index.html"}, {.path = "/hello", .scheme = "HtTpS"}});
    check(routed_only[0].status == 404 && routed_only[0].field("date") != "<none>" &&
          routed_only[1].body == "hello",
          "routes without document root accept mixed-case HTTPS");

    const auto continued = serve(directory.path(), {.routes = routes},
        {
            {.method = "POST", .path = "/upload",
             .fields = {{"expect", "100-CoNtInUe"}, length(3)}, .body = {"a", "bc"},
             .wait_continue = true},
            {.method = "POST", .path = "/upload", .fields = {{"expect", "100-continue"}},
             .body = {"abc"}, .wait_continue = true},
            {.method = "POST", .path = "/upload",
             .fields = {{"expect", "100-continue \t, 100-CoNtInUe"}, length(3)},
             .body = {"abc"}, .wait_continue = true},
            {.method = "POST", .path = "/upload",
             .fields = {{"expect", "custom=\"wait,100-continue,still\""},
                        {"expect", "100-continue"}, length(3)},
             .body = {"abc"}, .wait_continue = true},
            {.method = "POST", .path = "/upload",
             .fields = {{"expect", "custom=\"wait\\\",100-continue,still\",\t100-continue"}},
             .body = {"abc"}, .wait_continue = true},
            {.method = "POST", .path = "/upload",
             .fields = {{"expect", "100-continue"}, length(0)}},
            {.path = "/hello", .fields = {{"expect", "100-continue"}, length(3)}},
            {.method = "POST", .path = "/upload",
             .fields = {{"expect", "100-continue"}, length(3)}, .body = {"abc"}},
            {.method = "POST", .path = "/upload",
             .fields = {{"expect", "custom=\"wait,100-continue,still\", other"}}},
            {.method = "POST", .path = "/upload",
             .fields = {{"expect", "100-continue=other"}}},
        });
    for (std::size_t i = 0; i < 5; ++i)
        check(continued[i].status == 200 && continued[i].body == "3 294" &&
              continued[i].trailers.empty(), "final response follows exactly one Continue");
    check(continued[5].status == 200 && continued[5].body == "0 0" &&
          continued[5].trailers.empty(), "zero-length body needs no Continue");
    check(continued[6].status == 200 && continued[6].body == "hello" &&
          continued[6].trailers.empty(), "header-only decision sends a final response");
    check(continued[7].status == 200 && continued[7].body == "3 294" &&
          continued[7].trailers.empty(), "buffered content needs no Continue");
    for (std::size_t i = 8; i < 10; ++i)
        check(continued[i].status == 200 && continued[i].body == "0 0" &&
              continued[i].trailers.empty(), "only an exact expectation member sends Continue");
}
