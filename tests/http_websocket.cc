// The server handler uses only public headers. The test peers use the private
// HTTP codecs to exercise Extended CONNECT on persistent h2/h3 connections.
#include "eventloop/event_loop.h"
#include "eventloop/http/server.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"
#include "eventloop/quic.h"
#include "eventloop/tls_stream.h"
#include "eventloop/task_composition.h"
#include "eventloop/ws/web_socket.h"
#include "http2/hpack.h"
#include "http3/frames.h"
#include "http3/qpack.h"
#include "tls_test_certificate.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

using namespace eventloop;
using namespace std::chrono_literals;
namespace h2 = eventloop::http2::detail;
namespace h3 = eventloop::http3::detail;

namespace {
std::string_view stage = "starting";
auto check(bool value, std::string_view message) -> void
{
    if (!value) { std::cerr << "HTTP WebSocket at " << stage << ": " << message << '\n'; std::exit(1); }
}
auto bytes(std::string_view value) -> std::span<const std::byte>
{ return std::as_bytes(std::span(value)); }

auto abort_later(event_loop& loop, http::websocket_stream& stream) -> task<void>
{
    (void)co_await sleep_for(loop, 20ms);
    stream.close();
}

auto echo(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto accepted = flatten_result(co_await request.async_accept_websocket("chat"));
    if (!accepted) {
        check(accepted.error() == std::make_error_code(std::errc::invalid_argument),
              "invalid handshake returns invalid_argument");
        const std::array<http::header, 1> version {{{"sec-websocket-version", "13"}}};
        (void)co_await response.async_send(400, version);
        co_return;
    }
    check(request.connect_protocol() == "websocket", "route sees :protocol");
    check(!flatten_result(co_await response.async_start(200, {})), "HTTP I/O after acceptance");
    if (request.path() == "/abort") {
        std::array<std::byte, 8> buffer {};
        auto results = co_await when_all(accepted->async_read_some(buffer), abort_later(loop, *accepted));
        check(std::get<1>(results) == task_result::success, "local abort completion");
        auto read = flatten_result(std::move(std::get<0>(results)));
        check(!read && read.error() == std::make_error_code(std::errc::operation_canceled),
              "close cancels borrowed stream read");
        co_return;
    }
    auto socket = std::make_unique<ws::web_socket<http::websocket_stream>>(loop, *accepted, 256);
    if (request.path() == "/timeout") {
        const auto waited = co_await with_timeout(loop, socket->async_receive(), 20ms);
        check(waited && waited->state == timeout_result<
            std::expected<ws::message_view, std::error_code>>::outcome::timed_out,
            "cancelled WebSocket receive retires");
        co_return;
    }
    for (;;) {
        auto received = flatten_result(co_await socket->async_receive());
        if (!received || received->type == ws::message_type::close) co_return;
        if (received->type == ws::message_type::binary) {
            if (!flatten_result(co_await socket->async_send_binary(received->payload))) co_return;
        } else if (received->type == ws::message_type::text) {
            const std::u8string_view text(reinterpret_cast<const char8_t*>(received->payload.data()),
                                          received->payload.size());
            if (!flatten_result(co_await socket->async_send_text(text))) co_return;
        }
    }
}
auto hello(event_loop&, http::request&, http::response& response) -> task<void>
{ (void)co_await response.async_send(200, {}, bytes("hello")); }

struct wire {
    tls_stream* tcp {nullptr};
    quic_connection* quic {nullptr};
    std::map<std::uint64_t, std::vector<std::byte>> input {};
    h2::hpack_decoder decoder {};
};
struct frame {
    unsigned type {0};
    std::uint64_t id {0};
    bool end {false};
    std::vector<std::byte> payload;
};
auto integer(std::span<const std::byte> input) -> std::uint32_t
{
    std::uint32_t result = 0;
    for (auto b : input) result = (result << 8) | std::to_integer<std::uint32_t>(b);
    return result;
}
auto h2_frame(unsigned type, unsigned flags, std::uint64_t id,
              std::span<const std::byte> payload) -> std::vector<std::byte>
{
    std::vector<std::byte> out(9);
    out[0] = static_cast<std::byte>(payload.size() >> 16);
    out[1] = static_cast<std::byte>(payload.size() >> 8);
    out[2] = static_cast<std::byte>(payload.size());
    out[3] = static_cast<std::byte>(type);
    out[4] = static_cast<std::byte>(flags);
    for (unsigned i = 0; i < 4; ++i) out[5 + i] = static_cast<std::byte>(id >> (24 - i * 8));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}
auto send_raw(event_loop&, wire& peer, std::uint64_t id, std::span<const std::byte> data,
              bool fin = false) -> task<void>
{
    while (!data.empty()) {
        auto sent = peer.tcp ? flatten_result(co_await peer.tcp->async_write_some(data))
                             : flatten_result(co_await peer.quic->async_write(id, data, false));
        check(sent && *sent != 0, "write peer bytes");
        data = data.subspan(*sent);
    }
    if (fin) {
        if (peer.tcp) {
            auto out = h2_frame(0, 1, id, {});
            check(flatten_result(co_await peer.tcp->async_write_some(out)).has_value(), "send END_STREAM");
        } else check(flatten_result(co_await peer.quic->async_write(id, {}, true)).has_value(), "send FIN");
    }
}
auto send_frame(event_loop& loop, wire& peer, std::uint64_t id, unsigned type,
                std::span<const std::byte> payload, bool fin = false) -> task<void>
{
    std::vector<std::byte> out;
    if (peer.tcp) out = h2_frame(type, (type == 1 ? 4u : 0u) | (fin ? 1u : 0u), id, payload);
    else {
        out.resize(payload.size() + 16);
        const auto count = h3::encode_frame(type, payload, out);
        check(count.has_value(), "encode HTTP/3 frame");
        out.resize(*count);
    }
    (void)co_await send_raw(loop, peer, id, out, fin && !peer.tcp);
}
auto read_frame(event_loop& loop, wire& peer, std::uint64_t id) -> task<frame>
{
    auto& in = peer.input[peer.tcp ? 0 : id];
    for (;;) {
        frame result;
        std::size_t count = 0, start = 0;
        if (peer.tcp && in.size() >= 9) {
            count = integer(std::span(in).first(3)) + 9;
            start = 9;
            result.type = std::to_integer<unsigned>(in[3]);
            result.end = (std::to_integer<unsigned>(in[4]) & 1u) != 0;
            result.id = integer(std::span(in).subspan(5, 4));
        } else if (!peer.tcp) {
            const auto parsed = h3::decode_frame(in, 65536);
            if (parsed) {
                count = parsed->encoded_size;
                start = count - parsed->payload.size();
                result.type = static_cast<unsigned>(parsed->type);
                result.id = id;
            }
        }
        if (count && count <= in.size()) {
            result.payload.assign(in.begin() + static_cast<std::ptrdiff_t>(start),
                                  in.begin() + static_cast<std::ptrdiff_t>(count));
            in.erase(in.begin(), in.begin() + static_cast<std::ptrdiff_t>(count));
            if (peer.tcp && result.type == 4) {
                if (!result.end) (void)co_await send_frame(loop, peer, 0, 4, {}, true);
                continue;
            }
            if (peer.tcp && result.type == 8) continue;
            if (peer.tcp && result.type == 3 && result.id < id) continue;
            co_return result;
        }
        std::array<std::byte, 512> buffer {};
        auto got = peer.tcp ? flatten_result(co_await peer.tcp->async_read_some(buffer))
                            : flatten_result(co_await peer.quic->async_read(id, buffer));
        if (!got) {
            check(!peer.tcp && got.error() == make_error_code(quic_errc::stream_reset), "peer stream reset");
            co_return frame {.type = 3, .id = id, .payload = {}};
        }
        if (*got == 0) { check(in.empty(), "complete frames before FIN"); co_return frame {.id = id, .end = true, .payload = {}}; }
        in.insert(in.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*got));
    }
}
auto headers(event_loop& loop, wire& peer, std::uint64_t id, std::string_view method,
             std::string_view path, std::string_view protocol = {}, std::string_view version = "13",
             std::string_view offered = "other, chat", std::string_view length = {})
    -> task<void>
{
    std::vector<h2::field> fields {{":method", std::string(method)}, {":scheme", "https"},
        {":authority", "localhost"}, {":path", std::string(path)}};
    if (!protocol.empty()) fields.push_back({":protocol", std::string(protocol)});
    if (method == "CONNECT") {
        fields.push_back({"sec-websocket-version", std::string(version)});
        fields.push_back({"sec-websocket-protocol", std::string(offered)});
        fields.push_back({"sec-websocket-extensions", "permessage-deflate"});
        if (!length.empty()) fields.push_back({"content-length", std::string(length)});
    }
    std::vector<std::byte> block;
    if (peer.tcp) check(h2::hpack_encode(fields, block) == h2::hpack_error::none, "encode HPACK");
    else {
        std::vector<h3::field> views;
        for (const auto& field : fields) views.push_back({field.name, field.value});
        block.resize(2048);
        const auto count = h3::qpack_encode(views, block);
        check(count.has_value(), "encode QPACK");
        block.resize(*count);
    }
    (void)co_await send_frame(loop, peer, id, 1, block, method != "CONNECT");
}
auto status(wire& peer, const frame& frame, bool accepted = false) -> unsigned
{
    if (frame.type != 1) std::cerr << "frame type=" << frame.type << " id=" << frame.id << '\n';
    check(frame.type == 1, "response HEADERS");
    std::vector<h2::field> fields;
    if (peer.tcp) check(peer.decoder.decode(frame.payload, fields) == h2::hpack_error::none, "decode HPACK");
    else {
        std::array<h3::field, 32> views {};
        std::array<char, 2048> storage {};
        const auto count = h3::qpack_decode(frame.payload, views, storage);
        check(count.has_value(), "decode QPACK");
        for (std::size_t i = 0; i < *count; ++i) fields.push_back({std::string(views[i].name), std::string(views[i].value)});
    }
    unsigned code = 0;
    bool subprotocol = false;
    for (const auto& field : fields) {
        if (field.name == ":status") code = static_cast<unsigned>(std::stoul(field.value));
        if (field.name == "sec-websocket-protocol") subprotocol = field.value == "chat";
        if (accepted) check(field.name != "content-length" && field.name != "sec-websocket-accept" &&
                            field.name != "sec-websocket-extensions", "accepted tunnel fields");
    }
    if (accepted) check(!frame.end && subprotocol, "open tunnel and selected subprotocol");
    return code;
}
auto masked(unsigned opcode, std::string_view payload, bool final = true) -> std::vector<std::byte>
{
    check(payload.size() <= 125, "small test frame");
    std::vector<std::byte> result {static_cast<std::byte>((final ? 0x80u : 0u) | opcode),
        static_cast<std::byte>(0x80u | payload.size()), std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    for (std::size_t i = 0; i < payload.size(); ++i)
        result.push_back(static_cast<std::byte>(static_cast<unsigned char>(payload[i])) ^ result[2 + i % 4]);
    return result;
}
auto receive_data(event_loop& loop, wire& peer, std::uint64_t id, std::size_t count) -> task<std::vector<std::byte>>
{
    std::vector<std::byte> result;
    while (result.size() < count) {
        auto next = co_await read_frame(loop, peer, id);
        check(next && next->type == 0 && next->id == id && !next->end, "open DATA stream");
        result.insert(result.end(), next->payload.begin(), next->payload.end());
    }
    check(result.size() == count, "exact WebSocket frame length");
    co_return result;
}
auto get(event_loop& loop, wire& peer, std::uint64_t id) -> task<void>
{
    (void)co_await headers(loop, peer, id, "GET", "/hello");
    auto head = co_await read_frame(loop, peer, id);
    check(head && status(peer, *head) == 200 && head->id == id, "ordinary request HEADERS");
    std::string body;
    while (!head->end) {
        head = co_await read_frame(loop, peer, id);
        check(head && head->id == id && head->type == 0, "ordinary response DATA");
        body.append(reinterpret_cast<const char*>(head->payload.data()), head->payload.size());
    }
    check(body == "hello", "ordinary request on WebSocket connection");
}
auto scenario(event_loop& loop, wire& peer, std::uint64_t base) -> task<void>
{
    stage = "opening WebSocket";
    const auto step = peer.tcp ? 2u : 4u;
    (void)co_await headers(loop, peer, base, "CONNECT", "/chat", "websocket");
    auto head = co_await read_frame(loop, peer, base);
    check(head && status(peer, *head, true) == 200, "accept Extended CONNECT");
    stage = "HTTP with open WebSocket";
    (void)co_await get(loop, peer, base + step);
    stage = "echo frames";
    // Two frames in one DATA, then one fragmented message split across DATA.
    auto first = masked(2, "hello");
    auto second = masked(2, "world");
    first.insert(first.end(), second.begin(), second.end());
    (void)co_await send_frame(loop, peer, base, 0, first);
    auto received = co_await receive_data(loop, peer, base, 14);
    const std::string expected("\x82\x05hello\x82\x05world", 14);
    check(received && *received == std::vector<std::byte>(bytes(expected).begin(), bytes(expected).end()), "two echo frames");
    first = masked(1, "frag", false);
    second = masked(0, "ment");
    (void)co_await send_frame(loop, peer, base, 0, std::span(first).first(3));
    first.erase(first.begin(), first.begin() + 3);
    first.insert(first.end(), second.begin(), second.end());
    (void)co_await send_frame(loop, peer, base, 0, first);
    received = co_await receive_data(loop, peer, base, 10);
    check(received && (*received)[0] == std::byte{0x81} &&
          std::string(reinterpret_cast<const char*>(received->data() + 2), 8) == "fragment", "fragmented echo");
    // max_request_body is 32: a session may exchange many bounded messages.
    for (unsigned i = 0; i < 12; ++i) {
        first = masked(2, "more");
        (void)co_await send_frame(loop, peer, base, 0, first);
        received = co_await receive_data(loop, peer, base, 6);
        check(received.has_value(), "WebSocket beyond cumulative body limit");
    }
    first = masked(8, {});
    stage = "closing WebSocket";
    (void)co_await send_frame(loop, peer, base, 0, first, true);
    std::vector<std::byte> close;
    bool ended = false;
    while (!ended) {
        auto next = co_await read_frame(loop, peer, base);
        check(next && next->type == 0 && next->id == base, "graceful stream closure");
        close.insert(close.end(), next->payload.begin(), next->payload.end());
        ended = next->end;
    }
    check(close == std::vector<std::byte> {std::byte{0x88}, std::byte{0}}, "Close echo before FIN");
    (void)co_await get(loop, peer, base + 2 * step);
    const auto invalid = base + 3 * step;
    stage = "invalid frame";
    (void)co_await headers(loop, peer, invalid, "CONNECT", "/chat", "websocket");
    head = co_await read_frame(loop, peer, invalid);
    check(head && status(peer, *head, true) == 200, "second WebSocket");
    const std::array<std::byte, 3> unmasked {std::byte{0x82}, std::byte{1}, std::byte{'x'}};
    (void)co_await send_frame(loop, peer, invalid, 0, unmasked);
    for (;;) {
        auto next = co_await read_frame(loop, peer, invalid);
        check(next.has_value(), "receive stream failure");
        if (next->type == 3) {
            if (peer.tcp) check(integer(next->payload) == 8, "RST_STREAM CANCEL");
            break;
        }
    }
    (void)co_await get(loop, peer, base + 4 * step);
    const auto rejected = base + 5 * step;
    stage = "handshake rejection";
    (void)co_await headers(loop, peer, rejected, "CONNECT", "/chat", "websocket", "12");
    head = co_await read_frame(loop, peer, rejected);
    check(head && status(peer, *head) == 400, "version rejection");
    // Consume the rejected response and stop/reset frames before another request.
    if (peer.tcp) { while (!head->end) head = co_await read_frame(loop, peer, rejected); }
    else { while (head && !head->end && head->type != 3) head = co_await read_frame(loop, peer, rejected); }
    const auto unknown = base + 6 * step;
    stage = "unknown protocol";
    (void)co_await headers(loop, peer, unknown, "CONNECT", "/chat", "unknown");
    head = co_await read_frame(loop, peer, unknown);
    // h2 may still have NO_ERROR for the previously rejected stream.
    while (head && head->type == 3 && head->id == rejected) head = co_await read_frame(loop, peer, unknown);
    check(head && status(peer, *head) == 501, "unknown Extended CONNECT protocol");
    for (unsigned index = 0; index < 3; ++index) {
        const auto id = base + (7 + index * 2) * step;
        const std::string_view path = index == 0 ? "/timeout" : index == 1 ? "/abort" : "/chat";
        stage = index == 0 ? "receive cancellation" : index == 1 ? "local abort" : "peer reset";
        (void)co_await headers(loop, peer, id, "CONNECT", path, "websocket");
        head = co_await read_frame(loop, peer, id);
        check(head && status(peer, *head, true) == 200, "accept cancellation test stream");
        if (index == 2) {
            if (peer.tcp) {
                const std::array<std::byte, 4> cancel {std::byte{0}, std::byte{0}, std::byte{0}, std::byte{8}};
                (void)co_await send_frame(loop, peer, id, 3, cancel);
            } else check(peer.quic->reset_stream(id, 0x10c).has_value(), "reset peer send direction");
        } else {
            auto reset = co_await read_frame(loop, peer, id);
            check(reset && reset->type == 3, "cancelled stream resets");
            if (peer.tcp) check(integer(reset->payload) == 8, "cancel uses CANCEL");
        }
        (void)co_await get(loop, peer, id + step);
    }
    // Keep a receive pending until the owning connection/server shuts down.
    for (unsigned index = 0; index < 3; ++index) {
        const auto id = base + (13 + index) * step;
        stage = "invalid handshake fields";
        (void)co_await headers(loop, peer, id, "CONNECT", "/chat", "websocket", "13",
                               index == 0 ? "other" : index == 1 ? "chat," : "chat",
                               index == 2 ? "0" : "");
        head = co_await read_frame(loop, peer, id);
        check(head && status(peer, *head) == 400, "reject unoffered subprotocol, invalid list, or Content-Length");
        while (head && !head->end && head->type != 3) head = co_await read_frame(loop, peer, id);
    }
    const auto idle = base + 16 * step;
    stage = "shutdown with active WebSocket";
    (void)co_await headers(loop, peer, idle, "CONNECT", "/chat", "websocket");
    head = co_await read_frame(loop, peer, idle);
    check(head && status(peer, *head, true) == 200, "idle WebSocket before shutdown");
}

auto h2_client(event_loop& loop, std::uint16_t port, std::shared_ptr<tls_context> context,
               bool& done) -> task<void>
{
    stage = "h2 connect";
    auto owned = std::make_unique<tls_stream>(loop, ip_endpoint::loopback_v4(port), context,
        tls_client_options {.hostname = "localhost", .application_protocols = {"h2"}});
    auto* tcp = owned.get();
    loop.add(std::move(owned));
    check((co_await tcp->async_connect()).has_value(), "connect h2");
    check(flatten_result(co_await tcp->async_handshake()).has_value(), "handshake h2");
    wire peer {.tcp = tcp};
    (void)co_await send_raw(loop, peer, 0, bytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    (void)co_await send_frame(loop, peer, 0, 4, {});
    // Read SETTINGS directly before issuing Extended CONNECT.
    std::array<std::byte, 256> buffer {};
    const auto got = flatten_result(co_await tcp->async_read_some(buffer));
    check(got && *got >= 9 && buffer[3] == std::byte{4}, "server SETTINGS");
    const auto length = integer(std::span(buffer).first(3));
    check(*got >= 9 + length, "complete SETTINGS");
    bool enabled = false;
    for (std::size_t i = 9; i < 9 + length; i += 6)
        if (integer(std::span(buffer).subspan(i, 2)) == 8)
            enabled = integer(std::span(buffer).subspan(i + 2, 4)) == 1;
    check(enabled, "SETTINGS_ENABLE_CONNECT_PROTOCOL=1");
    peer.input[0].assign(buffer.begin() + static_cast<std::ptrdiff_t>(9 + length),
                         buffer.begin() + static_cast<std::ptrdiff_t>(*got));
    (void)co_await send_frame(loop, peer, 0, 4, {}, true);
    (void)co_await scenario(loop, peer, 1);
    tcp->close();
    done = true;
}
auto h3_client(event_loop& loop, quic_endpoint& endpoint, ip_endpoint address, bool& done) -> task<void>
{
    stage = "h3 connect";
    auto connected = flatten_result(co_await endpoint.async_connect(address, "localhost"));
    check(connected.has_value(), "connect h3");
    auto connection = std::move(*connected);
    wire peer {.quic = &connection};
    const auto control = flatten_result(co_await connection.async_open_stream(quic_stream_direction::unidirectional));
    check(control.has_value(), "client control stream");
    const std::array<std::byte, 3> settings {std::byte{0}, std::byte{4}, std::byte{0}};
    (void)co_await send_raw(loop, peer, *control, settings);
    bool enabled = false;
    stage = "h3 server settings";
    for (unsigned i = 0; i < 3; ++i) {
        auto id = flatten_result(co_await connection.async_accept_stream());
        check(id.has_value(), "server critical stream");
        std::array<std::byte, 32> buffer {};
        auto got = flatten_result(co_await connection.async_read(*id, buffer));
        check(got && *got != 0, "critical stream bytes");
        if (buffer[0] != std::byte{0}) continue;
        peer.input[*id].assign(buffer.begin() + 1, buffer.begin() + static_cast<std::ptrdiff_t>(*got));
        auto frame = co_await read_frame(loop, peer, *id);
        check(frame && frame->type == 4, "HTTP/3 SETTINGS");
        auto rest = std::span<const std::byte>(frame->payload);
        while (!rest.empty()) {
            const auto key = quic::detail::decode_varint(rest);
            check(key.has_value(), "setting key");
            rest = rest.subspan(key->encoded_size);
            const auto value = quic::detail::decode_varint(rest);
            check(value.has_value(), "setting value");
            rest = rest.subspan(value->encoded_size);
            if (key->value == 8) enabled = value->value == 1;
        }
    }
    check(enabled, "HTTP/3 Extended CONNECT advertisement");
    // Reserve all scenario stream IDs before using them.
    for (unsigned i = 0; i < 17; ++i)
        check(flatten_result(co_await connection.async_open_stream(quic_stream_direction::bidirectional)).has_value(), "request stream");
    (void)co_await scenario(loop, peer, 0);
    done = true;
}
auto watch(event_loop& loop, bool& done) -> task<void>
{
    for (unsigned i = 0; i < 1000 && !done; ++i) (void)co_await sleep_for(loop, 5ms);
    if (!done) std::cerr << "at " << stage << '\n';
    check(done, "scenario timed out");
    loop.shutdown(0ms);
}
} // namespace

auto main() -> int
{
    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-ws-" + std::to_string(std::random_device{}()));
    std::filesystem::create_directories(directory);
    struct cleanup { std::filesystem::path directory; ~cleanup() { std::filesystem::remove_all(directory); } } cleanup {directory};
    test::make_localhost_certificate(directory / "cert.pem", directory / "key.pem");
    auto routes = std::make_shared<http::router>();
    check(routes->add(http::method_type::connect, "/chat", echo).has_value() &&
          routes->add(http::method_type::connect, "/timeout", echo).has_value() &&
          routes->add(http::method_type::connect, "/abort", echo).has_value() &&
          routes->add(http::method_type::get, "/hello", hello).has_value(), "register routes");
    // Both test peers and server requests retain bounded frames concurrently.
    event_loop_options loop_options;
    loop_options.coroutine_frame_capacities[4] = 32;
    loop_options.coroutine_frame_capacities[5] = 8;
    {
        event_loop loop(loop_options);
        auto server = std::make_unique<http::https_server>(loop, ip_endpoint::loopback_v4(0),
            tls_context::make_server(directory / "cert.pem", directory / "key.pem"),
            http::server_options {.routes = routes, .max_request_body = 32});
        auto* listener = server.get();
        sockaddr_in local {};
        socklen_t size = sizeof(local);
        check(::getsockname(listener->descriptor(), reinterpret_cast<sockaddr*>(&local), &size) == 0,
              "listener endpoint");
        const auto port = ntohs(local.sin_port);
        loop.add(std::move(server));
        bool done = false;
        check(loop.spawn(listener->run()) == task_spawn_result::accepted, "spawn h2 server");
        check(loop.spawn(h2_client(loop, port, tls_context::make_client(directory / "cert.pem"), done)) == task_spawn_result::accepted, "spawn h2 peer");
        check(loop.spawn(watch(loop, done)) == task_spawn_result::accepted, "watch h2");
        (void)loop.run();
        check(done, "h2 completed");
    }
    {
        event_loop loop(loop_options);
        http::http3_server server(loop, ip_endpoint::loopback_v4(0), directory / "cert.pem", directory / "key.pem",
                                  {.routes = routes, .max_request_body = 32});
        quic_client_options options;
        constexpr std::array<std::uint8_t, 2> alpn {'h', '3'};
        options.alpn = alpn;
        options.trusted_ca = directory / "cert.pem";
        quic_endpoint endpoint(loop, ip_endpoint::loopback_v4(0), std::move(options));
        bool done = false;
        check(loop.spawn(server.run()) == task_spawn_result::accepted, "spawn h3 server");
        check(loop.spawn(h3_client(loop, endpoint, server.local_endpoint(), done)) == task_spawn_result::accepted, "spawn h3 peer");
        check(loop.spawn(watch(loop, done)) == task_spawn_result::accepted, "watch h3");
        (void)loop.run();
        check(done, "h3 completed");
    }
}
