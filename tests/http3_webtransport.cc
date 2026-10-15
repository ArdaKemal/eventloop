// WebTransport over HTTP/3 (draft-16) end to end: a real http::http3_server with
// routes and WebTransport enabled, driven by the raw client fixture in
// tests/fixtures/webtransport_client.h. Each case runs on its own event loop.
#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/request.h"
#include "eventloop/http/response.h"
#include "eventloop/http/router.h"
#include "eventloop/http/webtransport.h"
#include "eventloop/quic.h"
#include "eventloop/task.h"
#include "eventloop/task_composition.h"
#include "eventloop/ws/web_socket.h"
#include "fixtures/webtransport_client.h"
#include "http3/webtransport_wire.h"
#include "quic/varint.h"
#include "tls_test_certificate.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace eventloop;
using namespace eventloop::webtransport_fixture;
using namespace std::chrono_literals;
namespace wt = eventloop::http3::detail;
namespace h3 = eventloop::http3::detail;
using eventloop::http::webtransport_errc;
using eventloop::http::webtransport_session;
using eventloop::http::webtransport_stream;
using eventloop::http::webtransport_to_http3_error;

// HTTP/3 error codes (RFC 9114) and WebTransport codes (draft-16 4.4).
constexpr std::uint64_t h3_id_error = 0x108;
constexpr std::uint64_t h3_frame_error = 0x106;
constexpr std::uint64_t h3_request_rejected = 0x10b;
constexpr std::uint64_t h3_message_error = 0x10e;
constexpr std::uint64_t h3_settings_error = 0x109;
constexpr std::uint64_t h3_datagram_error = 0x33;
constexpr auto wt_session_gone = static_cast<std::uint64_t>(wt::wt_error::wt_session_gone);
constexpr auto wt_flow_control_error = static_cast<std::uint64_t>(wt::wt_error::wt_flow_control_error);
constexpr auto wt_buffered_rejected = static_cast<std::uint64_t>(wt::wt_error::wt_buffered_stream_rejected);

std::filesystem::path g_directory;
std::string g_case;

[[noreturn]] auto fail(std::string_view message) -> void
{
    std::fprintf(stderr, "http3_webtransport [%s]: %.*s\n", g_case.c_str(),
                 static_cast<int>(message.size()), message.data());
    std::abort();
}

auto check(bool condition, std::string_view message) -> void
{
    if (!condition) fail(message);
}

auto to_bytes(std::string_view text) -> std::vector<std::byte>
{
    std::vector<std::byte> bytes(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) bytes[i] = static_cast<std::byte>(text[i]);
    return bytes;
}

auto to_text(std::span<const std::byte> bytes) -> std::string
{
    std::string text(bytes.size(), '\0');
    for (std::size_t i = 0; i < bytes.size(); ++i) text[i] = static_cast<char>(bytes[i]);
    return text;
}

// Everything a handler records for the scenario to check.
struct observation {
    bool case_done {false};
    bool accepted {false};
    bool finished {false};
    bool write_done {false};
    std::uint64_t session_id {0};
    std::string protocol;
    std::string received;
    std::string datagram;
    std::size_t datagrams {0};
    std::optional<std::uint32_t> stream_error;
    std::error_code read_error;
    std::error_code write_error;
    std::error_code accept_error;
    std::error_code datagram_error;
    bool closed {false};
    bool close_remote {false};
    std::uint32_t close_code {0};
    std::string close_reason;
};

// Server-side protocols the echo route accepts, in server preference order.
constexpr std::array<std::string_view, 2> supported_protocols {"echo/1", "chat"};

// Waits until predicate holds; fails with operation_canceled after about 2 s.
template<typename Predicate>
auto wait_until(event_loop& loop, Predicate predicate)
    -> task<std::expected<void, std::error_code>>
{
    for (int i = 0; i < 2000; ++i) {
        if (predicate()) co_return std::expected<void, std::error_code> {};
        (void)co_await sleep_for(loop, 1ms);
    }
    if (predicate()) co_return std::expected<void, std::error_code> {};
    co_return std::unexpected(std::make_error_code(std::errc::timed_out));
}

// Writes every byte on a server stream, retrying partial acceptances.
auto send_all([[maybe_unused]] event_loop& loop, webtransport_stream& stream,
              std::span<const std::byte> bytes, bool fin)
    -> task<std::expected<void, std::error_code>>
{
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        auto sent = flatten_result(co_await stream.async_write(bytes.subspan(offset), false));
        if (!sent) co_return std::unexpected(sent.error());
        offset += *sent;
    }
    if (fin) {
        auto closed = flatten_result(co_await stream.async_write({}, true));
        if (!closed) co_return std::unexpected(closed.error());
    }
    co_return std::expected<void, std::error_code> {};
}

// Echoes one peer stream: a bidi stream is reflected; a uni stream is read and
// its bytes are sent back on a new server uni stream.
auto echo_one(event_loop& loop, webtransport_session& session, webtransport_stream stream)
    -> task<void>
{
    std::vector<std::byte> buffer(2048);
    if (stream.direction() == quic_stream_direction::unidirectional) {
        std::string data;
        for (;;) {
            auto count = flatten_result(co_await stream.async_read(buffer));
            if (!count || *count == 0) break;
            data.append(to_text(std::span<const std::byte>(buffer).first(*count)));
        }
        auto reply = flatten_result(co_await session.async_open_stream(quic_stream_direction::unidirectional));
        if (!reply) co_return;
        const auto bytes = to_bytes(data);
        (void)co_await send_all(loop, *reply, bytes, true);
        co_return;
    }
    for (;;) {
        auto count = flatten_result(co_await stream.async_read(buffer));
        if (!count) co_return;
        if (*count == 0) {
            (void)co_await send_all(loop, stream, {}, true);
            co_return;
        }
        if (!flatten_result(co_await send_all(loop, stream, std::span<const std::byte>(buffer).first(*count), false)))
            co_return;
    }
}

auto echo_datagrams(event_loop& loop, webtransport_session& session) -> task<void>
{
    (void)loop;
    std::vector<std::byte> buffer(1500);
    for (;;) {
        auto size = flatten_result(co_await session.async_receive_datagram(buffer));
        if (!size) co_return;
        (void)co_await session.async_send_datagram(std::span<const std::byte>(buffer).first(*size));
    }
}

// Accepts with the supported protocols, then echoes streams and datagrams until
// the session ends.
auto echo_session(event_loop& loop, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (!accepted) {
        obs->accept_error = accepted.error();
        co_return;
    }
    auto& session = *accepted;
    obs->accepted = true;
    obs->session_id = session.id();
    obs->protocol = std::string(session.protocol());
    task_handle<void> datagrams;
    check(loop.spawn(echo_datagrams(loop, session), datagrams) == task_spawn_result::accepted,
          "spawn datagram echo");
    for (;;) {
        auto stream = flatten_result(co_await session.async_accept_stream());
        if (!stream) break;
        co_await echo_one(loop, session, std::move(*stream));
    }
    co_await datagrams;
    obs->finished = true;
}

// Answers without accepting the session.
auto reject_session(event_loop&, http::request&, http::response& response) -> task<void>
{
    (void)co_await response.async_send(403, {}, {});
}

auto reject_missing_session(event_loop&, http::request&, http::response& response) -> task<void>
{
    (void)co_await response.async_send(404, {}, {});
}

// Accepts, opens one server bidi and one server uni stream, then waits for close.
auto open_session(event_loop& loop, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    obs->accepted = true;
    obs->session_id = session.id();
    std::optional<webtransport_stream> bidi;
    std::optional<webtransport_stream> uni;
    auto opened = flatten_result(co_await session.async_open_stream(quic_stream_direction::bidirectional));
    if (opened) {
        bidi = std::move(*opened);
        (void)co_await send_all(loop, *bidi, to_bytes("bidi-from-server"), true);
    }
    auto opened_uni = flatten_result(co_await session.async_open_stream(quic_stream_direction::unidirectional));
    if (opened_uni) {
        uni = std::move(*opened_uni);
        (void)co_await send_all(loop, *uni, to_bytes("uni-from-server"), true);
    }
    (void)co_await session.async_accept_stream();
    obs->finished = true;
}

auto open_limited_session(event_loop&, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto session = flatten_result(co_await request.async_accept_webtransport());
    check(session.has_value(), "accept stream-limit session");
    for (int i = 0; i < 2; ++i) {
        auto opened = flatten_result(co_await session->async_open_stream(quic_stream_direction::bidirectional));
        check(!opened && opened.error() == webtransport_errc::capacity_exceeded,
              "QUIC refusal does not consume session stream quota");
    }
    obs->finished = true;
    (void)co_await session->async_accept_stream();
}

auto reverse_reset_session(event_loop&, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto session = flatten_result(co_await request.async_accept_webtransport());
    check(session.has_value(), "accept reverse-reset session");
    auto stream = flatten_result(co_await session->async_open_stream(quic_stream_direction::bidirectional));
    check(stream.has_value(), "open reverse-reset stream");
    std::vector<std::byte> buffer(256);
    const auto read = flatten_result(co_await stream->async_read(buffer));
    if (!read) obs->read_error = read.error();
    obs->finished = true;
    (void)co_await session->async_accept_stream();
}

// Opens a server uni stream and writes 1 MiB; the client's window paces the writer.
auto bulk_session(event_loop& loop, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    obs->accepted = true;
    auto opened = flatten_result(co_await session.async_open_stream(quic_stream_direction::unidirectional));
    if (!opened) co_return;
    std::vector<std::byte> payload(1024 * 1024);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::byte>((i * 13) & 0xff);
    const auto sent = flatten_result(co_await send_all(loop, *opened, payload, true));
    obs->write_done = sent.has_value();
    if (!sent) obs->write_error = sent.error();
    (void)co_await session.async_accept_stream();
    obs->finished = true;
}

// Opens a server uni stream, writes 16 KiB, and records when the writer returns.
auto flow_session(event_loop& loop, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    obs->accepted = true;
    auto opened = flatten_result(co_await session.async_open_stream(quic_stream_direction::unidirectional));
    if (!opened) co_return;
    std::vector<std::byte> payload(16 * 1024, std::byte {0x5a});
    const auto sent = flatten_result(co_await send_all(loop, *opened, payload, true));
    obs->write_done = sent.has_value();
    if (!sent) obs->write_error = sent.error();
    (void)co_await session.async_accept_stream();
    obs->finished = true;
}

// Opens a server uni stream, writes one byte, and resets it with application
// code 7 (RESET_STREAM_AT, with the header reliable).
auto reset_session(event_loop& loop, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    obs->accepted = true;
    auto opened = flatten_result(co_await session.async_open_stream(quic_stream_direction::unidirectional));
    if (!opened) co_return;
    (void)co_await send_all(loop, *opened, to_bytes("x"), false);
    (void)opened->reset(7);
    auto next = flatten_result(co_await session.async_open_stream(quic_stream_direction::unidirectional));
    check(next.has_value(), "open after reset");
    *opened = std::move(*next);
    check(flatten_result(co_await opened->async_write(to_bytes("y"), true)).has_value(),
          "reset returns unused session credit");
    (void)co_await session.async_accept_stream();
    obs->finished = true;
}

// Accepts one peer stream and records its read error and application code.
auto observe_session(event_loop&, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    obs->accepted = true;
    auto stream = flatten_result(co_await session.async_accept_stream());
    if (!stream) {
        obs->read_error = stream.error();
        co_return;
    }
    std::vector<std::byte> buffer(256);
    for (;;) {
        auto count = flatten_result(co_await stream->async_read(buffer));
        if (!count) {
            obs->read_error = count.error();
            break;
        }
        if (*count == 0) break;
        obs->received += to_text(std::span<const std::byte>(buffer).first(*count));
    }
    obs->stream_error = stream->error_code();
    obs->finished = true;
}

// Opens a server bidi stream and writes until the peer stops it.
auto stop_session(event_loop& loop, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    obs->accepted = true;
    auto opened = flatten_result(co_await session.async_open_stream(quic_stream_direction::bidirectional));
    if (!opened) co_return;
    std::vector<std::byte> chunk(1024, std::byte {0x33});
    for (;;) {
        auto sent = flatten_result(co_await send_all(loop, *opened, chunk, false));
        if (!sent) {
            obs->write_error = sent.error();
            break;
        }
    }
    obs->stream_error = opened->error_code();
    *opened = webtransport_stream {};
    auto next = flatten_result(co_await session.async_open_stream(quic_stream_direction::bidirectional));
    check(next.has_value(), "open after peer STOP_SENDING");
    auto sent = flatten_result(co_await next->async_write(chunk, true));
    check(sent && *sent == chunk.size(), "peer reset returns discarded session credit");
    obs->write_done = true;
    (void)co_await session.async_accept_stream();
    obs->finished = true;
}

// Accepts the peer's bidi stream, then closes the session with code 5 and "bye".
auto bye_session(event_loop& loop, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    obs->accepted = true;
    auto held = flatten_result(co_await session.async_accept_stream());
    (void)loop;
    (void)co_await session.async_close(5, "bye");
    obs->finished = true;
}

// Holds the session open until the peer closes it or resets the CONNECT stream.
// Records the close information and the errors of pending operations.
auto remote_session(event_loop&, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    obs->accepted = true;
    std::optional<webtransport_stream> held;
    auto first = flatten_result(co_await session.async_accept_stream());
    if (first) {
        held = std::move(*first);
        auto second = flatten_result(co_await session.async_accept_stream());
        if (!second) obs->accept_error = second.error();
    } else {
        obs->accept_error = first.error();
    }
    if (const auto info = session.close_info()) {
        obs->closed = true;
        obs->close_remote = info->remote;
        obs->close_code = info->code;
        obs->close_reason = std::string(info->reason);
    }
    if (held) {
        std::vector<std::byte> buffer(64);
        auto count = flatten_result(co_await held->async_read(buffer));
        if (!count) obs->read_error = count.error();
    }
    obs->finished = true;
}

// Returns at once after accepting: the CONNECT stream then ends with FIN.
auto return_session(event_loop&, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (accepted) obs->accepted = true;
}

// Waits 150 ms before accepting, so streams and datagrams arrive while the
// session is still pending. Then reads them back.
auto buffer_session(event_loop& loop, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    (void)co_await sleep_for(loop, 150ms);
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    obs->accepted = true;
    auto stream = flatten_result(co_await session.async_accept_stream());
    if (stream) {
        std::vector<std::byte> buffer(256);
        for (;;) {
            auto count = flatten_result(co_await stream->async_read(buffer));
            if (!count || *count == 0) break;
            obs->received += to_text(std::span<const std::byte>(buffer).first(*count));
        }
    }
    std::vector<std::byte> datagram_buffer(1500);
    auto size = flatten_result(co_await session.async_receive_datagram(datagram_buffer));
    if (size) {
        obs->datagram = to_text(std::span<const std::byte>(datagram_buffer).first(*size));
        obs->datagrams = 1;
    }
    obs->finished = true;
    (void)co_await session.async_accept_stream();
}

// Waits for a datagram and a stream at the same time; both must end when the
// connection or the server closes.
auto wait_session(event_loop& loop, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    obs->accepted = true;
    task_handle<void> pending_datagram;
    check(loop.spawn(echo_datagrams(loop, session), pending_datagram) == task_spawn_result::accepted,
          "spawn pending datagram");
    auto stream = flatten_result(co_await session.async_accept_stream());
    if (!stream) obs->accept_error = stream.error();
    co_await pending_datagram;
    obs->finished = true;
}

// Sends a datagram larger than the session allows, then a small one.
auto oversize_session(event_loop&, http::request& request, http::response&) -> task<void>
{
    auto* obs = static_cast<observation*>(request.route_context());
    auto accepted = flatten_result(co_await request.async_accept_webtransport(supported_protocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    obs->accepted = true;
    std::vector<std::byte> big(session.max_datagram_size() + 1, std::byte {0x41});
    auto sent = flatten_result(co_await session.async_send_datagram(big));
    if (!sent) obs->datagram_error = sent.error();
    big.pop_back();
    obs->write_done = flatten_result(co_await session.async_send_datagram(big)).has_value();
    const auto small = to_bytes("ok");
    (void)co_await session.async_send_datagram(small);
    (void)co_await session.async_accept_stream();
    obs->finished = true;
}

auto hello(event_loop&, http::request&, http::response& response) -> task<void>
{
    const std::array<http::header, 1> fields {{{"content-type", "text/plain"}}};
    (void)co_await response.async_send(200, fields, to_bytes("hi"));
}

// WebSocket over HTTP/3 on a server that also enables WebTransport: echoes one text message.
auto websocket(event_loop& loop, http::request& request, http::response&) -> task<void>
{
    auto accepted = flatten_result(co_await request.async_accept_websocket());
    if (!accepted) co_return;
    auto socket = std::make_unique<ws::web_socket<http::websocket_stream>>(loop, *accepted);
    const auto received = co_await socket->async_receive();
    if (!received || !*received) co_return;
    const auto& message = **received;
    if (message.type == ws::message_type::text) {
        const auto text = std::u8string_view {
            reinterpret_cast<const char8_t*>(message.payload.data()), message.payload.size()};
        (void)co_await socket->async_send_text(text);
    }
    // Return only after the client's close frame: ending the handler first cancels the request.
    for (;;) {
        const auto next = co_await socket->async_receive();
        if (!next || !*next || (**next).type == ws::message_type::close) break;
    }
}

// Route table for one case; the observation is the route context.
auto make_routes(observation* obs) -> std::shared_ptr<http::router>
{
    auto routes = std::make_shared<http::router>();
    auto add = [&routes](http::method_type method, std::string_view path, http::handler function,
                         void* context) {
        check(routes->add(method, path, function, context).has_value(), "register route");
    };
    add(http::method_type::connect, "/echo", echo_session, obs);
    add(http::method_type::connect, "/reject", reject_session, obs);
    add(http::method_type::connect, "/reject-404", reject_missing_session, obs);
    add(http::method_type::connect, "/open", open_session, obs);
    add(http::method_type::connect, "/open-limited", open_limited_session, obs);
    add(http::method_type::connect, "/reverse-reset", reverse_reset_session, obs);
    add(http::method_type::connect, "/flow", flow_session, obs);
    add(http::method_type::connect, "/bulk", bulk_session, obs);
    add(http::method_type::connect, "/reset", reset_session, obs);
    add(http::method_type::connect, "/observe", observe_session, obs);
    add(http::method_type::connect, "/stop", stop_session, obs);
    add(http::method_type::connect, "/bye", bye_session, obs);
    add(http::method_type::connect, "/remote", remote_session, obs);
    add(http::method_type::connect, "/return", return_session, obs);
    add(http::method_type::connect, "/buffer", buffer_session, obs);
    add(http::method_type::connect, "/wait", wait_session, obs);
    add(http::method_type::connect, "/oversize", oversize_session, obs);
    add(http::method_type::connect, "/ws", websocket, obs);
    add(http::method_type::get, "/hello", hello, obs);
    return routes;
}

// ---- Client-side helpers ---------------------------------------------------

struct env {
    webtransport_client& client;
    http::http3_server& server;
    observation& obs;
};

using scenario = task<void> (*)(event_loop&, env&);

struct opened {
    request_stream stream;
    response_head head;
};

// Sends a request and reads its response HEADERS.
auto open_request([[maybe_unused]] event_loop& loop, env& e, request_options request)
    -> task<std::expected<opened, std::error_code>>
{
    auto stream = flatten_result(co_await e.client.async_send_request(request));
    if (!stream) co_return std::unexpected(stream.error());
    auto head = flatten_result(co_await e.client.async_read_response(*stream));
    if (!head) co_return std::unexpected(head.error());
    co_return opened {std::move(*stream), std::move(*head)};
}

auto connect_to([[maybe_unused]] event_loop& loop, env& e, std::string_view path)
    -> task<std::expected<opened, std::error_code>>
{
    request_options request;
    request.path = path;
    co_return flatten_result(co_await open_request(loop, e, request));
}

// Reads up to size bytes of a stream, stopping early at FIN.
auto read_text([[maybe_unused]] event_loop& loop, env& e, std::uint64_t id, std::size_t size)
    -> task<std::expected<std::string, std::error_code>>
{
    std::vector<std::byte> buffer(size);
    auto count = flatten_result(co_await e.client.async_read_all(id, buffer));
    if (!count) co_return std::unexpected(count.error());
    co_return to_text(std::span<const std::byte>(buffer).first(*count));
}

// True when the stream ends (FIN) without more data.
auto at_fin([[maybe_unused]] event_loop& loop, env& e, std::uint64_t id)
    -> task<std::expected<bool, std::error_code>>
{
    std::array<std::byte, 1> byte {};
    auto count = flatten_result(co_await e.client.connection().async_read(id, byte));
    if (!count) co_return std::unexpected(count.error());
    co_return *count == 0;
}

// The error from a task that returns one, or operation_canceled if it was cancelled.
auto error_of(std::expected<std::error_code, task_result> value) -> std::error_code
{
    return value ? *value : std::make_error_code(std::errc::operation_canceled);
}

// Reads until the stream fails; returns the error.
auto read_until_error([[maybe_unused]] event_loop& loop, env& e, std::uint64_t id)
    -> task<std::error_code>
{
    std::vector<std::byte> buffer(256);
    for (;;) {
        auto count = flatten_result(co_await e.client.connection().async_read(id, buffer));
        if (!count) co_return count.error();
        if (*count == 0) co_return std::error_code {};
    }
}

auto as_data_frame(std::span<const std::byte> payload) -> std::vector<std::byte>
{
    std::array<std::byte, 16> header {};
    const auto size = h3::encode_frame_header(h3::data_frame, payload.size(), header);
    check(size.has_value(), "DATA frame header");
    std::vector<std::byte> out(*size + payload.size());
    std::copy(header.begin(), header.begin() + static_cast<std::ptrdiff_t>(*size), out.begin());
    std::copy(payload.begin(), payload.end(), out.begin() + static_cast<std::ptrdiff_t>(*size));
    return out;
}

// A capsule: type, length, and value.
auto capsule_bytes(std::uint64_t type, std::span<const std::byte> value) -> std::vector<std::byte>
{
    std::array<std::byte, 16> header {};
    const auto size = wt::encode_capsule_header(type, value.size(), header);
    check(size.has_value(), "capsule header");
    std::vector<std::byte> out(*size + value.size());
    std::copy(header.begin(), header.begin() + static_cast<std::ptrdiff_t>(*size), out.begin());
    std::copy(value.begin(), value.end(), out.begin() + static_cast<std::ptrdiff_t>(*size));
    return out;
}

// WT_CLOSE_SESSION with a raw message (bypasses the encoder's checks).
auto close_capsule(std::uint32_t code, std::span<const std::byte> message) -> std::vector<std::byte>
{
    std::vector<std::byte> value {
        static_cast<std::byte>(code >> 24), static_cast<std::byte>(code >> 16),
        static_cast<std::byte>(code >> 8), static_cast<std::byte>(code)};
    value.insert(value.end(), message.begin(), message.end());
    return capsule_bytes(wt::wt_close_session_capsule, value);
}

// Credit the server grants on the CONNECT stream, updated by a pump task.
struct credit {
    std::uint64_t max_data {0};
    std::uint64_t max_bidi {0};
    std::uint64_t max_uni {0};
    bool ended {false};
};

// Reads capsules from the CONNECT stream until it ends or fails.
auto pump_capsules([[maybe_unused]] event_loop& loop, env& e, request_stream& stream, credit& out)
    -> task<void>
{
    for (;;) {
        auto event = flatten_result(co_await e.client.async_read_capsule(stream));
        if (!event || event->type == capsule::kind::end) break;
        switch (event->type) {
        case capsule::kind::max_data: out.max_data = event->value; break;
        case capsule::kind::max_streams_bidi: out.max_bidi = event->value; break;
        case capsule::kind::max_streams_uni: out.max_uni = event->value; break;
        default: break;
        }
    }
    out.ended = true;
}

// Reads a stream's bytes into out until FIN or full.
auto read_into([[maybe_unused]] event_loop& loop, env& e, std::uint64_t id,
               std::vector<std::byte>& out, std::size_t& count_out) -> task<void>
{
    auto count = flatten_result(co_await e.client.async_read_all(id, out));
    count_out = count ? *count : 0;
}

// Writes bytes in pieces of varying size (fragmented writes).
auto write_fragmented([[maybe_unused]] event_loop& loop, env& e, std::uint64_t id,
                      std::span<const std::byte> bytes) -> task<std::expected<void, std::error_code>>
{
    std::size_t offset = 0;
    std::size_t piece = 0;
    while (offset < bytes.size()) {
        const auto size = std::min(bytes.size() - offset, 1000 + (piece * 1777) % 6001);
        auto sent = flatten_result(co_await e.client.async_write_all(id, bytes.subspan(offset, size)));
        if (!sent) co_return std::unexpected(sent.error());
        offset += size;
        ++piece;
    }
    co_return std::expected<void, std::error_code> {};
}

auto drive(event_loop& loop, env& e, scenario body) -> task<void>
{
    auto connected = flatten_result(co_await e.client.async_connect(e.server.local_endpoint()));
    check(connected.has_value(), "client connects");
    // Cases that depend on peer limits check peer_settings().received themselves;
    // a case may close the connection before SETTINGS are read.
    (void)co_await e.client.async_wait_server_settings();
    co_await body(loop, e);
    co_await e.client.async_close();
    co_await e.server.async_close();
    e.obs.case_done = true;
    loop.shutdown(event_loop::clock::duration::zero());
}

// Polls the case so that it does not keep the loop alive after the case ends.
auto watchdog(event_loop& loop, const observation& obs) -> task<void>
{
    for (int i = 0; i < 3000 && !obs.case_done; ++i) (void)co_await sleep_for(loop, 10ms);
    if (!obs.case_done) fail("case timed out");
}

// Runs one case on its own loop, server, and client.
auto run_case(std::string_view name, const http::webtransport_options& wt,
              const client_options& client_settings_for_case, scenario body) -> void
{
    g_case = std::string(name);
    event_loop loop;
    observation obs;
    auto routes = make_routes(&obs);
    http::server_options options;
    options.routes = routes;
    options.document_root = g_directory / "www";
    options.webtransport = wt;
    http::http3_server server(loop, ip_endpoint::loopback_v4(0), g_directory / "cert.pem",
                              g_directory / "key.pem", options);
    client_options client_config = client_settings_for_case;
    client_config.trusted_ca = g_directory / "cert.pem";
    webtransport_client client(loop, ip_endpoint::loopback_v4(0), client_config);
    env e {client, server, obs};
    task_handle<void> serving;
    task_handle<void> driver;
    task_handle<void> guard;
    check(loop.spawn(server.run(), serving) == task_spawn_result::accepted, "spawn server");
    check(loop.spawn(drive(loop, e, body), driver) == task_spawn_result::accepted, "spawn case");
    check(loop.spawn(watchdog(loop, obs), guard) == task_spawn_result::accepted, "spawn watchdog");
    (void)loop.run();
    check(obs.case_done, "case completed");
    std::printf("  ok %s\n", g_case.c_str());
    std::fflush(stdout);
}

auto default_client() -> client_options
{
    return client_options {};
}

// ---- Cases -----------------------------------------------------------------

template<typename Predicate>
auto await_condition(event_loop& loop, Predicate predicate, std::string_view what) -> task<void>
{
    auto ok = flatten_result(co_await wait_until(loop, predicate));
    check(ok.has_value(), what);
}

auto read_body_exact([[maybe_unused]] event_loop& loop, env& e, request_stream& stream, std::size_t size)
    -> task<std::expected<std::string, std::error_code>>
{
    std::string text;
    std::vector<std::byte> buffer(256);
    while (text.size() < size) {
        auto count = flatten_result(co_await e.client.async_read_body(stream, buffer));
        if (!count) co_return std::unexpected(count.error());
        if (*count == 0) break;
        text += to_text(std::span<const std::byte>(buffer).first(*count));
    }
    co_return text;
}

auto get_request(std::string_view path) -> request_options
{
    request_options request;
    request.method = "GET";
    request.protocol = {};
    request.path = path;
    return request;
}

// Opens a bidi WebTransport stream and returns its ID.
auto open_bidi([[maybe_unused]] event_loop& loop, env& e, std::uint64_t session)
    -> task<std::expected<std::uint64_t, std::error_code>>
{
    co_return flatten_result(co_await e.client.async_open_stream(session, true));
}

// Sends one echo over a fresh bidi stream and checks the reply.
auto echo_once(event_loop& loop, env& e, std::uint64_t session, std::string_view text)
    -> task<std::expected<void, std::error_code>>
{
    auto id = flatten_result(co_await open_bidi(loop, e, session));
    if (!id) co_return std::unexpected(id.error());
    auto sent = flatten_result(co_await e.client.async_write_all(*id, to_bytes(text), true));
    if (!sent) co_return std::unexpected(sent.error());
    auto echoed = flatten_result(co_await read_text(loop, e, *id, text.size()));
    if (!echoed) co_return std::unexpected(echoed.error());
    if (*echoed != text) co_return std::unexpected(std::make_error_code(std::errc::protocol_error));
    co_return std::expected<void, std::error_code> {};
}

// Opens streams one after another, waiting for stream credit from WT_MAX_STREAMS.
auto echo_streams_with_credit(event_loop& loop, env& e, std::size_t count)
    -> task<std::expected<std::uint64_t, std::error_code>>
{
    auto opened = flatten_result(co_await open_request(loop, e, request_options {}));
    if (!opened) co_return std::unexpected(opened.error());
    const auto session = opened->stream.id();
    credit credits;
    credits.max_bidi = e.client.peer_settings().initial_max_streams_bidi.value_or(0);
    task_handle<void> pump;
    if (loop.spawn(pump_capsules(loop, e, opened->stream, credits), pump) != task_spawn_result::accepted)
        co_return std::unexpected(std::make_error_code(std::errc::resource_unavailable_try_again));
    for (std::size_t i = 0; i < count; ++i) {
        co_await await_condition(loop, [&] { return credits.max_bidi > i; }, "WT_MAX_STREAMS credit");
        const auto text = std::to_string(i);
        auto echoed = flatten_result(co_await echo_once(loop, e, session, text));
        if (!echoed) {
            e.client.connection().close();
            co_await pump;
            co_return std::unexpected(echoed.error());
        }
    }
    e.client.connection().close();
    co_await pump;
    co_return credits.max_bidi;
}

// ---- Settings --------------------------------------------------------------

auto t_settings_enabled([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    const auto& peer = e.client.peer_settings();
    check(peer.received, "server SETTINGS received");
    check(peer.connect_protocol.value_or(0) == 1, "SETTINGS_ENABLE_CONNECT_PROTOCOL is 1");
    check(peer.h3_datagram.value_or(0) == 1, "SETTINGS_H3_DATAGRAM is 1");
    check(peer.wt_enabled.value_or(0) == 1, "SETTINGS_WT_ENABLED is 1");
    check(peer.initial_max_data.value_or(0) == 12345, "WT_INITIAL_MAX_DATA as configured");
    check(peer.initial_max_streams_bidi.value_or(0) == 7, "WT_INITIAL_MAX_STREAMS_BIDI as configured");
    check(peer.initial_max_streams_uni.value_or(0) == 3, "WT_INITIAL_MAX_STREAMS_UNI as configured");
    co_return;
}

auto t_settings_disabled([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    const auto& peer = e.client.peer_settings();
    check(peer.received, "server SETTINGS received");
    check(!peer.wt_enabled && !peer.initial_max_data && !peer.initial_max_streams_bidi &&
          !peer.initial_max_streams_uni, "no WebTransport settings when disabled");
    check(!peer.h3_datagram, "H3_DATAGRAM absent when WebTransport is disabled");
    co_return;
}

// ---- Sessions: accept and reject -------------------------------------------

auto t_accept([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value(), "CONNECT /echo");
    check(session->head.status == 200, "accepted session answers 200");
    check(!session->head.wt_protocol, "no wt-protocol without WT-Available-Protocols");
    co_await await_condition(loop, [&] { return e.obs.accepted; }, "handler accepted");
    check(e.obs.session_id == session->stream.id(), "session ID is the CONNECT stream ID");
}

auto t_reject(event_loop& loop, env& e, std::string_view path, unsigned expected_status) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, path));
    check(session.has_value(), "CONNECT answered");
    check(session->head.status == expected_status, "rejected session gets the handler's status");
    check(!e.obs.accepted, "handler did not accept");
    co_return;
}

auto t_reject_403([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    co_await t_reject(loop, e, "/reject", 403);
}

auto t_reject_404([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    co_await t_reject(loop, e, "/reject-404", 404);
}

auto t_unsupported_path_404([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    co_await t_reject(loop, e, "/missing", 404);
}

auto t_disabled_501([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    co_await t_reject(loop, e, "/echo", 501);
}

// ---- Requirements (H3_MESSAGE_ERROR on the CONNECT stream) -----------------

auto expect_malformed([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    auto stream = flatten_result(co_await e.client.async_send_request(request_options {}));
    check(stream.has_value(), "send CONNECT");
    auto head = flatten_result(co_await e.client.async_read_response(*stream));
    check(!head.has_value(), "malformed CONNECT gets no response");
    check(e.client.connection().stream_reset_code(stream->id()) == h3_message_error,
          "CONNECT stream reset with H3_MESSAGE_ERROR");
}

auto t_requires_h3_datagram(event_loop& loop, env& e) -> task<void>
{
    check(e.client.peer_settings().received, "server SETTINGS received");
    co_await expect_malformed(loop, e);
}

auto t_requires_wt_enabled(event_loop& loop, env& e) -> task<void>
{
    check(e.client.peer_settings().received, "server SETTINGS received");
    co_await expect_malformed(loop, e);
}

auto t_requires_reset_stream_at(event_loop& loop, env& e) -> task<void>
{
    check(e.client.peer_settings().received, "server SETTINGS received");
    co_await expect_malformed(loop, e);
}

// H3_DATAGRAM without a QUIC DATAGRAM transport parameter is a connection error
// (RFC 9297 2.1.1), so no response arrives.
auto t_requires_max_datagram(event_loop& loop, env& e) -> task<void>
{
    auto stream = flatten_result(co_await e.client.async_send_request(request_options {}));
    if (!stream) co_return;
    auto head = flatten_result(co_await e.client.async_read_response(*stream));
    check(!head.has_value(), "no response without max_datagram_frame_size");
    (void)loop;
}

// ---- Protocol negotiation ---------------------------------------------------

auto t_protocol_negotiated(event_loop& loop, env& e) -> task<void>
{
    request_options request;
    request.available_protocols = "\"x/1\", \"chat\", \"echo/1\"";
    auto session = flatten_result(co_await open_request(loop, e, request));
    check(session.has_value(), "CONNECT with WT-Available-Protocols");
    check(session->head.status == 200, "200 with a protocol");
    check(session->head.wt_protocol == std::optional<std::string>("\"chat\""),
          "client's most preferred supported protocol is selected");
    co_await await_condition(loop, [&] { return e.obs.protocol == "chat"; }, "handler sees the selected protocol");
}

auto t_protocol_malformed(event_loop& loop, env& e) -> task<void>
{
    request_options request;
    request.available_protocols = "\"echo/1";
    auto session = flatten_result(co_await open_request(loop, e, request));
    check(session.has_value(), "CONNECT with malformed WT-Available-Protocols");
    check(session->head.status == 200, "session still accepted");
    check(!session->head.wt_protocol, "malformed list selects no protocol");
    co_await await_condition(loop, [&] { return e.obs.accepted; }, "handler accepted");
    check(e.obs.protocol.empty(), "handler sees no protocol");
}

// ---- Streams -----------------------------------------------------------------

auto t_echo_bidi([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto id = flatten_result(co_await open_bidi(loop, e, session->stream.id()));
    check(id.has_value(), "open bidi stream");
    check(flatten_result(co_await e.client.async_write_all(*id, to_bytes("hello stream"), true)).has_value(),
          "write with FIN");
    auto echoed = flatten_result(co_await read_text(loop, e, *id, 12));
    check(echoed.has_value() && *echoed == "hello stream", "bidi stream echoed");
    auto fin = flatten_result(co_await at_fin(loop, e, *id));
    check(fin.has_value() && *fin, "echo ends with FIN");
}

auto t_echo_uni([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto id = flatten_result(co_await e.client.async_open_stream(session->stream.id(), false));
    check(id.has_value(), "open uni stream");
    check(flatten_result(co_await e.client.async_write_all(*id, to_bytes("uni data"), true)).has_value(),
          "write uni with FIN");
    auto peer = flatten_result(co_await e.client.async_accept_peer_stream());
    check(peer.has_value(), "server uni stream");
    check(peer->type == wt::webtransport_uni_stream_type, "server stream is WT uni (0x54)");
    check(peer->session_id == session->stream.id(), "uni echo carries the session ID");
    auto echoed = flatten_result(co_await read_text(loop, e, peer->id, 8));
    check(echoed.has_value() && *echoed == "uni data", "uni stream echoed on a server uni stream");
}

auto t_server_opened([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/open"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    std::optional<peer_stream> bidi;
    std::optional<peer_stream> uni;
    for (int i = 0; i < 2; ++i) {
        auto peer = flatten_result(co_await e.client.async_accept_peer_stream());
        check(peer.has_value(), "server opened a stream");
        check(peer->session_id == session->stream.id(), "server stream carries the session ID");
        if (peer->type == wt::webtransport_bidi_signal) bidi = *peer;
        else if (peer->type == wt::webtransport_uni_stream_type) uni = *peer;
    }
    check(bidi.has_value() && uni.has_value(), "one bidi (0x41) and one uni (0x54) stream");
    auto bidi_text = flatten_result(co_await read_text(loop, e, bidi->id, 16));
    check(bidi_text.has_value() && *bidi_text == "bidi-from-server", "server bidi payload");
    auto uni_text = flatten_result(co_await read_text(loop, e, uni->id, 15));
    check(uni_text.has_value() && *uni_text == "uni-from-server", "server uni payload");
}

auto t_large_transfer(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto id = flatten_result(co_await open_bidi(loop, e, session->stream.id()));
    check(id.has_value(), "open bidi stream");
    constexpr std::size_t size = 1024 * 1024;
    std::vector<std::byte> payload(size);
    for (std::size_t i = 0; i < size; ++i) payload[i] = static_cast<std::byte>((i * 7 + 3) & 0xff);
    std::vector<std::byte> received(size);
    std::size_t got = 0;
    task_handle<void> reader;
    check(loop.spawn(read_into(loop, e, *id, received, got), reader) == task_spawn_result::accepted,
          "spawn reader");
    check(flatten_result(co_await write_fragmented(loop, e, *id, payload)).has_value(), "fragmented writes");
    check(flatten_result(co_await e.client.async_write_all(*id, {}, true)).has_value(), "FIN");
    co_await reader;
    check(got == size, "whole 1 MiB echoed");
    check(std::equal(payload.begin(), payload.end(), received.begin()), "1 MiB echoed intact");
}

// ---- Datagrams --------------------------------------------------------------

auto t_datagram_echo([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    const auto id = session->stream.id();
    check(flatten_result(co_await e.client.async_send_datagram(id, to_bytes("ping"))).has_value(),
          "send datagram");
    auto echoed = flatten_result(co_await e.client.async_receive_datagram());
    check(echoed.has_value() && echoed->session_id == id, "datagram echoed for the session");
    check(echoed.has_value() && to_text(echoed->payload) == "ping", "datagram payload");
}

auto t_oversize_send([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/oversize"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto maximum = flatten_result(co_await e.client.async_receive_datagram());
    check(maximum && e.obs.write_done, "maximum-sized datagram sent");
    auto small = flatten_result(co_await e.client.async_receive_datagram());
    check(small.has_value() && to_text(small->payload) == "ok", "small datagram after the failed send");
    check(e.obs.datagram_error == make_error_code(webtransport_errc::datagram_size),
          "oversize datagram fails with datagram_size");
}

// ---- Several sessions, limits, and regressions -----------------------------

auto t_multi_sessions([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    std::array<std::uint64_t, 3> ids {};
    std::array<opened, 3> sessions {};
    for (std::size_t i = 0; i < 3; ++i) {
        auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
        check(session.has_value() && session->head.status == 200, "session accepted");
        ids[i] = session->stream.id();
        sessions[i] = std::move(*session);
    }
    std::array<std::uint64_t, 3> streams {};
    for (std::size_t i = 0; i < 3; ++i) {
        streams[i] = flatten_result(co_await open_bidi(loop, e, ids[i])).value_or(0);
        check(streams[i] != 0, "open bidi per session");
        check(flatten_result(co_await e.client.async_write_all(streams[i], to_bytes("s" + std::to_string(i)), true)).has_value(),
              "write per session");
        check(flatten_result(co_await e.client.async_send_datagram(ids[i], to_bytes("d" + std::to_string(i)))).has_value(),
              "datagram per session");
    }
    for (std::size_t i = 0; i < 3; ++i) {
        auto echoed = flatten_result(co_await read_text(loop, e, streams[i], 2));
        check(echoed.has_value() && *echoed == "s" + std::to_string(i), "stream stays with its session");
    }
    for (std::size_t i = 0; i < 3; ++i) {
        auto got = flatten_result(co_await e.client.async_receive_datagram());
        check(got.has_value(), "datagram received");
        bool matched = false;
        for (std::size_t k = 0; k < 3; ++k) {
            if (got->session_id == ids[k] && to_text(got->payload) == "d" + std::to_string(k)) matched = true;
        }
        check(matched, "datagram stays with its session");
    }
}

auto t_max_sessions([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    auto first = flatten_result(co_await connect_to(loop, e, "/echo"));
    auto second = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(first.has_value() && first->head.status == 200, "first session");
    check(second.has_value() && second->head.status == 200, "second session");
    auto third = flatten_result(co_await e.client.async_send_request(request_options {}));
    check(third.has_value(), "third CONNECT sent");
    auto refused = flatten_result(co_await e.client.async_read_response(*third));
    check(!refused.has_value(), "third session is refused");
    check(e.client.connection().stream_reset_code(third->id()) == h3_request_rejected,
          "refused CONNECT resets with H3_REQUEST_REJECTED");
    auto hello_stream = flatten_result(co_await open_request(loop, e, get_request("/hello")));
    check(hello_stream.has_value() && hello_stream->head.status == 200,
          "ordinary GET still works on the connection");
    auto body = flatten_result(co_await read_body_exact(loop, e, hello_stream->stream, 2));
    check(body.has_value() && *body == "hi", "GET body");
}

auto t_regression_get([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "WebTransport session accepted");
    auto hello_stream = flatten_result(co_await open_request(loop, e, get_request("/hello")));
    check(hello_stream.has_value() && hello_stream->head.status == 200, "GET route answers 200");
    auto body = flatten_result(co_await read_body_exact(loop, e, hello_stream->stream, 2));
    check(body.has_value() && *body == "hi", "GET route body");
    auto page = flatten_result(co_await open_request(loop, e, get_request("/index.html")));
    check(page.has_value() && page->head.status == 200, "static file answers 200");
    auto text = flatten_result(co_await read_body_exact(loop, e, page->stream, 11));
    check(text.has_value() && *text == "static page", "static file body");
    check(flatten_result(co_await echo_once(loop, e, session->stream.id(), "still works")).has_value(),
          "WebTransport still works after GET");
}

auto t_regression_websocket([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    request_options request;
    request.protocol = "websocket";
    request.path = "/ws";
    request.extra_name = "sec-websocket-version";
    request.extra_value = "13";
    auto session = flatten_result(co_await open_request(loop, e, request));
    check(session.has_value() && session->head.status == 200, "WebSocket over HTTP/3 accepted");
    // Masked client text frame "hello", mask 01 02 03 04.
    const std::array<std::byte, 11> frame {std::byte {0x81}, std::byte {0x85}, std::byte {1},
        std::byte {2}, std::byte {3}, std::byte {4},
        std::byte {'h' ^ 1}, std::byte {'e' ^ 2}, std::byte {'l' ^ 3}, std::byte {'l' ^ 4},
        std::byte {'o' ^ 1}};
    check(flatten_result(co_await e.client.async_send_capsule(session->stream, frame)).has_value(),
          "send WebSocket frame");
    auto reply = flatten_result(co_await read_body_exact(loop, e, session->stream, 7));
    check(reply.has_value() && *reply == std::string("\x81\x05hello", 7), "unmasked text echo");
    // A masked close frame, then FIN: the server returns only after this, so the echo
    // is never cut off by its own handler ending the request.
    const std::array<std::byte, 6> close_frame {std::byte {0x88}, std::byte {0x80}, std::byte {1},
        std::byte {2}, std::byte {3}, std::byte {4}};
    check(flatten_result(co_await e.client.async_send_capsule(session->stream, close_frame)).has_value(),
          "send close frame");
    check(flatten_result(co_await e.client.async_write_raw(session->stream, {}, true)).has_value(), "FIN");
}

// ---- Flow control -----------------------------------------------------------

// The server's writer blocks at the client's WT_MAX_DATA until the client grants more.
auto t_flow_writer_blocks([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    check(e.client.peer_settings().received, "server SETTINGS received");
    auto session = flatten_result(co_await connect_to(loop, e, "/flow"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto peer = flatten_result(co_await e.client.async_accept_peer_stream());
    check(peer.has_value() && peer->type == wt::webtransport_uni_stream_type, "server uni stream");
    std::vector<std::byte> first(4096);
    auto head = flatten_result(co_await e.client.async_read_all(peer->id, first));
    check(head.has_value() && *head == 4096, "4 KiB allowed by the client's limit");
    (void)co_await sleep_for(loop, 50ms);
    check(!e.obs.write_done, "writer blocked at the session data limit");
    std::array<std::byte, 16> grant {};
    auto grant_size = wt::encode_max_data(100000, grant);
    check(grant_size.has_value(), "encode WT_MAX_DATA");
    check(flatten_result(co_await e.client.async_send_capsule(session->stream,
        std::span<const std::byte>(grant).first(*grant_size))).has_value(), "grant WT_MAX_DATA");
    co_await await_condition(loop, [&] { return e.obs.write_done; }, "writer resumes after the grant");
    std::vector<std::byte> rest(16 * 1024 - 4096);
    auto tail = flatten_result(co_await e.client.async_read_all(peer->id, rest));
    check(tail.has_value() && *tail == rest.size(), "remaining bytes delivered");
}

// The client writes past the server's session data limit: CONNECT resets with WT_FLOW_CONTROL_ERROR.
// Reads CONNECT capsules until the stream ends or fails (the server may send
// renewals first). Returns the failure, or the kind of FIN.
auto read_until_connect_failure([[maybe_unused]] event_loop& loop, env& e, request_stream& stream)
    -> task<std::expected<capsule::kind, std::error_code>>
{
    for (;;) {
        auto next = flatten_result(co_await e.client.async_read_capsule(stream));
        if (!next) co_return std::unexpected(next.error());
        if (next->type == capsule::kind::end) co_return capsule::kind::end;
    }
}

auto t_flow_client_exceeds_data(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto id = flatten_result(co_await open_bidi(loop, e, session->stream.id()));
    check(id.has_value(), "open bidi stream");
    // Four KiB against a 1 KiB session window: the first read that takes more
    // than the window is a flow-control error.
    std::vector<std::byte> big(4096, std::byte {0x42});
    (void)co_await e.client.async_write_all(*id, big, false);
    auto next = flatten_result(co_await read_until_connect_failure(loop, e, session->stream));
    check(!next.has_value(), "CONNECT stream reset");
    check(e.client.connection().stream_reset_code(session->stream.id()) == wt_flow_control_error,
          "CONNECT reset with WT_FLOW_CONTROL_ERROR");
}

// Opening a second bidi stream beyond the server's WT_INITIAL_MAX_STREAMS_BIDI is a flow-control error.
auto t_flow_client_exceeds_streams(event_loop& loop, env& e) -> task<void>
{
    auto healthy = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(healthy.has_value() && healthy->head.status == 200, "healthy session accepted");
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto first = flatten_result(co_await open_bidi(loop, e, session->stream.id()));
    auto second = flatten_result(co_await open_bidi(loop, e, session->stream.id()));
    check(first.has_value() && second.has_value(), "two streams opened");
    auto next = flatten_result(co_await read_until_connect_failure(loop, e, session->stream));
    check(!next.has_value(), "CONNECT stream reset");
    check(e.client.connection().stream_reset_code(session->stream.id()) == wt_flow_control_error,
          "CONNECT reset with WT_FLOW_CONTROL_ERROR");
    check(flatten_result(co_await e.client.async_send_datagram(healthy->stream.id(), to_bytes("alive"))).has_value(),
          "send on healthy session");
    auto reply = flatten_result(co_await e.client.async_receive_datagram());
    check(reply && reply->session_id == healthy->stream.id() && to_text(reply->payload) == "alive",
          "another session's violation preserves the healthy session");
}

// Streams beyond the initial limit open as WT_MAX_STREAMS arrives.
auto t_renew_streams(event_loop& loop, env& e) -> task<void>
{
    check(e.client.peer_settings().received, "server SETTINGS received");
    auto renewed = flatten_result(co_await echo_streams_with_credit(loop, e, 6));
    check(renewed.has_value(), "six echoed streams with renewed credit");
    check(*renewed > 2, "WT_MAX_STREAMS renewal received beyond the initial 2");
}

// Forty streams through an initial limit of four.
auto t_many_streams(event_loop& loop, env& e) -> task<void>
{
    check(e.client.peer_settings().received, "server SETTINGS received");
    auto renewed = flatten_result(co_await echo_streams_with_credit(loop, e, 40));
    check(renewed.has_value(), "forty echoed streams");
    check(*renewed >= 40, "credit covers forty streams");
}

// Session data grants renew as the server consumes the client's data.
auto t_renew_data(event_loop& loop, env& e) -> task<void>
{
    check(e.client.peer_settings().received, "server SETTINGS received");
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    credit credits;
    credits.max_data = e.client.peer_settings().initial_max_data.value_or(0);
    task_handle<void> pump;
    check(loop.spawn(pump_capsules(loop, e, session->stream, credits), pump) == task_spawn_result::accepted,
          "spawn capsule pump");
    constexpr std::size_t chunk = 1024;
    std::uint64_t sent = 0;
    for (int round = 0; round < 5; ++round) {
        co_await await_condition(loop, [&] { return credits.max_data >= sent + chunk; },
                                 "WT_MAX_DATA renewal");
        auto id = flatten_result(co_await open_bidi(loop, e, session->stream.id()));
        check(id.has_value(), "open bidi stream");
        std::vector<std::byte> payload(chunk, std::byte {static_cast<unsigned char>('a' + round)});
        check(flatten_result(co_await e.client.async_write_all(*id, payload, true)).has_value(), "write chunk");
        std::vector<std::byte> echoed(chunk);
        auto count = flatten_result(co_await e.client.async_read_all(*id, echoed));
        check(count.has_value() && *count == chunk && echoed == payload, "chunk echoed");
        sent += chunk;
    }
    check(credits.max_data > chunk, "WT_MAX_DATA renewed beyond the initial window");
    e.client.connection().close();
    co_await pump;
}

// With no WT_INITIAL_* from the client, flow control is off: one session at a time.
auto t_flow_disabled_one_session(event_loop& loop, env& e) -> task<void>
{
    auto first = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(first.has_value() && first->head.status == 200, "first session accepted");
    auto second = flatten_result(co_await e.client.async_send_request(request_options {}));
    check(second.has_value(), "second CONNECT sent");
    auto refused = flatten_result(co_await e.client.async_read_response(*second));
    check(!refused.has_value(), "second session refused");
    check(e.client.connection().stream_reset_code(second->id()) == h3_request_rejected,
          "second CONNECT reset with H3_REQUEST_REJECTED");
}

// ---- Fragmented and malformed input ------------------------------------------

auto t_fragmented_stream(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto id = flatten_result(co_await e.client.connection().async_open_stream(quic_stream_direction::bidirectional));
    check(id.has_value(), "open raw bidi stream");
    std::array<std::byte, 16> header {};
    const auto header_size = wt::encode_stream_header(false, session->stream.id(), header);
    check(header_size.has_value(), "stream header");
    std::vector<std::byte> bytes(header.begin(), header.begin() + static_cast<std::ptrdiff_t>(*header_size));
    const auto body = to_bytes("fragment");
    bytes.insert(bytes.end(), body.begin(), body.end());
    for (const auto byte : bytes) {
        std::array<std::byte, 1> one {byte};
        check(flatten_result(co_await e.client.async_write_all(*id, one)).has_value(), "one byte");
    }
    check(flatten_result(co_await e.client.async_write_all(*id, {}, true)).has_value(), "FIN");
    auto echoed = flatten_result(co_await read_text(loop, e, *id, 8));
    check(echoed.has_value() && *echoed == "fragment", "byte-by-byte stream echoed");
}

auto t_fragmented_capsule(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/remote"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    const auto frame = as_data_frame(close_capsule(42, to_bytes("frag")));
    for (const auto byte : frame) {
        std::array<std::byte, 1> one {byte};
        check(flatten_result(co_await e.client.async_write_raw(session->stream, one)).has_value(), "one byte");
    }
    co_await await_condition(loop, [&] { return e.obs.finished; }, "close processed");
    check(e.obs.close_remote && e.obs.close_code == 42 && e.obs.close_reason == "frag",
          "close capsule assembled from single bytes");
}

// A WebTransport stream header naming session 2 (not a client bidi stream): H3_ID_ERROR closes the connection.
auto t_session_id_not_bidi(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    // A raw uni stream: the bytes below are its header, not a valid one.
    auto id = flatten_result(co_await e.client.connection().async_open_stream(quic_stream_direction::unidirectional));
    check(id.has_value(), "open raw uni stream");
    // Stream type 0x54 as a two-byte varint, then session ID 2.
    const std::array<std::byte, 3> header {std::byte {0x40}, std::byte {0x54}, std::byte {0x02}};
    check(flatten_result(co_await e.client.async_write_all(*id, header)).has_value(), "write bad header");
    auto next = flatten_result(co_await e.client.async_read_capsule(session->stream));
    check(!next.has_value(), "connection closed after H3_ID_ERROR");
    (void)loop;
}

auto t_frame_error_stream_signal(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    // WT_STREAM (0x41) frame on the CONNECT stream after HEADERS.
    const std::array<std::byte, 3> frame {std::byte {0x40}, std::byte {0x41}, std::byte {0x00}};
    check(flatten_result(co_await e.client.async_write_raw(session->stream, frame)).has_value(), "write frame");
    auto next = flatten_result(co_await e.client.async_read_capsule(session->stream));
    check(!next.has_value(), "connection closed");
    check(!e.client.connection().stream_reset_code(session->stream.id()).has_value(),
          "H3_FRAME_ERROR closes the connection, not just the stream");
    (void)loop;
}

auto t_bad_utf8_close(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/remote"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    const std::array<std::byte, 1> bad {std::byte {0xff}};
    const auto capsule = close_capsule(4, bad);
    check(flatten_result(co_await e.client.async_send_capsule(session->stream, capsule)).has_value(), "send");
    auto next = flatten_result(co_await e.client.async_read_capsule(session->stream));
    check(!next.has_value(), "CONNECT stream reset");
    check(e.client.connection().stream_reset_code(session->stream.id()) == h3_message_error,
          "invalid UTF-8 reason resets with H3_MESSAGE_ERROR");
    (void)loop;
}

auto t_long_reason_close(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/remote"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    const std::vector<std::byte> long_reason(1025, std::byte {'a'});
    const auto capsule = close_capsule(4, long_reason);
    check(flatten_result(co_await e.client.async_send_capsule(session->stream, capsule)).has_value(), "send");
    auto next = flatten_result(co_await e.client.async_read_capsule(session->stream));
    check(!next.has_value(), "CONNECT stream reset");
    check(e.client.connection().stream_reset_code(session->stream.id()) == h3_message_error,
          "1025-byte reason resets with H3_MESSAGE_ERROR");
    (void)loop;
}

auto t_prohibited_capsule(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    const std::array<std::byte, 1> value {std::byte {0}};
    const auto capsule = capsule_bytes(wt::wt_max_stream_data_capsule, value);
    check(flatten_result(co_await e.client.async_send_capsule(session->stream, capsule)).has_value(), "send");
    auto next = flatten_result(co_await e.client.async_read_capsule(session->stream));
    check(!next.has_value(), "CONNECT stream reset");
    check(e.client.connection().stream_reset_code(session->stream.id()) == wt_flow_control_error,
          "WT_MAX_STREAM_DATA resets with WT_FLOW_CONTROL_ERROR");
}

auto t_datagram_quarter_id_too_large(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    std::array<std::byte, 16> packet {};
    auto size = quic::detail::encode_varint(std::uint64_t {1} << 60, packet);
    check(size.has_value(), "encode quarter stream ID");
    packet[*size] = std::byte {'x'};
    check(flatten_result(co_await e.client.async_send_raw_datagram(
        std::span<const std::byte>(packet).first(*size + 1))).has_value(), "send datagram");
    auto next = flatten_result(co_await e.client.async_read_capsule(session->stream));
    check(!next.has_value(), "connection closed after H3_DATAGRAM_ERROR");
    (void)loop;
}

// ---- Resets ------------------------------------------------------------------

auto t_server_reset_code(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/reset"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto peer = flatten_result(co_await e.client.async_accept_peer_stream());
    check(peer.has_value() && peer->type == wt::webtransport_uni_stream_type, "uni stream header readable");
    check(peer->session_id == session->stream.id(), "header names the session");
    const auto error = error_of(co_await read_until_error(loop, e, peer->id));
    check(error == make_error_code(quic_errc::stream_reset), "reset stream read fails");
    check(e.client.connection().stream_reset_code(peer->id) == webtransport_to_http3_error(7),
          "RESET_STREAM_AT carries WebTransport code 7");
    auto next = flatten_result(co_await e.client.async_accept_peer_stream());
    check(next.has_value(), "new stream after reset");
    auto body = flatten_result(co_await read_text(loop, e, next->id, 1));
    check(body && *body == "y", "discarded bytes do not consume session credit");
}

auto t_client_reset_code(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/observe"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto id = flatten_result(co_await open_bidi(loop, e, session->stream.id()));
    check(id.has_value(), "open bidi stream");
    check(flatten_result(co_await e.client.async_write_all(*id, to_bytes("data"), false)).has_value(), "write");
    // The header and "data" stay reliable (RESET_STREAM_AT), so the server still
    // accepts the stream and reads the data before the reset.
    std::array<std::byte, 16> header {};
    const auto header_size = wt::encode_stream_header(false, session->stream.id(), header);
    check(header_size.has_value(), "stream header size");
    check(e.client.connection().reset_stream_at(*id, webtransport_to_http3_error(7),
        *header_size + 4).has_value(), "client reset");
    co_await await_condition(loop, [&] { return e.obs.finished; }, "server observed the reset");
    check(e.obs.stream_error == std::optional<std::uint32_t>(7), "server sees application code 7");
    check(e.obs.read_error == make_error_code(webtransport_errc::stream_reset), "server read reports stream_reset");
}

auto t_client_stop_sending(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/stop"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto peer = flatten_result(co_await e.client.async_accept_peer_stream());
    check(peer.has_value() && peer->type == wt::webtransport_bidi_signal, "server bidi stream");
    check(e.client.connection().stop_sending(peer->id, webtransport_to_http3_error(9)).has_value(),
          "client STOP_SENDING");
    co_await await_condition(loop, [&] { return e.obs.write_error.value() != 0; }, "server write fails");
    check(e.obs.write_error == make_error_code(webtransport_errc::stream_reset), "write reports stream_reset");
    check(e.obs.stream_error == std::optional<std::uint32_t>(9), "server sees application code 9");
    co_await await_condition(loop, [&] { return e.obs.write_done; }, "discarded credit available on next stream");
    auto next = flatten_result(co_await e.client.async_accept_peer_stream());
    check(next.has_value(), "next server stream after peer reset");
    auto body = flatten_result(co_await read_text(loop, e, next->id, 1024));
    check(body && body->size() == 1024, "next stream uses the refunded credit");
}

auto t_stop_credit_wait(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/flow"));
    check(session && session->head.status == 200, "session accepted");
    auto peer = flatten_result(co_await e.client.async_accept_peer_stream());
    check(peer.has_value(), "server uni stream");
    std::vector<std::byte> body(4096);
    const auto read = flatten_result(co_await e.client.async_read_all(peer->id, body));
    check(read && *read == body.size(), "entire session grant reached the peer");
    check(e.client.connection().stop_sending(peer->id, webtransport_to_http3_error(9)).has_value(),
          "STOP_SENDING with no queued body to refund");
    co_await await_condition(loop, [&] { return e.obs.write_error.value() != 0; }, "credit-blocked write wakes");
    check(e.obs.write_error == make_error_code(webtransport_errc::stream_reset), "write reports peer reset");
}

auto t_quic_open_limit(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/open-limited"));
    check(session && session->head.status == 200, "session accepted");
    co_await await_condition(loop, [&] { return e.obs.finished; }, "both opens return capacity_exceeded");
}

auto t_reverse_reset_flow(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/reverse-reset"));
    check(session && session->head.status == 200, "session accepted");
    auto peer = flatten_result(co_await e.client.async_accept_peer_stream());
    check(peer.has_value(), "server bidi stream");
    check(flatten_result(co_await e.client.async_write_all(peer->id, to_bytes("abcdefghijkl"))).has_value(),
          "queue twelve reverse-direction body bytes");
    // Fix final size at 12, then discard the reliable prefix before transmission.
    const auto code = webtransport_to_http3_error(7);
    check(e.client.connection().reset_stream_at(peer->id, code, 12).has_value(), "fix reset final size");
    check(e.client.connection().reset_stream_at(peer->id, code, 0).has_value(), "discard reset prefix");
    co_await await_condition(loop, [&] { return e.obs.finished; }, "server observed reverse reset");
    check(e.obs.read_error == make_error_code(webtransport_errc::flow_control_error),
          "reverse-direction final size excludes no header and exceeds the ten-byte window");
}

// ---- Termination -------------------------------------------------------------

auto t_client_close_capsule(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/remote"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto id = flatten_result(co_await open_bidi(loop, e, session->stream.id()));
    check(id.has_value(), "open bidi stream");
    check(flatten_result(co_await e.client.async_write_all(*id, to_bytes("hold"), false)).has_value(), "write");
    check(flatten_result(co_await e.client.async_send_capsule(session->stream,
        close_capsule(42, to_bytes("done")))).has_value(), "send WT_CLOSE_SESSION");
    co_await await_condition(loop, [&] { return e.obs.finished; }, "server saw the close");
    check(e.obs.closed && e.obs.close_remote && e.obs.close_code == 42 && e.obs.close_reason == "done",
          "server sees remote code and reason");
    co_await await_condition(loop, [&] {
        return e.client.connection().stream_stop_sending_code(*id).has_value();
    }, "server stops the peer stream");
    check(e.client.connection().stream_stop_sending_code(*id) == wt_session_gone,
          "stream stopped with WT_SESSION_GONE");
    auto end = flatten_result(co_await e.client.async_read_capsule(session->stream));
    check(end.has_value() && end->type == capsule::kind::end, "CONNECT stream FIN after the close");
}

auto t_server_close_capsule(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/bye"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto id = flatten_result(co_await open_bidi(loop, e, session->stream.id()));
    check(id.has_value(), "open bidi stream");
    check(flatten_result(co_await e.client.async_write_all(*id, to_bytes("hold"), false)).has_value(), "write");
    auto close = flatten_result(co_await e.client.async_read_capsule(session->stream));
    check(close.has_value() && close->type == capsule::kind::close_session, "WT_CLOSE_SESSION from server");
    check(close->code == 5 && close->reason == "bye", "code 5 and reason bye");
    auto end = flatten_result(co_await e.client.async_read_capsule(session->stream));
    check(end.has_value() && end->type == capsule::kind::end, "FIN after the close capsule");
    const auto error = error_of(co_await read_until_error(loop, e, *id));
    check(error == make_error_code(quic_errc::stream_reset), "open stream reset");
    check(e.client.connection().stream_reset_code(*id) == wt_session_gone, "reset with WT_SESSION_GONE");
}

auto t_client_fin_ends_pending_accept(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/remote"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    check(flatten_result(co_await e.client.async_write_raw(session->stream, {}, true)).has_value(), "FIN");
    co_await await_condition(loop, [&] { return e.obs.finished; }, "pending accept completes");
    check(e.obs.accept_error == make_error_code(webtransport_errc::session_closed),
          "pending accept fails with session_closed");
    check(e.obs.close_remote && e.obs.close_code == 0, "FIN closes remotely with code 0");
}

auto t_handler_return_fin([[maybe_unused]] event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/return"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    // Returning from the handler closes the session: WT_CLOSE_SESSION with code 0, then FIN.
    auto close = flatten_result(co_await e.client.async_read_capsule(session->stream));
    check(close.has_value() && close->type == capsule::kind::close_session && close->code == 0,
          "handler return sends WT_CLOSE_SESSION 0");
    auto end = flatten_result(co_await e.client.async_read_capsule(session->stream));
    check(end.has_value() && end->type == capsule::kind::end, "handler return sends CONNECT FIN");
}

// ---- Buffering -----------------------------------------------------------------

auto t_buffered_before_response(event_loop& loop, env& e) -> task<void>
{
    request_options request;
    request.path = "/buffer";
    auto sent = flatten_result(co_await e.client.async_send_request(request));
    check(sent.has_value(), "send CONNECT");
    const auto session = sent->id();
    auto id = flatten_result(co_await e.client.async_open_stream(session, true));
    check(id.has_value(), "stream before the response");
    check(flatten_result(co_await e.client.async_write_all(*id, to_bytes("early"), true)).has_value(), "write");
    check(flatten_result(co_await e.client.async_send_datagram(session, to_bytes("dgram"))).has_value(),
          "datagram before the response");
    auto head = flatten_result(co_await e.client.async_read_response(*sent));
    check(head.has_value() && head->status == 200, "accepted after the buffered traffic");
    co_await await_condition(loop, [&] { return e.obs.finished; }, "handler drained the buffers");
    check(e.obs.received == "early", "buffered stream delivered after accept");
    check(e.obs.datagram == "dgram", "buffered datagram delivered after accept");
}

auto t_buffer_limit(event_loop& loop, env& e) -> task<void>
{
    request_options request;
    request.path = "/buffer";
    auto sent = flatten_result(co_await e.client.async_send_request(request));
    check(sent.has_value(), "send CONNECT");
    const auto session = sent->id();
    auto first = flatten_result(co_await e.client.async_open_stream(session, true));
    auto second = flatten_result(co_await e.client.async_open_stream(session, true));
    auto third = flatten_result(co_await e.client.async_open_stream(session, true));
    check(first.has_value() && second.has_value() && third.has_value(), "three streams");
    check(flatten_result(co_await e.client.async_write_all(*second, to_bytes("b"), false)).has_value(), "write b");
    check(flatten_result(co_await e.client.async_write_all(*third, to_bytes("c"), false)).has_value(), "write c");
    auto head = flatten_result(co_await e.client.async_read_response(*sent));
    check(head.has_value() && head->status == 200, "accepted");
    co_await await_condition(loop, [&] {
        return e.client.connection().stream_stop_sending_code(*third).has_value();
    }, "excess stream refused");
    check(e.client.connection().stream_stop_sending_code(*third) == wt_buffered_rejected,
          "excess stream refused with WT_BUFFERED_STREAM_REJECTED");
    check(e.client.connection().stream_stop_sending_code(*second) == wt_buffered_rejected,
          "second excess stream refused too");
}

auto t_session_gone_stream(event_loop& loop, env& e) -> task<void>
{
    auto rejected = flatten_result(co_await connect_to(loop, e, "/reject"));
    check(rejected.has_value() && rejected->head.status == 403, "session rejected");
    auto id = flatten_result(co_await e.client.async_open_stream(rejected->stream.id(), true));
    check(id.has_value(), "stream for the rejected session");
    check(flatten_result(co_await e.client.async_write_all(*id, to_bytes("x"), false)).has_value(), "write");
    co_await await_condition(loop, [&] {
        return e.client.connection().stream_stop_sending_code(*id).has_value();
    }, "stream refused");
    check(e.client.connection().stream_stop_sending_code(*id) == wt_session_gone,
          "stream refused with WT_SESSION_GONE");
}

// ---- Cancellation ------------------------------------------------------------

auto t_pending_ops_on_connection_close(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/wait"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    co_await await_condition(loop, [&] { return e.obs.accepted; }, "handler accepted");
    (void)co_await sleep_for(loop, 50ms);
    e.client.connection().close();
    co_await await_condition(loop, [&] { return e.obs.finished; }, "pending operations complete");
    check(e.obs.accept_error == make_error_code(webtransport_errc::session_closed),
          "pending accept fails with session_closed");
}

auto t_server_close_active_sessions(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/wait"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    co_await await_condition(loop, [&] { return e.obs.accepted; }, "handler accepted");
    e.server.close();
    co_await await_condition(loop, [&] { return e.obs.finished; }, "pending operations complete on server close");
}

// ---- Resources ---------------------------------------------------------------

auto t_many_sessions_sequential(event_loop& loop, env& e) -> task<void>
{
    for (int i = 0; i < 200; ++i) {
        auto session = flatten_result(co_await connect_to(loop, e, "/return"));
        check(session.has_value() && session->head.status == 200, "session accepted");
        auto close = flatten_result(co_await e.client.async_read_capsule(session->stream));
        check(close.has_value() && close->type == capsule::kind::close_session, "session closes");
        auto end = flatten_result(co_await e.client.async_read_capsule(session->stream));
        check(end.has_value() && end->type == capsule::kind::end, "session ends with FIN");
    }
}

// HEADERS after the session is accepted: H3_FRAME_UNEXPECTED is a connection error.
auto t_headers_after_accept(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/echo"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    std::array<std::byte, 512> frame {};
    const auto size = encode_request(request_options {}, frame);
    check(size.has_value(), "encode HEADERS frame");
    check(flatten_result(co_await e.client.async_write_raw(session->stream,
        std::span<const std::byte>(frame).first(*size))).has_value(), "send HEADERS");
    auto next = flatten_result(co_await e.client.async_read_capsule(session->stream));
    check(!next.has_value(), "connection closed after an unexpected HEADERS frame");
    check(!e.client.connection().stream_reset_code(session->stream.id()).has_value(),
          "H3_FRAME_UNEXPECTED closes the connection, not just the stream");
}

// Bytes after WT_CLOSE_SESSION, sent in the same flight so the reset is not
// behind our own acknowledged FIN: the CONNECT stream resets with H3_MESSAGE_ERROR,
// and the handler still sees the peer's close code and reason.
// `as_capsule` puts the bytes in the DATA payload; otherwise they follow as their own
// frame (a HEADERS frame must not be read as a capsule).
auto close_then(event_loop& loop, env& e, std::vector<std::byte> extra, bool as_capsule)
    -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/remote"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto payload = close_capsule(42, to_bytes("done"));
    if (as_capsule) {
        payload.insert(payload.end(), extra.begin(), extra.end());
        check(flatten_result(co_await e.client.async_write_raw(session->stream, as_data_frame(payload))).has_value(),
              "send close and bytes after it");
    } else {
        check(flatten_result(co_await e.client.async_write_raw(session->stream, as_data_frame(payload))).has_value(),
              "send close");
        check(flatten_result(co_await e.client.async_write_raw(session->stream, extra)).has_value(),
              "send bytes after it");
    }
    co_await await_condition(loop, [&] { return e.obs.finished; }, "server saw the close");
    check(e.obs.close_remote && e.obs.close_code == 42 && e.obs.close_reason == "done",
          "handler keeps the peer's close code and reason");
    co_await await_condition(loop, [&] {
        return e.client.connection().stream_reset_code(session->stream.id()).has_value();
    }, "CONNECT stream reset");
    check(e.client.connection().stream_reset_code(session->stream.id()) == h3_message_error,
          "bytes after WT_CLOSE_SESSION reset with H3_MESSAGE_ERROR");
}

auto t_data_after_close(event_loop& loop, env& e) -> task<void>
{
    std::array<std::byte, 16> drain {};
    const auto drain_size = wt::encode_drain_session(drain);
    check(drain_size.has_value(), "encode WT_DRAIN_SESSION");
    co_await close_then(loop, e, std::vector<std::byte>(drain.begin(),
        drain.begin() + static_cast<std::ptrdiff_t>(*drain_size)), true);
}

// A HEADERS frame after WT_CLOSE_SESSION is also data after the close: H3_MESSAGE_ERROR,
// not H3_FRAME_UNEXPECTED.
auto t_headers_after_close(event_loop& loop, env& e) -> task<void>
{
    std::array<std::byte, 512> frame {};
    const auto size = encode_request(request_options {}, frame);
    check(size.has_value(), "encode HEADERS frame");
    co_await close_then(loop, e, std::vector<std::byte>(frame.begin(),
        frame.begin() + static_cast<std::ptrdiff_t>(*size)), false);
}

// Server writes 1 MiB through a 32 KiB client window; the client grants WT_MAX_DATA
// as it consumes (consumed + window once half the window is used). The window must
// exceed QUIC's 16 KiB per-stream send buffer, or the server's QUIC write is never short.
auto t_bulk_transfer_credit(event_loop& loop, env& e) -> task<void>
{
    auto session = flatten_result(co_await connect_to(loop, e, "/bulk"));
    check(session.has_value() && session->head.status == 200, "session accepted");
    auto peer = flatten_result(co_await e.client.async_accept_peer_stream());
    check(peer.has_value() && peer->type == wt::webtransport_uni_stream_type, "server uni stream");
    constexpr std::size_t total = 1024 * 1024;
    constexpr std::uint64_t window = 32 * 1024;
    std::uint64_t granted = window;
    std::uint64_t received = 0;
    std::vector<std::byte> buffer(1024);
    bool intact = true;
    while (received < total) {
        auto count = flatten_result(co_await e.client.async_read_all(peer->id, buffer));
        check(count.has_value() && *count > 0, "bulk data keeps arriving");
        for (std::size_t i = 0; i < *count; ++i) {
            intact = intact && buffer[i] == static_cast<std::byte>((received + i) * 13 & 0xff);
        }
        received += *count;
        if (granted - received < window / 2) {
            granted = received + window;
            std::array<std::byte, 16> grant {};
            const auto grant_size = wt::encode_max_data(granted, grant);
            check(grant_size.has_value(), "encode WT_MAX_DATA");
            check(flatten_result(co_await e.client.async_send_capsule(session->stream,
                std::span<const std::byte>(grant).first(*grant_size))).has_value(), "grant WT_MAX_DATA");
        }
    }
    check(received == total && intact, "1 MiB arrives intact");
    auto fin = flatten_result(co_await at_fin(loop, e, peer->id));
    check(fin.has_value() && *fin, "bulk stream ends with FIN");
}

// ---- Setup and main ----------------------------------------------------------

struct wt_setup {
    bool enabled {true};
    std::size_t max_sessions {4};
    std::uint64_t bidi {32};
    std::uint64_t uni {8};
    std::uint64_t data {256 * 1024};
    std::size_t buffered_streams {8};
};

auto make_wt(wt_setup setup) -> http::webtransport_options
{
    http::webtransport_options wt;
    wt.enabled = setup.enabled;
    wt.max_sessions = setup.max_sessions;
    wt.initial_max_streams_bidi = setup.bidi;
    wt.initial_max_streams_uni = setup.uni;
    wt.initial_max_data = setup.data;
    wt.buffered_streams = setup.buffered_streams;
    return wt;
}

struct client_setup {
    bool h3_datagram {true};
    bool wt_enabled {true};
    bool reset_stream_at {true};
    std::uint64_t max_datagram {1232};
    // Clears the client's WT_INITIAL_* values, which turns session flow control off.
    bool flow_control {true};
    std::uint64_t data {1024 * 1024};
    std::uint64_t bidi {16};
    std::uint64_t uni {16};
    std::uint64_t stream_data {64 * 1024};
    std::uint64_t quic_bidi {100};
};

auto make_client(client_setup setup) -> client_options
{
    client_options options;
    options.settings.h3_datagram = setup.h3_datagram;
    options.settings.wt_enabled = setup.wt_enabled;
    options.limits.reset_stream_at = setup.reset_stream_at;
    options.limits.max_datagram_frame_size = setup.max_datagram;
    options.limits.max_stream_data = setup.stream_data;
    options.limits.max_streams_bidi = setup.quic_bidi;
    if (setup.flow_control) {
        options.settings.initial_max_data = setup.data;
        options.settings.initial_max_streams_bidi = setup.bidi;
        options.settings.initial_max_streams_uni = setup.uni;
    } else {
        options.settings.initial_max_data.reset();
        options.settings.initial_max_streams_bidi.reset();
        options.settings.initial_max_streams_uni.reset();
    }
    return options;
}

auto write_certificates_and_pages() -> void
{
    g_directory = std::filesystem::temp_directory_path() /
        ("eventloop-webtransport-" + std::to_string(std::random_device {}()));
    std::filesystem::create_directories(g_directory / "www");
    eventloop::test::make_localhost_certificate(g_directory / "cert.pem", g_directory / "key.pem");
    std::ofstream(g_directory / "www" / "index.html") << "static page";
}

} // namespace

auto main() -> int
{
    write_certificates_and_pages();
    struct cleanup {
        std::filesystem::path directory;
        ~cleanup() { std::filesystem::remove_all(directory); }
    } remove_directory {g_directory};

    std::puts("HTTP/3 WebTransport end-to-end cases:");
    // Settings
    run_case("settings enabled", make_wt({.bidi = 7, .uni = 3, .data = 12345}), default_client(), t_settings_enabled);
    run_case("settings disabled", make_wt({.enabled = false}), default_client(), t_settings_disabled);
    // Accept and reject
    run_case("accept", make_wt({}), default_client(), t_accept);
    run_case("reject 403", make_wt({}), default_client(), t_reject_403);
    run_case("reject 404", make_wt({}), default_client(), t_reject_404);
    run_case("unsupported path 404", make_wt({}), default_client(), t_unsupported_path_404);
    run_case("disabled 501", make_wt({.enabled = false}), default_client(), t_disabled_501);
    // Requirements
    run_case("requires H3_DATAGRAM", make_wt({}), make_client({.h3_datagram = false}), t_requires_h3_datagram);
    run_case("requires WT_ENABLED", make_wt({}), make_client({.wt_enabled = false}), t_requires_wt_enabled);
    run_case("requires reset_stream_at", make_wt({}), make_client({.reset_stream_at = false}), t_requires_reset_stream_at);
    run_case("requires max_datagram_frame_size", make_wt({}), make_client({.max_datagram = 0}), t_requires_max_datagram);
    // Protocols
    run_case("protocol negotiated", make_wt({}), default_client(), t_protocol_negotiated);
    run_case("protocol list malformed", make_wt({}), default_client(), t_protocol_malformed);
    // Streams
    run_case("echo bidi", make_wt({}), default_client(), t_echo_bidi);
    run_case("echo uni", make_wt({}), default_client(), t_echo_uni);
    run_case("server opened streams", make_wt({}), default_client(), t_server_opened);
    run_case("1 MiB fragmented transfer", make_wt({.data = 2 * 1024 * 1024}), default_client(), t_large_transfer);
    // Datagrams
    run_case("datagram echo", make_wt({}), default_client(), t_datagram_echo);
    run_case("oversize datagram", make_wt({}), default_client(), t_oversize_send);
    run_case("small peer datagram limit", make_wt({}), make_client({.max_datagram = 64}), t_oversize_send);
    // Sessions and regressions
    run_case("multiple sessions", make_wt({}), default_client(), t_multi_sessions);
    run_case("max sessions and GET", make_wt({.max_sessions = 2}), default_client(), t_max_sessions);
    run_case("GET and static files", make_wt({}), default_client(), t_regression_get);
    run_case("WebSocket over HTTP/3", make_wt({}), default_client(), t_regression_websocket);
    // Flow control
    run_case("writer blocks at WT_MAX_DATA", make_wt({}), make_client({.data = 4096}), t_flow_writer_blocks);
    run_case("client exceeds session data", make_wt({.data = 1024}), default_client(), t_flow_client_exceeds_data);
    run_case("client exceeds stream limit", make_wt({.bidi = 1}), default_client(), t_flow_client_exceeds_streams);
    run_case("WT_MAX_STREAMS renewal", make_wt({.bidi = 2}), default_client(), t_renew_streams);
    run_case("forty streams", make_wt({.bidi = 4}), default_client(), t_many_streams);
    run_case("WT_MAX_DATA renewal", make_wt({.data = 2048}), default_client(), t_renew_data);
    run_case("flow control disabled", make_wt({}), make_client({.flow_control = false}), t_flow_disabled_one_session);
    // Fragmented and malformed input
    run_case("fragmented stream header and data", make_wt({}), default_client(), t_fragmented_stream);
    run_case("fragmented capsule", make_wt({}), default_client(), t_fragmented_capsule);
    run_case("session ID not a bidi stream", make_wt({}), default_client(), t_session_id_not_bidi);
    run_case("WT_STREAM frame on CONNECT", make_wt({}), default_client(), t_frame_error_stream_signal);
    run_case("invalid UTF-8 close reason", make_wt({}), default_client(), t_bad_utf8_close);
    run_case("1025-byte close reason", make_wt({}), default_client(), t_long_reason_close);
    run_case("prohibited WT_MAX_STREAM_DATA", make_wt({}), default_client(), t_prohibited_capsule);
    run_case("quarter stream ID above 2^60-1", make_wt({}), default_client(), t_datagram_quarter_id_too_large);
    run_case("HEADERS after acceptance closes the connection", make_wt({}), default_client(), t_headers_after_accept);
    run_case("data after WT_CLOSE_SESSION", make_wt({}), default_client(), t_data_after_close);
    run_case("HEADERS after WT_CLOSE_SESSION", make_wt({}), default_client(), t_headers_after_close);
    run_case("1 MiB through a 32 KiB client window", make_wt({}), make_client({.data = 32 * 1024}), t_bulk_transfer_credit);
    // Resets
    run_case("server reset code 7", make_wt({}), make_client({.data = 1}), t_server_reset_code);
    run_case("client reset code 7", make_wt({}), default_client(), t_client_reset_code);
    run_case("client STOP_SENDING", make_wt({}), make_client({.data = 4096, .stream_data = 4}), t_client_stop_sending);
    run_case("STOP_SENDING wakes session-credit wait", make_wt({}), make_client({.data = 4096}), t_stop_credit_wait);
    run_case("QUIC open failure preserves session quota", make_wt({}), make_client({.bidi = 1, .quic_bidi = 0}), t_quic_open_limit);
    run_case("reverse reset session flow control", make_wt({.data = 10}), default_client(), t_reverse_reset_flow);
    // Termination
    run_case("client close capsule", make_wt({}), default_client(), t_client_close_capsule);
    run_case("server close capsule", make_wt({}), default_client(), t_server_close_capsule);
    run_case("client FIN ends pending accept", make_wt({}), default_client(), t_client_fin_ends_pending_accept);
    run_case("handler return sends FIN", make_wt({}), default_client(), t_handler_return_fin);
    // Buffering
    run_case("streams and datagrams before response", make_wt({}), default_client(), t_buffered_before_response);
    run_case("buffered stream limit", make_wt({.buffered_streams = 1}), default_client(), t_buffer_limit);
    run_case("stream for a rejected session", make_wt({}), default_client(), t_session_gone_stream);
    // Cancellation
    run_case("pending operations end on connection close", make_wt({}), default_client(), t_pending_ops_on_connection_close);
    run_case("server close with active session", make_wt({}), default_client(), t_server_close_active_sessions);
    // Resources
    run_case("200 sessions on one connection", make_wt({}), default_client(), t_many_sessions_sequential);
    std::puts("HTTP/3 WebTransport tests passed");
    return 0;
}
