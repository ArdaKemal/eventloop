// WebTransport echo routes shared by examples/webtransport_echo_server.cc and
// tests/http3_webtransport_example.cc. "/echo" accepts a session (protocol
// echo/1 when offered), echoes every bidi stream, answers each uni stream on a
// new server uni stream, and echoes datagrams.
#pragma once

#include "eventloop/event_loop.h"
#include "eventloop/http/request.h"
#include "eventloop/http/response.h"
#include "eventloop/http/webtransport.h"
#include "eventloop/task.h"
#include "eventloop/task_composition.h"

#include <array>
#include <cstddef>
#include <expected>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

namespace webtransport_echo {

inline constexpr std::array<std::string_view, 1> protocols {"echo/1"};

// Writes all of bytes, retrying partial writes; false once the peer stops reading.
inline auto write_all([[maybe_unused]] eventloop::event_loop& loop,
                      eventloop::http::webtransport_stream& stream,
                      std::span<const std::byte> bytes, bool fin)
    -> eventloop::task<bool>
{
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        auto sent = eventloop::flatten_result(co_await stream.async_write(bytes.subspan(offset), false));
        if (!sent) co_return false;
        offset += *sent;
    }
    if (fin) {
        auto closed = eventloop::flatten_result(co_await stream.async_write({}, true));
        if (!closed) co_return false;
    }
    co_return true;
}

inline auto echo_stream(eventloop::event_loop& loop, eventloop::http::webtransport_session& session,
                        eventloop::http::webtransport_stream stream) -> eventloop::task<void>
{
    std::vector<std::byte> buffer(2048);
    eventloop::http::webtransport_stream reply;
    if (stream.direction() == eventloop::quic_stream_direction::unidirectional) {
        auto opened = eventloop::flatten_result(
            co_await session.async_open_stream(eventloop::quic_stream_direction::unidirectional));
        if (!opened) co_return;
        reply = std::move(*opened);
    }
    auto& output = reply.valid() ? reply : stream;
    for (;;) {
        auto count = eventloop::flatten_result(co_await stream.async_read(buffer));
        if (!count) co_return;
        if (*count == 0) {
            (void)co_await write_all(loop, output, {}, true);
            co_return;
        }
        auto written = co_await write_all(loop, output, std::span<const std::byte>(buffer).first(*count), false);
        if (!written || !*written) co_return;
    }
}

inline auto echo_datagrams(eventloop::event_loop&, eventloop::http::webtransport_session& session)
    -> eventloop::task<void>
{
    std::vector<std::byte> buffer(1500);
    for (;;) {
        auto size = eventloop::flatten_result(co_await session.async_receive_datagram(buffer));
        if (!size) co_return;
        (void)co_await session.async_send_datagram(std::span<const std::byte>(buffer).first(*size));
    }
}

inline auto echo_session(eventloop::event_loop& loop, eventloop::http::request& request,
                         eventloop::http::response&) -> eventloop::task<void>
{
    auto accepted = eventloop::flatten_result(co_await request.async_accept_webtransport(protocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    eventloop::task_handle<void> datagrams;
    if (loop.spawn(echo_datagrams(loop, session), datagrams) != eventloop::task_spawn_result::accepted)
        co_return;
    for (;;) {
        auto stream = eventloop::flatten_result(co_await session.async_accept_stream());
        if (!stream) break;
        co_await echo_stream(loop, session, std::move(*stream));
    }
    co_await datagrams;
}

} // namespace webtransport_echo
