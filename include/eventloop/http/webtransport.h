#pragma once

#include "eventloop/quic.h"
#include "eventloop/task.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>

namespace eventloop::http {

// WebTransport over HTTP/3 (draft-ietf-webtrans-http3-16), server role.
// Enable it with server_options::webtransport on an http3_server with routes;
// a route handler accepts an Extended CONNECT request whose :protocol is
// webtransport-h3 with request::async_accept_webtransport(). See
// docs/webtransport.md.
//
// Zero is reserved for success, as std::error_code requires.
enum class webtransport_errc {
    // The session ended: closed by either side, its CONNECT stream ended or
    // was reset, or the connection closed. close_info() tells why.
    session_closed = 1,
    // The peer reset this stream (read) or asked it to stop (write);
    // webtransport_stream::error_code() has the peer's application code.
    stream_reset,
    // The stream was reset or stopped locally.
    stream_closed,
    // A bounded queue, table, or waiter pool is full.
    capacity_exceeded,
    // A datagram larger than max_datagram_size(), or a receive buffer smaller
    // than the next datagram (which stays queued).
    datagram_size,
    // The peer violated session flow control; the session is closed.
    flow_control_error,
};

[[nodiscard]] auto make_error_code(webtransport_errc value) noexcept -> std::error_code;

} // namespace eventloop::http

namespace std {
template<>
struct is_error_code_enum<eventloop::http::webtransport_errc> : true_type {};
} // namespace std

namespace eventloop::http {

// Per-connection limits; fixed storage is reserved for each connection when
// the server is constructed.
struct webtransport_options {
    bool enabled {false};
    // Concurrent sessions per HTTP/3 connection, 1..16. A CONNECT beyond it
    // is refused with H3_REQUEST_REJECTED. When the client does not enable
    // session flow control the limit is one session (draft-16 5.1).
    std::size_t max_sessions {4};
    // Initial session limits advertised in SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI,
    // _UNI and _MAX_DATA. Credit is renewed as the application consumes data
    // and peer streams finish. Bidirectional streams are capped at 100 and
    // unidirectional at 8 per connection by QUIC; values must be below 2^60.
    std::uint64_t initial_max_streams_bidi {32};
    std::uint64_t initial_max_streams_uni {8};
    std::uint64_t initial_max_data {256 * 1024};
    // Received datagrams queued per session, 1..64; a full queue drops new
    // datagrams. Payloads are limited to 1200 bytes in each direction.
    std::size_t datagram_queue {8};
    // Streams and datagrams that arrive before their session is established,
    // per connection, 0..64 each. Excess streams are refused with
    // WT_BUFFERED_STREAM_REJECTED; excess datagrams are dropped.
    std::size_t buffered_streams {8};
    std::size_t buffered_datagrams {8};
};

// The terminal state of a session.
struct webtransport_close_info {
    // The 32-bit application code from WT_CLOSE_SESSION, 0 for a clean close
    // without one.
    std::uint32_t code {0};
    // The UTF-8 message from WT_CLOSE_SESSION, at most 1024 bytes. Valid until
    // the session handle is destroyed.
    std::string_view reason {};
    // True when the peer closed or reset the session (or the connection ended);
    // false when it was closed locally.
    bool remote {false};
};

namespace detail { class webtransport_connection; struct webtransport_access; }

// One WebTransport stream. It is a handle into its connection's bounded
// stream table: move-only, used on the owning loop, and valid until the
// session ends.
// One read and one write may be pending at a time; spans are borrowed through
// completion, including cancellation.
class webtransport_stream {
public:
    webtransport_stream() noexcept = default;
    webtransport_stream(webtransport_stream&& other) noexcept;
    auto operator=(webtransport_stream&& other) noexcept -> webtransport_stream&;
    webtransport_stream(const webtransport_stream&) = delete;
    auto operator=(const webtransport_stream&) -> webtransport_stream& = delete;
    // Abandons any direction still open: RESET_STREAM_AT and STOP_SENDING
    // with application code 0.
    ~webtransport_stream();

    [[nodiscard]] auto valid() const noexcept -> bool;
    // The QUIC stream ID.
    [[nodiscard]] auto id() const noexcept -> std::uint64_t;
    [[nodiscard]] auto direction() const noexcept -> quic_stream_direction;
    // Whether this endpoint opened the stream.
    [[nodiscard]] auto local() const noexcept -> bool;

    // Reads stream body bytes; 0 is the peer's FIN. Fails on a send-only
    // stream with invalid_argument.
    [[nodiscard]] auto async_read(std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Returns the bytes accepted, possibly fewer than supplied, waiting while
    // session flow control or the stream's send buffer is full. fin ends the
    // stream when every supplied byte is accepted. Fails on a receive-only
    // stream with invalid_argument.
    [[nodiscard]] auto async_write(std::span<const std::byte> buffer, bool fin = false)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Abandons sending with RESET_STREAM_AT, keeping the stream header
    // reliable (draft-16 4.4). A finished send side is unchanged.
    auto reset(std::uint32_t code) noexcept -> std::expected<void, std::error_code>;
    // Asks the peer to stop sending with STOP_SENDING.
    auto stop_sending(std::uint32_t code) noexcept -> std::expected<void, std::error_code>;
    // After stream_reset: the peer's 32-bit application code, or nullopt when
    // its HTTP/3 code is outside the WebTransport application range.
    [[nodiscard]] auto error_code() const noexcept -> std::optional<std::uint32_t>;

private:
    friend struct detail::webtransport_access;
    detail::webtransport_connection* connection_ {nullptr};
    std::uint32_t slot_ {0};
    std::uint32_t generation_ {0};
};

// An accepted WebTransport session, borrowed from its route handler: keep it
// and every operation on it inside that handler. Returning from the handler,
// or destroying the session, ends it like close() with code 0. All operations
// run on the owning loop; spans are borrowed through completion, including
// cancellation. One accept, one open, one datagram send, and one datagram
// receive may be pending at a time; another returns operation_in_progress.
// Pending operations fail with session_closed when the session ends.
class webtransport_session {
public:
    webtransport_session() noexcept = default;
    webtransport_session(webtransport_session&& other) noexcept;
    auto operator=(webtransport_session&& other) noexcept -> webtransport_session&;
    webtransport_session(const webtransport_session&) = delete;
    auto operator=(const webtransport_session&) -> webtransport_session& = delete;
    ~webtransport_session();

    [[nodiscard]] auto valid() const noexcept -> bool;
    // The session ID: the CONNECT stream's ID.
    [[nodiscard]] auto id() const noexcept -> std::uint64_t;
    // The protocol selected from WT-Available-Protocols, or empty.
    [[nodiscard]] auto protocol() const noexcept -> std::string_view;
    // Set once the session has ended.
    [[nodiscard]] auto close_info() const noexcept -> std::optional<webtransport_close_info>;
    // True after the peer sent WT_DRAIN_SESSION.
    [[nodiscard]] auto draining() const noexcept -> bool;
    // The largest datagram payload that can currently be sent.
    [[nodiscard]] auto max_datagram_size() const noexcept -> std::size_t;

    // Waits for the next peer-initiated stream, in arrival order.
    [[nodiscard]] auto async_accept_stream()
        -> task<std::expected<webtransport_stream, std::error_code>>;
    // Opens a stream, waiting while the peer's session stream limit is
    // reached. A QUIC stream limit reports capacity_exceeded at once: QUIC gives
    // no notification to wait on.
    [[nodiscard]] auto async_open_stream(quic_stream_direction direction)
        -> task<std::expected<webtransport_stream, std::error_code>>;
    // Queues one datagram; it may be lost. Waits only while the connection's
    // datagram send queue is full.
    [[nodiscard]] auto async_send_datagram(std::span<const std::byte> payload)
        -> task<std::expected<void, std::error_code>>;
    // Receives the next datagram, waiting while the session queue is empty.
    [[nodiscard]] auto async_receive_datagram(std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Sends WT_DRAIN_SESSION, asking the peer to finish soon.
    [[nodiscard]] auto async_drain() -> task<std::expected<void, std::error_code>>;
    // Sends WT_CLOSE_SESSION with code and reason (truncated at a UTF-8
    // boundary to 1024 bytes), ends the CONNECT stream, and resets every
    // stream of the session with WT_SESSION_GONE. Completes once the capsule
    // is queued; the session is closed when it returns.
    [[nodiscard]] auto async_close(std::uint32_t code = 0, std::string_view reason = {})
        -> task<std::expected<void, std::error_code>>;

private:
    friend struct detail::webtransport_access;
    detail::webtransport_connection* connection_ {nullptr};
    std::uint32_t slot_ {0};
    std::uint32_t generation_ {0};
};

// Maps between 32-bit WebTransport application error codes and the HTTP/3
// error codes carried on the wire (draft-16 4.4).
[[nodiscard]] constexpr auto webtransport_to_http3_error(std::uint32_t code) noexcept
    -> std::uint64_t
{
    return 0x52e4a40fa8dbULL + code + code / 0x1e;
}
[[nodiscard]] constexpr auto http3_to_webtransport_error(std::uint64_t code) noexcept
    -> std::optional<std::uint32_t>
{
    if (code < 0x52e4a40fa8dbULL || code > 0x52e5ac983162ULL || (code - 0x21) % 0x1f == 0)
        return std::nullopt;
    const auto shifted = code - 0x52e4a40fa8dbULL;
    return static_cast<std::uint32_t>(shifted - shifted / 0x1f);
}

} // namespace eventloop::http
