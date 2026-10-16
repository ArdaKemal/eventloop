#pragma once

// Per-connection WebTransport engine (draft-16 and browser draft-07), server
// role. server.cc owns one per connection slot, created with the server when
// server_options::webtransport.enabled, and drives it through the methods
// below; the public webtransport_session / webtransport_stream handles
// forward here. Everything runs on the connection's owning loop.

#include "eventloop/http/webtransport.h"
#include "eventloop/quic.h"
#include "eventloop/task.h"

#include "request_stream.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

namespace eventloop::http3::detail { struct peer_critical_streams; }

namespace eventloop::http::detail {

class webtransport_connection {
public:
    // Reserves every table and buffer for one connection: sessions,
    // per-session datagram queues and capsule buffers, the stream table, and
    // the buffered-stream/datagram slots. Throws std::invalid_argument for
    // options outside their documented ranges.
    webtransport_connection(event_loop& loop, const webtransport_options& options);
    ~webtransport_connection();
    webtransport_connection(const webtransport_connection&) = delete;
    auto operator=(const webtransport_connection&) -> webtransport_connection& = delete;

    // --- Connection lifecycle (serve_connection) ---

    // Starts serving a new connection. critical is the connection's peer
    // SETTINGS record; the engine installs its on_settings hook there.
    // request_open(context, id) reports whether a request stream with that ID
    // is still being served (used to decide whether a stream/datagram for an
    // unknown session ID may still find its session). Spawns the datagram
    // dispatcher. Returns false if the dispatcher frame cannot be allocated
    // (the caller then closes the connection with H3_INTERNAL_ERROR).
    [[nodiscard]] auto attach(quic_connection& connection,
                              http3::detail::peer_critical_streams& critical,
                              bool (*request_open)(void* context, std::uint64_t id) noexcept,
                              void* context) noexcept -> bool;
    // Ends every session (remote = true, as if the connection closed), fails
    // pending operations with session_closed, cancels and awaits every task
    // the engine spawned, and resets the tables for the next connection.
    // Called once per attach(), after request tasks were cancelled and
    // awaited, before the connection handle is released.
    [[nodiscard]] auto shutdown() -> task<void>;

    // --- Peer data streams ---

    // A client bidirectional stream began with WT_STREAM 0x41 + session ID;
    // body holds bytes already read after the header (at most 16). header is
    // the header length in bytes. Validates the session ID (H3_ID_ERROR closes
    // the connection), then queues the stream on its session, buffers it, or
    // refuses it (WT_BUFFERED_STREAM_REJECTED / WT_SESSION_GONE / session
    // flow-control error). Never blocks.
    auto peer_bidirectional(std::uint64_t stream_id, std::uint64_t session_id,
                            std::size_t header, std::span<const std::byte> body) noexcept -> void;
    // Same for a client unidirectional stream of type 0x54.
    auto peer_unidirectional(std::uint64_t stream_id, std::uint64_t session_id,
                             std::size_t header, std::span<const std::byte> body) noexcept -> void;
    // A request stream finished being served. Buffered streams and datagrams
    // that named it as their session, when it did not become a session, are
    // refused with WT_SESSION_GONE / dropped.
    auto request_finished(std::uint64_t request_id) noexcept -> void;

    // --- Session establishment (negotiated WebTransport CONNECT protocol) ---

    enum class admission {
        accepted,
        // Session table full, or a second session while flow control is
        // disabled: reset the CONNECT stream with H3_REQUEST_REJECTED.
        rejected,
        // Client SETTINGS, transport parameters, or CONNECT token do not
        // meet the negotiated version's requirements:
        // the request is malformed, H3_MESSAGE_ERROR.
        malformed,
        // The connection ended or the waiting task was cancelled.
        cancelled,
    };
    // Reserves a session slot for connect_id, waits until the client's
    // SETTINGS have arrived (draft-16 3.1, draft-version negotiation rule),
    // and checks the requirements and session limits. On accepted, *slot
    // holds the reservation, which the caller must hand to establish() or
    // release(). draft07 requires the legacy token/settings and no mutual
    // draft-16 support; otherwise draft-16's RESET_STREAM_AT is mandatory.
    [[nodiscard]] auto admit(std::uint64_t connect_id, std::uint32_t& slot,
                              bool draft07 = false) -> task<admission>;
    // The route handler accepted: the 2xx response has been written.
    // request_frames holds the CONNECT stream parser (already switched to
    // accept_connect()) and pending the unparsed bytes already read after the
    // request HEADERS; both are copied, then the capsules in pending are
    // processed. protocol is the selected WT-Protocol (copied). Spawns the
    // session's CONNECT-stream reader and capsule writer, moves buffered
    // streams and datagrams to the session. Fails with capacity_exceeded if a
    // task frame cannot be allocated (the caller resets the CONNECT stream
    // with H3_INTERNAL_ERROR).
    [[nodiscard]] auto establish(std::uint32_t slot, const http3::detail::request_frames& frames,
                                 std::span<const std::byte> pending, std::string_view protocol)
        -> std::expected<webtransport_session, std::error_code>;
    // Drops a reservation that was never established.
    auto release(std::uint32_t slot) noexcept -> void;
    // The route handler returned. An open session closes as with code 0 (FIN
    // on the CONNECT stream; streams reset with WT_SESSION_GONE). The slot is
    // reused once its handle, reader, writer, and pending operations retire. Never blocks.
    auto handler_returned(std::uint32_t slot) noexcept -> void;

private:
    friend struct webtransport_access;
    class state;
    std::unique_ptr<state> state_;
};

} // namespace eventloop::http::detail
