// Test-only raw HTTP/3 client for WebTransport over HTTP/3 (draft-16). It drives
// quic_endpoint directly, so tests can send exact bytes, malformed frames, and
// capsules that the server must reject. Everything runs on the owning loop.
#pragma once

#include "eventloop/event_loop.h"
#include "eventloop/quic.h"
#include "eventloop/task.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace eventloop::webtransport_fixture {

inline constexpr std::array<std::uint8_t, 2> h3_alpn {'h', '3'};

// SETTINGS the client advertises. Disabled or unset entries are omitted.
struct client_settings {
    bool connect_protocol {true};
    bool h3_datagram {true};
    bool wt_enabled {true};
    std::optional<std::uint64_t> initial_max_data {1024 * 1024};
    std::optional<std::uint64_t> initial_max_streams_bidi {16};
    std::optional<std::uint64_t> initial_max_streams_uni {16};
};

struct client_options {
    // Defaults satisfy the WebTransport requirements; tests override them to
    // exercise the negative cases.
    quic_transport_limits limits {.max_datagram_frame_size = 1232, .reset_stream_at = true};
    client_settings settings {};
    std::filesystem::path trusted_ca;
};

// SETTINGS the server sent on its control stream; absent entries are nullopt.
struct server_settings {
    bool received {false};
    std::optional<std::uint64_t> connect_protocol;
    std::optional<std::uint64_t> h3_datagram;
    std::optional<std::uint64_t> wt_enabled;
    std::optional<std::uint64_t> initial_max_data;
    std::optional<std::uint64_t> initial_max_streams_bidi;
    std::optional<std::uint64_t> initial_max_streams_uni;
};

// Fields of an Extended CONNECT (or ordinary) request. Empty views are omitted
// from the request: protocol, origin, available_protocols, extra_name.
struct request_options {
    std::string_view method {"CONNECT"};
    std::string_view protocol {"webtransport-h3"};
    std::string_view scheme {"https"};
    std::string_view authority {"localhost"};
    std::string_view path {"/echo"};
    std::string_view origin {};
    std::string_view available_protocols {};
    // One more field, for example sec-websocket-version on a WebSocket request.
    std::string_view extra_name {};
    std::string_view extra_value {};
};

// The response HEADERS of a request stream.
struct response_head {
    unsigned status {0};
    std::optional<std::string> wt_protocol;
};

// One WebTransport capsule read from a CONNECT stream.
struct capsule {
    enum class kind {
        end, // FIN on the CONNECT stream
        close_session,
        drain_session,
        max_data,
        max_streams_bidi,
        max_streams_uni,
        data_blocked,
        streams_blocked_bidi,
        streams_blocked_uni,
        datagram,
    };
    kind type {kind::end};
    std::uint64_t value {0};   // the maximum, or the datagram payload size
    std::uint32_t code {0};    // WT_CLOSE_SESSION application code
    std::string reason;        // WT_CLOSE_SESSION message
};

// A stream the server opened: a WebTransport uni stream (type 0x54) or bidi
// signal (0x41), with its session ID read from the header.
struct peer_stream {
    std::uint64_t id {0};
    std::uint64_t type {0};
    std::uint64_t session_id {0};
};

struct datagram {
    std::uint64_t session_id {0};
    std::vector<std::byte> payload;
};

// Pure encoders and decoders, usable without a connection.
[[nodiscard]] auto encode_settings_frame(const client_settings& settings,
    std::span<std::byte> output) noexcept -> std::expected<std::size_t, std::error_code>;
[[nodiscard]] auto encode_request(const request_options& request,
    std::span<std::byte> output) noexcept -> std::expected<std::size_t, std::error_code>;
[[nodiscard]] auto decode_response(std::span<const std::byte> field_block)
    -> std::expected<response_head, std::error_code>;

class webtransport_client;
struct stream_state;
struct client_core;

// A request stream: the CONNECT stream of a session, or an ordinary request.
// Owns the frame reader state for that stream; reads must go through the
// client, and one read may be pending at a time.
class request_stream {
public:
    request_stream() noexcept;
    ~request_stream();
    request_stream(request_stream&& other) noexcept;
    auto operator=(request_stream&& other) noexcept -> request_stream&;
    request_stream(const request_stream&) = delete;
    auto operator=(const request_stream&) -> request_stream& = delete;

    [[nodiscard]] auto id() const noexcept -> std::uint64_t;

    // Wraps a stream the client has already opened; used by the client.
    explicit request_stream(std::uint64_t id);

private:
    friend class webtransport_client;
    std::unique_ptr<stream_state> state_;
};

class webtransport_client {
public:
    webtransport_client(event_loop& loop, ip_endpoint local, client_options options);
    webtransport_client(const webtransport_client&) = delete;
    auto operator=(const webtransport_client&) -> webtransport_client& = delete;
    // async_close() must have completed.
    ~webtransport_client();

    // Handshake, then the control stream (with SETTINGS) and both QPACK streams.
    [[nodiscard]] auto async_connect(ip_endpoint server)
        -> task<std::expected<void, std::error_code>>;
    // Reads the server's control stream until its SETTINGS arrive.
    [[nodiscard]] auto async_wait_server_settings()
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] auto peer_settings() const noexcept -> const server_settings&;
    [[nodiscard]] auto connection() noexcept -> quic_connection&;
    // Closes the connection and the endpoint.
    [[nodiscard]] auto async_close() -> task<void>;

    // Sends a request HEADERS frame on a new bidi stream.
    [[nodiscard]] auto async_send_request(const request_options& request)
        -> task<std::expected<request_stream, std::error_code>>;
    // Reads the first HEADERS frame on the stream.
    [[nodiscard]] auto async_read_response(request_stream& stream)
        -> task<std::expected<response_head, std::error_code>>;
    // Reads DATA payload bytes, skipping other frames. 0 is the FIN.
    [[nodiscard]] auto async_read_body(request_stream& stream, std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Reads the next capsule from DATA payload; kind::end at FIN.
    [[nodiscard]] auto async_read_capsule(request_stream& stream)
        -> task<std::expected<capsule, std::error_code>>;
    // Wraps capsule bytes in one DATA frame and writes it.
    [[nodiscard]] auto async_send_capsule(request_stream& stream,
                                          std::span<const std::byte> capsule_bytes)
        -> task<std::expected<void, std::error_code>>;
    // Writes raw bytes on the stream, bypassing frame encoding.
    [[nodiscard]] auto async_write_raw(request_stream& stream, std::span<const std::byte> bytes,
                                       bool fin = false)
        -> task<std::expected<void, std::error_code>>;

    // Opens a client-initiated WebTransport stream and writes its header.
    [[nodiscard]] auto async_open_stream(std::uint64_t session_id, bool bidirectional)
        -> task<std::expected<std::uint64_t, std::error_code>>;
    // Writes every byte, retrying partial acceptances; fin closes the send side.
    [[nodiscard]] auto async_write_all(std::uint64_t stream_id,
                                       std::span<const std::byte> bytes, bool fin = false)
        -> task<std::expected<void, std::error_code>>;
    // Reads until FIN or until buffer is full; returns the byte count.
    [[nodiscard]] auto async_read_all(std::uint64_t stream_id, std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Accepts the next server-opened stream and parses its WebTransport header.
    [[nodiscard]] auto async_accept_peer_stream()
        -> task<std::expected<peer_stream, std::error_code>>;

    // HTTP Datagrams: the quarter stream ID prefix is added or parsed here.
    [[nodiscard]] auto async_send_datagram(std::uint64_t session_id,
                                           std::span<const std::byte> payload)
        -> task<std::expected<void, std::error_code>>;
    // Sends the bytes as one QUIC DATAGRAM with no prefix.
    [[nodiscard]] auto async_send_raw_datagram(std::span<const std::byte> bytes)
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] auto async_receive_datagram()
        -> task<std::expected<datagram, std::error_code>>;
    [[nodiscard]] auto async_receive_raw_datagram()
        -> task<std::expected<std::vector<std::byte>, std::error_code>>;

private:
    event_loop& loop_;
    std::unique_ptr<client_core> core_;
};

} // namespace eventloop::webtransport_fixture
