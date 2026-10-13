#pragma once

#include "eventloop/ip_endpoint.h"
#include "eventloop/task.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>

namespace eventloop {

// Public loop-affine QUIC surface. All operations are called and completed on
// the endpoint's owning event-loop thread. Connections are owned by their
// endpoint in bounded slots; quic_connection is a move-only handle that
// must not outlive the endpoint. Caller buffers passed to stream/datagram
// operations remain valid until the awaited operation completes, including
// cancellation. H3/WebTransport/0-RTT are out of scope.
enum class quic_role { client, server };

enum class quic_version { v1, v2 };

enum class quic_stream_direction { bidirectional, unidirectional };

// Zero is reserved for success, as std::error_code requires.
enum class quic_errc {
    invalid_argument = 1,
    invalid_state,
    capacity_exceeded,
    not_connected,
    wrong_loop,
    stream_limit,
    stream_reset,
    peer_closed,
    datagram_not_supported,
    output_too_small,
    tls_failure,
};

[[nodiscard]] auto make_error_code(quic_errc value) noexcept -> std::error_code;

} // namespace eventloop

namespace std {
template<>
struct is_error_code_enum<eventloop::quic_errc> : true_type {};
} // namespace std

namespace eventloop {

// Requested limits advertised in the QUIC transport parameters. Receive data
// windows are capped to reserved storage: 4 KiB per stream and 128 KiB per
// connection. Smaller requests are preserved. Consuming data replenishes these
// windows, so they do not limit the total stream or connection transfer size.
// Active streams are capped to 32 bidirectional and 8 unidirectional streams
// per initiator. Local opens also obey the peer's cumulative MAX_STREAMS grant.
// Completed streams release storage after final ACK and receive completion;
// the endpoint sends new MAX_STREAMS credit for retired peer streams.
// Unset datagram size (0) disables RFC 9221 DATAGRAM negotiation.
struct quic_transport_limits {
    std::uint64_t max_idle_timeout_ms {30000};
    std::uint64_t max_data {1024 * 1024};
    std::uint64_t max_stream_data {64 * 1024};
    std::uint64_t max_streams_bidi {32};
    std::uint64_t max_streams_uni {8};
    std::uint64_t max_datagram_frame_size {0};
    // Maximum UDP payload advertised and used for application packets, clamped
    // to 1200..8192 and negotiated down to the peer's advertised limit. The
    // default is the standard Ethernet payload (1500 MTU) because path MTU
    // discovery is not implemented; constrained paths may lower it. Handshake
    // packets remain bounded at 1200 so anti-amplification is unaffected.
    std::uint64_t max_udp_payload_size {1472};
};

namespace quic::detail { struct worker_group_access; }

// Connects server endpoints on different loops that share a port, so each
// forwards packets for connections another endpoint owns (see docs/quic.md).
// Construct once and pass it to every endpoint; endpoints may use it from
// any thread.
class quic_worker_group {
public:
    // workers is 1..256; anything else throws std::invalid_argument.
    explicit quic_worker_group(std::size_t workers);
    ~quic_worker_group();
    quic_worker_group(const quic_worker_group&) = delete;
    auto operator=(const quic_worker_group&) -> quic_worker_group& = delete;

    [[nodiscard]] auto workers() const noexcept -> std::size_t;

private:
    friend struct quic::detail::worker_group_access;
    class implementation;
    std::unique_ptr<implementation> implementation_;
};

struct quic_server_options {
    std::filesystem::path certificate_chain;
    std::filesystem::path private_key;
    std::span<const std::uint8_t> alpn;
    quic_transport_limits limits {};
    // Reserved at endpoint construction; 1..256. Exhaustion rejects a new connection.
    std::size_t connection_capacity {8};
    // SO_REUSEPORT, so one endpoint per loop can share a port. Delivery to the
    // owning endpoint relies on the kernel's address hash; see docs/quic.md.
    bool reuse_port {false};
    // When set, the first byte of every connection ID this endpoint issues,
    // so a steering layer can find the owning endpoint. Unset keeps the
    // connection ID fully random.
    std::optional<std::uint8_t> worker_index {};
    // Forwards misrouted packets between endpoints sharing the port. Requires
    // worker_index below the group's size, unique among open endpoints.
    std::shared_ptr<quic_worker_group> worker_group {};
};

struct quic_client_options {
    std::span<const std::uint8_t> alpn;
    quic_transport_limits limits {};
    std::filesystem::path trusted_ca; // empty uses the system trust store
    quic_version version {quic_version::v1};
};

class quic_endpoint;

class [[nodiscard]] quic_connection {
public:
    quic_connection() noexcept = default;
    ~quic_connection() = default;
    quic_connection(quic_connection&& other) noexcept;
    auto operator=(quic_connection&& other) noexcept -> quic_connection&;
    quic_connection(const quic_connection&) = delete;
    auto operator=(const quic_connection&) -> quic_connection& = delete;

    [[nodiscard]] auto valid() const noexcept -> bool;
    [[nodiscard]] auto remote_endpoint() const noexcept -> ip_endpoint;

    // Client-initiated streams only. Server-initiated streams arrive through
    // async_accept_stream().
    [[nodiscard]] auto async_open_stream(quic_stream_direction direction)
        -> task<std::expected<std::uint64_t, std::error_code>>;
    [[nodiscard]] auto async_accept_stream()
        -> task<std::expected<std::uint64_t, std::error_code>>;
    // A zero-byte read means the peer closed its side (FIN). The buffer is
    // caller-owned and must remain valid until the await completes.
    [[nodiscard]] auto async_read(std::uint64_t stream_id,
                                  std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Returns the accepted byte count, which can be smaller than the buffer.
    // Retry the remainder; fin closes the send side only when all supplied
    // bytes are accepted. The buffer remains borrowed through completion.
    [[nodiscard]] auto async_write(std::uint64_t stream_id,
                                   std::span<const std::byte> buffer, bool fin)
        -> task<std::expected<std::size_t, std::error_code>>;
    // RFC 9221 DATAGRAMs. Both fail with quic_errc::datagram_not_supported
    // when DATAGRAM was not negotiated in that direction. Send fails with
    // quic_errc::invalid_argument for a payload that cannot fit one packet at
    // the connection's current datagram size, and waits only while the queue
    // is full. Receive waits only while the queue is empty and fails with
    // quic_errc::output_too_small, leaving the DATAGRAM queued, when the
    // buffer is smaller than the next one.
    [[nodiscard]] auto async_send_datagram(std::span<const std::byte> payload)
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] auto async_receive_datagram(std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Abandons the send side with RESET_STREAM and an application error code
    // (at most 2^62-1). Queued bytes not yet transmitted are discarded and
    // later writes fail with quic_errc::stream_reset. A send side that already
    // ended in a reset or fully acknowledged data is left unchanged. Unknown or
    // receive-only streams return quic_errc::invalid_argument.
    [[nodiscard]] auto reset_stream(std::uint64_t stream_id,
                                    std::uint64_t error_code) noexcept
        -> std::expected<void, std::error_code>;
    // Asks the peer to stop sending with STOP_SENDING and an application error
    // code. Buffered and later data on the stream are discarded, the peer's
    // RESET_STREAM is consumed internally, and later reads fail with
    // quic_errc::invalid_state. Unknown or send-only streams return
    // quic_errc::invalid_argument.
    [[nodiscard]] auto stop_sending(std::uint64_t stream_id,
                                    std::uint64_t error_code) noexcept
        -> std::expected<void, std::error_code>;
    // Requests a graceful close. The endpoint slot is released once the driver
    // retires; await valid() to observe release. One transport CONNECTION_CLOSE
    // with NO_ERROR is sent first; it is not retransmitted.
    auto close(std::error_code reason = {}) noexcept -> void;
    // Closes like close(), sending an application CONNECTION_CLOSE with
    // error_code instead (APPLICATION_ERROR before 1-RTT keys exist); codes
    // above 2^62-1 are clamped. The first close requested wins.
    auto close_application(std::uint64_t error_code) noexcept -> void;

    // Internal: constructs a handle into an endpoint-owned slot. Only
    // quic_endpoint produces valid handles.
    quic_connection(quic_endpoint* endpoint, std::size_t slot,
                    std::uint32_t generation) noexcept;

private:
    friend class quic_endpoint;

    quic_endpoint* endpoint_ {};
    std::size_t slot_ {};
    std::uint32_t generation_ {};
};

class quic_endpoint {
public:
    // The caller must construct, run, and destroy the endpoint on one loop
    // thread. The TLS context is built from the supplied certificate/key.
    quic_endpoint(event_loop& loop, ip_endpoint local, quic_server_options options);
    // Client endpoint. The TLS context trusts trusted_ca, or the system store
    // when trusted_ca is empty.
    quic_endpoint(event_loop& loop, ip_endpoint local, quic_client_options options);
    ~quic_endpoint();
    quic_endpoint(const quic_endpoint&) = delete;
    auto operator=(const quic_endpoint&) -> quic_endpoint& = delete;

    [[nodiscard]] auto local_endpoint() const noexcept -> ip_endpoint;
    // Resolves when a new accepted connection completes its handshake. A
    // connection that fails or is closed by its peer before acceptance
    // reports its own error instead, and acceptance continues; after close(),
    // or when cancelled, it reports operation_canceled.
    [[nodiscard]] auto async_accept()
        -> task<std::expected<quic_connection, std::error_code>>;
    // Starts a client connection to server and resolves once the handshake
    // completes. server_name is used for SNI and certificate verification.
    [[nodiscard]] auto async_connect(ip_endpoint server, std::string_view server_name)
        -> task<std::expected<quic_connection, std::error_code>>;
    // Stops accepting, stops every connection pump, and resolves once all
    // endpoint-owned tasks have retired. Must be awaited before destruction.
    [[nodiscard]] auto async_close() -> task<void>;
    auto close() noexcept -> void;

    // Internal: defined under src/quic. Public only so out-of-line helpers can
    // name it.
    class implementation;

private:
    friend class quic_connection;
    std::unique_ptr<implementation> implementation_;
};

} // namespace eventloop
