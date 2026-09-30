#pragma once

#include "eventloop/ip_endpoint.h"
#include "eventloop/task.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>

namespace eventloop {

// Public loop-affine QUIC surface. All operations are called and completed on
// the endpoint's owning event-loop thread. Connections are owned by their
// endpoint in fixed-capacity slots; quic_connection is a move-only handle that
// must not outlive the endpoint. Caller buffers passed to stream/datagram
// operations remain valid until the awaited operation completes, including
// cancellation. H3/WebTransport/0-RTT are out of scope.
enum class quic_role { client, server };

enum class quic_version { v1, v2 };

enum class quic_stream_direction { bidirectional, unidirectional };

enum class quic_errc {
    invalid_argument,
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
// Unset datagram size (0) disables RFC 9221 DATAGRAM negotiation.
struct quic_transport_limits {
    std::uint64_t max_idle_timeout_ms {30000};
    std::uint64_t max_data {1024 * 1024};
    std::uint64_t max_stream_data {64 * 1024};
    std::uint64_t max_streams_bidi {32};
    std::uint64_t max_streams_uni {8};
    std::uint64_t max_datagram_frame_size {0};
};

struct quic_server_options {
    std::filesystem::path certificate_chain;
    std::filesystem::path private_key;
    std::span<const std::uint8_t> alpn;
    quic_transport_limits limits {};
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
    // Writes a full buffer; fin closes the send side. Returns the accepted
    // byte count unless cancelled.
    [[nodiscard]] auto async_write(std::uint64_t stream_id,
                                   std::span<const std::byte> buffer, bool fin)
        -> task<std::expected<std::size_t, std::error_code>>;
    [[nodiscard]] auto async_send_datagram(std::span<const std::byte> payload)
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] auto async_receive_datagram(std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Requests a graceful close. The endpoint slot is released once the driver
    // retires; await valid() to observe release.
    auto close(std::error_code reason = {}) noexcept -> void;

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
    // Resolves when a new accepted connection completes its handshake.
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
