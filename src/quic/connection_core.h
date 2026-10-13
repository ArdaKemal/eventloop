#pragma once

#include "quic/connection_lifecycle.h"
#include "quic/crypto_send_buffer.h"
#include "quic/frame_policy.h"
#include "quic/key_update.h"
#include "quic/protected_packet.h"
#include "quic/received_packet_ranges.h"
#include "quic/tls_provider.h"

#include <thread>

namespace eventloop::quic::detail {

enum class connection_error {
    invalid_state, invalid_configuration, unavailable_keys, malformed_packet,
    authentication_failed, protocol_violation, capacity_exceeded, tls_failure,
    provider_failure, output_too_small, unsupported_frame,
    key_update_violation, aead_limit_reached,
};

// All callbacks execute synchronously on the owner thread and must not reenter
// the core. Frame views expire when receive() returns. ACK/stream/path/recovery
// processing is the owner's responsibility, and exhaustion must return false.
struct connection_callbacks {
    void* argument {};
    bool (*validate_parameters)(void*, std::span<const std::uint8_t>) noexcept {};
    bool (*frame)(void*, tls_level, const decoded_frame&) noexcept {};
};

// Internal TLS/packet orchestration, not an endpoint or complete QUIC engine.
// Construct, call and destroy on the owning loop thread. The owner supplies
// routing, anti-amplification, recovery, stream state and UDP transmission.
class connection_core {
public:
    static constexpr std::size_t crypto_capacity = 16384;
    static constexpr std::size_t receive_range_capacity = 128;
    explicit connection_core(endpoint_role role, connection_callbacks callbacks,
                             lifecycle_time_point started = {});
    ~connection_core();
    connection_core(const connection_core&) = delete;
    auto operator=(const connection_core&) -> connection_core& = delete;

    [[nodiscard]] auto initialize(SSL_CTX*, const tls_options&, std::uint32_t version,
        std::span<const std::uint8_t> original_dcid) -> std::expected<void, connection_error>;
    [[nodiscard]] auto advance(lifecycle_time_point now)
        -> std::expected<tls_progress, connection_error>;
    [[nodiscard]] auto state() const noexcept -> connection_state;
    [[nodiscard]] auto handshake_confirmed() const noexcept -> bool;
    // RFC 9287: local_grease_quic_bit is true when this endpoint advertised the
    // grease_quic_bit transport parameter, so a zero QUIC bit is accepted.
    // peer_grease_quic_bit becomes true only after the peer's authenticated
    // transport parameters are validated, permitting the bit to be greased on
    // send. The TLS adapter always appends the empty parameter, so local
    // support is enabled at initialize().
    [[nodiscard]] auto local_grease_quic_bit() const noexcept -> bool;
    [[nodiscard]] auto peer_grease_quic_bit() const noexcept -> bool;
    [[nodiscard]] auto keys_available(tls_level, tls_direction) const noexcept -> bool;
    // Inspect before build(); successful build() consumes this number.
    [[nodiscard]] auto next_packet_number(tls_level) const noexcept
        -> std::optional<std::uint64_t>;
    // RFC 9000 17.1 and A.2: the encoded length of the next packet number,
    // wide enough for twice the distance to the largest acknowledged number.
    // build() always uses it; callers padding Initial packets read it first.
    [[nodiscard]] auto packet_number_length(tls_level) const noexcept -> std::uint8_t;
    // Record the largest packet number the peer acknowledged at this level.
    auto packet_acknowledged(tls_level, std::uint64_t largest) noexcept -> void;
    // Apply a validated Retry before any authenticated response, preserving
    // TLS's exact ClientHello and the Initial packet-number send sequence.
    [[nodiscard]] auto apply_retry(std::span<const std::uint8_t>)
        -> std::expected<void, connection_error>;
    [[nodiscard]] auto initiate_key_update(lifecycle_time_point, lifecycle_duration)
        -> std::expected<void, key_update_error>;
    // ACKs must first be checked against successfully transmitted history.
    [[nodiscard]] auto acknowledge_application_packet(std::uint64_t,
        lifecycle_time_point, lifecycle_duration) noexcept
        -> std::expected<void, key_update_error>;
    // Call after successful UDP send. acknowledged_peer_packet is present only
    // when that packet's ACK covers peer_update_packet().
    [[nodiscard]] auto application_packet_sent(std::uint64_t,
        std::optional<std::uint64_t> acknowledged_peer_packet = {}) noexcept
        -> std::expected<void, key_update_error>;
    [[nodiscard]] auto peer_update_packet() const noexcept -> std::optional<std::uint64_t>;
    [[nodiscard]] auto application_key_phase() const noexcept -> bool;
    // Successful transmission hook for RFC 9001 encryption-level retirement.
    auto encryption_level_sent(tls_level) noexcept -> void;
    [[nodiscard]] auto level_discarded(tls_level) const noexcept -> bool;
    [[nodiscard]] auto next_crypto(tls_level, std::size_t maximum) const noexcept
        -> crypto_send_chunk;
    [[nodiscard]] auto next_crypto_probe(tls_level, std::size_t maximum,
        std::uint64_t from = 0) const noexcept
        -> crypto_send_chunk;
    [[nodiscard]] auto mark_crypto_sent(tls_level, std::uint64_t offset, std::size_t size)
        -> std::expected<void, connection_error>;
    [[nodiscard]] auto acknowledge_crypto(tls_level, std::uint64_t offset, std::size_t size)
        -> std::expected<void, connection_error>;
    [[nodiscard]] auto lose_crypto(tls_level, std::uint64_t offset, std::size_t size)
        -> std::expected<void, connection_error>;

    // fields.packet_number/version are replaced with this connection's values.
    // Successful construction consumes a PN, even if UDP subsequently fails.
    // The owner records sent frame ranges only after successful transmission.
    [[nodiscard]] auto build(protected_packet_fields fields,
        std::span<const std::uint8_t> payload, std::span<std::uint8_t> output,
        std::span<std::uint8_t> scratch) -> std::expected<std::size_t, connection_error>;
    // Returns the PN of the immediately preceding build() at this level when
    // its packet is discarded before transmission, so no PN gap is created.
    auto unbuild(tls_level) noexcept -> void;
    [[nodiscard]] auto receive(std::span<const std::uint8_t> datagram, std::size_t offset,
        std::size_t short_cid_length, std::span<std::uint8_t> packet_scratch,
        std::span<std::uint8_t> plaintext, std::span<std::uint8_t> auth_scratch,
        lifecycle_time_point now, lifecycle_duration pto)
        -> std::expected<opened_protected_packet, connection_error>;
    // Authentication-only 1-RTT inspection for candidate-path routing. Writes
    // caller scratch/plaintext and reuses EVP contexts, but does not commit
    // packet numbers, key updates, lifecycle/timers, failures or frame effects.
    // The owner must still pass accepted packets to receive() for processing.
    [[nodiscard]] auto authenticate_application_packet(
        std::span<const std::uint8_t> datagram, std::size_t offset,
        std::size_t short_cid_length, std::span<std::uint8_t> packet_scratch,
        std::span<std::uint8_t> plaintext, std::span<std::uint8_t> auth_scratch)
        -> std::expected<opened_protected_packet, connection_error>;
    [[nodiscard]] auto make_ack(tls_level, std::uint64_t delay,
        std::span<std::byte> storage) const
        -> std::expected<decoded_frame, received_packet_error>;
    [[nodiscard]] auto retire_ack(tls_level, std::uint64_t largest)
        -> std::expected<bool, received_packet_error>;
    [[nodiscard]] auto close_sent(lifecycle_time_point, lifecycle_duration) noexcept -> bool;
    // A verified stateless reset enters draining (RFC 9000 10.3.1).
    [[nodiscard]] auto stateless_reset(lifecycle_time_point, lifecycle_duration) noexcept -> bool;
    [[nodiscard]] auto poll(lifecycle_time_point, lifecycle_duration) noexcept -> bool;
    // Called by the owner only after a complete UDP datagram was transmitted.
    [[nodiscard]] auto packet_sent(lifecycle_time_point, bool ack_eliciting)
        noexcept -> bool;
    [[nodiscard]] auto next_deadline(lifecycle_duration current_pto) const noexcept
        -> std::optional<lifecycle_time_point>;
    [[nodiscard]] auto failure() const noexcept -> std::optional<connection_error>;
    // TLS alert raised by the local handshake, for CRYPTO_ERROR (0x100+alert).
    [[nodiscard]] auto tls_alert() const noexcept -> std::optional<std::uint8_t>
    { check_owner(); return tls_.alert(); }
    // Available before authenticated TLS transport-parameter validation runs.
    [[nodiscard]] auto peer_initial_source_cid() const noexcept
        -> std::optional<std::span<const std::byte>>
    {
        if (!peer_initial_source_cid_seen_) return {};
        return std::span(peer_initial_source_cid_).first(peer_initial_source_cid_size_);
    }

private:
    auto check_owner() const noexcept -> void;
    auto discard_level(tls_level) noexcept -> void;
    static auto send_crypto(void*, tls_level, std::span<const std::byte>) noexcept -> bool;
    static auto install_secret(void*, tls_level, tls_direction, std::uint16_t,
                               std::span<const std::uint8_t>) noexcept -> bool;
    auto fail(connection_error) noexcept -> std::unexpected<connection_error>;
    auto dispatch(tls_level, packet_kind, std::span<const std::byte>,
        lifecycle_time_point, lifecycle_duration) -> std::expected<void, connection_error>;
    std::thread::id owner_ {std::this_thread::get_id()};
    endpoint_role role_;
    connection_callbacks callbacks_;
    connection_lifecycle lifecycle_;
    std::array<std::array<std::byte, crypto_capacity>, 3> input_bytes_ {};
    std::array<std::array<std::byte, crypto_capacity / 8>, 3> coverage_ {};
    crypto_receive_buffer initial_ {input_bytes_[0], coverage_[0]};
    crypto_receive_buffer handshake_ {input_bytes_[1], coverage_[1]};
    crypto_receive_buffer application_ {input_bytes_[2], coverage_[2]};
    std::array<crypto_send_buffer<crypto_capacity>, 3> output_ {};
    std::array<received_packet_ranges<receive_range_capacity>, 3> received_ {};
    std::array<std::array<std::optional<aes_128_gcm_keys>, 2>, 3> keys_ {};
    std::array<std::uint64_t, 3> next_packet_number_ {};
    std::array<std::optional<std::uint64_t>, 3> largest_acknowledged_ {};
    std::array<bool, 3> discarded_levels_ {};
    packet_protection_context protection_;
    key_update_state key_update_;
    std::array<std::array<std::uint8_t, 32>, 2> application_secrets_ {};
    std::array<bool, 2> application_secret_ready_ {};
    std::array<std::uint64_t, 3> encrypted_packets_ {};
    std::uint64_t failed_authentications_ {0};
    std::optional<lifecycle_time_point> next_local_update_;
    std::optional<lifecycle_time_point> previous_key_retirement_;
    std::optional<std::uint64_t> phase_first_sent_;
    bool phase_acknowledged_ {false};
    bool update_occurred_ {false};
    bool key_update_ready_ {false};
    tls_provider tls_ {{&initial_, &handshake_, &application_},
                       {this, send_crypto, install_secret}};
    std::optional<connection_error> failure_;
    std::uint32_t version_ {version_1};
    std::array<std::byte, 20> peer_initial_source_cid_ {};
    std::size_t peer_initial_source_cid_size_ {0};
    bool peer_initial_source_cid_seen_ {false};
    lifecycle_duration local_idle_timeout_ {};
    bool initialized_ {false};
    bool retry_applied_ {false};
    bool confirmed_ {false};
    // RFC 9287 QUIC-bit greasing. A xorshift stream seeded once avoids a CSPRNG
    // call per packet; the bit is not security sensitive.
    bool local_grease_quic_bit_ {true};
    bool peer_grease_quic_bit_ {false};
    std::uint64_t grease_prng_ {0x9e3779b97f4a7c15ULL};
};

} // namespace eventloop::quic::detail
