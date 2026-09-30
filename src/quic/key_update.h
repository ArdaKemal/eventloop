#pragma once

#include "quic/packet_protection.h"

#include <chrono>

namespace eventloop::quic::detail {

enum class key_update_error {
    not_initialized,
    already_initialized,
    invalid_input,
    crypto_failure,
    handshake_not_confirmed,
    current_phase_not_acknowledged,
    peer_update_unacknowledged,
    peer_update_pending,
    authentication_failed,
    wrong_key_phase,
    invalid_packet_number,
    previous_keys_unavailable,
    retirement_not_due,
};

enum class receive_key_slot { previous, current, next };
using key_update_time = std::chrono::microseconds;

// One loop-affine 1-RTT connection's AES-128-GCM/SHA-256 phase state.
// Remove HP using the unchanged current HP key, select current/previous/next
// by the unmasked key phase and full packet number, then authenticate with
// receive_keys(slot). Call on_received ONLY with the actual authentication
// result. It atomically advances both directions on authenticated peer updates.
// Local initiation immediately advances receive_keys_for_send_phase() too;
// receive_keys(current) retains the last authenticated peer phase until a
// next-key packet authenticates. Failed attempts never generate or commit keys.
//
// Record every sent 1-RTT packet after transmission. Validate ACK ranges against
// sent history before on_acknowledged; this helper does not retain sent ranges.
// After sending an ACK covering peer_update_packet(), call on_ack_sent with its
// transmitted PN. All ACKs for peer updates must use send_keys()/send_phase().
// Call retire_previous on the monotonic 3-PTO deadline. AEAD usage limits,
// duplicate-packet suppression, timing-safe candidate authentication, and the
// recommended 3-PTO delay between local updates remain caller responsibilities.
class key_update_state {
public:
    key_update_state() = default;
    key_update_state(const key_update_state&) = delete;
    auto operator=(const key_update_state&) -> key_update_state& = delete;

    [[nodiscard]] auto initialize(std::uint32_t version,
        std::span<const std::uint8_t> send_secret,
        std::span<const std::uint8_t> receive_secret)
        -> std::expected<void, key_update_error>;
    auto confirm_handshake() noexcept -> void { handshake_confirmed_ = true; }
    [[nodiscard]] auto on_sent(std::uint64_t packet_number) noexcept
        -> std::expected<void, key_update_error>;
    [[nodiscard]] auto on_acknowledged(std::uint64_t packet_number) noexcept
        -> std::expected<void, key_update_error>;
    [[nodiscard]] auto initiate_update()
        -> std::expected<void, key_update_error>;
    [[nodiscard]] auto on_received(receive_key_slot slot, bool key_phase,
        std::uint64_t packet_number, bool authenticated,
        key_update_time now, key_update_time pto)
        -> std::expected<void, key_update_error>;
    [[nodiscard]] auto on_ack_sent(std::uint64_t sent_packet_number,
        std::uint64_t acknowledged_peer_packet) noexcept
        -> std::expected<void, key_update_error>;
    [[nodiscard]] auto retire_previous(key_update_time now) noexcept
        -> std::expected<void, key_update_error>;

    [[nodiscard]] auto send_keys() const noexcept -> const aes_128_gcm_keys*
    { return initialized_ ? &send_.keys : nullptr; }
    [[nodiscard]] auto receive_keys(receive_key_slot slot) const noexcept
        -> const aes_128_gcm_keys*;
    [[nodiscard]] auto receive_keys_for_send_phase() const noexcept
        -> const aes_128_gcm_keys*
    {
        return receive_keys(send_phase_ == receive_phase_
            ? receive_key_slot::current : receive_key_slot::next);
    }
    [[nodiscard]] auto send_phase() const noexcept -> bool { return send_phase_; }
    [[nodiscard]] auto receive_phase() const noexcept -> bool { return receive_phase_; }
    [[nodiscard]] auto peer_update_packet() const noexcept
        -> std::optional<std::uint64_t> { return peer_update_packet_; }
    [[nodiscard]] auto retirement_deadline() const noexcept
        -> std::optional<key_update_time> { return retirement_deadline_; }

private:
    struct material {
        std::array<std::uint8_t, 32> secret {};
        aes_128_gcm_keys keys {};
        ~material();
    };
    [[nodiscard]] auto next_material(const material& current) const
        -> std::expected<material, key_update_error>;
    auto replace_send(const material& next) noexcept -> void;

    material send_, receive_, next_receive_;
    material previous_receive_; // only keys retained; the old secret is erased
    std::uint32_t version_ {0};
    bool initialized_ {false};
    bool handshake_confirmed_ {false};
    bool send_phase_ {false};
    bool receive_phase_ {false};
    bool send_phase_acknowledged_ {false};
    bool previous_available_ {false};
    std::optional<std::uint64_t> first_sent_, last_sent_;
    std::optional<std::uint64_t> first_received_, largest_received_;
    std::optional<std::uint64_t> largest_previous_received_;
    std::optional<std::uint64_t> peer_update_packet_;
    std::optional<key_update_time> retirement_deadline_;
};

} // namespace eventloop::quic::detail
