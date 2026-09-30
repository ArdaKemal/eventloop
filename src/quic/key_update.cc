#include "quic/key_update.h"

#include <openssl/crypto.h>

#include <algorithm>

namespace eventloop::quic::detail {

key_update_state::material::~material()
{
    OPENSSL_cleanse(secret.data(), secret.size());
    OPENSSL_cleanse(&keys, sizeof(keys));
}

auto key_update_state::next_material(const material& current) const
    -> std::expected<material, key_update_error>
{
    const auto secret = derive_next_traffic_secret(version_, current.secret);
    if (!secret) return std::unexpected(key_update_error::crypto_failure);
    material next;
    next.secret = *secret;
    const auto keys = derive_aes_128_gcm_keys(version_, next.secret);
    if (!keys) return std::unexpected(key_update_error::crypto_failure);
    next.keys = *keys;
    next.keys.hp = current.keys.hp;
    return next;
}

auto key_update_state::initialize(std::uint32_t version,
    std::span<const std::uint8_t> send_secret,
    std::span<const std::uint8_t> receive_secret)
    -> std::expected<void, key_update_error>
{
    if (initialized_) return std::unexpected(key_update_error::already_initialized);
    if (!is_supported_version(version) || send_secret.size() != 32 ||
        receive_secret.size() != 32)
        return std::unexpected(key_update_error::invalid_input);
    material send, receive, next;
    const auto send_keys = derive_aes_128_gcm_keys(version, send_secret);
    const auto receive_keys = derive_aes_128_gcm_keys(version, receive_secret);
    const auto next_secret = derive_next_traffic_secret(version, receive_secret);
    if (!send_keys || !receive_keys || !next_secret)
        return std::unexpected(key_update_error::crypto_failure);
    next.secret = *next_secret;
    const auto next_keys = derive_aes_128_gcm_keys(version, next.secret);
    if (!next_keys) return std::unexpected(key_update_error::crypto_failure);
    std::copy(send_secret.begin(), send_secret.end(), send.secret.begin());
    std::copy(receive_secret.begin(), receive_secret.end(), receive.secret.begin());
    send.keys = *send_keys;
    receive.keys = *receive_keys;
    next.keys = *next_keys;
    next.keys.hp = receive.keys.hp;
    send_ = send;
    receive_ = receive;
    next_receive_ = next;
    version_ = version;
    initialized_ = true;
    return {};
}

auto key_update_state::on_sent(std::uint64_t pn) noexcept
    -> std::expected<void, key_update_error>
{
    if (!initialized_) return std::unexpected(key_update_error::not_initialized);
    if (pn > max_packet_number || (last_sent_ && pn <= *last_sent_))
        return std::unexpected(key_update_error::invalid_packet_number);
    if (!first_sent_) first_sent_ = pn;
    last_sent_ = pn;
    return {};
}

auto key_update_state::on_acknowledged(std::uint64_t pn) noexcept
    -> std::expected<void, key_update_error>
{
    if (!initialized_) return std::unexpected(key_update_error::not_initialized);
    if (pn > max_packet_number || !last_sent_ || pn > *last_sent_)
        return std::unexpected(key_update_error::invalid_packet_number);
    // Delayed ACKs for older phases do not confirm the current phase.
    if (first_sent_ && pn >= *first_sent_) send_phase_acknowledged_ = true;
    return {};
}

auto key_update_state::replace_send(const material& next) noexcept -> void
{
    send_ = next;
    send_phase_ = !send_phase_;
    send_phase_acknowledged_ = false;
    first_sent_.reset();
}

auto key_update_state::initiate_update()
    -> std::expected<void, key_update_error>
{
    if (!initialized_) return std::unexpected(key_update_error::not_initialized);
    if (!handshake_confirmed_)
        return std::unexpected(key_update_error::handshake_not_confirmed);
    if (peer_update_packet_)
        return std::unexpected(key_update_error::peer_update_unacknowledged);
    if (send_phase_ != receive_phase_)
        return std::unexpected(key_update_error::peer_update_pending);
    if (!send_phase_acknowledged_)
        return std::unexpected(key_update_error::current_phase_not_acknowledged);
    const auto next = next_material(send_);
    if (!next) return std::unexpected(next.error());
    replace_send(*next);
    // receive_ remains usable until authentication under next_receive_.
    return {};
}

auto key_update_state::receive_keys(receive_key_slot slot) const noexcept
    -> const aes_128_gcm_keys*
{
    if (!initialized_) return nullptr;
    switch (slot) {
    case receive_key_slot::previous:
        return previous_available_ ? &previous_receive_.keys : nullptr;
    case receive_key_slot::current: return &receive_.keys;
    case receive_key_slot::next: return &next_receive_.keys;
    }
    return nullptr;
}

auto key_update_state::on_received(receive_key_slot slot, bool phase,
    std::uint64_t pn, bool authenticated, key_update_time now, key_update_time pto)
    -> std::expected<void, key_update_error>
{
    if (!initialized_) return std::unexpected(key_update_error::not_initialized);
    if (!authenticated)
        return std::unexpected(key_update_error::authentication_failed);
    if (pn > max_packet_number)
        return std::unexpected(key_update_error::invalid_packet_number);
    if (slot == receive_key_slot::previous) {
        if (!previous_available_)
            return std::unexpected(key_update_error::previous_keys_unavailable);
        if (phase == receive_phase_)
            return std::unexpected(key_update_error::wrong_key_phase);
        if (!first_received_ || pn >= *first_received_)
            return std::unexpected(key_update_error::invalid_packet_number);
        if (!largest_previous_received_ || pn > *largest_previous_received_)
            largest_previous_received_ = pn;
        return {};
    }
    if (slot == receive_key_slot::current) {
        if (phase != receive_phase_)
            return std::unexpected(key_update_error::wrong_key_phase);
        if (largest_previous_received_ && pn <= *largest_previous_received_)
            return std::unexpected(key_update_error::invalid_packet_number);
        if (!first_received_ || pn < *first_received_) first_received_ = pn;
        if (!largest_received_ || pn > *largest_received_) largest_received_ = pn;
        return {};
    }
    if (slot != receive_key_slot::next || phase == receive_phase_)
        return std::unexpected(key_update_error::wrong_key_phase);
    if (!handshake_confirmed_)
        return std::unexpected(key_update_error::handshake_not_confirmed);
    if (peer_update_packet_)
        return std::unexpected(key_update_error::peer_update_unacknowledged);
    if (largest_received_ && pn <= *largest_received_)
        return std::unexpected(key_update_error::invalid_packet_number);
    if (now.count() < 0 || pto.count() <= 0)
        return std::unexpected(key_update_error::invalid_input);

    // Prepare every fallible operation before changing either direction.
    const auto next_receive = next_material(next_receive_);
    if (!next_receive) return std::unexpected(next_receive.error());
    std::optional<material> next_send;
    if (send_phase_ != phase) {
        const auto derived = next_material(send_);
        if (!derived) return std::unexpected(derived.error());
        next_send = *derived;
    }
    const auto headroom = key_update_time::max().count() - now.count();
    const auto deadline = pto.count() > headroom / 3
        ? key_update_time::max() : now + pto * 3;
    if (next_send) replace_send(*next_send);
    previous_receive_ = material {};
    previous_receive_.keys = receive_.keys;
    previous_available_ = true;
    receive_ = next_receive_;
    next_receive_ = *next_receive;
    receive_phase_ = phase;
    largest_previous_received_ = largest_received_;
    first_received_ = pn;
    largest_received_ = pn;
    peer_update_packet_ = pn;
    retirement_deadline_ = deadline;
    return {};
}

auto key_update_state::on_ack_sent(std::uint64_t sent_pn,
    std::uint64_t acknowledged_peer_packet) noexcept
    -> std::expected<void, key_update_error>
{
    if (!initialized_) return std::unexpected(key_update_error::not_initialized);
    if (!peer_update_packet_ || acknowledged_peer_packet != *peer_update_packet_ ||
        send_phase_ != receive_phase_ || !first_sent_ || !last_sent_ ||
        sent_pn < *first_sent_ || sent_pn > *last_sent_)
        return std::unexpected(key_update_error::invalid_input);
    peer_update_packet_.reset();
    return {};
}

auto key_update_state::retire_previous(key_update_time now) noexcept
    -> std::expected<void, key_update_error>
{
    if (!initialized_) return std::unexpected(key_update_error::not_initialized);
    if (!previous_available_ || !retirement_deadline_)
        return std::unexpected(key_update_error::previous_keys_unavailable);
    if (now < *retirement_deadline_)
        return std::unexpected(key_update_error::retirement_not_due);
    OPENSSL_cleanse(&previous_receive_.keys, sizeof(previous_receive_.keys));
    previous_available_ = false;
    retirement_deadline_.reset();
    return {};
}

} // namespace eventloop::quic::detail
