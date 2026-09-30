#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>

namespace eventloop::quic::detail {

enum class connection_state : std::uint8_t {
    handshake,
    active,
    closing,
    draining,
    closed,
};

using lifecycle_time_point = std::chrono::steady_clock::time_point;
using lifecycle_duration = lifecycle_time_point::duration;

[[nodiscard]] constexpr auto lifecycle_deadline(lifecycle_time_point origin,
                                                lifecycle_duration delay) noexcept
    -> lifecycle_time_point
{
    if (delay <= lifecycle_duration::zero()) return origin;
    const auto maximum = lifecycle_duration::max().count();
    if (origin.time_since_epoch().count() > maximum - delay.count()) {
        return lifecycle_time_point::max();
    }
    return origin + delay;
}

[[nodiscard]] constexpr auto lifecycle_three_pto(lifecycle_duration pto) noexcept
    -> lifecycle_duration
{
    if (pto <= lifecycle_duration::zero()) return lifecycle_duration::zero();
    if (pto.count() > lifecycle_duration::max().count() / 3) {
        return lifecycle_duration::max();
    }
    return pto * 3;
}

// Caller supplies monotonically nondecreasing times and positive current PTOs
// computed by recovery (including the applicable packet space and backoff).
// This helper owns no packets, keys, streams, or I/O. Closing permits only
// CONNECTION_CLOSE packets; its caller applies rate and amplification limits.
class connection_lifecycle {
public:
    constexpr explicit connection_lifecycle(lifecycle_time_point started = {})
        noexcept : last_event_(started), idle_origin_(started) {}

    [[nodiscard]] constexpr auto state() const noexcept -> connection_state
    { return state_; }

    [[nodiscard]] constexpr auto can_send_data() const noexcept -> bool
    { return live(); }

    [[nodiscard]] constexpr auto can_send_close() const noexcept -> bool
    { return live() || state_ == connection_state::closing; }

    [[nodiscard]] constexpr auto negotiated_idle_timeout() const noexcept
        -> lifecycle_duration
    { return idle_timeout_; }

    // Zero means disabled. Invalid values and invalid transitions change nothing.
    [[nodiscard]] constexpr auto negotiate_idle_timeout(
        lifecycle_duration local, lifecycle_duration peer,
        lifecycle_time_point now) noexcept -> bool
    {
        if (!live() || now < last_event_ || local.count() < 0 || peer.count() < 0) {
            return false;
        }
        idle_timeout_ = local == lifecycle_duration::zero() ? peer
            : peer == lifecycle_duration::zero() ? local : std::min(local, peer);
        last_event_ = now;
        return true;
    }

    [[nodiscard]] constexpr auto handshake_complete(lifecycle_time_point now)
        noexcept -> bool
    {
        if (state_ != connection_state::handshake || now < last_event_) return false;
        state_ = connection_state::active;
        last_event_ = now;
        return true;
    }

    // Call only after authenticating and successfully processing a peer packet.
    [[nodiscard]] constexpr auto packet_received(lifecycle_time_point now)
        noexcept -> bool
    {
        if (!live() || now < last_event_) return false;
        idle_origin_ = last_event_ = now;
        sent_since_receive_ = false;
        return true;
    }

    [[nodiscard]] constexpr auto packet_sent(lifecycle_time_point now,
                                            bool ack_eliciting) noexcept -> bool
    {
        if (!live() || now < last_event_) return false;
        if (ack_eliciting && !sent_since_receive_) {
            idle_origin_ = now;
            sent_since_receive_ = true;
        }
        last_event_ = now;
        return true;
    }

    [[nodiscard]] constexpr auto idle_deadline(lifecycle_duration current_pto)
        const noexcept -> std::optional<lifecycle_time_point>
    {
        if (!live() || idle_timeout_ == lifecycle_duration::zero() ||
            current_pto <= lifecycle_duration::zero()) return std::nullopt;
        return lifecycle_deadline(idle_origin_,
            std::max(idle_timeout_, lifecycle_three_pto(current_pto)));
    }

    [[nodiscard]] constexpr auto termination_deadline() const noexcept
        -> std::optional<lifecycle_time_point>
    { return termination_deadline_; }

    [[nodiscard]] constexpr auto next_deadline(lifecycle_duration current_pto)
        const noexcept -> std::optional<lifecycle_time_point>
    {
        if (termination_deadline_) return termination_deadline_;
        return idle_deadline(current_pto);
    }

    // Invoke after sending the first CONNECTION_CLOSE. Repeated close sends
    // never extend the closing period.
    [[nodiscard]] constexpr auto close_sent(lifecycle_time_point now,
                                           lifecycle_duration current_pto)
        noexcept -> bool
    {
        if (!live() || !valid_timer_event(now, current_pto)) return false;
        termination_deadline_ = lifecycle_deadline(now,
            lifecycle_three_pto(current_pto));
        last_event_ = now;
        state_ = connection_state::closing;
        return true;
    }

    // Also used for a verified stateless reset. Any optional final close
    // response must be sent before invoking this method.
    [[nodiscard]] constexpr auto enter_draining(lifecycle_time_point now,
                                               lifecycle_duration current_pto)
        noexcept -> bool
    {
        if ((!live() && state_ != connection_state::closing) ||
            !valid_timer_event(now, current_pto)) return false;
        if (state_ != connection_state::closing) {
            termination_deadline_ = lifecycle_deadline(now,
                lifecycle_three_pto(current_pto));
        }
        last_event_ = now;
        state_ = connection_state::draining;
        return true;
    }

    // A successful poll need not change state. Idle expiry is a silent close.
    [[nodiscard]] constexpr auto poll(lifecycle_time_point now,
                                     lifecycle_duration current_pto) noexcept
        -> bool
    {
        if (state_ == connection_state::closed ||
            !valid_timer_event(now, current_pto)) return false;
        const auto deadline = next_deadline(current_pto);
        last_event_ = now;
        if (deadline && now >= *deadline) {
            state_ = connection_state::closed;
            termination_deadline_.reset();
        }
        return true;
    }

private:
    [[nodiscard]] constexpr auto live() const noexcept -> bool
    {
        return state_ == connection_state::handshake ||
               state_ == connection_state::active;
    }

    [[nodiscard]] constexpr auto valid_timer_event(
        lifecycle_time_point now, lifecycle_duration pto) const noexcept -> bool
    { return now >= last_event_ && pto > lifecycle_duration::zero(); }

    connection_state state_ {connection_state::handshake};
    lifecycle_time_point last_event_;
    lifecycle_time_point idle_origin_;
    lifecycle_duration idle_timeout_ {};
    std::optional<lifecycle_time_point> termination_deadline_;
    bool sent_since_receive_ {false};
};

} // namespace eventloop::quic::detail
