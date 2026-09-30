#pragma once

#include "quic/recovery_timer.h"

#include <algorithm>
#include <cstddef>
#include <expected>
#include <limits>
#include <optional>

namespace eventloop::quic::detail {

enum class congestion_error {
    invalid_datagram_size,
    invalid_packet_size,
    invalid_time,
    flight_overflow,
    flight_underflow,
    congestion_blocked,
};

struct congestion_packet {
    recovery_time_point sent_time {};
    std::size_t bytes {0};
    bool in_flight {false};
};

// RFC 9002 Section 7 and Appendix B. One instance belongs to one network
// path and accounts for in-flight packets from all packet number spaces.
// The caller retires each packet exactly once on ACK, loss, or key discard.
class newreno_congestion_controller {
public:
    constexpr newreno_congestion_controller() noexcept = default;

    [[nodiscard]] constexpr auto reset(std::size_t max_datagram_size) noexcept
        -> std::expected<void, congestion_error>
    {
        if (max_datagram_size < 1200 ||
            max_datagram_size > std::numeric_limits<std::size_t>::max() / 2)
            return std::unexpected(congestion_error::invalid_datagram_size);

        max_datagram_size_ = max_datagram_size;
        const auto initial_cap = std::max(std::size_t {14720},
                                          max_datagram_size * 2);
        congestion_window_ = std::min(saturated_bytes_multiply(
                                          max_datagram_size, 10), initial_cap);
        bytes_in_flight_ = 0;
        slow_start_threshold_ = std::numeric_limits<std::size_t>::max();
        recovery_start_.reset();
        in_recovery_period_ = false;
        avoidance_credit_ = 0;
        return {};
    }

    [[nodiscard]] constexpr auto can_send(std::size_t bytes) const noexcept
        -> bool
    {
        return bytes > 0 && bytes <= max_datagram_size_ &&
               bytes_in_flight_ <= congestion_window_ &&
               bytes <= congestion_window_ - bytes_in_flight_;
    }

    // Probe packets and a packet sent when entering recovery may bypass cwnd,
    // but must still be counted in flight. Anti-amplification and pacing are
    // separate constraints for the eventual endpoint.
    [[nodiscard]] constexpr auto on_packet_sent(
        std::size_t bytes, bool in_flight, bool bypass_window = false) noexcept
        -> std::expected<void, congestion_error>
    {
        if (bytes == 0 || bytes > max_datagram_size_)
            return std::unexpected(congestion_error::invalid_packet_size);
        if (!in_flight) return {};
        if (bytes > std::numeric_limits<std::size_t>::max() - bytes_in_flight_)
            return std::unexpected(congestion_error::flight_overflow);
        if (!bypass_window && !can_send(bytes))
            return std::unexpected(congestion_error::congestion_blocked);
        bytes_in_flight_ += bytes;
        return {};
    }

    // app_or_flow_limited is supplied at ACK processing time by the sender.
    [[nodiscard]] constexpr auto on_packet_acked(
        congestion_packet packet, bool app_or_flow_limited = false) noexcept
        -> std::expected<void, congestion_error>
    {
        if (const auto error = validate_retired_packet(packet); error)
            return std::unexpected(*error);
        if (!packet.in_flight) return {};

        bytes_in_flight_ -= packet.bytes;
        if (recovery_start_ && packet.sent_time > *recovery_start_)
            in_recovery_period_ = false;
        if (app_or_flow_limited || in_recovery(packet.sent_time)) return {};

        if (congestion_window_ < slow_start_threshold_) {
            congestion_window_ = saturated_bytes_add(congestion_window_,
                                                      packet.bytes);
        } else {
            // Byte counting avoids the integer truncation of MSS*acked/cwnd.
            // A single ACK can grow the window by at most one datagram.
            avoidance_credit_ = saturated_bytes_add(avoidance_credit_,
                                                     packet.bytes);
            if (avoidance_credit_ >= congestion_window_) {
                avoidance_credit_ -= congestion_window_;
                congestion_window_ = saturated_bytes_add(congestion_window_,
                                                         max_datagram_size_);
            }
        }
        return {};
    }

    [[nodiscard]] constexpr auto on_packet_lost(
        congestion_packet packet, recovery_time_point now) noexcept
        -> std::expected<void, congestion_error>
    {
        if (const auto error = validate_retired_packet(packet); error)
            return std::unexpected(*error);
        if (now < packet.sent_time)
            return std::unexpected(congestion_error::invalid_time);
        if (!packet.in_flight) return {};
        bytes_in_flight_ -= packet.bytes;
        begin_congestion_event(packet.sent_time, now);
        return {};
    }

    // ECN-CE uses the send time of the largest newly acknowledged packet.
    [[nodiscard]] constexpr auto on_ecn_ce(
        recovery_time_point sent_time, recovery_time_point now) noexcept
        -> std::expected<void, congestion_error>
    {
        if (now < sent_time)
            return std::unexpected(congestion_error::invalid_time);
        begin_congestion_event(sent_time, now);
        return {};
    }

    // Initial/Handshake key discard removes flight without a congestion event.
    [[nodiscard]] constexpr auto on_packet_discarded(
        congestion_packet packet) noexcept -> std::expected<void, congestion_error>
    {
        if (const auto error = validate_retired_packet(packet); error)
            return std::unexpected(*error);
        if (packet.in_flight) bytes_in_flight_ -= packet.bytes;
        return {};
    }

    constexpr auto on_persistent_congestion() noexcept -> void
    {
        congestion_window_ = minimum_window();
        // A subsequent ACK resumes slow start, as required by Section 7.3.
        slow_start_threshold_ = std::numeric_limits<std::size_t>::max();
        recovery_start_.reset();
        in_recovery_period_ = false;
        avoidance_credit_ = 0;
    }

    [[nodiscard]] constexpr auto congestion_window() const noexcept
        -> std::size_t { return congestion_window_; }
    [[nodiscard]] constexpr auto bytes_in_flight() const noexcept
        -> std::size_t { return bytes_in_flight_; }
    [[nodiscard]] constexpr auto slow_start_threshold() const noexcept
        -> std::size_t { return slow_start_threshold_; }
    [[nodiscard]] constexpr auto minimum_window() const noexcept
        -> std::size_t { return max_datagram_size_ * 2; }
    [[nodiscard]] constexpr auto recovery_start() const noexcept
        -> std::optional<recovery_time_point> { return recovery_start_; }
    [[nodiscard]] constexpr auto in_recovery_period() const noexcept
        -> bool { return in_recovery_period_; }

private:
    [[nodiscard]] static constexpr auto saturated_bytes_add(
        std::size_t left, std::size_t right) noexcept -> std::size_t
    {
        const auto maximum = std::numeric_limits<std::size_t>::max();
        return right > maximum - left ? maximum : left + right;
    }

    [[nodiscard]] static constexpr auto saturated_bytes_multiply(
        std::size_t value, std::size_t factor) noexcept -> std::size_t
    {
        const auto maximum = std::numeric_limits<std::size_t>::max();
        return value > maximum / factor ? maximum : value * factor;
    }

    [[nodiscard]] constexpr auto validate_retired_packet(
        congestion_packet packet) const noexcept
        -> std::optional<congestion_error>
    {
        if (packet.bytes == 0 || packet.bytes > max_datagram_size_)
            return congestion_error::invalid_packet_size;
        if (packet.in_flight && packet.bytes > bytes_in_flight_)
            return congestion_error::flight_underflow;
        return std::nullopt;
    }

    [[nodiscard]] constexpr auto in_recovery(
        recovery_time_point sent_time) const noexcept -> bool
    {
        return recovery_start_ && sent_time <= *recovery_start_;
    }

    constexpr auto begin_congestion_event(recovery_time_point sent_time,
                                          recovery_time_point now) noexcept -> void
    {
        if (in_recovery_period_ || in_recovery(sent_time)) return;
        recovery_start_ = now;
        in_recovery_period_ = true;
        slow_start_threshold_ = congestion_window_ / 2;
        congestion_window_ = std::max(slow_start_threshold_, minimum_window());
        avoidance_credit_ = 0;
    }

    std::size_t max_datagram_size_ {1200};
    std::size_t congestion_window_ {12000};
    std::size_t bytes_in_flight_ {0};
    std::size_t slow_start_threshold_ {std::numeric_limits<std::size_t>::max()};
    std::size_t avoidance_credit_ {0};
    std::optional<recovery_time_point> recovery_start_ {};
    bool in_recovery_period_ {false};
};

} // namespace eventloop::quic::detail
