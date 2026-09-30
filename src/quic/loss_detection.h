#pragma once

#include "quic/recovery_timer.h"

#include <algorithm>
#include <cstdint>

namespace eventloop::quic::detail {

inline constexpr std::uint64_t k_packet_threshold = 3;

// RFC 9002 Section 6.1.2: max(9/8 * max(RTTs), 1 ms).
[[nodiscard]] constexpr auto loss_delay(recovery_duration latest_rtt,
                                        recovery_duration smoothed_rtt) noexcept
    -> recovery_duration
{
    const auto rtt = std::max(nonnegative(latest_rtt),
                              nonnegative(smoothed_rtt));
    return std::max(saturated_add(rtt, rtt / 8),
                    recovery_duration {timer_granularity});
}

// Count later packets actually transmitted through the largest acknowledged
// packet; numeric packet-number distance is invalid when the sender leaves gaps.
[[nodiscard]] constexpr auto packet_threshold_lost(
    std::uint64_t later_sent_count) noexcept -> bool
{
    return later_sent_count >= k_packet_threshold;
}

[[nodiscard]] constexpr auto time_threshold_lost(
    recovery_duration time_since_sent, recovery_duration latest_rtt,
    recovery_duration smoothed_rtt) noexcept -> bool
{
    return time_since_sent >= loss_delay(latest_rtt, smoothed_rtt);
}

// Later-sent count is in the same packet-number space and includes the largest
// acknowledged packet. The caller supplies a nonnegative elapsed time; a
// negative value never meets the delay.
[[nodiscard]] constexpr auto packet_is_lost(
    bool unacknowledged, bool in_flight, std::uint64_t later_sent_count,
    recovery_duration time_since_sent,
    recovery_duration latest_rtt, recovery_duration smoothed_rtt) noexcept
    -> bool
{
    return unacknowledged && in_flight && later_sent_count > 0 &&
           (packet_threshold_lost(later_sent_count) ||
            time_threshold_lost(time_since_sent, latest_rtt, smoothed_rtt));
}

} // namespace eventloop::quic::detail
