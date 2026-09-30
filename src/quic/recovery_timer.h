#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace eventloop::quic::detail {

enum class packet_number_space : std::uint8_t {
    initial,
    handshake,
    application_data,
};

using recovery_duration = std::chrono::microseconds;
inline constexpr auto initial_rtt = std::chrono::milliseconds {333};
inline constexpr auto timer_granularity = std::chrono::milliseconds {1};

using recovery_time_point = std::chrono::steady_clock::time_point;

struct scheduled_loss {
    packet_number_space space;
    recovery_time_point deadline;
};

// RFC 9002 erratum 9169: absent loss deadlines must not participate in the
// minimum. A zero time point remains a valid deadline.
[[nodiscard]] constexpr auto earliest_loss_deadline(
    const std::array<std::optional<recovery_time_point>, 3>& deadlines) noexcept
    -> std::optional<scheduled_loss>
{
    std::optional<scheduled_loss> earliest;
    for (std::size_t index = 0; index < deadlines.size(); ++index) {
        if (!deadlines[index]) continue;
        if (!earliest || *deadlines[index] < earliest->deadline) {
            earliest = scheduled_loss {
                static_cast<packet_number_space>(index), *deadlines[index]};
        }
    }
    return earliest;
}

[[nodiscard]] constexpr auto nonnegative(recovery_duration value) noexcept
    -> recovery_duration
{
    return value < recovery_duration::zero() ? recovery_duration::zero() : value;
}

[[nodiscard]] constexpr auto saturated_add(recovery_duration left,
                                            recovery_duration right) noexcept
    -> recovery_duration
{
    left = nonnegative(left);
    right = nonnegative(right);
    const auto maximum = recovery_duration::max().count();
    if (right.count() > maximum - left.count()) return recovery_duration::max();
    return left + right;
}

[[nodiscard]] constexpr auto saturated_multiply(recovery_duration value,
                                                 std::uint32_t factor) noexcept
    -> recovery_duration
{
    value = nonnegative(value);
    if (factor != 0 &&
        value.count() > recovery_duration::max().count() / factor) {
        return recovery_duration::max();
    }
    return recovery_duration {value.count() * factor};
}

[[nodiscard]] constexpr auto weighted_average(recovery_duration old_value,
                                               recovery_duration new_value,
                                               std::int64_t denominator) noexcept
    -> recovery_duration
{
    // Compute floor(((denominator - 1) * old + new) / denominator)
    // without overflowing the underlying signed duration representation.
    const auto old_count = nonnegative(old_value).count();
    const auto new_count = nonnegative(new_value).count();
    const auto old_weight = denominator - 1;
    const auto whole = (old_count / denominator) * old_weight +
                       new_count / denominator;
    const auto remainder = ((old_count % denominator) * old_weight +
                            new_count % denominator) / denominator;
    return recovery_duration {whole + remainder};
}

class rtt_estimator {
public:
    constexpr explicit rtt_estimator(recovery_duration starting_rtt = initial_rtt)
        noexcept
    {
        reset(starting_rtt);
    }

    constexpr auto reset(recovery_duration starting_rtt = initial_rtt) noexcept
        -> void
    {
        const auto value = nonnegative(starting_rtt);
        latest_rtt_ = recovery_duration::zero();
        min_rtt_ = recovery_duration::zero();
        smoothed_rtt_ = value;
        rttvar_ = value / 2;
        has_sample_ = false;
    }

    constexpr auto update(recovery_duration sample,
                          recovery_duration reported_ack_delay,
                          recovery_duration max_ack_delay,
                          packet_number_space space,
                          bool handshake_confirmed) noexcept -> void
    {
        sample = nonnegative(sample);
        latest_rtt_ = sample;
        if (!has_sample_) {
            min_rtt_ = sample;
            smoothed_rtt_ = sample;
            rttvar_ = sample / 2;
            has_sample_ = true;
            return;
        }

        min_rtt_ = std::min(min_rtt_, sample);
        auto ack_delay = space == packet_number_space::initial
            ? recovery_duration::zero() : nonnegative(reported_ack_delay);
        if (handshake_confirmed) {
            ack_delay = std::min(ack_delay, nonnegative(max_ack_delay));
        }
        auto adjusted = sample;
        if (ack_delay <= sample && sample - ack_delay >= min_rtt_) {
            adjusted -= ack_delay;
        }

        const auto deviation = smoothed_rtt_ >= adjusted
            ? smoothed_rtt_ - adjusted : adjusted - smoothed_rtt_;
        // RFC 9002 verified erratum 7539: use the previous smoothed RTT.
        rttvar_ = weighted_average(rttvar_, deviation, 4);
        smoothed_rtt_ = weighted_average(smoothed_rtt_, adjusted, 8);
    }

    [[nodiscard]] constexpr auto pto_duration(
        packet_number_space space, bool handshake_confirmed,
        recovery_duration max_ack_delay, std::uint32_t pto_count,
        recovery_duration granularity = timer_granularity) const noexcept
        -> std::optional<recovery_duration>
    {
        if (space == packet_number_space::application_data &&
            !handshake_confirmed) return std::nullopt;

        granularity = std::max(nonnegative(granularity), recovery_duration {1});
        const auto variance = saturated_multiply(rttvar_, 4);
        auto base = saturated_add(smoothed_rtt_,
                                  std::max(variance, granularity));
        if (space == packet_number_space::application_data) {
            base = saturated_add(base, nonnegative(max_ack_delay));
        }
        base = std::max(base, granularity);
        for (std::uint32_t count = 0; count < pto_count; ++count) {
            base = saturated_multiply(base, 2);
            if (base == recovery_duration::max()) break;
        }
        return base;
    }

    [[nodiscard]] constexpr auto has_sample() const noexcept -> bool
    { return has_sample_; }
    [[nodiscard]] constexpr auto latest_rtt() const noexcept -> recovery_duration
    { return latest_rtt_; }
    [[nodiscard]] constexpr auto min_rtt() const noexcept -> recovery_duration
    { return min_rtt_; }
    [[nodiscard]] constexpr auto smoothed_rtt() const noexcept
        -> recovery_duration
    { return smoothed_rtt_; }
    [[nodiscard]] constexpr auto rttvar() const noexcept -> recovery_duration
    { return rttvar_; }

private:
    recovery_duration latest_rtt_ {};
    recovery_duration min_rtt_ {};
    recovery_duration smoothed_rtt_ {};
    recovery_duration rttvar_ {};
    bool has_sample_ {false};
};

} // namespace eventloop::quic::detail
