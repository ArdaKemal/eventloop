#pragma once

#include "quic/recovery_timer.h"
#include "quic/varint.h"

#include <array>
#include <expected>
#include <optional>

namespace eventloop::quic::detail {

enum class ecn_codepoint : std::uint8_t { not_ect, ect0, ect1, ce };
enum class ecn_error {
    invalid_space, invalid_codepoint, counter_overflow, invalid_ack,
    missing_feedback, decreasing_feedback, inconsistent_feedback, disabled
};

struct ecn_counts {
    std::uint64_t ect0 {0};
    std::uint64_t ect1 {0};
    std::uint64_t ce {0};
};

struct ecn_ack_result {
    bool ignored_reordered {false};
    std::uint64_t newly_reported_ce {0};
};

// RFC 9000 13.4.2 / RFC 9002 7.1. Connection-wide cumulative accounting is
// separate for each packet-number space. Failure conservatively disables ECN
// on every path. Migration must preserve these totals; reset starts a new
// connection only. The caller supplies only first-time acknowledgments from
// its validated sent-packet history, including packets previously deemed lost.
// Record each QUIC packet in a coalesced datagram with the datagram's marking.
class ecn_state {
public:
    constexpr auto reset() noexcept -> void { *this = ecn_state {}; }
    constexpr auto disable() noexcept -> void { enabled_ = false; }
    [[nodiscard]] constexpr auto enabled() const noexcept -> bool
    { return enabled_; }

    [[nodiscard]] constexpr auto on_packet_sent(
        packet_number_space space, ecn_codepoint marking,
        std::uint64_t count = 1) noexcept -> std::expected<void, ecn_error>
    {
        const auto index = space_index(space);
        if (!index) return std::unexpected(ecn_error::invalid_space);
        if (marking != ecn_codepoint::not_ect && marking != ecn_codepoint::ect0 &&
            marking != ecn_codepoint::ect1)
            return std::unexpected(ecn_error::invalid_codepoint);
        if (marking == ecn_codepoint::not_ect) return {};
        if (!enabled_) return std::unexpected(ecn_error::disabled);
        auto& state = spaces_[*index];
        auto& counter = marking == ecn_codepoint::ect0 ? state.sent.ect0
                                                      : state.sent.ect1;
        if (count > max_varint_value - counter)
            return fail(ecn_error::counter_overflow);
        counter += count;
        return {};
    }

    [[nodiscard]] constexpr auto on_ack(
        packet_number_space space, std::uint64_t largest_acknowledged,
        ecn_counts newly_acknowledged,
        std::optional<ecn_counts> feedback) noexcept
        -> std::expected<ecn_ack_result, ecn_error>
    {
        const auto index = space_index(space);
        if (!index) return std::unexpected(ecn_error::invalid_space);
        if (!enabled_) return std::unexpected(ecn_error::disabled);
        auto& state = spaces_[*index];
        if (largest_acknowledged > max_varint_value || newly_acknowledged.ce != 0 ||
            newly_acknowledged.ect0 > state.sent.ect0 - state.acked.ect0 ||
            newly_acknowledged.ect1 > state.sent.ect1 - state.acked.ect1)
            return fail(ecn_error::invalid_ack);

        // Reordered ACKs cannot cause ECN validation failure (RFC 9000).
        const bool reordered = state.largest && largest_acknowledged <= *state.largest;
        if (reordered) {
            state.acked.ect0 += newly_acknowledged.ect0;
            state.acked.ect1 += newly_acknowledged.ect1;
            return ecn_ack_result {true, 0};
        }

        std::uint64_t ce_delta = 0;
        if (!feedback) {
            if (newly_acknowledged.ect0 != 0 || newly_acknowledged.ect1 != 0)
                return fail(ecn_error::missing_feedback);
        } else {
            const auto counts = *feedback;
            if (counts.ect0 > max_varint_value || counts.ect1 > max_varint_value ||
                counts.ce > max_varint_value)
                return fail(ecn_error::counter_overflow);
            if (counts.ect0 < state.feedback.ect0 ||
                counts.ect1 < state.feedback.ect1 || counts.ce < state.feedback.ce)
                return fail(ecn_error::decreasing_feedback);
            ce_delta = counts.ce - state.feedback.ce;
            const auto ect0_delta = counts.ect0 - state.feedback.ect0;
            const auto ect1_delta = counts.ect1 - state.feedback.ect1;
            // Each sum is bounded by twice the 62-bit wire limit.
            if (counts.ect0 > state.sent.ect0 || counts.ect1 > state.sent.ect1 ||
                counts.ce > state.sent.ect0 + state.sent.ect1 - counts.ect0 - counts.ect1 ||
                ect0_delta + ce_delta < newly_acknowledged.ect0 ||
                ect1_delta + ce_delta < newly_acknowledged.ect1 ||
                ect0_delta + ect1_delta + ce_delta <
                    newly_acknowledged.ect0 + newly_acknowledged.ect1)
                return fail(ecn_error::inconsistent_feedback);
            state.feedback = counts;
        }
        state.acked.ect0 += newly_acknowledged.ect0;
        state.acked.ect1 += newly_acknowledged.ect1;
        state.largest = largest_acknowledged;
        return ecn_ack_result {false, ce_delta};
    }

private:
    struct space_state {
        ecn_counts sent {};
        ecn_counts acked {};
        ecn_counts feedback {};
        std::optional<std::uint64_t> largest {};
    };
    [[nodiscard]] static constexpr auto space_index(packet_number_space space)
        noexcept -> std::optional<std::size_t>
    {
        const auto index = static_cast<std::size_t>(space);
        if (index >= 3) return {};
        return index;
    }
    constexpr auto fail(ecn_error error) noexcept -> std::unexpected<ecn_error>
    { enabled_ = false; return std::unexpected(error); }

    std::array<space_state, 3> spaces_ {};
    bool enabled_ {true};
};

} // namespace eventloop::quic::detail
