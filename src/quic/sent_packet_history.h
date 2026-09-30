#pragma once

#include "quic/ack_ranges.h"
#include "quic/loss_detection.h"
#include "quic/recovery_timer.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <ratio>
#include <span>
#include <type_traits>

namespace eventloop::quic::detail {

struct sent_packet {
    std::uint64_t number {0};
    recovery_time_point sent_time {};
    bool ack_eliciting {false};
    bool in_flight {false};
    std::size_t bytes {0};
};

struct detected_losses {
    std::size_t count {0};
    std::optional<recovery_duration> next_delay {};
};

enum class sent_packet_error {
    capacity_exhausted,
    invalid_packet_number,
    invalid_ack,
    invalid_time,
    output_full,
};

// One packet number space. Sent numbers increase strictly and may have gaps.
// Sent ranges remain recorded after ACK/loss removal so a delayed ACK can be
// distinguished from an ACK for a number that was never sent. Each gap consumes
// one of the fixed range slots for the lifetime of this history.
template<std::size_t Capacity, std::size_t SentRangeCapacity = Capacity>
class sent_packet_history {
public:
    [[nodiscard]] constexpr auto record(sent_packet packet) noexcept
        -> std::expected<void, sent_packet_error>
    {
        if (packet.number > max_varint_value ||
            (highest_sent_ && packet.number <= *highest_sent_))
            return std::unexpected(sent_packet_error::invalid_packet_number);
        if (size_ == Capacity)
            return std::unexpected(sent_packet_error::capacity_exhausted);
        const bool extends_range = highest_sent_ &&
            packet.number == *highest_sent_ + 1;
        if (!extends_range && sent_range_count_ == SentRangeCapacity)
            return std::unexpected(sent_packet_error::capacity_exhausted);
        if (extends_range)
            sent_ranges_[sent_range_count_ - 1].largest = packet.number;
        else
            sent_ranges_[sent_range_count_++] = {packet.number, packet.number};
        packets_[size_++] = packet;
        highest_sent_ = packet.number;
        return {};
    }

    [[nodiscard]] constexpr auto remove(std::uint64_t packet_number) noexcept
        -> bool
    {
        for (std::size_t index = 0; index < size_; ++index) {
            if (packets_[index].number != packet_number) continue;
            for (std::size_t next = index + 1; next < size_; ++next)
                packets_[next - 1] = packets_[next];
            --size_;
            return true;
        }
        return false;
    }

    // Validates ACK ranges, the sent-number high-water mark, and output
    // capacity before changing records. ACK-frame syntax is normally checked
    // by decode_frame(); this also validates the range fields defensively.
    // Metadata-only ACK path: no RTT update. Output contains only newly
    // acknowledged retained records, in descending packet-number order.
    // Previously ACKed or explicitly removed records are ignored; their
    // numbers remain in the sent-range ledger.
    [[nodiscard]] constexpr auto acknowledge(const decoded_frame& frame,
                                              std::span<sent_packet> output)
        noexcept -> std::expected<std::size_t, sent_packet_error>
    {
        const auto preview = preflight_ack(frame, output.size());
        if (!preview) return std::unexpected(preview.error());
        commit_ack(frame, output, preview->count);
        return preview->count;
    }

    // The ACK delay argument is already decoded into microseconds by the
    // caller. RTT state is shared across packet-number spaces by the caller.
    [[nodiscard]] constexpr auto acknowledge_with_rtt(
        const decoded_frame& frame, recovery_time_point now,
        recovery_duration decoded_ack_delay, recovery_duration max_ack_delay,
        packet_number_space space, bool handshake_confirmed,
        rtt_estimator& estimator, std::span<sent_packet> output) noexcept
        -> std::expected<std::size_t, sent_packet_error>
    {
        const auto preview = preflight_ack(frame, output.size());
        if (!preview) return std::unexpected(preview.error());
        std::optional<recovery_duration> sample;
        if (preview->largest_new && preview->any_ack_eliciting) {
            if (now < preview->largest_new->sent_time)
                return std::unexpected(sent_packet_error::invalid_time);
            sample = elapsed_between(now, preview->largest_new->sent_time);
        }
        commit_ack(frame, output, preview->count);
        if (sample)
            estimator.update(*sample, decoded_ack_delay, max_ack_delay,
                             space, handshake_confirmed);
        return preview->count;
    }

    [[nodiscard]] constexpr auto largest_acked() const noexcept
        -> std::optional<std::uint64_t>
    { return largest_acked_; }

private:
    struct ack_preview {
        std::size_t count {0};
        std::optional<sent_packet> largest_new {};
        bool any_ack_eliciting {false};
    };

    [[nodiscard]] constexpr auto preflight_ack(const decoded_frame& frame,
                                                std::size_t output_capacity)
        const noexcept -> std::expected<ack_preview, sent_packet_error>
    {
        auto cursor = ack_range_cursor::from_frame(frame);
        if (!cursor || !highest_sent_ ||
            frame.largest_acknowledged > *highest_sent_)
            return std::unexpected(sent_packet_error::invalid_ack);

        ack_preview preview;
        for (;;) {
            const auto range = cursor->next();
            if (!range) return std::unexpected(sent_packet_error::invalid_ack);
            if (!*range) break;
            if (!range_was_sent((*range)->smallest, (*range)->largest))
                return std::unexpected(sent_packet_error::invalid_ack);
            for (std::size_t index = size_; index > 0; --index) {
                const auto& packet = packets_[index - 1];
                if (packet.number < (*range)->smallest ||
                    packet.number > (*range)->largest) continue;
                ++preview.count;
                preview.any_ack_eliciting |= packet.ack_eliciting;
                if (packet.number == frame.largest_acknowledged)
                    preview.largest_new = packet;
            }
        }
        if (preview.count > output_capacity)
            return std::unexpected(sent_packet_error::output_full);
        return preview;
    }

    constexpr auto commit_ack(const decoded_frame& frame,
                              std::span<sent_packet> output,
                              std::size_t acknowledged) noexcept -> void
    {
        if (!largest_acked_ || frame.largest_acknowledged > *largest_acked_)
            largest_acked_ = frame.largest_acknowledged;
        if (acknowledged == 0) return;
        auto cursor = ack_range_cursor::from_frame(frame);
        std::size_t written = 0;
        for (;;) {
            const auto range = cursor->next();
            if (!*range) break; // Already validated in the first pass.
            for (std::size_t index = size_; index > 0; --index) {
                const auto& packet = packets_[index - 1];
                if (packet.number >= (*range)->smallest &&
                    packet.number <= (*range)->largest)
                    output[written++] = packet;
            }
        }

        std::size_t kept = 0;
        std::size_t removed = acknowledged;
        for (std::size_t index = 0; index < size_; ++index) {
            if (removed != 0 &&
                packets_[index].number == output[removed - 1].number) {
                --removed;
            } else {
                packets_[kept++] = packets_[index];
            }
        }
        size_ = kept;
    }

public:
    // The caller supplies the largest acknowledged packet in this number
    // space. No RTT, PTO, or congestion state is updated here.
    [[nodiscard]] constexpr auto detect_lost(
        std::uint64_t largest_acked, recovery_time_point now,
        recovery_duration latest_rtt, recovery_duration smoothed_rtt,
        std::span<sent_packet> output) noexcept
        -> std::expected<detected_losses, sent_packet_error>
    {
        if (!number_was_sent(largest_acked))
            return std::unexpected(sent_packet_error::invalid_ack);

        const auto delay = loss_delay(latest_rtt, smoothed_rtt);
        detected_losses result;
        for (std::size_t index = size_; index > 0; --index) {
            const auto& packet = packets_[index - 1];
            if (!packet.in_flight || packet.number >= largest_acked) continue;
            if (now < packet.sent_time)
                return std::unexpected(sent_packet_error::invalid_time);
            const auto age = elapsed_between(now, packet.sent_time);
            if (later_sent_reaches_threshold(packet.number, largest_acked) ||
                age >= delay) {
                ++result.count;
                continue;
            }
            const auto remaining = delay - age;
            if (!result.next_delay || remaining < *result.next_delay)
                result.next_delay = remaining;
        }
        if (result.count > output.size())
            return std::unexpected(sent_packet_error::output_full);
        if (result.count == 0) return result;

        std::size_t written = 0;
        for (std::size_t index = size_; index > 0; --index) {
            const auto& packet = packets_[index - 1];
            if (!packet.in_flight || packet.number >= largest_acked) continue;
            const auto age = elapsed_between(now, packet.sent_time);
            if (later_sent_reaches_threshold(packet.number, largest_acked) ||
                age >= delay)
                output[written++] = packet;
        }

        std::size_t kept = 0;
        std::size_t removed = result.count;
        for (std::size_t index = 0; index < size_; ++index) {
            if (removed != 0 &&
                packets_[index].number == output[removed - 1].number) {
                --removed;
            } else {
                packets_[kept++] = packets_[index];
            }
        }
        size_ = kept;
        return result;
    }

    [[nodiscard]] constexpr auto remaining() const noexcept
        -> std::span<const sent_packet>
    { return {packets_.data(), size_}; }

    [[nodiscard]] constexpr auto size() const noexcept -> std::size_t
    { return size_; }

    [[nodiscard]] constexpr auto highest_sent() const noexcept
        -> std::optional<std::uint64_t>
    { return highest_sent_; }

    constexpr auto reset() noexcept -> void
    {
        size_ = 0;
        sent_range_count_ = 0;
        highest_sent_.reset();
        largest_acked_.reset();
    }

private:
    struct sent_number_range {
        std::uint64_t smallest {0};
        std::uint64_t largest {0};
    };

    [[nodiscard]] constexpr auto number_was_sent(std::uint64_t number)
        const noexcept -> bool
    {
        for (std::size_t index = sent_range_count_; index > 0; --index) {
            const auto& range = sent_ranges_[index - 1];
            if (number > range.largest) return false;
            if (number >= range.smallest) return true;
        }
        return false;
    }

    [[nodiscard]] constexpr auto range_was_sent(std::uint64_t smallest,
                                                 std::uint64_t largest)
        const noexcept -> bool
    {
        for (std::size_t index = sent_range_count_; index > 0; --index) {
            const auto& range = sent_ranges_[index - 1];
            if (largest > range.largest) return false;
            if (largest < range.smallest) continue;
            return smallest >= range.smallest;
        }
        return false;
    }

    // RFC 9002's numeric-distance pseudocode assumes the sender makes no
    // packet-number gaps. Count actual transmissions through largest_acked.
    [[nodiscard]] constexpr auto later_sent_reaches_threshold(
        std::uint64_t packet_number, std::uint64_t largest_acked)
        const noexcept -> bool
    {
        std::uint64_t later = 0;
        for (std::size_t index = sent_range_count_; index > 0; --index) {
            const auto& range = sent_ranges_[index - 1];
            if (range.largest <= packet_number) break;
            if (range.smallest > largest_acked) continue;
            const auto smallest = std::max(range.smallest, packet_number + 1);
            const auto largest = std::min(range.largest, largest_acked);
            const auto count = largest - smallest + 1;
            if (packet_threshold_lost(later + count)) return true;
            later += count;
        }
        return false;
    }

    [[nodiscard]] static constexpr auto elapsed_between(
        recovery_time_point later, recovery_time_point earlier) noexcept
        -> recovery_duration
    {
        using clock_duration = recovery_time_point::duration;
        using clock_rep = clock_duration::rep;
        using unsigned_rep = std::make_unsigned_t<clock_rep>;
        using clock_to_micro = std::ratio_divide<clock_duration::period,
                                                 recovery_duration::period>;
        static_assert(std::is_signed_v<clock_rep> && sizeof(clock_rep) <= 8);
        static_assert(clock_to_micro::num == 1,
                      "steady_clock ticks must divide one microsecond");
        const auto ticks = static_cast<unsigned_rep>(
            later.time_since_epoch().count()) -
            static_cast<unsigned_rep>(earlier.time_since_epoch().count());
        const auto micros = ticks /
            static_cast<unsigned_rep>(clock_to_micro::den);
        if (micros > static_cast<unsigned_rep>(
                         recovery_duration::max().count()))
            return recovery_duration::max();
        return recovery_duration {static_cast<recovery_duration::rep>(micros)};
    }

    std::array<sent_packet, Capacity> packets_ {};
    std::array<sent_number_range, SentRangeCapacity> sent_ranges_ {};
    std::size_t size_ {0};
    std::size_t sent_range_count_ {0};
    std::optional<std::uint64_t> highest_sent_ {};
    std::optional<std::uint64_t> largest_acked_ {};
};

} // namespace eventloop::quic::detail
