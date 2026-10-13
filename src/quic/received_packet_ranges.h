#pragma once

#include "quic/ack_ranges.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace eventloop::quic::detail {

enum class received_packet_error {
    invalid_packet_number,
    retired_packet_number,
    invalid_retirement,
    empty,
    invalid_ack_delay,
};

// One instance tracks one packet-number space. When full, a disjoint newer
// packet evicts the oldest range (RFC 9000 13.2.3) and raises the acceptance
// floor past it; a disjoint packet older than every range is refused as
// retired. Explicit retirement also advances the floor.
template <std::size_t Capacity>
class received_packet_ranges {
    static_assert(Capacity > 0);

public:
    [[nodiscard]] constexpr auto size() const noexcept -> std::size_t
    {
        return size_;
    }

    [[nodiscard]] constexpr auto ranges() const noexcept
        -> std::span<const ack_range>
    {
        return {ranges_.data(), size_};
    }

    [[nodiscard]] constexpr auto largest_received() const noexcept
        -> std::optional<std::uint64_t>
    {
        return largest_received_;
    }

    [[nodiscard]] constexpr auto minimum_acceptable() const noexcept
        -> std::uint64_t
    {
        return minimum_acceptable_;
    }

    constexpr auto reset() noexcept -> void
    {
        size_ = 0;
        largest_received_.reset();
        minimum_acceptable_ = 0;
    }

    // Returns false for a duplicate. A failed insertion leaves every range
    // unchanged.
    [[nodiscard]] constexpr auto insert(std::uint64_t number) noexcept
        -> std::expected<bool, received_packet_error>
    {
        if (number > max_varint_value)
            return std::unexpected(received_packet_error::invalid_packet_number);
        if (number < minimum_acceptable_)
            return std::unexpected(received_packet_error::retired_packet_number);

        std::size_t index = 0;
        while (index < size_ && ranges_[index].largest > number) {
            if (number >= ranges_[index].smallest) return false;
            ++index;
        }
        if (index < size_ && number >= ranges_[index].smallest &&
            number <= ranges_[index].largest)
            return false;

        const bool join_above = index > 0 &&
            ranges_[index - 1].smallest > number &&
            ranges_[index - 1].smallest - number == 1;
        const bool join_below = index < size_ &&
            number > ranges_[index].largest &&
            number - ranges_[index].largest == 1;
        if (join_above && join_below) {
            ranges_[index - 1].smallest = ranges_[index].smallest;
            for (std::size_t at = index; at + 1 < size_; ++at)
                ranges_[at] = ranges_[at + 1];
            --size_;
        } else if (join_above) {
            ranges_[index - 1].smallest = number;
        } else if (join_below) {
            ranges_[index].largest = number;
        } else {
            if (size_ == Capacity) {
                if (index == size_)
                    return std::unexpected(received_packet_error::retired_packet_number);
                minimum_acceptable_ = ranges_[size_ - 1].largest + 1;
                --size_;
            }
            for (std::size_t at = size_; at > index; --at)
                ranges_[at] = ranges_[at - 1];
            ranges_[index] = ack_range {number, number};
            ++size_;
        }
        if (!largest_received_ || number > *largest_received_)
            largest_received_ = number;
        return true;
    }

    // Call only after the packet carrying an ACK with this Largest
    // Acknowledged value is itself acknowledged. Values not represented by a
    // retained range are rejected; stale retirements are harmless no-ops.
    [[nodiscard]] constexpr auto retire_through(
        std::uint64_t largest_acknowledged) noexcept
        -> std::expected<bool, received_packet_error>
    {
        if (largest_acknowledged > max_varint_value || !largest_received_ ||
            largest_acknowledged > *largest_received_)
            return std::unexpected(received_packet_error::invalid_retirement);
        if (largest_acknowledged < minimum_acceptable_) return false;

        bool retained = false;
        for (std::size_t index = 0; index < size_; ++index)
            if (ranges_[index].smallest <= largest_acknowledged &&
                largest_acknowledged <= ranges_[index].largest) {
                retained = true;
                break;
            }
        if (!retained)
            return std::unexpected(received_packet_error::invalid_retirement);

        minimum_acceptable_ = largest_acknowledged + 1;
        std::size_t kept = 0;
        for (std::size_t index = 0; index < size_; ++index) {
            auto range = ranges_[index];
            if (range.largest < minimum_acceptable_) continue;
            if (range.smallest < minimum_acceptable_)
                range.smallest = minimum_acceptable_;
            ranges_[kept++] = range;
        }
        size_ = kept;
        return true;
    }

    // Only gap/range pairs are written to storage. The returned frame borrows
    // those bytes; the caller supplies ACK delay in already encoded units.
    // The newest range is always included. Older ranges are included in order
    // until the next gap/range pair does not fit. On failure storage is unchanged.
    [[nodiscard]] constexpr auto make_ack(std::uint64_t ack_delay,
                                          std::span<std::byte> storage) const noexcept
        -> std::expected<decoded_frame, received_packet_error>
    {
        if (size_ == 0)
            return std::unexpected(received_packet_error::empty);
        if (ack_delay > max_varint_value)
            return std::unexpected(received_packet_error::invalid_ack_delay);

        std::size_t needed = 0;
        std::size_t pair_count = 0;
        for (std::size_t index = 1; index < size_; ++index) {
            const auto gap = ranges_[index - 1].smallest -
                             ranges_[index].largest - 2;
            const auto length = ranges_[index].largest -
                                ranges_[index].smallest;
            const auto pair_size = varint_size(gap) + varint_size(length);
            if (pair_size > storage.size() - needed)
                break;
            needed += pair_size;
            ++pair_count;
        }

        std::size_t cursor = 0;
        for (std::size_t index = 1; index <= pair_count; ++index) {
            const auto gap = ranges_[index - 1].smallest -
                             ranges_[index].largest - 2;
            const auto length = ranges_[index].largest -
                                ranges_[index].smallest;
            cursor += *encode_varint(gap, storage.subspan(cursor));
            cursor += *encode_varint(length, storage.subspan(cursor));
        }
        decoded_frame frame;
        frame.type = 0x02;
        frame.largest_acknowledged = ranges_[0].largest;
        frame.ack_delay = ack_delay;
        frame.ack_range_count = pair_count;
        frame.first_ack_range = ranges_[0].largest - ranges_[0].smallest;
        frame.ack_ranges = storage.first(needed);
        return frame;
    }

private:
    std::array<ack_range, Capacity> ranges_ {};
    std::size_t size_ {0};
    std::optional<std::uint64_t> largest_received_ {};
    std::uint64_t minimum_acceptable_ {0};
};

} // namespace eventloop::quic::detail
