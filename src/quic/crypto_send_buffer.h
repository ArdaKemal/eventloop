#pragma once

#include "quic/varint.h"

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <type_traits>

namespace eventloop::quic::detail {

enum class crypto_send_error {
    invalid_offset,
    invalid_range,
    capacity_exceeded,
    unsent_data,
};

struct crypto_send_chunk {
    std::uint64_t offset {0};
    std::span<const std::byte> data {};
};

// One encryption level's CRYPTO stream. Capacity is the maximum unacknowledged
// window; append copies provider output so its source may be released. No
// storage or allocation is supplied by the caller. Returned spans are valid
// until the next append, acknowledge, or reset.
template<std::size_t Capacity>
class crypto_send_buffer {
    static_assert(Capacity > 0);

public:
    [[nodiscard]] constexpr auto base_offset() const noexcept -> std::uint64_t
    {
        return base_;
    }

    [[nodiscard]] constexpr auto next_offset() const noexcept -> std::uint64_t
    {
        return end_;
    }

    [[nodiscard]] constexpr auto buffered_size() const noexcept -> std::size_t
    {
        return static_cast<std::size_t>(end_ - base_);
    }

    constexpr auto reset() noexcept -> void
    {
        base_ = 0;
        end_ = 0;
        pending_begin_ = 0;
        flags_.fill(0);
    }

    // Retry occurs before any authenticated response can acknowledge CRYPTO.
    // Preserve the exact TLS bytes while making the whole first flight pending.
    [[nodiscard]] constexpr auto retransmit_initial() noexcept -> bool
    {
        if (base_ != 0) return false;
        for (auto offset = base_; offset < end_; ++offset)
            if (flags_[offset % Capacity] & acked_flag) return false;
        for (auto offset = base_; offset < end_; ++offset)
            flags_[offset % Capacity] = pending_flag;
        pending_begin_ = base_;
        return true;
    }

    // Returns the offset assigned to the first appended byte. Failure leaves
    // both offsets and contents unchanged.
    [[nodiscard]] constexpr auto append(std::span<const std::byte> data) noexcept
        -> std::expected<std::uint64_t, crypto_send_error>
    {
        if (data.size() > max_varint_value - end_)
            return std::unexpected(crypto_send_error::invalid_offset);
        if (data.size() > Capacity - buffered_size())
            return std::unexpected(crypto_send_error::capacity_exceeded);
        const auto offset = end_;
        if (data.empty()) return offset;
        const auto slot = static_cast<std::size_t>(end_ % Capacity);
        const auto first = std::min(data.size(), Capacity - slot);
        std::copy_n(data.begin(), first, bytes_.begin() + slot);
        std::fill_n(flags_.begin() + slot, first, pending_flag);
        std::copy(data.begin() + first, data.end(), bytes_.begin());
        std::fill_n(flags_.begin(), data.size() - first, pending_flag);
        end_ += data.size();
        return offset;
    }

    // Selects the lowest pending interval. The span stops at the ring wrap,
    // a non-pending byte, or max_size. The caller records the transmitted
    // interval with mark_sent() only after packet construction succeeds.
    [[nodiscard]] constexpr auto next_pending(std::size_t max_size) const noexcept
        -> crypto_send_chunk
    {
        if (max_size == 0 || pending_begin_ == end_) return {};
        const auto slot = static_cast<std::size_t>(pending_begin_ % Capacity);
        const auto limit = std::min({max_size, Capacity - slot,
                                     static_cast<std::size_t>(end_ - pending_begin_)});
        const auto length = matching_flags_prefix(
            std::span(flags_).subspan(slot, limit), pending_flag, pending_flag);
        return {pending_begin_, std::span<const std::byte>(bytes_).subspan(slot, length)};
    }

    // PTO selects transmitted bytes without marking the original packet lost
    // or mutating pending state. ACKed bytes are never selected.
    [[nodiscard]] constexpr auto next_unacknowledged(std::size_t max_size) const noexcept
        -> crypto_send_chunk
    {
        if (max_size == 0) return {};
        for (auto offset = base_; offset < end_; ++offset) {
            const auto slot = static_cast<std::size_t>(offset % Capacity);
            if ((flags_[slot] & (sent_flag | acked_flag)) != sent_flag) continue;
            const auto limit = std::min({max_size, Capacity - slot,
                                         static_cast<std::size_t>(end_ - offset)});
            std::size_t length = 0;
            while (length < limit &&
                   (flags_[slot + length] & (sent_flag | acked_flag)) == sent_flag) ++length;
            return {offset, std::span<const std::byte>(bytes_).subspan(slot, length)};
        }
        return {};
    }

    // Read-only validation for owner-thread packet submission preflight.
    [[nodiscard]] constexpr auto preflight_mark_sent(std::uint64_t offset,
                                           std::size_t length) const noexcept
        -> std::expected<void, crypto_send_error>
    {
        if (!valid_range(offset, length))
            return std::unexpected(crypto_send_error::invalid_range);
        if (offset < base_)
            return std::unexpected(crypto_send_error::invalid_range);
        if (!range_has_flags(offset, length, acked_flag, 0))
            return std::unexpected(crypto_send_error::invalid_range);
        return {};
    }

    // Repeated and overlapping transmissions are legal, including probes.
    // A later loss can make any unacknowledged byte pending again.
    [[nodiscard]] constexpr auto mark_sent(std::uint64_t offset,
                                           std::size_t length) noexcept
        -> std::expected<void, crypto_send_error>
    {
        if (const auto result = preflight_mark_sent(offset, length); !result) return result;
        // Preflight excluded ACKed bytes; every remaining byte becomes sent
        // and non-pending, including overlapping probes and retransmissions.
        fill_flags(offset, length, sent_flag);
        if (pending_begin_ >= offset && pending_begin_ < offset + length)
            pending_begin_ = offset + length;
        advance_pending();
        return {};
    }

    // ACK and loss reports may cover subranges of a transmitted CRYPTO frame.
    // Retired prefixes and duplicate reports are harmless. Reports for bytes
    // never sent are rejected without mutation.
    [[nodiscard]] constexpr auto acknowledge(std::uint64_t offset,
                                              std::size_t length) noexcept
        -> std::expected<void, crypto_send_error>
    {
        if (!valid_range(offset, length))
            return std::unexpected(crypto_send_error::invalid_range);
        const auto start = std::max(offset, base_);
        const auto finish = offset + length;
        if (start < finish && !range_has_flags(start, static_cast<std::size_t>(finish - start), sent_flag, sent_flag))
            return std::unexpected(crypto_send_error::unsent_data);
        if (start < finish) {
            if (start == base_) {
                // Validation proved this entire prefix sent. Retire it in
                // bulk, then inspect any suffix ACKed by an earlier report.
                fill_flags(start, static_cast<std::size_t>(finish - start), 0);
                base_ = finish;
            } else {
                fill_flags(start, static_cast<std::size_t>(finish - start), acked_flag | sent_flag);
            }
        }
        while (base_ < end_) {
            const auto slot = static_cast<std::size_t>(base_ % Capacity);
            const auto limit = std::min(Capacity - slot, static_cast<std::size_t>(end_ - base_));
            const auto length = matching_flags_prefix(
                std::span(flags_).subspan(slot, limit), acked_flag, acked_flag);
            std::fill_n(flags_.begin() + slot, length, 0);
            base_ += length;
            if (length != limit) break;
        }
        pending_begin_ = std::max(pending_begin_, base_);
        advance_pending();
        return {};
    }

    [[nodiscard]] constexpr auto mark_lost(std::uint64_t offset,
                                           std::size_t length) noexcept
        -> std::expected<void, crypto_send_error>
    {
        if (!valid_range(offset, length))
            return std::unexpected(crypto_send_error::invalid_range);
        const auto start = std::max(offset, base_);
        const auto finish = offset + length;
        if (start < finish && !range_has_flags(start, static_cast<std::size_t>(finish - start), sent_flag, sent_flag))
            return std::unexpected(crypto_send_error::unsent_data);
        for (auto pos = start; pos < finish; ++pos) {
            auto& flag = flags_[pos % Capacity];
            if ((flag & acked_flag) == 0) {
                flag |= pending_flag;
                pending_begin_ = std::min(pending_begin_, pos);
            }
        }
        return {};
    }

private:
    [[nodiscard]] static constexpr auto has_flags(std::span<const std::uint8_t> flags,
        std::uint8_t mask, std::uint8_t expected) noexcept -> bool
    {
        return matching_flags_prefix(flags, mask, expected) == flags.size();
    }
    [[nodiscard]] static constexpr auto matching_flags_prefix(std::span<const std::uint8_t> flags,
        std::uint8_t mask, std::uint8_t expected) noexcept -> std::size_t
    {
        std::size_t i = 0;
        if (!std::is_constant_evaluated()) {
            // Uniform byte masks work in either endian order. memcpy permits
            // unaligned loads without aliasing or reading beyond the segment.
            constexpr std::uint64_t repeat = 0x0101010101010101;
            const auto word_mask = repeat * mask;
            const auto word_expected = repeat * expected;
            for (; flags.size() - i >= sizeof(std::uint64_t); i += sizeof(std::uint64_t)) {
                std::uint64_t word;
                std::memcpy(&word, flags.data() + i, sizeof(word));
                if ((word & word_mask) != word_expected) break;
            }
        }
        for (; i < flags.size(); ++i)
            if ((flags[i] & mask) != expected) break;
        return i;
    }
    [[nodiscard]] constexpr auto range_has_flags(std::uint64_t offset,
        std::size_t length, std::uint8_t mask, std::uint8_t expected) const noexcept -> bool
    {
        const auto slot = static_cast<std::size_t>(offset % Capacity);
        const auto first = std::min(length, Capacity - slot);
        return has_flags(std::span(flags_).subspan(slot, first), mask, expected) &&
            has_flags(std::span(flags_).first(length - first), mask, expected);
    }
    constexpr auto fill_flags(std::uint64_t offset, std::size_t length,
        std::uint8_t value) noexcept -> void
    {
        const auto slot = static_cast<std::size_t>(offset % Capacity);
        const auto first = std::min(length, Capacity - slot);
        std::fill_n(flags_.begin() + slot, first, value);
        std::fill_n(flags_.begin(), length - first, value);
    }
    // Lowest pending byte, or end_ when all buffered bytes are in flight.
    // Retain it across packet selection so an ACK-blocked stream does not
    // rescan its whole ring for every packet sent on another stream.
    constexpr auto advance_pending() noexcept -> void
    {
        while (pending_begin_ < end_ &&
               (flags_[pending_begin_ % Capacity] & pending_flag) == 0)
            ++pending_begin_;
    }
    [[nodiscard]] constexpr auto valid_range(std::uint64_t offset,
                                              std::size_t length) const noexcept
        -> bool
    {
        return offset <= end_ && length <= end_ - offset;
    }

    static constexpr std::uint8_t pending_flag = 1;
    static constexpr std::uint8_t sent_flag = 2;
    static constexpr std::uint8_t acked_flag = 4;
    std::array<std::byte, Capacity> bytes_ {};
    std::array<std::uint8_t, Capacity> flags_ {};
    std::uint64_t base_ {0};
    std::uint64_t end_ {0};
    std::uint64_t pending_begin_ {0};
};

} // namespace eventloop::quic::detail
