#pragma once

#include "quic/varint.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

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
//
// Byte state is tracked as intervals instead of a per-byte flag array. `base_`
// is the acknowledged prefix (SND.UNA) and `acked_` holds out-of-order ACKs
// (SACK); `sent_` is every transmitted interval and unsent bytes are its
// complement in [base_, end_); `lost_` is transmitted-but-unacknowledged bytes
// queued for retransmission. Selection and validation are O(intervals) rather
// than O(bytes), matching msquic's SparseAckRanges and mvfst's IntervalSet.
template<std::size_t Capacity>
class crypto_send_buffer {
    static_assert(Capacity > 0);
    static constexpr std::size_t max_ranges = Capacity < 64 ? Capacity : 64;

    struct offset_range {
        std::uint64_t begin {0};
        std::uint64_t end {0};
    };

    // Sorted, non-overlapping, non-adjacent half-open intervals [begin, end).
    // Capacity is bounded by the tracked window; more than `max_ranges` holes
    // is reported as crypto_send_error::capacity_exceeded rather than corrupting.
    struct range_set {
        std::array<offset_range, max_ranges> ranges_ {};
        std::size_t size_ {0};

        constexpr auto clear() noexcept -> void { size_ = 0; }
        [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size_ == 0; }
        [[nodiscard]] constexpr auto front() const noexcept -> std::uint64_t
        { return ranges_[0].begin; }

        [[nodiscard]] constexpr auto contains(std::uint64_t value) const noexcept -> bool
        {
            for (std::size_t i = 0; i < size_; ++i)
                if (ranges_[i].begin <= value && value < ranges_[i].end) return true;
            return false;
        }
        [[nodiscard]] constexpr auto covers(std::uint64_t begin, std::uint64_t end) const noexcept -> bool
        {
            if (begin >= end) return true;
            for (std::size_t i = 0; i < size_; ++i)
                if (ranges_[i].begin <= begin && end <= ranges_[i].end) return true;
            return false;
        }
        [[nodiscard]] constexpr auto intersects(std::uint64_t begin, std::uint64_t end) const noexcept -> bool
        {
            for (std::size_t i = 0; i < size_; ++i)
                if (ranges_[i].begin < end && begin < ranges_[i].end) return true;
            return false;
        }
        [[nodiscard]] constexpr auto interval_end(std::uint64_t value) const noexcept -> std::uint64_t
        {
            for (std::size_t i = 0; i < size_; ++i)
                if (ranges_[i].begin <= value && value < ranges_[i].end) return ranges_[i].end;
            return value;
        }
        // First offset in [from, limit) present in the set, or limit.
        [[nodiscard]] constexpr auto first_present(std::uint64_t from, std::uint64_t limit) const noexcept -> std::uint64_t
        {
            if (from >= limit) return limit;
            for (std::size_t i = 0; i < size_; ++i) {
                if (ranges_[i].end <= from) continue;
                if (ranges_[i].begin >= limit) break;
                return std::max(ranges_[i].begin, from);
            }
            return limit;
        }
        // First offset in [from, limit) absent from the set, or limit.
        [[nodiscard]] constexpr auto first_missing(std::uint64_t from, std::uint64_t limit) const noexcept -> std::uint64_t
        {
            if (from >= limit) return limit;
            for (std::size_t i = 0; i < size_; ++i) {
                if (ranges_[i].end <= from) continue;
                if (ranges_[i].begin > from) return from;
                return std::min(ranges_[i].end, limit);
            }
            return from;
        }

        [[nodiscard]] constexpr auto add(std::uint64_t begin, std::uint64_t end) noexcept -> bool
        {
            if (begin >= end) return true;
            std::size_t i = 0;
            while (i < size_ && ranges_[i].end < begin) ++i;
            auto merged_begin = begin;
            auto merged_end = end;
            std::size_t j = i;
            while (j < size_ && ranges_[j].begin <= merged_end) {
                merged_begin = std::min(merged_begin, ranges_[j].begin);
                merged_end = std::max(merged_end, ranges_[j].end);
                ++j;
            }
            const auto removed = j - i;
            if (removed == 0) {
                if (size_ == max_ranges) return false;
                for (std::size_t k = size_; k > i; --k) ranges_[k] = ranges_[k - 1];
                ++size_;
            } else {
                std::size_t write = i + 1;
                for (std::size_t read = j; read < size_; ++read) ranges_[write++] = ranges_[read];
                size_ = write;
            }
            ranges_[i] = {merged_begin, merged_end};
            return true;
        }

        constexpr auto remove(std::uint64_t begin, std::uint64_t end) noexcept -> void
        {
            if (begin >= end) return;
            std::size_t write = 0;
            for (std::size_t i = 0; i < size_; ++i) {
                const auto r = ranges_[i];
                if (r.end <= begin || r.begin >= end) {
                    ranges_[write++] = r;
                    continue;
                }
                if (r.begin < begin && write < max_ranges) ranges_[write++] = {r.begin, begin};
                if (r.end > end && write < max_ranges) ranges_[write++] = {end, r.end};
            }
            size_ = write;
        }

        constexpr auto drop_below(std::uint64_t value) noexcept -> void
        {
            std::size_t write = 0;
            for (std::size_t i = 0; i < size_; ++i) {
                auto r = ranges_[i];
                if (r.end <= value) continue;
                if (r.begin < value) r.begin = value;
                ranges_[write++] = r;
            }
            size_ = write;
        }
    };

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
        sent_.clear();
        acked_.clear();
        lost_.clear();
    }

    // Retry occurs before any authenticated response can acknowledge CRYPTO.
    // Preserve the exact TLS bytes while making the whole first flight pending.
    [[nodiscard]] constexpr auto retransmit_initial() noexcept -> bool
    {
        if (base_ != 0 || !acked_.empty()) return false;
        sent_.clear();
        lost_.clear();
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
        std::copy(data.begin() + first, data.end(), bytes_.begin());
        end_ += data.size();
        return offset;
    }

    // Selects the lowest pending interval. The span stops at the ring wrap,
    // a non-pending byte, or max_size. The caller records the transmitted
    // interval with mark_sent() only after packet construction succeeds.
    [[nodiscard]] constexpr auto next_pending(std::size_t max_size) const noexcept
        -> crypto_send_chunk
    {
        if (max_size == 0 || base_ == end_) return {};
        auto start = sent_.first_missing(base_, end_);
        if (!lost_.empty() && lost_.front() < start) start = lost_.front();
        if (start >= end_) return {};
        auto run_end = start;
        for (;;) {
            if (run_end >= end_) break;
            if (!sent_.contains(run_end)) {
                run_end = sent_.first_present(run_end, end_);
                continue;
            }
            if (lost_.contains(run_end)) {
                run_end = lost_.interval_end(run_end);
                continue;
            }
            break;
        }
        const auto slot = static_cast<std::size_t>(start % Capacity);
        const auto length = std::min({max_size,
            static_cast<std::size_t>(run_end - start),
            Capacity - slot});
        return {start, std::span<const std::byte>(bytes_).subspan(slot, length)};
    }

    // PTO selects transmitted bytes without marking the original packet lost
    // or mutating pending state. ACKed bytes are never selected. A later
    // probe passes the end of the previous one to carry different bytes.
    [[nodiscard]] constexpr auto next_unacknowledged(std::size_t max_size,
        std::uint64_t from = 0) const noexcept -> crypto_send_chunk
    {
        if (max_size == 0 || base_ == end_) return {};
        for (std::size_t i = 0; i < sent_.size_; ++i) {
            const auto begin = std::max({sent_.ranges_[i].begin, base_, from});
            const auto end = std::min(sent_.ranges_[i].end, end_);
            auto cur = begin;
            while (cur < end) {
                const auto ack_end = acked_.interval_end(cur);
                if (ack_end > cur) { cur = ack_end; continue; }
                const auto block_end = std::min(end, acked_.first_present(cur, end));
                const auto slot = static_cast<std::size_t>(cur % Capacity);
                const auto length = std::min({max_size,
                    static_cast<std::size_t>(block_end - cur),
                    Capacity - slot});
                return {cur, std::span<const std::byte>(bytes_).subspan(slot, length)};
            }
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
        if (acked_.intersects(offset, offset + length))
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
        if (!commit_mark_sent(offset, length))
            return std::unexpected(crypto_send_error::capacity_exceeded);
        return {};
    }

    // Commit a range the caller already validated with preflight_mark_sent in
    // the same serialized operation. Skips the redundant rescan.
    constexpr auto mark_sent_trusted(std::uint64_t offset,
                                     std::size_t length) noexcept -> void
    {
        (void)commit_mark_sent(offset, length);
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
        if (start < finish && !sent_.covers(start, finish))
            return std::unexpected(crypto_send_error::unsent_data);
        // Ordered ACKs retire the prefix without creating a temporary SACK
        // interval only to find and erase it again in advance_base().
        if (start < finish && start == base_ && acked_.empty()) {
            base_ = finish;
            sent_.drop_below(base_);
            lost_.drop_below(base_);
            return {};
        }
        if (start < finish) {
            lost_.remove(start, finish);
            if (!acked_.add(start, finish))
                return std::unexpected(crypto_send_error::capacity_exceeded);
        }
        advance_base();
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
        if (start < finish && !sent_.covers(start, finish))
            return std::unexpected(crypto_send_error::unsent_data);
        auto cur = start;
        while (cur < finish) {
            const auto ack_end = acked_.interval_end(cur);
            if (ack_end > cur) { cur = ack_end; continue; }
            const auto block_end = std::min(finish, acked_.first_present(cur, finish));
            if (!lost_.add(cur, block_end))
                return std::unexpected(crypto_send_error::capacity_exceeded);
            cur = block_end;
        }
        return {};
    }

private:
    [[nodiscard]] constexpr auto commit_mark_sent(std::uint64_t offset,
                                                  std::size_t length) noexcept -> bool
    {
        lost_.remove(offset, offset + length);
        return sent_.add(offset, offset + length);
    }

    // Advance the acknowledged prefix (SND.UNA) over contiguous ACKed bytes and
    // drop state below it.
    constexpr auto advance_base() noexcept -> void
    {
        for (;;) {
            const auto next = acked_.interval_end(base_);
            if (next <= base_) break;
            base_ = next;
        }
        sent_.drop_below(base_);
        acked_.drop_below(base_);
        lost_.drop_below(base_);
    }

    [[nodiscard]] constexpr auto valid_range(std::uint64_t offset,
                                              std::size_t length) const noexcept
        -> bool
    {
        return offset <= end_ && length <= end_ - offset;
    }

    std::array<std::byte, Capacity> bytes_ {};
    range_set sent_ {};
    range_set acked_ {};
    range_set lost_ {};
    std::uint64_t base_ {0};
    std::uint64_t end_ {0};
};

} // namespace eventloop::quic::detail
