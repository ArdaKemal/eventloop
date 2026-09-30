#pragma once

#include "quic/frames.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace eventloop::quic::detail {

struct ack_range {
    std::uint64_t smallest {0};
    std::uint64_t largest {0};
};

// The frame and its borrowed ACK bytes must remain alive for this cursor.
// A zero ACK Range Count still yields the First ACK Range.
class ack_range_cursor {
public:
    [[nodiscard]] static constexpr auto from_frame(const decoded_frame& frame)
        noexcept -> std::expected<ack_range_cursor, frame_error>
    {
        if (frame.type != 0x02 && frame.type != 0x03)
            return std::unexpected(frame_error::invalid_frame);
        if (frame.largest_acknowledged > max_varint_value ||
            frame.first_ack_range > max_varint_value ||
            frame.ack_range_count > max_varint_value)
            return std::unexpected(frame_error::invalid_value);
        if (frame.first_ack_range > frame.largest_acknowledged)
            return std::unexpected(frame_error::invalid_ack_range);
        if (frame.ack_range_count > frame.ack_ranges.size() / 2)
            return std::unexpected(frame_error::truncated);
        return ack_range_cursor {frame.largest_acknowledged,
                                 frame.first_ack_range,
                                 frame.ack_range_count, frame.ack_ranges};
    }

    [[nodiscard]] constexpr auto next() noexcept
        -> std::expected<std::optional<ack_range>, frame_error>
    {
        if (failed_) return std::unexpected(error_);
        if (first_pending_) {
            first_pending_ = false;
            return std::optional<ack_range> {ack_range {smallest_, largest_}};
        }
        if (remaining_ == 0) {
            if (cursor_ != encoded_.size())
                return fail(frame_error::invalid_ack_range);
            return std::nullopt;
        }

        const auto gap = decode_varint(encoded_.subspan(cursor_));
        if (!gap) return fail(frame_error::truncated);
        cursor_ += gap->encoded_size;
        const auto range = decode_varint(encoded_.subspan(cursor_));
        if (!range) return fail(frame_error::truncated);
        cursor_ += range->encoded_size;
        if (smallest_ < 2 || gap->value > smallest_ - 2)
            return fail(frame_error::invalid_ack_range);
        largest_ = smallest_ - gap->value - 2;
        if (range->value > largest_)
            return fail(frame_error::invalid_ack_range);
        smallest_ = largest_ - range->value;
        --remaining_;
        return std::optional<ack_range> {ack_range {smallest_, largest_}};
    }

private:
    constexpr ack_range_cursor(std::uint64_t largest, std::uint64_t first,
                               std::uint64_t count,
                               std::span<const std::byte> encoded) noexcept
        : largest_(largest), smallest_(largest - first), remaining_(count),
          encoded_(encoded) {}

    [[nodiscard]] constexpr auto fail(frame_error error) noexcept
        -> std::expected<std::optional<ack_range>, frame_error>
    {
        failed_ = true;
        error_ = error;
        return std::unexpected(error);
    }

    std::uint64_t largest_;
    std::uint64_t smallest_;
    std::uint64_t remaining_;
    std::span<const std::byte> encoded_;
    std::size_t cursor_ {0};
    frame_error error_ {frame_error::invalid_ack_range};
    bool first_pending_ {true};
    bool failed_ {false};
};

} // namespace eventloop::quic::detail
