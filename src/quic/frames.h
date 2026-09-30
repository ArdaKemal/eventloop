#pragma once

#include "quic/varint.h"

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>

namespace eventloop::quic::detail {

enum class frame_error { truncated, invalid_frame, invalid_value, invalid_ack_range,
                         invalid_connection_id, output_too_small };

// Decode one frame from a decrypted packet payload. Every span borrows input.
// Packet-number-space, peer state, and negotiated-extension rules are left to
// the transport because this API has no connection or packet context.
struct decoded_frame {
    std::uint64_t type {0};
    std::size_t encoded_size {0};
    std::uint64_t stream_id {0};
    std::uint64_t offset {0};
    std::uint64_t limit {0};
    std::uint64_t error_code {0};
    std::uint64_t frame_type {0};
    std::uint64_t final_size {0};
    std::uint64_t sequence_number {0};
    std::uint64_t retire_prior_to {0};
    std::uint64_t largest_acknowledged {0};
    std::uint64_t ack_delay {0};
    std::uint64_t first_ack_range {0};
    std::uint64_t ack_range_count {0};
    std::array<std::uint64_t, 3> ecn_counts {};
    // Encoded gap/range pairs, validated but not materialized.
    std::span<const std::byte> ack_ranges {};
    std::span<const std::byte> data {};
    std::span<const std::byte> connection_id {};
    std::span<const std::byte> stateless_reset_token {};
    std::span<const std::byte> reason_phrase {};
    bool fin {false};
};

// Encode one frame into caller storage. The entire input is validated before
// output is changed. ACK range pairs are decoded and written as canonical
// varints; encoded_size is output metadata and is ignored here. Output must not
// overlap any borrowed input span (ACK ranges, data, connection ID, stateless
// reset token, or reason phrase).
[[nodiscard]] constexpr auto encode_frame(const decoded_frame& frame,
                                          std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, frame_error>
{
    std::size_t size = 0;
    const auto add_size = [&](std::size_t amount) constexpr -> bool {
        if (amount > std::numeric_limits<std::size_t>::max() - size)
            return false;
        size += amount;
        return true;
    };
    const auto add_number = [&](std::uint64_t value) constexpr -> bool {
        const auto length = varint_size(value);
        return length != 0 && add_size(length);
    };
    const auto add_payload = [&](std::span<const std::byte> data) constexpr -> bool {
        return add_size(data.size());
    };
    const auto add_length_payload = [&](std::span<const std::byte> data)
        constexpr -> bool {
        if (data.size() > max_varint_value) return false;
        return add_number(static_cast<std::uint64_t>(data.size())) &&
               add_payload(data);
    };

    if (!add_number(frame.type))
        return std::unexpected(frame_error::invalid_frame);
    switch (frame.type) {
    case 0x00: case 0x01: case 0x1e:
        break;
    case 0x02: case 0x03: {
        if (!add_number(frame.largest_acknowledged) ||
            !add_number(frame.ack_delay) ||
            !add_number(frame.ack_range_count) ||
            !add_number(frame.first_ack_range))
            return std::unexpected(frame_error::invalid_value);
        if (frame.first_ack_range > frame.largest_acknowledged)
            return std::unexpected(frame_error::invalid_ack_range);
        auto smallest = frame.largest_acknowledged - frame.first_ack_range;
        std::size_t cursor = 0;
        if (frame.ack_range_count > frame.ack_ranges.size() / 2)
            return std::unexpected(frame_error::invalid_ack_range);
        for (std::uint64_t i = 0; i < frame.ack_range_count; ++i) {
            const auto gap = decode_varint(frame.ack_ranges.subspan(cursor));
            if (!gap) return std::unexpected(frame_error::invalid_ack_range);
            cursor += gap->encoded_size;
            const auto range = decode_varint(frame.ack_ranges.subspan(cursor));
            if (!range) return std::unexpected(frame_error::invalid_ack_range);
            cursor += range->encoded_size;
            if (smallest < 2 || gap->value > smallest - 2)
                return std::unexpected(frame_error::invalid_ack_range);
            const auto largest = smallest - gap->value - 2;
            if (range->value > largest)
                return std::unexpected(frame_error::invalid_ack_range);
            smallest = largest - range->value;
            if (!add_number(gap->value) || !add_number(range->value))
                return std::unexpected(frame_error::invalid_value);
        }
        if (cursor != frame.ack_ranges.size())
            return std::unexpected(frame_error::invalid_ack_range);
        if (frame.type == 0x03)
            for (const auto count : frame.ecn_counts)
                if (!add_number(count))
                    return std::unexpected(frame_error::invalid_value);
        break;
    }
    case 0x04:
        if (!add_number(frame.stream_id) || !add_number(frame.error_code) ||
            !add_number(frame.final_size))
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x05:
        if (!add_number(frame.stream_id) || !add_number(frame.error_code))
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x06:
        if (frame.offset > max_varint_value ||
            frame.data.size() > max_varint_value - frame.offset ||
            !add_number(frame.offset) || !add_length_payload(frame.data))
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x07:
        if (frame.data.empty() || !add_length_payload(frame.data))
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x10: case 0x12: case 0x13: case 0x14: case 0x16: case 0x17:
        if ((frame.type == 0x12 || frame.type == 0x13 ||
             frame.type == 0x16 || frame.type == 0x17) &&
            frame.limit > (std::uint64_t {1} << 60))
            return std::unexpected(frame_error::invalid_value);
        if (!add_number(frame.limit))
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x11: case 0x15:
        if (!add_number(frame.stream_id) || !add_number(frame.limit))
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x18:
        if (frame.connection_id.empty() || frame.connection_id.size() > 20 ||
            frame.stateless_reset_token.size() != 16 ||
            frame.retire_prior_to > frame.sequence_number)
            return std::unexpected(frame_error::invalid_connection_id);
        if (!add_number(frame.sequence_number) ||
            !add_number(frame.retire_prior_to) || !add_size(1) ||
            !add_payload(frame.connection_id) ||
            !add_payload(frame.stateless_reset_token))
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x19:
        if (!add_number(frame.sequence_number))
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x1a: case 0x1b:
        if (frame.data.size() != 8)
            return std::unexpected(frame_error::invalid_value);
        if (!add_payload(frame.data))
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x1c: case 0x1d:
        if (!add_number(frame.error_code) ||
            (frame.type == 0x1c && !add_number(frame.frame_type)) ||
            !add_length_payload(frame.reason_phrase))
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x30: case 0x31:
        if ((frame.type == 0x31 && !add_length_payload(frame.data)) ||
            (frame.type == 0x30 && !add_payload(frame.data)))
            return std::unexpected(frame_error::invalid_value);
        break;
    default:
        if (frame.type < 0x08 || frame.type > 0x0f)
            return std::unexpected(frame_error::invalid_frame);
        if (frame.fin != ((frame.type & 0x01) != 0) ||
            ((frame.type & 0x04) == 0 && frame.offset != 0) ||
            frame.offset > max_varint_value ||
            frame.data.size() > max_varint_value - frame.offset ||
            !add_number(frame.stream_id) ||
            ((frame.type & 0x04) && !add_number(frame.offset)) ||
            ((frame.type & 0x02) && !add_number(
                static_cast<std::uint64_t>(frame.data.size()))) ||
            !add_payload(frame.data))
            return std::unexpected(frame_error::invalid_value);
    }
    if (size > output.size())
        return std::unexpected(frame_error::output_too_small);

    std::size_t cursor = 0;
    const auto write_number = [&](std::uint64_t value) constexpr {
        const auto written = encode_varint(value, output.subspan(cursor));
        cursor += *written;
    };
    const auto write_payload = [&](std::span<const std::byte> data) constexpr {
        std::copy(data.begin(), data.end(), output.subspan(cursor).begin());
        cursor += data.size();
    };
    const auto write_length_payload = [&](std::span<const std::byte> data)
        constexpr {
        write_number(static_cast<std::uint64_t>(data.size()));
        write_payload(data);
    };
    write_number(frame.type);
    switch (frame.type) {
    case 0x00: case 0x01: case 0x1e: break;
    case 0x02: case 0x03: {
        write_number(frame.largest_acknowledged);
        write_number(frame.ack_delay);
        write_number(frame.ack_range_count);
        write_number(frame.first_ack_range);
        std::size_t range_cursor = 0;
        for (std::uint64_t i = 0; i < frame.ack_range_count; ++i) {
            const auto gap = *decode_varint(frame.ack_ranges.subspan(range_cursor));
            range_cursor += gap.encoded_size;
            const auto range = *decode_varint(frame.ack_ranges.subspan(range_cursor));
            range_cursor += range.encoded_size;
            write_number(gap.value);
            write_number(range.value);
        }
        if (frame.type == 0x03)
            for (const auto count : frame.ecn_counts) write_number(count);
        break;
    }
    case 0x04:
        write_number(frame.stream_id);
        write_number(frame.error_code);
        write_number(frame.final_size);
        break;
    case 0x05:
        write_number(frame.stream_id);
        write_number(frame.error_code);
        break;
    case 0x06:
        write_number(frame.offset);
        write_length_payload(frame.data);
        break;
    case 0x07: write_length_payload(frame.data); break;
    case 0x10: case 0x12: case 0x13: case 0x14: case 0x16: case 0x17:
        write_number(frame.limit); break;
    case 0x11: case 0x15:
        write_number(frame.stream_id);
        write_number(frame.limit);
        break;
    case 0x18:
        write_number(frame.sequence_number);
        write_number(frame.retire_prior_to);
        output[cursor++] = static_cast<std::byte>(frame.connection_id.size());
        write_payload(frame.connection_id);
        write_payload(frame.stateless_reset_token);
        break;
    case 0x19: write_number(frame.sequence_number); break;
    case 0x1a: case 0x1b: write_payload(frame.data); break;
    case 0x1c: case 0x1d:
        write_number(frame.error_code);
        if (frame.type == 0x1c) write_number(frame.frame_type);
        write_length_payload(frame.reason_phrase);
        break;
    case 0x30: case 0x31:
        if (frame.type == 0x31) write_length_payload(frame.data);
        else write_payload(frame.data);
        break;
    default:
        write_number(frame.stream_id);
        if (frame.type & 0x04) write_number(frame.offset);
        if (frame.type & 0x02)
            write_number(static_cast<std::uint64_t>(frame.data.size()));
        write_payload(frame.data);
    }
    return cursor;
}

[[nodiscard]] constexpr auto decode_frame(std::span<const std::byte> input)
    noexcept -> std::expected<decoded_frame, frame_error>
{
    const auto type = decode_varint(input);
    if (!type) return std::unexpected(frame_error::truncated);
    decoded_frame frame;
    frame.type = type->value;
    std::size_t cursor = type->encoded_size;

    const auto number = [&](std::uint64_t& value) constexpr -> bool {
        const auto decoded = decode_varint(input.subspan(cursor));
        if (!decoded) return false;
        value = decoded->value;
        cursor += decoded->encoded_size;
        return true;
    };
    const auto payload = [&](std::span<const std::byte>& value,
                             std::uint64_t length) constexpr -> bool {
        if (length > input.size() - cursor) return false;
        value = input.subspan(cursor, static_cast<std::size_t>(length));
        cursor += value.size();
        return true;
    };
    std::uint64_t length = 0;
    switch (frame.type) {
    case 0x00: // PADDING: one byte per decoded frame.
    case 0x01: // PING
    case 0x1e: // HANDSHAKE_DONE
        break;
    case 0x02: case 0x03: { // ACK / ACK_ECN
        if (!number(frame.largest_acknowledged) || !number(frame.ack_delay) ||
            !number(frame.ack_range_count) || !number(frame.first_ack_range))
            return std::unexpected(frame_error::truncated);
        if (frame.first_ack_range > frame.largest_acknowledged)
            return std::unexpected(frame_error::invalid_ack_range);
        auto smallest = frame.largest_acknowledged - frame.first_ack_range;
        const auto range_start = cursor;
        // Each pair requires at least two bytes, even with short varints.
        if (frame.ack_range_count > (input.size() - cursor) / 2)
            return std::unexpected(frame_error::truncated);
        for (std::uint64_t i = 0; i < frame.ack_range_count; ++i) {
            std::uint64_t gap = 0;
            std::uint64_t range = 0;
            if (!number(gap) || !number(range))
                return std::unexpected(frame_error::truncated);
            if (smallest < 2 || gap > smallest - 2)
                return std::unexpected(frame_error::invalid_ack_range);
            const auto largest = smallest - gap - 2;
            if (range > largest)
                return std::unexpected(frame_error::invalid_ack_range);
            smallest = largest - range;
        }
        frame.ack_ranges = input.subspan(range_start, cursor - range_start);
        if (frame.type == 0x03) {
            for (auto& count : frame.ecn_counts)
                if (!number(count)) return std::unexpected(frame_error::truncated);
        }
        break;
    }
    case 0x04: // RESET_STREAM
        if (!number(frame.stream_id) || !number(frame.error_code) ||
            !number(frame.final_size))
            return std::unexpected(frame_error::truncated);
        break;
    case 0x05: // STOP_SENDING
        if (!number(frame.stream_id) || !number(frame.error_code))
            return std::unexpected(frame_error::truncated);
        break;
    case 0x06: // CRYPTO
        if (!number(frame.offset) || !number(length) ||
            !payload(frame.data, length))
            return std::unexpected(frame_error::truncated);
        if (frame.data.size() > max_varint_value - frame.offset)
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x07: // NEW_TOKEN
        if (!number(length) || !payload(frame.data, length))
            return std::unexpected(frame_error::truncated);
        if (frame.data.empty())
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x10: // MAX_DATA
    case 0x12: case 0x13: // MAX_STREAMS
    case 0x14: // DATA_BLOCKED
    case 0x16: case 0x17: // STREAMS_BLOCKED
        if (!number(frame.limit)) return std::unexpected(frame_error::truncated);
        if ((frame.type == 0x12 || frame.type == 0x13 ||
             frame.type == 0x16 || frame.type == 0x17) &&
            frame.limit > (std::uint64_t {1} << 60))
            return std::unexpected(frame_error::invalid_value);
        break;
    case 0x11: // MAX_STREAM_DATA
    case 0x15: // STREAM_DATA_BLOCKED
        if (!number(frame.stream_id) || !number(frame.limit))
            return std::unexpected(frame_error::truncated);
        break;
    case 0x18: { // NEW_CONNECTION_ID
        if (!number(frame.sequence_number) || !number(frame.retire_prior_to))
            return std::unexpected(frame_error::truncated);
        if (cursor == input.size()) return std::unexpected(frame_error::truncated);
        const auto cid_length = std::to_integer<std::uint8_t>(input[cursor++]);
        if (cid_length == 0 || cid_length > 20 ||
            frame.retire_prior_to > frame.sequence_number)
            return std::unexpected(frame_error::invalid_connection_id);
        if (!payload(frame.connection_id, cid_length) ||
            !payload(frame.stateless_reset_token, 16))
            return std::unexpected(frame_error::truncated);
        break;
    }
    case 0x19: // RETIRE_CONNECTION_ID
        if (!number(frame.sequence_number))
            return std::unexpected(frame_error::truncated);
        break;
    case 0x1a: case 0x1b: // PATH_CHALLENGE / PATH_RESPONSE
        if (!payload(frame.data, 8))
            return std::unexpected(frame_error::truncated);
        break;
    case 0x1c: case 0x1d: // CONNECTION_CLOSE
        if (!number(frame.error_code))
            return std::unexpected(frame_error::truncated);
        if (frame.type == 0x1c && !number(frame.frame_type))
            return std::unexpected(frame_error::truncated);
        if (!number(length) || !payload(frame.reason_phrase, length))
            return std::unexpected(frame_error::truncated);
        break;
    case 0x30: case 0x31: // DATAGRAM, with optional length
        length = input.size() - cursor;
        if (frame.type == 0x31 && !number(length))
            return std::unexpected(frame_error::truncated);
        if (!payload(frame.data, length))
            return std::unexpected(frame_error::truncated);
        break;
    default:
        if (frame.type >= 0x08 && frame.type <= 0x0f) {
            frame.fin = (frame.type & 0x01) != 0;
            if (!number(frame.stream_id))
                return std::unexpected(frame_error::truncated);
            if ((frame.type & 0x04) && !number(frame.offset))
                return std::unexpected(frame_error::truncated);
            length = input.size() - cursor;
            if ((frame.type & 0x02) && !number(length))
                return std::unexpected(frame_error::truncated);
            if (!payload(frame.data, length))
                return std::unexpected(frame_error::truncated);
            if (frame.data.size() > max_varint_value - frame.offset)
                return std::unexpected(frame_error::invalid_value);
        } else {
            return std::unexpected(frame_error::invalid_frame);
        }
    }
    frame.encoded_size = cursor;
    return frame;
}

} // namespace eventloop::quic::detail
