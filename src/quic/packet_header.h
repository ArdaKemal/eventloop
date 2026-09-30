#pragma once

#include "quic/varint.h"
#include "quic/version.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace eventloop::quic::detail {

enum class packet_header_error {
    truncated,
    invalid_header,
    invalid_length,
    unsupported_version,
};

enum class packet_kind {
    initial,
    zero_rtt,
    handshake,
    retry,
    version_negotiation,
    short_header,
};

struct packet_header {
    packet_kind kind {};
    std::uint32_t version {0};
    std::uint8_t first_byte {0};
    // All spans borrow storage from the datagram passed to parse_packet_header.
    std::span<const std::byte> packet {};
    std::span<const std::byte> destination_cid {};
    std::span<const std::byte> source_cid {};
    std::span<const std::byte> token {};
    std::span<const std::byte> version_list {};
    std::span<const std::byte> retry_integrity_tag {};
    std::size_t packet_offset {0};
    std::size_t header_end_offset {0};
    std::size_t packet_end_offset {0};
    // For protected packets, the packet number begins at header_end_offset.
    // Its length is unknown until header protection is removed.
};

// Parse one packet in a UDP datagram. Length-bearing long headers can be
// followed by another packet at packet_end_offset. Short, Retry, and Version
// Negotiation packets consume the rest of the datagram.
// Enable grease_quic_bit when advertising RFC 9287 support. This accepts either
// value of bit 0x40 without relaxing other header checks.
[[nodiscard]] constexpr auto parse_packet_header(
    std::span<const std::byte> datagram, std::size_t offset = 0,
    std::optional<std::size_t> short_destination_cid_length = std::nullopt,
    bool grease_quic_bit = false) noexcept
    -> std::expected<packet_header, packet_header_error>
{
    if (offset >= datagram.size()) {
        return std::unexpected(packet_header_error::truncated);
    }
    const auto input = datagram.subspan(offset);
    const auto first = std::to_integer<std::uint8_t>(input[0]);
    packet_header result;
    result.first_byte = first;
    result.packet_offset = offset;
    result.packet_end_offset = datagram.size();

    if ((first & 0x80) == 0) {
        if (!grease_quic_bit && (first & 0x40) == 0) {
            return std::unexpected(packet_header_error::invalid_header);
        }
        if (!short_destination_cid_length || *short_destination_cid_length > 20) {
            return std::unexpected(packet_header_error::invalid_length);
        }
        if (input.size() < 2 || *short_destination_cid_length > input.size() - 2) {
            return std::unexpected(packet_header_error::truncated);
        }
        result.kind = packet_kind::short_header;
        result.destination_cid = input.subspan(1, *short_destination_cid_length);
        result.header_end_offset = offset + 1 + *short_destination_cid_length;
        result.packet = input;
        return result;
    }

    if (input.size() < 7) {
        return std::unexpected(packet_header_error::truncated);
    }
    result.version = (std::to_integer<std::uint32_t>(input[1]) << 24) |
                     (std::to_integer<std::uint32_t>(input[2]) << 16) |
                     (std::to_integer<std::uint32_t>(input[3]) << 8) |
                      std::to_integer<std::uint32_t>(input[4]);
    // Version Negotiation is version independent; its fixed bit is arbitrary.
    if (result.version != 0 && !grease_quic_bit && (first & 0x40) == 0) {
        return std::unexpected(packet_header_error::invalid_header);
    }
    if (result.version != 0 && !is_supported_version(result.version)) {
        return std::unexpected(packet_header_error::unsupported_version);
    }

    std::size_t cursor = 5;
    const auto destination_length = std::to_integer<std::uint8_t>(input[cursor++]);
    if (result.version != 0 && destination_length > 20) {
        return std::unexpected(packet_header_error::invalid_length);
    }
    if (destination_length > input.size() - cursor) {
        return std::unexpected(packet_header_error::truncated);
    }
    result.destination_cid = input.subspan(cursor, destination_length);
    cursor += destination_length;
    if (cursor == input.size()) {
        return std::unexpected(packet_header_error::truncated);
    }
    const auto source_length = std::to_integer<std::uint8_t>(input[cursor++]);
    if (result.version != 0 && source_length > 20) {
        return std::unexpected(packet_header_error::invalid_length);
    }
    if (source_length > input.size() - cursor) {
        return std::unexpected(packet_header_error::truncated);
    }
    result.source_cid = input.subspan(cursor, source_length);
    cursor += source_length;

    if (result.version == 0) {
        const auto remaining = input.size() - cursor;
        if (remaining == 0 || remaining % 4 != 0) {
            return std::unexpected(packet_header_error::invalid_length);
        }
        result.kind = packet_kind::version_negotiation;
        result.version_list = input.subspan(cursor);
        result.header_end_offset = datagram.size();
        result.packet = input;
        return result;
    }

    switch (decode_long_header_type(result.version, (first >> 4) & 3)) {
    case long_packet_type::initial: result.kind = packet_kind::initial; break;
    case long_packet_type::zero_rtt: result.kind = packet_kind::zero_rtt; break;
    case long_packet_type::handshake: result.kind = packet_kind::handshake; break;
    case long_packet_type::retry: result.kind = packet_kind::retry; break;
    }

    if (result.kind == packet_kind::retry) {
        if (input.size() - cursor < 16) {
            return std::unexpected(packet_header_error::truncated);
        }
        result.token = input.subspan(cursor, input.size() - cursor - 16);
        result.retry_integrity_tag = input.last(16);
        result.header_end_offset = offset + cursor;
        result.packet = input;
        return result;
    }

    if (result.kind == packet_kind::initial) {
        const auto token_length = decode_varint(input.subspan(cursor));
        if (!token_length) {
            return std::unexpected(packet_header_error::truncated);
        }
        cursor += token_length->encoded_size;
        if (token_length->value > input.size() - cursor) {
            return std::unexpected(packet_header_error::truncated);
        }
        result.token = input.subspan(cursor,
                                     static_cast<std::size_t>(token_length->value));
        cursor += result.token.size();
    }

    const auto payload_length = decode_varint(input.subspan(cursor));
    if (!payload_length) {
        return std::unexpected(packet_header_error::truncated);
    }
    cursor += payload_length->encoded_size;
    if (payload_length->value == 0) {
        return std::unexpected(packet_header_error::invalid_length);
    }
    if (payload_length->value > input.size() - cursor) {
        return std::unexpected(packet_header_error::truncated);
    }
    const auto packet_size = cursor + static_cast<std::size_t>(payload_length->value);
    result.header_end_offset = offset + cursor;
    result.packet_end_offset = offset + packet_size;
    result.packet = input.first(packet_size);
    return result;
}

} // namespace eventloop::quic::detail
