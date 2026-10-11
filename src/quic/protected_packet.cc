#include "quic/protected_packet.h"

#include "quic/varint.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace eventloop::quic::detail {
namespace {

[[nodiscard]] auto map_protection_error(protection_error error) noexcept
    -> protected_packet_error
{
    switch (error) {
    case protection_error::invalid_input: return protected_packet_error::invalid_input;
    case protection_error::unsupported_version: return protected_packet_error::unsupported_version;
    case protection_error::output_too_small: return protected_packet_error::output_too_small;
    case protection_error::authentication_failed: return protected_packet_error::authentication_failed;
    case protection_error::provider_failure: return protected_packet_error::provider_failure;
    }
    return protected_packet_error::provider_failure;
}

[[nodiscard]] auto bytes(std::span<const std::uint8_t> input) noexcept
    -> std::span<const std::byte>
{
    return {reinterpret_cast<const std::byte*>(input.data()), input.size()};
}

[[nodiscard]] auto writable_bytes(std::span<std::uint8_t> input) noexcept
    -> std::span<std::byte>
{
    return {reinterpret_cast<std::byte*>(input.data()), input.size()};
}

auto write_u32(std::uint32_t value, std::span<std::uint8_t> output) noexcept -> void
{
    for (std::size_t i = 0; i < 4; ++i) {
        output[i] = static_cast<std::uint8_t>(value >> ((3 - i) * 8));
    }
}

[[nodiscard]] auto long_type(packet_kind kind) noexcept -> long_packet_type
{
    switch (kind) {
    case packet_kind::initial: return long_packet_type::initial;
    case packet_kind::zero_rtt: return long_packet_type::zero_rtt;
    case packet_kind::handshake: return long_packet_type::handshake;
    default: return long_packet_type::retry;
    }
}

} // namespace

auto build_protected_packet(
    packet_protection_context& context,
    const protected_packet_fields& fields, const aes_128_gcm_keys& keys,
    std::span<const std::uint8_t> plaintext,
    std::span<std::uint8_t> output, std::span<std::uint8_t> scratch)
    -> std::expected<std::size_t, protected_packet_error>
{
    if (!is_supported_version(fields.version)) {
        return std::unexpected(protected_packet_error::unsupported_version);
    }
    const auto short_header = fields.kind == packet_kind::short_header;
    if ((!short_header && fields.kind != packet_kind::initial &&
         fields.kind != packet_kind::zero_rtt && fields.kind != packet_kind::handshake) ||
        fields.destination_cid.size() > 20 || fields.source_cid.size() > 20 ||
        fields.token.size() > max_protected_packet_size ||
        fields.packet_number > max_packet_number ||
        fields.packet_number_length < 1 || fields.packet_number_length > 4 ||
        (short_header && (!fields.source_cid.empty() || !fields.token.empty())) ||
        (!short_header && (fields.key_phase || fields.spin_bit)) ||
        (fields.kind != packet_kind::initial && !fields.token.empty()) ||
        plaintext.size() > max_protected_packet_size) {
        return std::unexpected(protected_packet_error::invalid_input);
    }

    const auto pn_length = static_cast<std::size_t>(fields.packet_number_length);
    const auto padding = std::size_t{4} - pn_length > plaintext.size()
        ? std::size_t{4} - pn_length - plaintext.size() : 0;
    const auto padded_size = plaintext.size() + padding;
    if (scratch.size() < padded_size) {
        return std::unexpected(protected_packet_error::output_too_small);
    }
    const auto payload_length = pn_length + padded_size + 16;
    const auto token_length_size = fields.kind == packet_kind::initial
        ? varint_size(fields.token.size()) : 0;
    const auto length_size = short_header ? 0 : varint_size(payload_length);
    const auto header_size = short_header
        ? 1 + fields.destination_cid.size() + pn_length
        : 1 + 4 + 1 + fields.destination_cid.size() + 1 +
          fields.source_cid.size() + token_length_size + fields.token.size() +
          length_size + pn_length;
    if (padded_size > max_protected_packet_size - 16 ||
        payload_length > max_protected_packet_size ||
        header_size > max_protected_packet_size - padded_size - 16) {
        return std::unexpected(protected_packet_error::invalid_input);
    }
    const auto packet_size = header_size + padded_size + 16;
    if (output.size() < packet_size) {
        return std::unexpected(protected_packet_error::output_too_small);
    }

    auto cursor = std::size_t{0};
    if (short_header) {
        output[cursor++] = static_cast<std::uint8_t>(
            (fields.quic_bit ? 0x40 : 0) | (fields.spin_bit ? 0x20 : 0) |
            (fields.key_phase ? 0x04 : 0) | (pn_length - 1));
        std::copy(fields.destination_cid.begin(), fields.destination_cid.end(),
                  output.begin() + static_cast<std::ptrdiff_t>(cursor));
        cursor += fields.destination_cid.size();
    } else {
        output[cursor++] = static_cast<std::uint8_t>(
            0x80 | (fields.quic_bit ? 0x40 : 0) |
            (static_cast<unsigned>(long_header_type_bits(fields.version, long_type(fields.kind))) << 4) |
            (pn_length - 1));
        write_u32(fields.version, output.subspan(cursor, 4));
        cursor += 4;
        output[cursor++] = static_cast<std::uint8_t>(fields.destination_cid.size());
        std::copy(fields.destination_cid.begin(), fields.destination_cid.end(),
                  output.begin() + static_cast<std::ptrdiff_t>(cursor));
        cursor += fields.destination_cid.size();
        output[cursor++] = static_cast<std::uint8_t>(fields.source_cid.size());
        std::copy(fields.source_cid.begin(), fields.source_cid.end(),
                  output.begin() + static_cast<std::ptrdiff_t>(cursor));
        cursor += fields.source_cid.size();
        if (fields.kind == packet_kind::initial) {
            const auto encoded = encode_varint(fields.token.size(),
                                               writable_bytes(output.subspan(cursor)));
            cursor += *encoded;
            std::copy(fields.token.begin(), fields.token.end(),
                      output.begin() + static_cast<std::ptrdiff_t>(cursor));
            cursor += fields.token.size();
        }
        const auto encoded = encode_varint(payload_length,
                                           writable_bytes(output.subspan(cursor)));
        cursor += *encoded;
    }
    const auto pn_offset = cursor;
    for (std::size_t i = 0; i < pn_length; ++i) {
        output[cursor + pn_length - 1 - i] = static_cast<std::uint8_t>(
            fields.packet_number >> (i * 8));
    }
    cursor += pn_length;
    std::fill_n(scratch.begin(), padding, std::uint8_t{0});
    std::copy(plaintext.begin(), plaintext.end(),
              scratch.begin() + static_cast<std::ptrdiff_t>(padding));
    const auto sealed = seal_payload(context, keys, fields.packet_number,
                                     output.first(cursor), scratch.first(padded_size),
                                     output.subspan(cursor, padded_size + 16));
    if (!sealed) {
        return std::unexpected(map_protection_error(sealed.error()));
    }
    const auto protected_length = apply_aes_header_protection(
        context, keys, output.first(packet_size), pn_offset, false);
    if (!protected_length) {
        return std::unexpected(map_protection_error(protected_length.error()));
    }
    return packet_size;
}

auto open_protected_packet(
    packet_protection_context& context,
    std::span<const std::uint8_t> datagram, std::size_t offset,
    std::optional<std::size_t> short_destination_cid_length,
    std::uint32_t expected_version, const aes_128_gcm_keys& keys,
    std::optional<std::uint64_t> largest_received,
    std::span<std::uint8_t> scratch, std::span<std::uint8_t> plaintext,
    std::span<std::uint8_t> auth_scratch, bool grease_quic_bit)
    -> std::expected<opened_protected_packet, protected_packet_error>
{
    if (!is_supported_version(expected_version)) {
        return std::unexpected(protected_packet_error::unsupported_version);
    }
    const auto parsed = parse_packet_header(bytes(datagram), offset,
                                            short_destination_cid_length, grease_quic_bit);
    if (!parsed) {
        return std::unexpected(parsed.error() == packet_header_error::unsupported_version
            ? protected_packet_error::unsupported_version
            : protected_packet_error::malformed_packet);
    }
    if ((parsed->kind != packet_kind::short_header &&
         parsed->kind != packet_kind::initial &&
         parsed->kind != packet_kind::zero_rtt &&
         parsed->kind != packet_kind::handshake) ||
        (parsed->kind != packet_kind::short_header &&
         parsed->version != expected_version) ||
        parsed->packet.size() > max_protected_packet_size) {
        return std::unexpected(protected_packet_error::invalid_input);
    }
    if (scratch.size() < parsed->packet.size()) {
        return std::unexpected(protected_packet_error::output_too_small);
    }
    std::memcpy(scratch.data(), datagram.data() + offset, parsed->packet.size());
    auto packet = scratch.first(parsed->packet.size());
    const auto pn_offset = parsed->header_end_offset - parsed->packet_offset;
    const auto pn_length = apply_aes_header_protection(context, keys, packet, pn_offset, true);
    if (!pn_length) {
        return std::unexpected(pn_length.error() == protection_error::invalid_input
            ? protected_packet_error::malformed_packet
            : map_protection_error(pn_length.error()));
    }
    const auto header_size = pn_offset + *pn_length;
    if (header_size > packet.size() || packet.size() - header_size < 16) {
        return std::unexpected(protected_packet_error::malformed_packet);
    }
    std::uint32_t truncated = 0;
    for (std::size_t i = 0; i < *pn_length; ++i) {
        truncated = (truncated << 8) | packet[pn_offset + i];
    }
    const auto packet_number = reconstruct_packet_number(
        truncated, *pn_length, largest_received);
    if (!packet_number) {
        return std::unexpected(protected_packet_error::invalid_input);
    }
    const auto opened = open_payload(context, keys, *packet_number, packet.first(header_size),
                                     packet.subspan(header_size), plaintext, auth_scratch);
    if (!opened) {
        return std::unexpected(map_protection_error(opened.error()));
    }
    const auto short_header = parsed->kind == packet_kind::short_header;
    if ((packet[0] & (short_header ? 0x18 : 0x0c)) != 0) {
        return std::unexpected(protected_packet_error::reserved_bits);
    }
    return opened_protected_packet {
        parsed->kind, expected_version, *packet_number,
        short_header && (packet[0] & 0x04) != 0,
        short_header && (packet[0] & 0x20) != 0,
        *opened, parsed->packet_end_offset,
    };
}

auto build_protected_packet(
    const protected_packet_fields& fields, const aes_128_gcm_keys& keys,
    std::span<const std::uint8_t> plaintext,
    std::span<std::uint8_t> output, std::span<std::uint8_t> scratch)
    -> std::expected<std::size_t, protected_packet_error>
{
    packet_protection_context context;
    return build_protected_packet(context, fields, keys, plaintext, output, scratch);
}
auto open_protected_packet(
    std::span<const std::uint8_t> datagram, std::size_t offset,
    std::optional<std::size_t> short_destination_cid_length,
    std::uint32_t version, const aes_128_gcm_keys& keys,
    std::optional<std::uint64_t> largest_received,
    std::span<std::uint8_t> scratch, std::span<std::uint8_t> plaintext,
    bool grease_quic_bit)
    -> std::expected<opened_protected_packet, protected_packet_error>
{
    packet_protection_context context;
    std::array<std::uint8_t, 65511> auth_scratch;
    return open_protected_packet(context, datagram, offset, short_destination_cid_length,
                                 version, keys, largest_received, scratch, plaintext,
                                 auth_scratch, grease_quic_bit);
}

} // namespace eventloop::quic::detail
