#pragma once

#include "quic/packet_header.h"
#include "quic/packet_protection.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace eventloop::quic::detail {

inline constexpr std::size_t max_protected_packet_size = 65527;

enum class protected_packet_error {
    invalid_input,
    unsupported_version,
    output_too_small,
    malformed_packet,
    authentication_failed,
    provider_failure,
};

struct protected_packet_fields {
    packet_kind kind {packet_kind::initial};
    std::uint32_t version {version_1};
    std::span<const std::uint8_t> destination_cid {};
    std::span<const std::uint8_t> source_cid {};
    std::span<const std::uint8_t> token {};
    std::uint64_t packet_number {0};
    std::uint8_t packet_number_length {1};
    bool key_phase {false};
    bool spin_bit {false};
    // RFC 9287: clearing requires known peer support. The caller selects each
    // packet's value; codecs do not generate randomness or negotiate support.
    bool quic_bit {true};
};

struct opened_protected_packet {
    packet_kind kind {};
    std::uint32_t version {0};
    std::uint64_t packet_number {0};
    bool key_phase {false};
    bool spin_bit {false};
    std::size_t plaintext_size {0};
    std::size_t packet_end_offset {0};
};

// Writes one protected packet. plaintext is an encoded frame sequence.
// scratch needs plaintext.size() + up to 3 bytes for valid PADDING frames,
// placed before plaintext so a trailing lengthless STREAM frame keeps its
// exact data. All plaintext/CID/token inputs, output, and scratch must be
// pairwise disjoint.
[[nodiscard]] auto build_protected_packet(
    const protected_packet_fields& fields, const aes_128_gcm_keys& keys,
    std::span<const std::uint8_t> plaintext,
    std::span<std::uint8_t> output, std::span<std::uint8_t> scratch)
    -> std::expected<std::size_t, protected_packet_error>;

// Same buffer contract as the stateless overload; reuses provider contexts.
[[nodiscard]] auto build_protected_packet(
    packet_protection_context& context,
    const protected_packet_fields& fields, const aes_128_gcm_keys& keys,
    std::span<const std::uint8_t> plaintext,
    std::span<std::uint8_t> output, std::span<std::uint8_t> scratch)
    -> std::expected<std::size_t, protected_packet_error>;

// Unprotects one packet at offset within a datagram. For a short header,
// short_destination_cid_length is required; long headers infer it from wire.
// scratch receives a mutable copy of the protected packet, while plaintext
// receives authenticated frame bytes (including any PADDING frames).
// The datagram, scratch, and plaintext buffers must be disjoint.
// grease_quic_bit enables RFC 9287 receive support after local advertisement;
// header protection, authentication, and reserved-bit checks still apply.
[[nodiscard]] auto open_protected_packet(
    std::span<const std::uint8_t> datagram, std::size_t offset,
    std::optional<std::size_t> short_destination_cid_length,
    std::uint32_t expected_version, const aes_128_gcm_keys& keys,
    std::optional<std::uint64_t> largest_received,
    std::span<std::uint8_t> scratch, std::span<std::uint8_t> plaintext,
    bool grease_quic_bit = false)
    -> std::expected<opened_protected_packet, protected_packet_error>;

// packet_scratch requires the complete protected packet size. auth_scratch
// requires ciphertext payload size minus the 16-byte tag. Both scratch buffers,
// datagram, and plaintext must be pairwise disjoint. Scratch is not application
// data; auth_scratch is cleared after use. No per-packet temporary allocation.
[[nodiscard]] auto open_protected_packet(
    packet_protection_context& context,
    std::span<const std::uint8_t> datagram, std::size_t offset,
    std::optional<std::size_t> short_destination_cid_length,
    std::uint32_t expected_version, const aes_128_gcm_keys& keys,
    std::optional<std::uint64_t> largest_received,
    std::span<std::uint8_t> packet_scratch, std::span<std::uint8_t> plaintext,
    std::span<std::uint8_t> auth_scratch, bool grease_quic_bit = false)
    -> std::expected<opened_protected_packet, protected_packet_error>;

} // namespace eventloop::quic::detail
