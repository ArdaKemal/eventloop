#pragma once

#include "quic/packet_header.h"
#include "quic/packet_protection.h"

namespace eventloop::quic::detail {

// RFC 9000 Section 17.2.5 / RFC 9369 Section 4.1. Retry has no Length
// field or packet number and consumes the entire UDP datagram.
// Input spans, scratch, and output must be mutually disjoint where written.
// scratch and output each need 7 + client_scid.size() + retry_scid.size() +
// token.size() + 16 bytes. Output is unchanged on any failure.
[[nodiscard]] auto build_retry_packet(
    std::uint32_t version, std::span<const std::uint8_t> original_dcid,
    std::span<const std::uint8_t> client_scid,
    std::span<const std::uint8_t> retry_scid,
    std::span<const std::uint8_t> token,
    std::span<std::uint8_t> scratch, std::span<std::uint8_t> output)
    -> std::expected<std::size_t, protection_error>;

// Returned spans borrow datagram storage. The connection must separately check
// its client SCID, reject repeated Retry, and enforce handshake acceptance rules.
[[nodiscard]] auto parse_and_validate_retry_packet(
    std::span<const std::uint8_t> datagram, std::uint32_t expected_version,
    std::span<const std::uint8_t> original_dcid)
    -> std::expected<packet_header, protection_error>;

} // namespace eventloop::quic::detail
