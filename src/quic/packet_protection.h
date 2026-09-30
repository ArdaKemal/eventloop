#pragma once

#include "quic/version.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <thread>

namespace eventloop::quic::detail {

inline constexpr std::uint64_t max_packet_number = (std::uint64_t{1} << 62) - 1;

enum class protection_error {
    invalid_input,
    unsupported_version,
    output_too_small,
    authentication_failed,
    provider_failure,
};

struct initial_secrets {
    std::array<std::uint8_t, 32> client {};
    std::array<std::uint8_t, 32> server {};
};

struct aes_128_gcm_keys {
    std::array<std::uint8_t, 16> key {};
    std::array<std::uint8_t, 12> iv {};
    std::array<std::uint8_t, 16> hp {};
};

// Construct, use, and destroy on the owning loop thread; calls must not overlap.
// EVP contexts are allocated and initialized once. Provider internals may allocate.
// A failed initialization is reported by ready()/provider_failure; no heap fallback.
class packet_protection_context {
public:
    packet_protection_context() noexcept;
    ~packet_protection_context();
    packet_protection_context(const packet_protection_context&) = delete;
    auto operator=(const packet_protection_context&) -> packet_protection_context& = delete;
    packet_protection_context(packet_protection_context&&) = delete;
    auto operator=(packet_protection_context&&) -> packet_protection_context& = delete;
    [[nodiscard]] auto ready() const noexcept -> bool;
    // Output requires plaintext.size()+16 bytes, disjoint from header and plaintext.
    [[nodiscard]] auto seal(const aes_128_gcm_keys&, std::uint64_t,
        std::span<const std::uint8_t>, std::span<const std::uint8_t>,
        std::span<std::uint8_t>) -> std::expected<std::size_t, protection_error>;
    // scratch requires ciphertext.size()-16 bytes and must be disjoint from
    // header, ciphertext, and output. Output may alias ciphertext. Scratch is
    // cleared after use; output is untouched until authentication succeeds.
    [[nodiscard]] auto open(const aes_128_gcm_keys&, std::uint64_t,
        std::span<const std::uint8_t>, std::span<const std::uint8_t>,
        std::span<std::uint8_t>, std::span<std::uint8_t>)
        -> std::expected<std::size_t, protection_error>;
    [[nodiscard]] auto protect_header(const aes_128_gcm_keys&,
        std::span<std::uint8_t>, std::size_t, bool)
        -> std::expected<std::size_t, protection_error>;
private:
    void* seal_ {};
    void* open_ {};
    void* hp_ {};
    std::thread::id owner_;
    bool initialized_ {};
};

[[nodiscard]] auto seal_payload(packet_protection_context& context,
    const aes_128_gcm_keys& keys, std::uint64_t packet_number,
    std::span<const std::uint8_t> header, std::span<const std::uint8_t> plaintext,
    std::span<std::uint8_t> output) -> std::expected<std::size_t, protection_error>;
[[nodiscard]] auto open_payload(packet_protection_context& context,
    const aes_128_gcm_keys& keys, std::uint64_t packet_number,
    std::span<const std::uint8_t> header, std::span<const std::uint8_t> ciphertext,
    std::span<std::uint8_t> output, std::span<std::uint8_t> scratch)
    -> std::expected<std::size_t, protection_error>;
[[nodiscard]] auto apply_aes_header_protection(packet_protection_context& context,
    const aes_128_gcm_keys& keys, std::span<std::uint8_t> packet,
    std::size_t packet_number_offset, bool removing)
    -> std::expected<std::size_t, protection_error>;

// The caller owns key lifetime and packet buffers. These functions are the
// private OpenSSL provider boundary; TLS traffic secrets enter here unchanged.
[[nodiscard]] auto derive_initial_secrets(
    std::uint32_t version, std::span<const std::uint8_t> client_initial_dcid)
    -> std::expected<initial_secrets, protection_error>;

[[nodiscard]] auto derive_aes_128_gcm_keys(
    std::uint32_t version, std::span<const std::uint8_t> traffic_secret)
    -> std::expected<aes_128_gcm_keys, protection_error>;

// RFC 9001 Section 6 / RFC 9369 Section 3.3.2, SHA-256 traffic secrets.
[[nodiscard]] auto derive_next_traffic_secret(
    std::uint32_t version, std::span<const std::uint8_t> traffic_secret)
    -> std::expected<std::array<std::uint8_t, 32>, protection_error>;

// Header includes the unprotected packet number. Output receives ciphertext
// followed by a 16-byte tag. The packet number is the full 62-bit value.
[[nodiscard]] auto seal_payload(
    const aes_128_gcm_keys& keys, std::uint64_t packet_number,
    std::span<const std::uint8_t> header,
    std::span<const std::uint8_t> plaintext,
    std::span<std::uint8_t> output)
    -> std::expected<std::size_t, protection_error>;

// Authentication failure never writes unauthenticated plaintext to output.
[[nodiscard]] auto open_payload(
    const aes_128_gcm_keys& keys, std::uint64_t packet_number,
    std::span<const std::uint8_t> header,
    std::span<const std::uint8_t> ciphertext_and_tag,
    std::span<std::uint8_t> output)
    -> std::expected<std::size_t, protection_error>;

// packet_number_offset is relative to this packet, not the UDP datagram.
// Applying twice restores the header. On removal, call with removing=true
// because the packet number length is protected until the first byte is unmasked.
[[nodiscard]] auto apply_aes_header_protection(
    const aes_128_gcm_keys& keys, std::span<std::uint8_t> packet,
    std::size_t packet_number_offset, bool removing)
    -> std::expected<std::size_t, protection_error>;

// largest_received is absent before the first authenticated packet.
[[nodiscard]] auto reconstruct_packet_number(
    std::uint32_t truncated, std::size_t encoded_length,
    std::optional<std::uint64_t> largest_received)
    -> std::expected<std::uint64_t, protection_error>;

// Retry integrity authenticates an empty plaintext with the pseudo-packet
// (ODCID length, ODCID, and the Retry packet without its trailing tag) as AD.
// The input packet includes its version and complete CIDs. Token bytes are
// opaque. Validation checks packet structure before authenticating the tag.
[[nodiscard]] auto generate_retry_integrity_tag(
    std::uint32_t version, std::span<const std::uint8_t> original_dcid,
    std::span<const std::uint8_t> retry_without_tag)
    -> std::expected<std::array<std::uint8_t, 16>, protection_error>;

[[nodiscard]] auto validate_retry_integrity_tag(
    std::uint32_t version, std::span<const std::uint8_t> original_dcid,
    std::span<const std::uint8_t> retry_with_tag)
    -> std::expected<void, protection_error>;

} // namespace eventloop::quic::detail
