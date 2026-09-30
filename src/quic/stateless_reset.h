#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>

namespace eventloop::quic::detail {

using stateless_reset_token = std::array<std::byte, 16>;

enum class stateless_reset_error {
    invalid_token,
    insufficient_unpredictable_bytes,
    response_not_smaller,
    output_too_small,
    connection_may_be_active,
    invalid_datagram,
};

// Caller supplies cryptographically unpredictable prefix bytes and a token
// bound to the triggering packet's destination CID. It must establish that
// this CID cannot belong to an active connection on ANY endpoint sharing the
// reset key (RFC 9000 Section 21.11), before passing false below. The prefix
// length selects the response length; for triggers <= 43 bytes, prefer a
// response one byte shorter. Rate limiting remains the endpoint's job.
// Input spans may overlap output; errors leave output unchanged.
[[nodiscard]] inline auto encode_stateless_reset(
    std::span<const std::byte> unpredictable_bytes,
    std::span<const std::byte> token,
    std::size_t triggering_datagram_size,
    bool connection_may_be_active,
    std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, stateless_reset_error>
{
    if (connection_may_be_active)
        return std::unexpected(stateless_reset_error::connection_may_be_active);
    if (token.size() != 16)
        return std::unexpected(stateless_reset_error::invalid_token);
    if (unpredictable_bytes.size() < 5)
        return std::unexpected(
            stateless_reset_error::insufficient_unpredictable_bytes);
    // Subtract before adding to avoid overflow for arbitrary caller spans.
    if (triggering_datagram_size <= 21 ||
        unpredictable_bytes.size() >= triggering_datagram_size - 16)
        return std::unexpected(stateless_reset_error::response_not_smaller);
    const auto size = unpredictable_bytes.size() + 16;
    if (output.size() < size)
        return std::unexpected(stateless_reset_error::output_too_small);

    stateless_reset_token saved_token;
    std::memcpy(saved_token.data(), token.data(), saved_token.size());
    std::memmove(output.data(), unpredictable_bytes.data(),
                 unpredictable_bytes.size());
    output[0] = (output[0] & std::byte {0x3f}) | std::byte {0x40};
    std::memcpy(output.data() + unpredictable_bytes.size(),
                saved_token.data(), saved_token.size());
    return size;
}

// Pass the ENTIRE datagram after its first packet cannot be associated with a
// connection or cannot be decrypted. Tokens must be for CIDs already used,
// still active, and associated with this remote address; the caller filters
// retired/unused tokens. A true result requires entering draining immediately.
// Detection deliberately ignores header bits: RFC 9000 Section 10.3 requires
// recognizing valid suffixes even on packets resembling a long header.
[[nodiscard]] inline auto detect_stateless_reset(
    std::span<const std::byte> failed_datagram,
    std::span<const stateless_reset_token> active_peer_tokens) noexcept
    -> std::expected<bool, stateless_reset_error>
{
    if (failed_datagram.size() < 21)
        return std::unexpected(stateless_reset_error::invalid_datagram);
    const auto suffix = failed_datagram.last(16);
    std::uint32_t matched = 0;
    for (const auto& token : active_peer_tokens) {
        // Observable accumulator accesses prevent replacement with an
        // early-exit library comparison. Every byte of every token is read.
        volatile std::uint32_t difference = 0;
        for (std::size_t i = 0; i < token.size(); ++i)
            difference = difference |
                std::to_integer<std::uint32_t>(suffix[i] ^ token[i]);
        // difference is in [0,255]; unsigned underflow identifies zero.
        matched |= (static_cast<std::uint32_t>(difference) - 1U) >> 31;
    }
    return matched != 0;
}

} // namespace eventloop::quic::detail
