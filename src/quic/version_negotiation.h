#pragma once

#include "quic/packet_header.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>

namespace eventloop::quic::detail {

enum class version_negotiation_error {
    invalid_connection_id,
    invalid_version_list,
    output_too_small,
    invalid_packet,
    connection_id_mismatch,
    prior_packet_processed,
    offered_version_listed,
    no_common_version,
    downgrade_detected,
};

[[nodiscard]] constexpr auto valid_version_list(
    std::span<const std::uint32_t> versions) noexcept -> bool
{
    if (versions.empty()) return false;
    for (std::size_t i = 0; i < versions.size(); ++i) {
        if (versions[i] == 0) return false;
        for (std::size_t j = 0; j < i; ++j)
            if (versions[j] == versions[i]) return false;
    }
    return true;
}

[[nodiscard]] constexpr auto is_reserved_version_number(
    std::uint32_t version) noexcept -> bool
{
    return (version & 0x0f0f0f0fU) == 0x0a0a0a0aU;
}

// The 7 low bits are arbitrary. The caller supplies entropy for them; the
// fixed bit is intentionally not required. The packet's DCID echoes the
// triggering Initial's SCID, and its SCID echoes that Initial's DCID.
[[nodiscard]] constexpr auto encode_version_negotiation(
    std::span<const std::byte> initial_dcid,
    std::span<const std::byte> initial_scid,
    std::span<const std::uint32_t> supported_versions,
    std::uint8_t unused_bits,
    std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, version_negotiation_error>
{
    if (initial_dcid.size() > std::numeric_limits<std::uint8_t>::max() ||
        initial_scid.size() > std::numeric_limits<std::uint8_t>::max())
        return std::unexpected(version_negotiation_error::invalid_connection_id);
    if (!valid_version_list(supported_versions))
        return std::unexpected(version_negotiation_error::invalid_version_list);
    const auto header_size = std::size_t {7} + initial_dcid.size() +
                             initial_scid.size();
    if (output.size() < header_size ||
        supported_versions.size() > (output.size() - header_size) / 4)
        return std::unexpected(version_negotiation_error::output_too_small);

    output[0] = static_cast<std::byte>(0x80U | (unused_bits & 0x7fU));
    for (std::size_t i = 1; i < 5; ++i) output[i] = std::byte {0};
    std::size_t cursor = 5;
    output[cursor++] = static_cast<std::byte>(initial_scid.size());
    std::copy(initial_scid.begin(), initial_scid.end(), output.begin() + cursor);
    cursor += initial_scid.size();
    output[cursor++] = static_cast<std::byte>(initial_dcid.size());
    std::copy(initial_dcid.begin(), initial_dcid.end(), output.begin() + cursor);
    cursor += initial_dcid.size();
    for (const auto version : supported_versions) {
        output[cursor++] = static_cast<std::byte>(version >> 24);
        output[cursor++] = static_cast<std::byte>(version >> 16);
        output[cursor++] = static_cast<std::byte>(version >> 8);
        output[cursor++] = static_cast<std::byte>(version);
    }
    return cursor;
}

[[nodiscard]] constexpr auto version_at(std::span<const std::byte> bytes,
                                         std::size_t index) noexcept
    -> std::uint32_t
{
    const auto offset = index * 4;
    return (std::to_integer<std::uint32_t>(bytes[offset]) << 24) |
           (std::to_integer<std::uint32_t>(bytes[offset + 1]) << 16) |
           (std::to_integer<std::uint32_t>(bytes[offset + 2]) << 8) |
            std::to_integer<std::uint32_t>(bytes[offset + 3]);
}

// Validate an unauthenticated VN packet received for the triggering Initial.
// Client preference is ordered from most to least preferred. prior_packet_processed
// includes a successfully processed Retry or earlier VN packet. The selected
// version must still be authenticated via Version Information during handshake.
[[nodiscard]] constexpr auto validate_version_negotiation(
    std::span<const std::byte> packet,
    std::span<const std::byte> initial_dcid,
    std::span<const std::byte> initial_scid,
    std::uint32_t offered_version,
    std::span<const std::uint32_t> client_preference,
    bool prior_packet_processed = false) noexcept
    -> std::expected<std::uint32_t, version_negotiation_error>
{
    if (prior_packet_processed)
        return std::unexpected(version_negotiation_error::prior_packet_processed);
    if (offered_version == 0 || !valid_version_list(client_preference) ||
        std::find(client_preference.begin(), client_preference.end(),
                  offered_version) == client_preference.end())
        return std::unexpected(version_negotiation_error::invalid_version_list);
    const auto parsed = parse_packet_header(packet);
    if (!parsed || parsed->kind != packet_kind::version_negotiation ||
        parsed->version != 0)
        return std::unexpected(version_negotiation_error::invalid_packet);
    if (!std::equal(parsed->destination_cid.begin(),
                    parsed->destination_cid.end(),
                    initial_scid.begin(), initial_scid.end()) ||
        !std::equal(parsed->source_cid.begin(), parsed->source_cid.end(),
                    initial_dcid.begin(), initial_dcid.end()))
        return std::unexpected(version_negotiation_error::connection_id_mismatch);

    const auto list = parsed->version_list;
    const auto count = list.size() / 4;
    for (std::size_t i = 0; i < count; ++i) {
        const auto version = version_at(list, i);
        if (version == 0)
            return std::unexpected(version_negotiation_error::invalid_version_list);
        if (version == offered_version)
            return std::unexpected(version_negotiation_error::offered_version_listed);
        for (std::size_t j = 0; j < i; ++j)
            if (version_at(list, j) == version)
                return std::unexpected(version_negotiation_error::invalid_version_list);
    }
    for (const auto version : client_preference) {
        if (is_reserved_version_number(version)) continue;
        for (std::size_t i = 0; i < count; ++i)
            if (version_at(list, i) == version) return version;
    }
    return std::unexpected(version_negotiation_error::no_common_version);
}

// Run after the second handshake authenticates the server's RFC 9368 Version
// Information. The attempted version was selected from the VN packet. The
// negotiated version can differ if the new first flight allows a compatible
// switch. Selection is checked against the server's Available Versions plus
// the Negotiated Version, as required by RFC 9368 Section 4.
[[nodiscard]] constexpr auto validate_authenticated_version_information(
    std::uint32_t original_version,
    std::uint32_t attempted_version,
    std::uint32_t negotiated_version,
    std::uint32_t server_chosen_version,
    std::span<const std::uint32_t> server_available_versions,
    std::span<const std::uint32_t> client_advertised_versions,
    std::span<const std::uint32_t> client_preference) noexcept
    -> std::expected<void, version_negotiation_error>
{
    if (original_version == 0 || attempted_version == 0 ||
        negotiated_version == 0 || server_chosen_version == 0 ||
        !valid_version_list(client_advertised_versions) ||
        !valid_version_list(client_preference) ||
        (server_available_versions.size() != 0 &&
         !valid_version_list(server_available_versions)))
        return std::unexpected(version_negotiation_error::invalid_version_list);
    if (server_available_versions.empty())
        return std::unexpected(version_negotiation_error::downgrade_detected);
    if (std::find(client_advertised_versions.begin(),
                  client_advertised_versions.end(), attempted_version) ==
            client_advertised_versions.end() ||
        std::find(client_preference.begin(), client_preference.end(),
                  attempted_version) == client_preference.end() ||
        is_reserved_version_number(attempted_version) ||
        is_reserved_version_number(negotiated_version))
        return std::unexpected(version_negotiation_error::downgrade_detected);
    if (server_chosen_version != negotiated_version ||
        std::find(client_advertised_versions.begin(),
                  client_advertised_versions.end(), server_chosen_version) ==
            client_advertised_versions.end())
        return std::unexpected(version_negotiation_error::downgrade_detected);
    // Original Version is only a special case for unauthenticated VN packets.
    // Here the RFC 9368 check replays client selection over Available Versions
    // plus Negotiated Version using the client's preference order.
    for (const auto version : client_preference) {
        if (is_reserved_version_number(version)) continue;
        if (version == negotiated_version ||
            std::find(server_available_versions.begin(),
                      server_available_versions.end(), version) !=
                server_available_versions.end())
            return version == attempted_version
                       ? std::expected<void, version_negotiation_error> {}
                       : std::unexpected(
                             version_negotiation_error::downgrade_detected);
    }
    return std::unexpected(version_negotiation_error::downgrade_detected);
}

} // namespace eventloop::quic::detail
