#pragma once

#include "quic/transport_parameters.h"
#include "quic/version_negotiation.h"

namespace eventloop::quic::detail {

enum class parameter_validation_error {
    invalid_observation, invalid_parameters, forbidden_parameter,
    missing_initial_source_cid, initial_source_cid_mismatch,
    missing_original_destination_cid, original_destination_cid_mismatch,
    missing_retry_source_cid, unexpected_retry_source_cid, retry_source_cid_mismatch,
    missing_version_information, chosen_version_mismatch,
    negotiated_version_not_advertised, version_downgrade,
};

struct parameter_handshake_observations {
    parameter_sender peer_role {};
    std::span<const std::byte> peer_first_initial_scid {};
    std::span<const std::byte> original_initial_dcid {};
    bool retry_used {false};
    std::span<const std::byte> retry_scid {};
    // First flight of this connection, and final authenticated wire version.
    std::uint32_t client_chosen_version {version_1};
    std::uint32_t negotiated_version {version_1};
    bool acted_on_version_negotiation {false};
    // Exact client Version Information list, and its VN selection preference.
    std::span<const std::uint32_t> client_available_versions {};
    std::span<const std::uint32_t> client_version_preference {};
};

// RFC 9000 Sections 7.3, 18.1 and 18.2; RFC 9368 Sections 3 and 4;
// RFC 9369 Section 4.1. Run after wire decoding and before accepting TLS.
// Does not replace the connection's compatible-version selection procedure.
[[nodiscard]] constexpr auto validate_peer_transport_parameters(
    const transport_parameters& parameters,
    const parameter_handshake_observations& seen) noexcept
    -> std::expected<void, parameter_validation_error>
{
    using error = parameter_validation_error;
    if ((seen.peer_role != parameter_sender::client && seen.peer_role != parameter_sender::server) ||
        seen.peer_first_initial_scid.size() > 20 || seen.original_initial_dcid.size() > 20 ||
        seen.retry_scid.size() > 20 || (!seen.retry_used && !seen.retry_scid.empty()) ||
        !is_supported_version(seen.client_chosen_version) ||
        !is_supported_version(seen.negotiated_version))
        return std::unexpected(error::invalid_observation);
    if (parameters.count > transport_parameters::max_entries)
        return std::unexpected(error::invalid_parameters);
    for (std::size_t i = 0; i < parameters.count; ++i) {
        const auto& p = parameters.entries[i];
        for (std::size_t j = 0; j < i; ++j)
            if (p.id == parameters.entries[j].id)
                return std::unexpected(error::invalid_parameters);
        const auto valid = validate_parameter(p.id, p.value, seen.peer_role);
        if (!valid)
            return std::unexpected(valid.error() == parameter_error::forbidden_parameter
                ? error::forbidden_parameter : error::invalid_parameters);
    }
    const auto find = [&](parameter_id id) { return parameters.find(static_cast<std::uint64_t>(id)); };
    const auto initial = find(parameter_id::initial_source_connection_id);
    if (!initial) return std::unexpected(error::missing_initial_source_cid);
    if (!std::ranges::equal(initial->value, seen.peer_first_initial_scid))
        return std::unexpected(error::initial_source_cid_mismatch);
    if (seen.peer_role == parameter_sender::server) {
        const auto original = find(parameter_id::original_destination_connection_id);
        if (!original) return std::unexpected(error::missing_original_destination_cid);
        if (!std::ranges::equal(original->value, seen.original_initial_dcid))
            return std::unexpected(error::original_destination_cid_mismatch);
        const auto retry = find(parameter_id::retry_source_connection_id);
        if (seen.retry_used && !retry) return std::unexpected(error::missing_retry_source_cid);
        if (!seen.retry_used && retry) return std::unexpected(error::unexpected_retry_source_cid);
        if (retry && !std::ranges::equal(retry->value, seen.retry_scid))
            return std::unexpected(error::retry_source_cid_mismatch);
    }
    const auto versions = find(parameter_id::version_information);
    if (!versions) {
        if (seen.client_chosen_version == version_2 || seen.negotiated_version == version_2)
            return std::unexpected(error::missing_version_information);
        if (seen.peer_role == parameter_sender::server && seen.acted_on_version_negotiation)
            return std::unexpected(error::missing_version_information);
        if (seen.client_chosen_version != seen.negotiated_version)
            return std::unexpected(error::missing_version_information);
        return {};
    }
    const auto chosen = version_at(versions->value, 0);
    const auto expected = seen.peer_role == parameter_sender::client
        ? seen.client_chosen_version : seen.negotiated_version;
    if (chosen != expected) return std::unexpected(error::chosen_version_mismatch);
    if (seen.peer_role == parameter_sender::client) {
        bool advertised = false;
        for (std::size_t i = 1; i < versions->value.size() / 4; ++i)
            advertised |= version_at(versions->value, i) == seen.negotiated_version;
        if (!advertised) return std::unexpected(error::negotiated_version_not_advertised);
        return {};
    }
    if (!valid_version_list(seen.client_available_versions))
        return std::unexpected(error::invalid_observation);
    if (std::ranges::find(seen.client_available_versions, chosen) == seen.client_available_versions.end())
        return std::unexpected(error::negotiated_version_not_advertised);
    if (!seen.acted_on_version_negotiation) return {};
    if (!valid_version_list(seen.client_version_preference))
        return std::unexpected(error::invalid_observation);
    if (versions->value.size() == 4) return std::unexpected(error::version_downgrade);
    for (const auto candidate : seen.client_version_preference) {
        if (is_reserved_version_number(candidate)) continue;
        bool available = candidate == chosen;
        for (std::size_t i = 1; i < versions->value.size() / 4; ++i)
            available |= candidate == version_at(versions->value, i);
        if (available)
            return candidate == seen.client_chosen_version
                ? std::expected<void, error>{} : std::unexpected(error::version_downgrade);
    }
    return std::unexpected(error::version_downgrade);
}
} // namespace eventloop::quic::detail
