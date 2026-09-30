#pragma once

#include "quic/frames.h"
#include "quic/packet_header.h"

#include <cstdint>
#include <expected>

namespace eventloop::quic::detail {

enum class endpoint_role { client, server };

enum class frame_policy_error {
    packet_has_no_frames,
    unknown_frame_type,
    prohibited_packet_kind,
    prohibited_sender_role,
};

// Validate a received frame's placement. The role is that of the receiver.
// Negotiation, connection state, and packet contents are checked elsewhere.
[[nodiscard]] constexpr auto validate_frame_policy(
    packet_kind packet, std::uint64_t type, endpoint_role receiver) noexcept
    -> std::expected<void, frame_policy_error>
{
    if (packet == packet_kind::retry ||
        packet == packet_kind::version_negotiation)
        return std::unexpected(frame_policy_error::packet_has_no_frames);

    if (type > 0x1e && type != 0x30 && type != 0x31)
        return std::unexpected(frame_policy_error::unknown_frame_type);

    if (packet == packet_kind::zero_rtt && receiver != endpoint_role::server)
        return std::unexpected(frame_policy_error::prohibited_sender_role);

    if ((type == 0x07 || type == 0x1e) && receiver != endpoint_role::client)
        return std::unexpected(frame_policy_error::prohibited_sender_role);

    const auto initial_or_handshake =
        packet == packet_kind::initial || packet == packet_kind::handshake;
    if (initial_or_handshake) {
        switch (type) {
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x06: case 0x1c:
            return {};
        default:
            return std::unexpected(frame_policy_error::prohibited_packet_kind);
        }
    }

    if (packet == packet_kind::zero_rtt) {
        switch (type) {
        case 0x02: case 0x03: case 0x06: case 0x07:
        case 0x19: case 0x1b: case 0x1e:
            return std::unexpected(frame_policy_error::prohibited_packet_kind);
        default:
            return {};
        }
    }

    return {};
}

[[nodiscard]] constexpr auto validate_frame_policy(
    packet_kind packet, const decoded_frame& frame,
    endpoint_role receiver) noexcept -> std::expected<void, frame_policy_error>
{
    return validate_frame_policy(packet, frame.type, receiver);
}

} // namespace eventloop::quic::detail
