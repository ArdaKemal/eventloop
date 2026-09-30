#pragma once

#include "quic/varint.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace eventloop::quic::detail {

enum class parameter_id : std::uint64_t {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    version_information = 0x11,
    max_datagram_frame_size = 0x20,
    grease_quic_bit = 0x2ab2,
};

enum class parameter_sender { client, server };

enum class parameter_error {
    truncated,
    duplicate,
    invalid_value,
    forbidden_parameter,
    resource_limit,
    output_too_small,
};

struct transport_parameter {
    std::uint64_t id {0};
    // This view borrows its bytes from the input or caller until encoding ends.
    std::span<const std::byte> value {};
};

struct transport_parameters {
    static constexpr std::size_t max_entries = 128;
    static constexpr std::size_t max_encoded_size = 65535;

    std::array<transport_parameter, max_entries> entries {};
    std::size_t count {0};

    [[nodiscard]] constexpr auto find(std::uint64_t id) const noexcept
        -> const transport_parameter*
    {
        for (std::size_t i = 0; i < count; ++i) {
            if (entries[i].id == id) return &entries[i];
        }
        return nullptr;
    }
};

[[nodiscard]] constexpr auto parameter_integer(std::span<const std::byte> value)
    noexcept -> std::expected<std::uint64_t, parameter_error>
{
    const auto decoded = decode_varint(value);
    if (!decoded || decoded->encoded_size != value.size()) {
        return std::unexpected(parameter_error::invalid_value);
    }
    return decoded->value;
}

[[nodiscard]] constexpr auto validate_parameter(
    std::uint64_t id, std::span<const std::byte> value,
    parameter_sender sender) noexcept -> std::expected<void, parameter_error>
{
    if (sender == parameter_sender::client &&
        (id == 0x00 || id == 0x02 || id == 0x0d || id == 0x10)) {
        return std::unexpected(parameter_error::forbidden_parameter);
    }

    if (id == 0x00 || id == 0x0f || id == 0x10) {
        if (value.size() > 20) {
            return std::unexpected(parameter_error::invalid_value);
        }
    } else if (id == 0x02) {
        if (value.size() != 16) {
            return std::unexpected(parameter_error::invalid_value);
        }
    } else if (id == 0x0d) {
        // 4+2 IPv4, 16+2 IPv6, one CID length byte, and 16 token bytes.
        if (value.size() < 42) {
            return std::unexpected(parameter_error::invalid_value);
        }
        const auto cid_size = std::to_integer<std::uint8_t>(value[24]);
        if (cid_size == 0 || cid_size > 20 ||
            value.size() != 25 + cid_size + 16) {
            return std::unexpected(parameter_error::invalid_value);
        }
    } else if (id == 0x0c || id == 0x2ab2) {
        if (!value.empty()) {
            return std::unexpected(parameter_error::invalid_value);
        }
    } else if (id == 0x11) {
        if (value.size() < 4 || value.size() % 4 != 0) {
            return std::unexpected(parameter_error::invalid_value);
        }
        const auto chosen = (std::to_integer<std::uint32_t>(value[0]) << 24) |
                            (std::to_integer<std::uint32_t>(value[1]) << 16) |
                            (std::to_integer<std::uint32_t>(value[2]) << 8) |
                             std::to_integer<std::uint32_t>(value[3]);
        if (chosen == 0) {
            return std::unexpected(parameter_error::invalid_value);
        }
        bool chosen_offered = false;
        for (std::size_t i = 4; i < value.size(); i += 4) {
            const auto available =
                (std::to_integer<std::uint32_t>(value[i]) << 24) |
                (std::to_integer<std::uint32_t>(value[i + 1]) << 16) |
                (std::to_integer<std::uint32_t>(value[i + 2]) << 8) |
                 std::to_integer<std::uint32_t>(value[i + 3]);
            if (available == 0) {
                return std::unexpected(parameter_error::invalid_value);
            }
            chosen_offered |= available == chosen;
        }
        if (sender == parameter_sender::client && !chosen_offered) {
            return std::unexpected(parameter_error::invalid_value);
        }
    } else if (id == 0x01 || (id >= 0x03 && id <= 0x0b) ||
               id == 0x0e || id == 0x20) {
        const auto number = parameter_integer(value);
        if (!number) return std::unexpected(number.error());
        if ((id == 0x03 && (*number < 1200 || *number > 65527)) ||
            ((id == 0x08 || id == 0x09) && *number > (1ULL << 60)) ||
            (id == 0x0a && *number > 20) ||
            (id == 0x0b && *number >= (1ULL << 14)) ||
            (id == 0x0e && *number < 2)) {
            return std::unexpected(parameter_error::invalid_value);
        }
    }
    return {};
}

[[nodiscard]] constexpr auto decode_transport_parameters(
    std::span<const std::byte> input, parameter_sender sender) noexcept
    -> std::expected<transport_parameters, parameter_error>
{
    if (input.size() > transport_parameters::max_encoded_size) {
        return std::unexpected(parameter_error::resource_limit);
    }
    transport_parameters parameters;
    while (!input.empty()) {
        const auto id = decode_varint(input);
        if (!id) return std::unexpected(parameter_error::truncated);
        input = input.subspan(id->encoded_size);
        const auto length = decode_varint(input);
        if (!length) return std::unexpected(parameter_error::truncated);
        input = input.subspan(length->encoded_size);
        if (length->value > input.size()) {
            return std::unexpected(parameter_error::truncated);
        }
        if (parameters.find(id->value)) {
            return std::unexpected(parameter_error::duplicate);
        }
        if (parameters.count == transport_parameters::max_entries) {
            return std::unexpected(parameter_error::resource_limit);
        }
        const auto value = input.first(static_cast<std::size_t>(length->value));
        if (const auto valid = validate_parameter(id->value, value, sender);
            !valid) return std::unexpected(valid.error());
        parameters.entries[parameters.count++] = {id->value, value};
        input = input.subspan(value.size());
    }
    return parameters;
}

[[nodiscard]] constexpr auto encode_transport_parameters(
    std::span<const transport_parameter> parameters, parameter_sender sender,
    std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, parameter_error>
{
    if (parameters.size() > transport_parameters::max_entries) {
        return std::unexpected(parameter_error::resource_limit);
    }
    std::size_t total = 0;
    for (std::size_t i = 0; i < parameters.size(); ++i) {
        const auto& entry = parameters[i];
        for (std::size_t j = 0; j < i; ++j) {
            if (parameters[j].id == entry.id) {
                return std::unexpected(parameter_error::duplicate);
            }
        }
        if (const auto valid = validate_parameter(entry.id, entry.value, sender);
            !valid) return std::unexpected(valid.error());
        const auto id_size = varint_size(entry.id);
        const auto length_size = varint_size(entry.value.size());
        if (id_size == 0 || length_size == 0 ||
            entry.value.size() > transport_parameters::max_encoded_size - total ||
            id_size + length_size > transport_parameters::max_encoded_size -
                total - entry.value.size()) {
            return std::unexpected(parameter_error::resource_limit);
        }
        total += id_size + length_size + entry.value.size();
    }
    if (output.size() < total) {
        return std::unexpected(parameter_error::output_too_small);
    }
    std::size_t offset = 0;
    for (const auto& entry : parameters) {
        const auto id_size = *encode_varint(entry.id, output.subspan(offset));
        offset += id_size;
        const auto length_size = *encode_varint(entry.value.size(),
                                                 output.subspan(offset));
        offset += length_size;
        for (const auto byte : entry.value) output[offset++] = byte;
    }
    return offset;
}

} // namespace eventloop::quic::detail
