#pragma once

#include "quic/varint.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>

namespace eventloop::http3::detail {

inline constexpr std::uint64_t data_frame = 0x00;
inline constexpr std::uint64_t headers_frame = 0x01;
inline constexpr std::uint64_t cancel_push_frame = 0x03;
inline constexpr std::uint64_t settings_frame = 0x04;
inline constexpr std::uint64_t push_promise_frame = 0x05;
inline constexpr std::uint64_t goaway_frame = 0x07;
inline constexpr std::uint64_t max_push_id_frame = 0x0d;
inline constexpr std::uint64_t qpack_max_table_capacity = 0x01;
inline constexpr std::uint64_t max_field_section_size = 0x06;
inline constexpr std::uint64_t qpack_blocked_streams = 0x07;

enum class frame_error {
    incomplete_input,
    value_out_of_range,
    output_too_small,
    payload_too_large,
    forbidden_frame_type,
    forbidden_setting,
    duplicate_setting,
    too_many_settings,
};

// RFC 9114 reserves these HTTP/2 types as errors, unlike ignorable extensions.
[[nodiscard]] constexpr auto forbidden_frame_type(std::uint64_t type) noexcept
    -> bool
{
    return type == 0x02 || type == 0x06 || type == 0x08 || type == 0x09;
}

[[nodiscard]] constexpr auto known_frame_type(std::uint64_t type) noexcept
    -> bool
{
    return type == data_frame || type == headers_frame ||
           type == cancel_push_frame || type == settings_frame ||
           type == push_promise_frame || type == goaway_frame ||
           type == max_push_id_frame;
}

// QUIC variable-length integer split across arbitrary read boundaries, for
// stream parsers that consume input without buffering whole frames.
struct varint_accumulator {
    std::array<std::byte, 8> bytes {};
    std::uint8_t have {0};
    std::uint8_t need {0};

    // Consumes octets from input until one integer completes.
    [[nodiscard]] auto feed(std::span<const std::byte>& input) noexcept
        -> std::optional<std::uint64_t>
    {
        while (!input.empty()) {
            if (have == 0)
                need = static_cast<std::uint8_t>(
                    1u << (std::to_integer<unsigned>(input.front()) >> 6));
            bytes[have++] = input.front();
            input = input.subspan(1);
            if (have == need) {
                have = 0;
                return quic::detail::decode_varint(std::span(bytes).first(need))->value;
            }
        }
        return std::nullopt;
    }
    [[nodiscard]] auto partial() const noexcept -> bool { return have != 0; }
};

struct frame_header {
    std::uint64_t type;
    std::uint64_t payload_size;
    std::size_t encoded_size;
};

// Header decoding needs at most 16 bytes. Unknown extension types are accepted;
// callers may skip their declared payload incrementally without buffering it.
// Stream placement and frame ordering remain the caller's responsibility.
[[nodiscard]] inline auto decode_frame_header(std::span<const std::byte> input)
    noexcept -> std::expected<frame_header, frame_error>
{
    const auto type = quic::detail::decode_varint(input);
    if (!type) return std::unexpected(frame_error::incomplete_input);
    if (forbidden_frame_type(type->value))
        return std::unexpected(frame_error::forbidden_frame_type);
    const auto size = quic::detail::decode_varint(input.subspan(type->encoded_size));
    if (!size) return std::unexpected(frame_error::incomplete_input);
    return frame_header {type->value, size->value,
                         type->encoded_size + size->encoded_size};
}

[[nodiscard]] inline auto encode_frame_header(
    std::uint64_t type, std::uint64_t payload_size, std::span<std::byte> output)
    noexcept -> std::expected<std::size_t, frame_error>
{
    const auto type_size = quic::detail::varint_size(type);
    const auto length_size = quic::detail::varint_size(payload_size);
    if (!type_size || !length_size)
        return std::unexpected(frame_error::value_out_of_range);
    if (forbidden_frame_type(type))
        return std::unexpected(frame_error::forbidden_frame_type);
    if (output.size() < type_size + length_size)
        return std::unexpected(frame_error::output_too_small);
    (void)quic::detail::encode_varint(type, output);
    (void)quic::detail::encode_varint(payload_size, output.subspan(type_size));
    return type_size + length_size;
}

struct frame_view {
    std::uint64_t type;
    std::span<const std::byte> payload;
    std::size_t encoded_size;
};

// The view borrows input and lasts only while that buffer remains unchanged.
// The caller supplies its buffering limit; trailing frames are left untouched.
[[nodiscard]] inline auto decode_frame(
    std::span<const std::byte> input, std::size_t max_payload_size) noexcept
    -> std::expected<frame_view, frame_error>
{
    const auto header = decode_frame_header(input);
    if (!header) return std::unexpected(header.error());
    if (header->payload_size > max_payload_size)
        return std::unexpected(frame_error::payload_too_large);
    if (header->payload_size > input.size() - header->encoded_size)
        return std::unexpected(frame_error::incomplete_input);
    const auto size = static_cast<std::size_t>(header->payload_size);
    return frame_view {header->type, input.subspan(header->encoded_size, size),
                       header->encoded_size + size};
}

// All encoders preserve output on failure. Payload may overlap output.
[[nodiscard]] inline auto encode_frame(
    std::uint64_t type, std::span<const std::byte> payload,
    std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, frame_error>
{
    std::byte header[16] {};
    const auto size = encode_frame_header(type, payload.size(), header);
    if (!size) return std::unexpected(size.error());
    if (output.size() < *size || payload.size() > output.size() - *size)
        return std::unexpected(frame_error::output_too_small);
    if (!payload.empty())
        std::memmove(output.data() + *size, payload.data(), payload.size());
    std::memcpy(output.data(), header, *size);
    return *size + payload.size();
}

struct setting {
    std::uint64_t identifier;
    std::uint64_t value;
};

[[nodiscard]] constexpr auto forbidden_setting(std::uint64_t id) noexcept -> bool
{
    return id >= 0x02 && id <= 0x05;
}

// Iteration borrows payload; a truncated pair leaves the cursor unchanged.
// Unknown settings (including grease identifiers) are returned for callers to
// ignore. Duplicate validation is performed separately over the entire payload.
class settings_iterator {
public:
    explicit settings_iterator(std::span<const std::byte> payload) noexcept
        : remaining_(payload) {}

    [[nodiscard]] auto next() noexcept
        -> std::expected<std::optional<setting>, frame_error>
    {
        if (remaining_.empty()) return std::optional<setting> {};
        const auto id = quic::detail::decode_varint(remaining_);
        if (!id) return std::unexpected(frame_error::incomplete_input);
        const auto value = quic::detail::decode_varint(
            remaining_.subspan(id->encoded_size));
        if (!value) return std::unexpected(frame_error::incomplete_input);
        if (forbidden_setting(id->value))
            return std::unexpected(frame_error::forbidden_setting);
        remaining_ = remaining_.subspan(id->encoded_size + value->encoded_size);
        return std::optional<setting> {setting {id->value, value->value}};
    }

private:
    std::span<const std::byte> remaining_;
};

// Fixed-storage validation uses bounded quadratic work to avoid allocating an
// identifier set. max_settings bounds that work, including unknown settings.
[[nodiscard]] inline auto validate_settings(
    std::span<const std::byte> payload, std::size_t max_settings) noexcept
    -> std::expected<std::size_t, frame_error>
{
    settings_iterator cursor(payload);
    std::size_t count = 0;
    for (;;) {
        const auto item = cursor.next();
        if (!item) return std::unexpected(item.error());
        if (!*item) return count;
        if (count == max_settings)
            return std::unexpected(frame_error::too_many_settings);
        settings_iterator previous(payload);
        for (std::size_t i = 0; i < count; ++i) {
            const auto earlier = previous.next();
            if ((**earlier).identifier == (**item).identifier)
                return std::unexpected(frame_error::duplicate_setting);
        }
        ++count;
    }
}

// SETTINGS payload only, for wrapping in encode_frame(settings_frame, ...).
// Settings storage must not overlap output. The caller bounds the entry count.
[[nodiscard]] inline auto encode_settings(
    std::span<const setting> settings, std::span<std::byte> output,
    std::size_t max_settings) noexcept
    -> std::expected<std::size_t, frame_error>
{
    if (settings.size() > max_settings)
        return std::unexpected(frame_error::too_many_settings);
    std::size_t size = 0;
    for (std::size_t i = 0; i < settings.size(); ++i) {
        const auto item = settings[i];
        if (forbidden_setting(item.identifier))
            return std::unexpected(frame_error::forbidden_setting);
        for (std::size_t j = 0; j < i; ++j) {
            if (settings[j].identifier == item.identifier)
                return std::unexpected(frame_error::duplicate_setting);
        }
        const auto id_size = quic::detail::varint_size(item.identifier);
        const auto value_size = quic::detail::varint_size(item.value);
        if (!id_size || !value_size)
            return std::unexpected(frame_error::value_out_of_range);
        if (id_size + value_size > output.size() - size)
            return std::unexpected(frame_error::output_too_small);
        size += id_size + value_size;
    }
    std::size_t offset = 0;
    for (const auto item : settings) {
        offset += *quic::detail::encode_varint(item.identifier, output.subspan(offset));
        offset += *quic::detail::encode_varint(item.value, output.subspan(offset));
    }
    return size;
}

} // namespace eventloop::http3::detail
