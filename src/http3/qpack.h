#pragma once

#include <cstddef>
#include <expected>
#include <span>
#include <string_view>

namespace eventloop::http3::detail {

inline constexpr std::size_t qpack_max_block_size = 64 * 1024;
inline constexpr std::size_t qpack_max_field_list_size = 64 * 1024;
inline constexpr std::size_t qpack_max_fields = 128;

struct field {
    std::string_view name;
    std::string_view value;
};

enum class qpack_error { invalid, limit_exceeded, dynamic_table_disabled };

// Zero dynamic-table capacity and zero blocked streams. These codecs allocate
// no heap memory. Encoding uses static references and uncompressed literals.
// Returns bytes written, or decoded field count respectively. On error output
// storage may have been partially written and must be discarded.
[[nodiscard]] auto qpack_encode(std::span<const field> fields,
    std::span<std::byte> output) noexcept -> std::expected<std::size_t, qpack_error>;

// Decoded views borrow string_storage or the immutable static table. They are
// valid until string_storage is reused. Input need only live through this call.
// The field-list bound includes 32 bytes of overhead per field (RFC 9114).
[[nodiscard]] auto qpack_decode(std::span<const std::byte> block,
    std::span<field> output, std::span<char> string_storage) noexcept
    -> std::expected<std::size_t, qpack_error>;

// Validate a complete encoder-stream instruction sequence. Setting capacity
// to zero is harmless; insertions, duplicates, and nonzero capacity are errors.
// Callers must reassemble incomplete instructions before calling this function.
[[nodiscard]] auto qpack_validate_encoder_instructions(
    std::span<const std::byte> instructions) noexcept
    -> std::expected<void, qpack_error>;

} // namespace eventloop::http3::detail
