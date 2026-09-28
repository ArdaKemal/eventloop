#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace eventloop::http2::detail {

// Limits apply to each complete field block. A connection must close after a
// decoding error, since its HPACK table can no longer be trusted.
inline constexpr std::size_t hpack_max_table_size = 4096;
inline constexpr std::size_t hpack_max_block_size = 64 * 1024;
inline constexpr std::size_t hpack_max_field_list_size = 64 * 1024;
inline constexpr std::size_t hpack_max_fields = 128;

struct field {
    std::string name;
    std::string value;
};

enum class hpack_error { none, invalid, limit_exceeded };

class hpack_decoder {
public:
    // Call after the peer has acknowledged our SETTINGS_HEADER_TABLE_SIZE.
    // A reduction requires a table-size update at the next block's start.
    [[nodiscard]] auto set_table_size_limit(std::size_t limit) -> hpack_error;
    [[nodiscard]] auto decode(std::span<const std::byte> block,
                              std::vector<field>& output) -> hpack_error;

private:
    std::vector<field> table_;
    std::size_t table_bytes_ = 0;
    std::size_t table_size_ = hpack_max_table_size;
    std::size_t table_size_limit_ = hpack_max_table_size;
    std::size_t required_first_size_ = hpack_max_table_size;
    bool update_required_ = false;

    [[nodiscard]] auto resolve(std::size_t index, field& result) const -> bool;
    auto insert(field entry) -> void;
    auto resize_table(std::size_t size) -> void;
};

// Stateless response encoder: literal fields, no indexing or Huffman coding.
[[nodiscard]] auto hpack_encode(std::span<const field> fields,
                                std::vector<std::byte>& output) -> hpack_error;

} // namespace eventloop::http2::detail
