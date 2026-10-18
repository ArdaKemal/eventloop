#pragma once

#include "eventloop/http/request.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
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
    // Each entry costs at least 32 octets of table size (RFC 7541 4.1).
    static constexpr std::size_t max_entries = hpack_max_table_size / 32;
    struct table_entry {
        std::uint16_t offset = 0;
        std::uint16_t name_size = 0;
        std::uint16_t value_size = 0;
    };
    // The dynamic table keeps entry octets in one ring that grows by
    // doubling to fit the live octets, up to hpack_max_table_size; once the
    // peer's working set fits, insertion and eviction do not allocate.
    std::unique_ptr<char[]> table_octets_;
    std::size_t ring_size_ = 0;
    std::array<table_entry, max_entries> entries_ {};
    std::size_t newest_ = 0;
    std::size_t entry_count_ = 0;
    std::size_t write_offset_ = 0;
    std::size_t table_bytes_ = 0;
    std::size_t table_size_ = hpack_max_table_size;
    std::size_t table_size_limit_ = hpack_max_table_size;
    std::size_t required_first_size_ = hpack_max_table_size;
    bool update_required_ = false;

    [[nodiscard]] auto resolve(std::size_t index, field& result) const -> bool;
    auto insert(const field& entry) -> void;
    auto evict_oldest() noexcept -> void;
    auto grow_ring(std::size_t needed) -> void;
    auto resize_table(std::size_t size) -> void;
    auto store(std::string_view octets) noexcept -> void;
    auto load(std::size_t offset, std::size_t size, std::string& output) const -> void;
};

// Stateless response encoder: literal fields, no indexing or Huffman coding.
// Replaces output, or with append adds to it; the field limits then count
// the whole block. Reusing output keeps its capacity.
[[nodiscard]] auto hpack_encode(std::span<const field> fields,
                                std::vector<std::byte>& output,
                                bool append = false) -> hpack_error;
[[nodiscard]] auto hpack_encode(std::span<const http::header> fields,
                                std::vector<std::byte>& output,
                                bool append = false) -> hpack_error;

} // namespace eventloop::http2::detail
