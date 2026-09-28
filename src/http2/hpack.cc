#include "hpack.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <string_view>
#include <utility>

namespace eventloop::http2::detail {
namespace {

struct static_field {
    std::string_view name;
    std::string_view value;
};

struct huffman_code {
    std::uint32_t code;
    std::uint8_t bits;
};

// RFC 7541 Appendices A and B.
constexpr std::array<static_field, 61> static_table {{
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""},
}};

// RFC 7541 Appendix B: symbol-indexed (code, bit length).
constexpr std::array<huffman_code, 257> huffman_table {{
    {0x1ff8u, 13},
    {0x7fffd8u, 23},
    {0xfffffe2u, 28},
    {0xfffffe3u, 28},
    {0xfffffe4u, 28},
    {0xfffffe5u, 28},
    {0xfffffe6u, 28},
    {0xfffffe7u, 28},
    {0xfffffe8u, 28},
    {0xffffeau, 24},
    {0x3ffffffcu, 30},
    {0xfffffe9u, 28},
    {0xfffffeau, 28},
    {0x3ffffffdu, 30},
    {0xfffffebu, 28},
    {0xfffffecu, 28},
    {0xfffffedu, 28},
    {0xfffffeeu, 28},
    {0xfffffefu, 28},
    {0xffffff0u, 28},
    {0xffffff1u, 28},
    {0xffffff2u, 28},
    {0x3ffffffeu, 30},
    {0xffffff3u, 28},
    {0xffffff4u, 28},
    {0xffffff5u, 28},
    {0xffffff6u, 28},
    {0xffffff7u, 28},
    {0xffffff8u, 28},
    {0xffffff9u, 28},
    {0xffffffau, 28},
    {0xffffffbu, 28},
    {0x14u, 6},
    {0x3f8u, 10},
    {0x3f9u, 10},
    {0xffau, 12},
    {0x1ff9u, 13},
    {0x15u, 6},
    {0xf8u, 8},
    {0x7fau, 11},
    {0x3fau, 10},
    {0x3fbu, 10},
    {0xf9u, 8},
    {0x7fbu, 11},
    {0xfau, 8},
    {0x16u, 6},
    {0x17u, 6},
    {0x18u, 6},
    {0x0u, 5},
    {0x1u, 5},
    {0x2u, 5},
    {0x19u, 6},
    {0x1au, 6},
    {0x1bu, 6},
    {0x1cu, 6},
    {0x1du, 6},
    {0x1eu, 6},
    {0x1fu, 6},
    {0x5cu, 7},
    {0xfbu, 8},
    {0x7ffcu, 15},
    {0x20u, 6},
    {0xffbu, 12},
    {0x3fcu, 10},
    {0x1ffau, 13},
    {0x21u, 6},
    {0x5du, 7},
    {0x5eu, 7},
    {0x5fu, 7},
    {0x60u, 7},
    {0x61u, 7},
    {0x62u, 7},
    {0x63u, 7},
    {0x64u, 7},
    {0x65u, 7},
    {0x66u, 7},
    {0x67u, 7},
    {0x68u, 7},
    {0x69u, 7},
    {0x6au, 7},
    {0x6bu, 7},
    {0x6cu, 7},
    {0x6du, 7},
    {0x6eu, 7},
    {0x6fu, 7},
    {0x70u, 7},
    {0x71u, 7},
    {0x72u, 7},
    {0xfcu, 8},
    {0x73u, 7},
    {0xfdu, 8},
    {0x1ffbu, 13},
    {0x7fff0u, 19},
    {0x1ffcu, 13},
    {0x3ffcu, 14},
    {0x22u, 6},
    {0x7ffdu, 15},
    {0x3u, 5},
    {0x23u, 6},
    {0x4u, 5},
    {0x24u, 6},
    {0x5u, 5},
    {0x25u, 6},
    {0x26u, 6},
    {0x27u, 6},
    {0x6u, 5},
    {0x74u, 7},
    {0x75u, 7},
    {0x28u, 6},
    {0x29u, 6},
    {0x2au, 6},
    {0x7u, 5},
    {0x2bu, 6},
    {0x76u, 7},
    {0x2cu, 6},
    {0x8u, 5},
    {0x9u, 5},
    {0x2du, 6},
    {0x77u, 7},
    {0x78u, 7},
    {0x79u, 7},
    {0x7au, 7},
    {0x7bu, 7},
    {0x7ffeu, 15},
    {0x7fcu, 11},
    {0x3ffdu, 14},
    {0x1ffdu, 13},
    {0xffffffcu, 28},
    {0xfffe6u, 20},
    {0x3fffd2u, 22},
    {0xfffe7u, 20},
    {0xfffe8u, 20},
    {0x3fffd3u, 22},
    {0x3fffd4u, 22},
    {0x3fffd5u, 22},
    {0x7fffd9u, 23},
    {0x3fffd6u, 22},
    {0x7fffdau, 23},
    {0x7fffdbu, 23},
    {0x7fffdcu, 23},
    {0x7fffddu, 23},
    {0x7fffdeu, 23},
    {0xffffebu, 24},
    {0x7fffdfu, 23},
    {0xffffecu, 24},
    {0xffffedu, 24},
    {0x3fffd7u, 22},
    {0x7fffe0u, 23},
    {0xffffeeu, 24},
    {0x7fffe1u, 23},
    {0x7fffe2u, 23},
    {0x7fffe3u, 23},
    {0x7fffe4u, 23},
    {0x1fffdcu, 21},
    {0x3fffd8u, 22},
    {0x7fffe5u, 23},
    {0x3fffd9u, 22},
    {0x7fffe6u, 23},
    {0x7fffe7u, 23},
    {0xffffefu, 24},
    {0x3fffdau, 22},
    {0x1fffddu, 21},
    {0xfffe9u, 20},
    {0x3fffdbu, 22},
    {0x3fffdcu, 22},
    {0x7fffe8u, 23},
    {0x7fffe9u, 23},
    {0x1fffdeu, 21},
    {0x7fffeau, 23},
    {0x3fffddu, 22},
    {0x3fffdeu, 22},
    {0xfffff0u, 24},
    {0x1fffdfu, 21},
    {0x3fffdfu, 22},
    {0x7fffebu, 23},
    {0x7fffecu, 23},
    {0x1fffe0u, 21},
    {0x1fffe1u, 21},
    {0x3fffe0u, 22},
    {0x1fffe2u, 21},
    {0x7fffedu, 23},
    {0x3fffe1u, 22},
    {0x7fffeeu, 23},
    {0x7fffefu, 23},
    {0xfffeau, 20},
    {0x3fffe2u, 22},
    {0x3fffe3u, 22},
    {0x3fffe4u, 22},
    {0x7ffff0u, 23},
    {0x3fffe5u, 22},
    {0x3fffe6u, 22},
    {0x7ffff1u, 23},
    {0x3ffffe0u, 26},
    {0x3ffffe1u, 26},
    {0xfffebu, 20},
    {0x7fff1u, 19},
    {0x3fffe7u, 22},
    {0x7ffff2u, 23},
    {0x3fffe8u, 22},
    {0x1ffffecu, 25},
    {0x3ffffe2u, 26},
    {0x3ffffe3u, 26},
    {0x3ffffe4u, 26},
    {0x7ffffdeu, 27},
    {0x7ffffdfu, 27},
    {0x3ffffe5u, 26},
    {0xfffff1u, 24},
    {0x1ffffedu, 25},
    {0x7fff2u, 19},
    {0x1fffe3u, 21},
    {0x3ffffe6u, 26},
    {0x7ffffe0u, 27},
    {0x7ffffe1u, 27},
    {0x3ffffe7u, 26},
    {0x7ffffe2u, 27},
    {0xfffff2u, 24},
    {0x1fffe4u, 21},
    {0x1fffe5u, 21},
    {0x3ffffe8u, 26},
    {0x3ffffe9u, 26},
    {0xffffffdu, 28},
    {0x7ffffe3u, 27},
    {0x7ffffe4u, 27},
    {0x7ffffe5u, 27},
    {0xfffecu, 20},
    {0xfffff3u, 24},
    {0xfffedu, 20},
    {0x1fffe6u, 21},
    {0x3fffe9u, 22},
    {0x1fffe7u, 21},
    {0x1fffe8u, 21},
    {0x7ffff3u, 23},
    {0x3fffeau, 22},
    {0x3fffebu, 22},
    {0x1ffffeeu, 25},
    {0x1ffffefu, 25},
    {0xfffff4u, 24},
    {0xfffff5u, 24},
    {0x3ffffeau, 26},
    {0x7ffff4u, 23},
    {0x3ffffebu, 26},
    {0x7ffffe6u, 27},
    {0x3ffffecu, 26},
    {0x3ffffedu, 26},
    {0x7ffffe7u, 27},
    {0x7ffffe8u, 27},
    {0x7ffffe9u, 27},
    {0x7ffffeau, 27},
    {0x7ffffebu, 27},
    {0xffffffeu, 28},
    {0x7ffffecu, 27},
    {0x7ffffedu, 27},
    {0x7ffffeeu, 27},
    {0x7ffffefu, 27},
    {0x7fffff0u, 27},
    {0x3ffffeeu, 26},
    {0x3fffffffu, 30},
}};

[[nodiscard]] constexpr auto byte(std::byte value) -> std::uint8_t
{
    return std::to_integer<std::uint8_t>(value);
}

[[nodiscard]] auto read_integer(std::span<const std::byte> input,
                                std::size_t& offset, unsigned prefix,
                                std::uint32_t& value) -> bool
{
    if (offset == input.size()) return false;
    const auto mask = static_cast<std::uint32_t>((1u << prefix) - 1);
    value = byte(input[offset++]) & mask;
    if (value != mask) return true;
    unsigned shift = 0;
    for (;;) {
        if (offset == input.size() || shift > 28) return false;
        const auto part = byte(input[offset++]);
        const auto digit = static_cast<std::uint32_t>(part & 0x7f);
        if (digit > (std::numeric_limits<std::uint32_t>::max() - value) >> shift) {
            return false;
        }
        value += digit << shift;
        if ((part & 0x80) == 0) return true;
        shift += 7;
    }
}

auto write_integer(std::uint32_t value, unsigned prefix, std::uint8_t bits,
                   std::vector<std::byte>& output) -> void
{
    const auto mask = (1u << prefix) - 1;
    if (value < mask) {
        output.push_back(std::byte {static_cast<std::uint8_t>(bits | value)});
        return;
    }
    output.push_back(std::byte {static_cast<std::uint8_t>(bits | mask)});
    value -= mask;
    while (value >= 128) {
        output.push_back(std::byte {static_cast<std::uint8_t>((value & 0x7f) | 0x80)});
        value >>= 7;
    }
    output.push_back(std::byte {static_cast<std::uint8_t>(value)});
}

struct huffman_node {
    std::uint16_t child[2] {};
    std::int16_t symbol = -1;
};

struct huffman_tree {
    std::array<huffman_node, 1024> nodes {};
    std::uint16_t count = 1;

    huffman_tree()
    {
        for (std::size_t symbol = 0; symbol < huffman_table.size(); ++symbol) {
            const auto [code, bits] = huffman_table[symbol];
            std::uint16_t node = 0;
            for (unsigned shift = bits; shift != 0; --shift) {
                const auto bit = (code >> (shift - 1)) & 1u;
                auto& next = nodes[node].child[bit];
                if (next == 0) next = count++;
                node = next;
            }
            nodes[node].symbol = static_cast<std::int16_t>(symbol);
        }
    }
};

[[nodiscard]] auto decode_huffman(std::span<const std::byte> input,
                                  std::string& output) -> hpack_error
{
    static const huffman_tree tree;
    std::uint16_t node = 0;
    unsigned pending = 0;
    bool pending_ones = true;
    for (const auto octet : input) {
        for (int shift = 7; shift >= 0; --shift) {
            const auto bit = (byte(octet) >> shift) & 1u;
            node = tree.nodes[node].child[bit];
            if (node == 0) return hpack_error::invalid;
            ++pending;
            pending_ones &= bit != 0;
            const auto symbol = tree.nodes[node].symbol;
            if (symbol < 0) continue;
            if (symbol == 256) return hpack_error::invalid; // EOS is never data.
            if (output.size() == hpack_max_field_list_size) {
                return hpack_error::limit_exceeded;
            }
            output.push_back(static_cast<char>(symbol));
            node = 0;
            pending = 0;
            pending_ones = true;
        }
    }
    // A partial final code must be at most seven leading one bits of EOS.
    return pending <= 7 && pending_ones ? hpack_error::none : hpack_error::invalid;
}

[[nodiscard]] auto read_string(std::span<const std::byte> input,
                               std::size_t& offset, std::string& output) -> hpack_error
{
    if (offset == input.size()) return hpack_error::invalid;
    const bool huffman = (byte(input[offset]) & 0x80) != 0;
    std::uint32_t length = 0;
    if (!read_integer(input, offset, 7, length)) return hpack_error::invalid;
    if (length > hpack_max_block_size) return hpack_error::limit_exceeded;
    if (length > input.size() - offset) return hpack_error::invalid;
    output.clear();
    const auto data = input.subspan(offset, length);
    offset += length;
    if (huffman) return decode_huffman(data, output);
    output.reserve(length);
    for (const auto octet : data) output.push_back(static_cast<char>(byte(octet)));
    return hpack_error::none;
}

auto write_string(std::string_view value, std::vector<std::byte>& output) -> void
{
    write_integer(static_cast<std::uint32_t>(value.size()), 7, 0, output);
    for (const unsigned char octet : value) output.push_back(std::byte {octet});
}

} // namespace

auto hpack_decoder::set_table_size_limit(std::size_t limit) -> hpack_error
{
    if (limit > hpack_max_table_size) return hpack_error::limit_exceeded;
    if (limit < table_size_) {
        required_first_size_ = std::min(required_first_size_, limit);
        update_required_ = true;
    }
    table_size_limit_ = limit;
    return hpack_error::none;
}

auto hpack_decoder::resolve(std::size_t index, field& result) const -> bool
{
    if (index == 0) return false;
    if (index <= static_table.size()) {
        const auto& source = static_table[index - 1];
        result.name = source.name;
        result.value = source.value;
        return true;
    }
    index -= static_table.size() + 1;
    if (index >= table_.size()) return false;
    result = table_[index];
    return true;
}

auto hpack_decoder::resize_table(std::size_t size) -> void
{
    table_size_ = size;
    while (table_bytes_ > table_size_) {
        const auto& last = table_.back();
        table_bytes_ -= last.name.size() + last.value.size() + 32;
        table_.pop_back();
    }
}

auto hpack_decoder::insert(field entry) -> void
{
    const auto size = entry.name.size() + entry.value.size() + 32;
    if (size > table_size_) {
        table_.clear();
        table_bytes_ = 0;
        return;
    }
    while (table_bytes_ + size > table_size_) {
        const auto& last = table_.back();
        table_bytes_ -= last.name.size() + last.value.size() + 32;
        table_.pop_back();
    }
    table_.insert(table_.begin(), std::move(entry));
    table_bytes_ += size;
}

auto hpack_decoder::decode(std::span<const std::byte> block,
                           std::vector<field>& output) -> hpack_error
{
    output.clear();
    if (block.size() > hpack_max_block_size) return hpack_error::limit_exceeded;
    std::size_t offset = 0;
    std::size_t list_bytes = 0;
    bool saw_field = false;
    bool saw_update = false;
    auto fail = [&](hpack_error error) {
        output.clear();
        return error;
    };
    auto append = [&](field entry) -> hpack_error {
        const auto size = entry.name.size() + entry.value.size() + 32;
        if (output.size() == hpack_max_fields || size > hpack_max_field_list_size - list_bytes) {
            return hpack_error::limit_exceeded;
        }
        list_bytes += size;
        output.push_back(std::move(entry));
        return hpack_error::none;
    };
    while (offset < block.size()) {
        const auto lead = byte(block[offset]);
        std::uint32_t index = 0;
        if ((lead & 0x80) != 0) {
            if (update_required_ && !saw_update) return fail(hpack_error::invalid);
            saw_field = true;
            if (!read_integer(block, offset, 7, index)) return fail(hpack_error::invalid);
            field entry;
            if (!resolve(index, entry)) return fail(hpack_error::invalid);
            if (const auto error = append(std::move(entry)); error != hpack_error::none) {
                return fail(error);
            }
            continue;
        }
        if ((lead & 0xe0) == 0x20) {
            if (saw_field || !read_integer(block, offset, 5, index) ||
                index > table_size_limit_ ||
                (update_required_ && !saw_update && index > required_first_size_)) {
                return fail(hpack_error::invalid);
            }
            resize_table(index);
            saw_update = true;
            update_required_ = false;
            required_first_size_ = hpack_max_table_size;
            continue;
        }
        if (update_required_ && !saw_update) return fail(hpack_error::invalid);
        saw_field = true;
        const bool indexed = (lead & 0xc0) == 0x40;
        const unsigned prefix = indexed ? 6 : 4;
        if (!read_integer(block, offset, prefix, index)) return fail(hpack_error::invalid);
        field entry;
        if (index != 0) {
            if (!resolve(index, entry)) return fail(hpack_error::invalid);
        } else if (const auto error = read_string(block, offset, entry.name);
                   error != hpack_error::none) {
            return fail(error);
        }
        if (const auto error = read_string(block, offset, entry.value);
            error != hpack_error::none) {
            return fail(error);
        }
        if (entry.name.empty()) return fail(hpack_error::invalid);
        if (indexed) insert(entry);
        if (const auto error = append(std::move(entry)); error != hpack_error::none) {
            return fail(error);
        }
    }
    if (update_required_ && !saw_update) return fail(hpack_error::invalid);
    return hpack_error::none;
}

auto hpack_encode(std::span<const field> fields,
                  std::vector<std::byte>& output) -> hpack_error
{
    output.clear();
    if (fields.size() > hpack_max_fields) return hpack_error::limit_exceeded;
    std::size_t list_bytes = 0;
    for (const auto& entry : fields) {
        const auto size = entry.name.size() + entry.value.size() + 32;
        if (entry.name.empty()) return hpack_error::invalid;
        if (size > hpack_max_field_list_size - list_bytes ||
            entry.name.size() > hpack_max_block_size ||
            entry.value.size() > hpack_max_block_size ||
            size > hpack_max_block_size - output.size()) {
            output.clear();
            return hpack_error::limit_exceeded;
        }
        list_bytes += size;
        output.push_back(std::byte {0}); // literal without indexing, new name
        write_string(entry.name, output);
        write_string(entry.value, output);
    }
    return hpack_error::none;
}

} // namespace eventloop::http2::detail
