#include "qpack.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>

namespace eventloop::http3::detail {
namespace {

// RFC 9204 Appendix A; unlike HPACK, indices start at zero.
constexpr std::array<field, 99> static_table {{
    {":authority", ""}, // 0
    {":path", "/"}, // 1
    {"age", "0"}, // 2
    {"content-disposition", ""}, // 3
    {"content-length", "0"}, // 4
    {"cookie", ""}, // 5
    {"date", ""}, // 6
    {"etag", ""}, // 7
    {"if-modified-since", ""}, // 8
    {"if-none-match", ""}, // 9
    {"last-modified", ""}, // 10
    {"link", ""}, // 11
    {"location", ""}, // 12
    {"referer", ""}, // 13
    {"set-cookie", ""}, // 14
    {":method", "CONNECT"}, // 15
    {":method", "DELETE"}, // 16
    {":method", "GET"}, // 17
    {":method", "HEAD"}, // 18
    {":method", "OPTIONS"}, // 19
    {":method", "POST"}, // 20
    {":method", "PUT"}, // 21
    {":scheme", "http"}, // 22
    {":scheme", "https"}, // 23
    {":status", "103"}, // 24
    {":status", "200"}, // 25
    {":status", "304"}, // 26
    {":status", "404"}, // 27
    {":status", "503"}, // 28
    {"accept", "*/*"}, // 29
    {"accept", "application/dns-message"}, // 30
    {"accept-encoding", "gzip, deflate, br"}, // 31
    {"accept-ranges", "bytes"}, // 32
    {"access-control-allow-headers", "cache-control"}, // 33
    {"access-control-allow-headers", "content-type"}, // 34
    {"access-control-allow-origin", "*"}, // 35
    {"cache-control", "max-age=0"}, // 36
    {"cache-control", "max-age=2592000"}, // 37
    {"cache-control", "max-age=604800"}, // 38
    {"cache-control", "no-cache"}, // 39
    {"cache-control", "no-store"}, // 40
    {"cache-control", "public, max-age=31536000"}, // 41
    {"content-encoding", "br"}, // 42
    {"content-encoding", "gzip"}, // 43
    {"content-type", "application/dns-message"}, // 44
    {"content-type", "application/javascript"}, // 45
    {"content-type", "application/json"}, // 46
    {"content-type", "application/x-www-form-urlencoded"}, // 47
    {"content-type", "image/gif"}, // 48
    {"content-type", "image/jpeg"}, // 49
    {"content-type", "image/png"}, // 50
    {"content-type", "text/css"}, // 51
    {"content-type", "text/html; charset=utf-8"}, // 52
    {"content-type", "text/plain"}, // 53
    {"content-type", "text/plain;charset=utf-8"}, // 54
    {"range", "bytes=0-"}, // 55
    {"strict-transport-security", "max-age=31536000"}, // 56
    {"strict-transport-security", "max-age=31536000; includesubdomains"}, // 57
    {"strict-transport-security", "max-age=31536000; includesubdomains; preload"}, // 58
    {"vary", "accept-encoding"}, // 59
    {"vary", "origin"}, // 60
    {"x-content-type-options", "nosniff"}, // 61
    {"x-xss-protection", "1; mode=block"}, // 62
    {":status", "100"}, // 63
    {":status", "204"}, // 64
    {":status", "206"}, // 65
    {":status", "302"}, // 66
    {":status", "400"}, // 67
    {":status", "403"}, // 68
    {":status", "421"}, // 69
    {":status", "425"}, // 70
    {":status", "500"}, // 71
    {"accept-language", ""}, // 72
    {"access-control-allow-credentials", "FALSE"}, // 73
    {"access-control-allow-credentials", "TRUE"}, // 74
    {"access-control-allow-headers", "*"}, // 75
    {"access-control-allow-methods", "get"}, // 76
    {"access-control-allow-methods", "get, post, options"}, // 77
    {"access-control-allow-methods", "options"}, // 78
    {"access-control-expose-headers", "content-length"}, // 79
    {"access-control-request-headers", "content-type"}, // 80
    {"access-control-request-method", "get"}, // 81
    {"access-control-request-method", "post"}, // 82
    {"alt-svc", "clear"}, // 83
    {"authorization", ""}, // 84
    {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"}, // 85
    {"early-data", "1"}, // 86
    {"expect-ct", ""}, // 87
    {"forwarded", ""}, // 88
    {"if-range", ""}, // 89
    {"origin", ""}, // 90
    {"purpose", "prefetch"}, // 91
    {"server", ""}, // 92
    {"timing-allow-origin", "*"}, // 93
    {"upgrade-insecure-requests", "1"}, // 94
    {"user-agent", ""}, // 95
    {"x-forwarded-for", ""}, // 96
    {"x-frame-options", "deny"}, // 97
    {"x-frame-options", "sameorigin"}, // 98
}};

// QPACK uses the RFC 7541 Appendix B Huffman alphabet. Kept local so
// HTTP/3 has no dependency on the stateful HTTP/2 compression implementation.
struct huffman_code { std::uint32_t code; std::uint8_t bits; };
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


constexpr auto byte(std::byte value) noexcept -> unsigned
{ return std::to_integer<unsigned>(value); }

// Accept redundant continuation encodings, but bound integers to uint64_t and
// ten continuation octets so malicious zero runs cannot consume unbounded work.
auto read_integer(std::span<const std::byte> input, std::size_t& cursor,
    unsigned prefix) noexcept -> std::expected<std::uint64_t, qpack_error>
{
    if (cursor == input.size()) return std::unexpected(qpack_error::invalid);
    const auto mask = (1u << prefix) - 1;
    std::uint64_t value = byte(input[cursor++]) & mask;
    if (value < mask) return value;
    for (unsigned shift = 0; shift <= 63; shift += 7) {
        if (cursor == input.size()) return std::unexpected(qpack_error::invalid);
        const auto octet = byte(input[cursor++]);
        const std::uint64_t part = octet & 127u;
        if (part > ((std::numeric_limits<std::uint64_t>::max() - value) >> shift))
            return std::unexpected(qpack_error::invalid);
        value += part << shift;
        if ((octet & 128u) == 0) return value;
    }
    return std::unexpected(qpack_error::invalid);
}

auto write_integer(std::span<std::byte> output, std::size_t& cursor,
    unsigned pattern, unsigned prefix, std::uint64_t value) noexcept -> bool
{
    const auto put = [&](unsigned octet) {
        if (cursor == output.size()) return false;
        output[cursor++] = static_cast<std::byte>(octet);
        return true;
    };
    const auto mask = (1u << prefix) - 1;
    if (value < mask) return put(pattern | static_cast<unsigned>(value));
    if (!put(pattern | mask)) return false;
    value -= mask;
    while (value >= 128) {
        if (!put(128u | static_cast<unsigned>(value & 127u))) return false;
        value >>= 7;
    }
    return put(static_cast<unsigned>(value));
}

auto write_string(std::span<std::byte> output, std::size_t& cursor,
    std::string_view value, unsigned pattern = 0, unsigned prefix = 7) noexcept -> bool
{
    if (!write_integer(output, cursor, pattern, prefix, value.size()) ||
        value.size() > output.size() - cursor) return false;
    for (const auto ch : value) output[cursor++] = static_cast<std::byte>(static_cast<unsigned char>(ch));
    return true;
}

auto read_string(std::span<const std::byte> input, std::size_t& cursor,
    unsigned prefix, unsigned huffman_bit, std::span<char> storage,
    std::size_t& used) noexcept -> std::expected<std::string_view, qpack_error>
{
    if (cursor == input.size()) return std::unexpected(qpack_error::invalid);
    const bool huffman = (byte(input[cursor]) & huffman_bit) != 0;
    const auto length = read_integer(input, cursor, prefix);
    if (!length || *length > input.size() - cursor)
        return std::unexpected(qpack_error::invalid);
    const auto data = input.subspan(cursor, static_cast<std::size_t>(*length));
    cursor += data.size();
    const auto start = used;
    if (!huffman) {
        if (data.size() > storage.size() - used)
            return std::unexpected(qpack_error::limit_exceeded);
        for (auto octet : data) storage[used++] = static_cast<char>(byte(octet));
    } else {
        static const huffman_tree tree;
        std::uint16_t node = 0;
        unsigned pending = 0;
        bool pending_ones = true;
        for (auto octet : data) for (int shift = 7; shift >= 0; --shift) {
            const auto bit = (byte(octet) >> shift) & 1u;
            node = tree.nodes[node].child[bit];
            if (node == 0) return std::unexpected(qpack_error::invalid);
            ++pending;
            pending_ones &= bit != 0;
            const auto symbol = tree.nodes[node].symbol;
            if (symbol < 0) continue;
            if (symbol == 256) return std::unexpected(qpack_error::invalid);
            if (used == storage.size()) return std::unexpected(qpack_error::limit_exceeded);
            storage[used++] = static_cast<char>(symbol);
            node = 0; pending = 0; pending_ones = true;
        }
        if (pending > 7 || !pending_ones) return std::unexpected(qpack_error::invalid);
    }
    if (used == start) return std::string_view {};
    return std::string_view(storage.data() + start, used - start);
}

auto charge_field(const field& value, std::size_t& total) noexcept -> bool
{
    if (32 > qpack_max_field_list_size - total) return false;
    total += 32;
    if (value.name.size() > qpack_max_field_list_size - total) return false;
    total += value.name.size();
    if (value.value.size() > qpack_max_field_list_size - total) return false;
    total += value.value.size();
    return true;
}
} // namespace

auto qpack_encode(std::span<const field> fields, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, qpack_error>
{
    if (fields.size() > qpack_max_fields) return std::unexpected(qpack_error::limit_exceeded);
    std::size_t total = 0;
    for (const auto& f : fields) if (!charge_field(f, total))
        return std::unexpected(qpack_error::limit_exceeded);
    output = output.first(std::min(output.size(), qpack_max_block_size));
    std::size_t cursor = 0;
    if (!write_integer(output, cursor, 0, 8, 0) || !write_integer(output, cursor, 0, 7, 0))
        return std::unexpected(qpack_error::limit_exceeded);
    for (const auto& f : fields) {
        std::size_t name_index = static_table.size(), exact = static_table.size();
        for (std::size_t i = 0; i < static_table.size(); ++i) {
            if (static_table[i].name != f.name) continue;
            if (name_index == static_table.size()) name_index = i;
            if (static_table[i].value == f.value) { exact = i; break; }
        }
        if (exact != static_table.size()) {
            if (!write_integer(output, cursor, 0xc0, 6, exact))
                return std::unexpected(qpack_error::limit_exceeded);
            continue;
        }
        if (name_index != static_table.size()) {
            if (!write_integer(output, cursor, 0x50, 4, name_index))
                return std::unexpected(qpack_error::limit_exceeded);
        } else if (!write_string(output, cursor, f.name, 0x20, 3))
            return std::unexpected(qpack_error::limit_exceeded);
        if (!write_string(output, cursor, f.value))
            return std::unexpected(qpack_error::limit_exceeded);
    }
    return cursor;
}

auto qpack_decode(std::span<const std::byte> block, std::span<field> output,
    std::span<char> string_storage) noexcept -> std::expected<std::size_t, qpack_error>
{
    if (block.size() > qpack_max_block_size) return std::unexpected(qpack_error::limit_exceeded);
    string_storage = string_storage.first(std::min(string_storage.size(), qpack_max_field_list_size));
    std::size_t cursor = 0, count = 0, used = 0, total = 0;
    const auto required = read_integer(block, cursor, 8);
    if (!required) return std::unexpected(required.error());
    if (*required != 0) return std::unexpected(qpack_error::dynamic_table_disabled);
    if (cursor == block.size()) return std::unexpected(qpack_error::invalid);
    const bool negative = (byte(block[cursor]) & 128u) != 0;
    const auto delta = read_integer(block, cursor, 7);
    if (!delta || negative) return std::unexpected(qpack_error::invalid);
    // Static-only sections may use any nonnegative Base (RFC 9204 4.5.1.2).
    while (cursor != block.size()) {
        if (count == output.size() || count == qpack_max_fields)
            return std::unexpected(qpack_error::limit_exceeded);
        field f;
        const auto first = byte(block[cursor]);
        if (first & 0x80u) {
            if (!(first & 0x40u)) return std::unexpected(qpack_error::dynamic_table_disabled);
            const auto index = read_integer(block, cursor, 6);
            if (!index || *index >= static_table.size()) return std::unexpected(qpack_error::invalid);
            f = static_table[static_cast<std::size_t>(*index)];
        } else if (first & 0x40u) {
            if (!(first & 0x10u)) return std::unexpected(qpack_error::dynamic_table_disabled);
            const auto index = read_integer(block, cursor, 4);
            if (!index || *index >= static_table.size()) return std::unexpected(qpack_error::invalid);
            f.name = static_table[static_cast<std::size_t>(*index)].name;
            const auto value = read_string(block, cursor, 7, 0x80, string_storage, used);
            if (!value) return std::unexpected(value.error());
            f.value = *value;
        } else if (first & 0x20u) {
            const auto name = read_string(block, cursor, 3, 0x08, string_storage, used);
            if (!name) return std::unexpected(name.error());
            f.name = *name;
            const auto value = read_string(block, cursor, 7, 0x80, string_storage, used);
            if (!value) return std::unexpected(value.error());
            f.value = *value;
        } else return std::unexpected(qpack_error::dynamic_table_disabled);
        if (!charge_field(f, total)) return std::unexpected(qpack_error::limit_exceeded);
        output[count++] = f;
    }
    return count;
}

auto qpack_validate_encoder_instructions(std::span<const std::byte> instructions) noexcept
    -> std::expected<void, qpack_error>
{
    if (instructions.size() > qpack_max_block_size)
        return std::unexpected(qpack_error::limit_exceeded);
    for (std::size_t cursor = 0; cursor != instructions.size();) {
        if ((byte(instructions[cursor]) & 0xe0u) != 0x20u)
            return std::unexpected(qpack_error::dynamic_table_disabled);
        const auto capacity = read_integer(instructions, cursor, 5);
        if (!capacity) return std::unexpected(capacity.error());
        if (*capacity != 0) return std::unexpected(qpack_error::dynamic_table_disabled);
    }
    return {};
}
} // namespace eventloop::http3::detail
