#include "http3.h"
#include "options.h"
#include "http_client_resolve.h"

#include "eventloop/quic.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <netdb.h>
#endif

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <stdexcept>
#include <cctype>
#include <unordered_set>
#include <vector>

namespace {
using namespace eventloop;
using http_client_example::url_parts;

struct huffman_code { std::uint32_t code; unsigned bits; };
// RFC 7541 Appendix B, also used by QPACK.
constexpr std::array<huffman_code, 257> huffman_codes {{
    {0x1ff8, 13},
    {0x7fffd8, 23},
    {0xfffffe2, 28},
    {0xfffffe3, 28},
    {0xfffffe4, 28},
    {0xfffffe5, 28},
    {0xfffffe6, 28},
    {0xfffffe7, 28},
    {0xfffffe8, 28},
    {0xffffea, 24},
    {0x3ffffffc, 30},
    {0xfffffe9, 28},
    {0xfffffea, 28},
    {0x3ffffffd, 30},
    {0xfffffeb, 28},
    {0xfffffec, 28},
    {0xfffffed, 28},
    {0xfffffee, 28},
    {0xfffffef, 28},
    {0xffffff0, 28},
    {0xffffff1, 28},
    {0xffffff2, 28},
    {0x3ffffffe, 30},
    {0xffffff3, 28},
    {0xffffff4, 28},
    {0xffffff5, 28},
    {0xffffff6, 28},
    {0xffffff7, 28},
    {0xffffff8, 28},
    {0xffffff9, 28},
    {0xffffffa, 28},
    {0xffffffb, 28},
    {0x14, 6},
    {0x3f8, 10},
    {0x3f9, 10},
    {0xffa, 12},
    {0x1ff9, 13},
    {0x15, 6},
    {0xf8, 8},
    {0x7fa, 11},
    {0x3fa, 10},
    {0x3fb, 10},
    {0xf9, 8},
    {0x7fb, 11},
    {0xfa, 8},
    {0x16, 6},
    {0x17, 6},
    {0x18, 6},
    {0x0, 5},
    {0x1, 5},
    {0x2, 5},
    {0x19, 6},
    {0x1a, 6},
    {0x1b, 6},
    {0x1c, 6},
    {0x1d, 6},
    {0x1e, 6},
    {0x1f, 6},
    {0x5c, 7},
    {0xfb, 8},
    {0x7ffc, 15},
    {0x20, 6},
    {0xffb, 12},
    {0x3fc, 10},
    {0x1ffa, 13},
    {0x21, 6},
    {0x5d, 7},
    {0x5e, 7},
    {0x5f, 7},
    {0x60, 7},
    {0x61, 7},
    {0x62, 7},
    {0x63, 7},
    {0x64, 7},
    {0x65, 7},
    {0x66, 7},
    {0x67, 7},
    {0x68, 7},
    {0x69, 7},
    {0x6a, 7},
    {0x6b, 7},
    {0x6c, 7},
    {0x6d, 7},
    {0x6e, 7},
    {0x6f, 7},
    {0x70, 7},
    {0x71, 7},
    {0x72, 7},
    {0xfc, 8},
    {0x73, 7},
    {0xfd, 8},
    {0x1ffb, 13},
    {0x7fff0, 19},
    {0x1ffc, 13},
    {0x3ffc, 14},
    {0x22, 6},
    {0x7ffd, 15},
    {0x3, 5},
    {0x23, 6},
    {0x4, 5},
    {0x24, 6},
    {0x5, 5},
    {0x25, 6},
    {0x26, 6},
    {0x27, 6},
    {0x6, 5},
    {0x74, 7},
    {0x75, 7},
    {0x28, 6},
    {0x29, 6},
    {0x2a, 6},
    {0x7, 5},
    {0x2b, 6},
    {0x76, 7},
    {0x2c, 6},
    {0x8, 5},
    {0x9, 5},
    {0x2d, 6},
    {0x77, 7},
    {0x78, 7},
    {0x79, 7},
    {0x7a, 7},
    {0x7b, 7},
    {0x7ffe, 15},
    {0x7fc, 11},
    {0x3ffd, 14},
    {0x1ffd, 13},
    {0xffffffc, 28},
    {0xfffe6, 20},
    {0x3fffd2, 22},
    {0xfffe7, 20},
    {0xfffe8, 20},
    {0x3fffd3, 22},
    {0x3fffd4, 22},
    {0x3fffd5, 22},
    {0x7fffd9, 23},
    {0x3fffd6, 22},
    {0x7fffda, 23},
    {0x7fffdb, 23},
    {0x7fffdc, 23},
    {0x7fffdd, 23},
    {0x7fffde, 23},
    {0xffffeb, 24},
    {0x7fffdf, 23},
    {0xffffec, 24},
    {0xffffed, 24},
    {0x3fffd7, 22},
    {0x7fffe0, 23},
    {0xffffee, 24},
    {0x7fffe1, 23},
    {0x7fffe2, 23},
    {0x7fffe3, 23},
    {0x7fffe4, 23},
    {0x1fffdc, 21},
    {0x3fffd8, 22},
    {0x7fffe5, 23},
    {0x3fffd9, 22},
    {0x7fffe6, 23},
    {0x7fffe7, 23},
    {0xffffef, 24},
    {0x3fffda, 22},
    {0x1fffdd, 21},
    {0xfffe9, 20},
    {0x3fffdb, 22},
    {0x3fffdc, 22},
    {0x7fffe8, 23},
    {0x7fffe9, 23},
    {0x1fffde, 21},
    {0x7fffea, 23},
    {0x3fffdd, 22},
    {0x3fffde, 22},
    {0xfffff0, 24},
    {0x1fffdf, 21},
    {0x3fffdf, 22},
    {0x7fffeb, 23},
    {0x7fffec, 23},
    {0x1fffe0, 21},
    {0x1fffe1, 21},
    {0x3fffe0, 22},
    {0x1fffe2, 21},
    {0x7fffed, 23},
    {0x3fffe1, 22},
    {0x7fffee, 23},
    {0x7fffef, 23},
    {0xfffea, 20},
    {0x3fffe2, 22},
    {0x3fffe3, 22},
    {0x3fffe4, 22},
    {0x7ffff0, 23},
    {0x3fffe5, 22},
    {0x3fffe6, 22},
    {0x7ffff1, 23},
    {0x3ffffe0, 26},
    {0x3ffffe1, 26},
    {0xfffeb, 20},
    {0x7fff1, 19},
    {0x3fffe7, 22},
    {0x7ffff2, 23},
    {0x3fffe8, 22},
    {0x1ffffec, 25},
    {0x3ffffe2, 26},
    {0x3ffffe3, 26},
    {0x3ffffe4, 26},
    {0x7ffffde, 27},
    {0x7ffffdf, 27},
    {0x3ffffe5, 26},
    {0xfffff1, 24},
    {0x1ffffed, 25},
    {0x7fff2, 19},
    {0x1fffe3, 21},
    {0x3ffffe6, 26},
    {0x7ffffe0, 27},
    {0x7ffffe1, 27},
    {0x3ffffe7, 26},
    {0x7ffffe2, 27},
    {0xfffff2, 24},
    {0x1fffe4, 21},
    {0x1fffe5, 21},
    {0x3ffffe8, 26},
    {0x3ffffe9, 26},
    {0xffffffd, 28},
    {0x7ffffe3, 27},
    {0x7ffffe4, 27},
    {0x7ffffe5, 27},
    {0xfffec, 20},
    {0xfffff3, 24},
    {0xfffed, 20},
    {0x1fffe6, 21},
    {0x3fffe9, 22},
    {0x1fffe7, 21},
    {0x1fffe8, 21},
    {0x7ffff3, 23},
    {0x3fffea, 22},
    {0x3fffeb, 22},
    {0x1ffffee, 25},
    {0x1ffffef, 25},
    {0xfffff4, 24},
    {0xfffff5, 24},
    {0x3ffffea, 26},
    {0x7ffff4, 23},
    {0x3ffffeb, 26},
    {0x7ffffe6, 27},
    {0x3ffffec, 26},
    {0x3ffffed, 26},
    {0x7ffffe7, 27},
    {0x7ffffe8, 27},
    {0x7ffffe9, 27},
    {0x7ffffea, 27},
    {0x7ffffeb, 27},
    {0xffffffe, 28},
    {0x7ffffec, 27},
    {0x7ffffed, 27},
    {0x7ffffee, 27},
    {0x7ffffef, 27},
    {0x7fffff0, 27},
    {0x3ffffee, 26},
    {0x3fffffff, 30}
}};
struct static_field { std::string_view name; std::string_view value; };
// RFC 9204 Appendix A.
constexpr std::array<static_field, 99> static_fields {{
    {":authority", ""},
    {":path", "/"},
    {"age", "0"},
    {"content-disposition", ""},
    {"content-length", "0"},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"referer", ""},
    {"set-cookie", ""},
    {":method", "CONNECT"},
    {":method", "DELETE"},
    {":method", "GET"},
    {":method", "HEAD"},
    {":method", "OPTIONS"},
    {":method", "POST"},
    {":method", "PUT"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "103"},
    {":status", "200"},
    {":status", "304"},
    {":status", "404"},
    {":status", "503"},
    {"accept", "*/*"},
    {"accept", "application/dns-message"},
    {"accept-encoding", "gzip, deflate, br"},
    {"accept-ranges", "bytes"},
    {"access-control-allow-headers", "cache-control"},
    {"access-control-allow-headers", "content-type"},
    {"access-control-allow-origin", "*"},
    {"cache-control", "max-age=0"},
    {"cache-control", "max-age=2592000"},
    {"cache-control", "max-age=604800"},
    {"cache-control", "no-cache"},
    {"cache-control", "no-store"},
    {"cache-control", "public, max-age=31536000"},
    {"content-encoding", "br"},
    {"content-encoding", "gzip"},
    {"content-type", "application/dns-message"},
    {"content-type", "application/javascript"},
    {"content-type", "application/json"},
    {"content-type", "application/x-www-form-urlencoded"},
    {"content-type", "image/gif"},
    {"content-type", "image/jpeg"},
    {"content-type", "image/png"},
    {"content-type", "text/css"},
    {"content-type", "text/html; charset=utf-8"},
    {"content-type", "text/plain"},
    {"content-type", "text/plain;charset=utf-8"},
    {"range", "bytes=0-"},
    {"strict-transport-security", "max-age=31536000"},
    {"strict-transport-security", "max-age=31536000; includesubdomains"},
    {"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
    {"vary", "accept-encoding"},
    {"vary", "origin"},
    {"x-content-type-options", "nosniff"},
    {"x-xss-protection", "1; mode=block"},
    {":status", "100"},
    {":status", "204"},
    {":status", "206"},
    {":status", "302"},
    {":status", "400"},
    {":status", "403"},
    {":status", "421"},
    {":status", "425"},
    {":status", "500"},
    {"accept-language", ""},
    {"access-control-allow-credentials", "FALSE"},
    {"access-control-allow-credentials", "TRUE"},
    {"access-control-allow-headers", "*"},
    {"access-control-allow-methods", "get"},
    {"access-control-allow-methods", "get, post, options"},
    {"access-control-allow-methods", "options"},
    {"access-control-expose-headers", "content-length"},
    {"access-control-request-headers", "content-type"},
    {"access-control-request-method", "get"},
    {"access-control-request-method", "post"},
    {"alt-svc", "clear"},
    {"authorization", ""},
    {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
    {"early-data", "1"},
    {"expect-ct", ""},
    {"forwarded", ""},
    {"if-range", ""},
    {"origin", ""},
    {"purpose", "prefetch"},
    {"server", ""},
    {"timing-allow-origin", "*"},
    {"upgrade-insecure-requests", "1"},
    {"user-agent", ""},
    {"x-forwarded-for", ""},
    {"x-frame-options", "deny"},
    {"x-frame-options", "sameorigin"}
}};


template<class T>
auto flatten(std::expected<std::expected<T, std::error_code>, task_result> result) -> std::expected<T, std::error_code>
{
    if (result) return std::move(*result);
    return std::unexpected(std::make_error_code(result.error() == task_result::frame_allocation_failure
        ? std::errc::not_enough_memory : std::errc::operation_canceled));
}

auto varint(std::uint64_t value, std::vector<std::byte>& output) -> bool
{
    if (value < 64) output.push_back(static_cast<std::byte>(value));
    else if (value < 16384) {
        output.push_back(static_cast<std::byte>(0x40 | (value >> 8)));
        output.push_back(static_cast<std::byte>(value & 255));
    } else if (value < (1u << 30)) {
        output.push_back(static_cast<std::byte>(0x80 | (value >> 24)));
        for (int shift : {16, 8, 0}) output.push_back(static_cast<std::byte>((value >> shift) & 255));
    } else return false;
    return true;
}

auto read_varint(std::span<const std::byte> bytes, std::size_t& pos, std::uint64_t& result) -> bool
{
    if (pos == bytes.size()) return false;
    const auto first = std::to_integer<unsigned>(bytes[pos]);
    const auto n = 1u << (first >> 6);
    if (n > bytes.size() - pos) return false;
    result = first & 0x3f;
    for (unsigned i = 1; i < n; ++i) result = (result << 8) | std::to_integer<unsigned>(bytes[pos + i]);
    pos += n;
    return true;
}

auto prefixed(std::uint64_t value, unsigned prefix_bits, unsigned marker, std::vector<std::byte>& output) -> bool
{
    const auto prefix = (1u << prefix_bits) - 1;
    if (value < prefix) { output.push_back(static_cast<std::byte>(marker | value)); return true; }
    output.push_back(static_cast<std::byte>(marker | prefix));
    value -= prefix;
    while (value >= 128) {
        output.push_back(static_cast<std::byte>((value & 127) | 128)); value >>= 7;
    }
    output.push_back(static_cast<std::byte>(value));
    return true;
}

auto literal(std::string_view name, std::string_view value, std::vector<std::byte>& output) -> bool
{
    if (name.size() > 512 || value.size() > 2048) return false;
    prefixed(name.size(), 3, 0x20, output); // QPACK literal name, no Huffman.
    for (char ch : name) output.push_back(static_cast<std::byte>(ch));
    prefixed(value.size(), 7, 0, output);
    for (char ch : value) output.push_back(static_cast<std::byte>(ch));
    return true;
}

auto frame(std::uint64_t type, std::span<const std::byte> payload, std::vector<std::byte>& output) -> bool
{
    return varint(type, output) && varint(payload.size(), output) &&
        (output.insert(output.end(), payload.begin(), payload.end()), true);
}

auto qpack_integer(std::span<const std::byte> bytes, std::size_t& pos, unsigned bits, unsigned& value) -> bool
{
    if (pos == bytes.size()) return false;
    const auto prefix = (1u << bits) - 1;
    std::uint64_t decoded = std::to_integer<unsigned>(bytes[pos++]) & prefix;
    if (decoded < prefix) { value = static_cast<unsigned>(decoded); return true; }
    unsigned shift = 0;
    while (pos < bytes.size() && shift < 35) {
        const auto byte = std::to_integer<unsigned>(bytes[pos++]);
        decoded += static_cast<std::uint64_t>(byte & 127u) << shift;
        if (decoded > 65536) return false;
        if (!(byte & 128u)) { value = static_cast<unsigned>(decoded); return true; }
        shift += 7;
    }
    return false;
}

auto decode_huffman(std::span<const std::byte> encoded, std::string& output) -> bool
{
    struct node { int child[2] {-1, -1}; int symbol {-1}; };
    static const auto tree = [] {
        std::array<node, 8192> nodes {};
        std::size_t used = 1;
        for (unsigned symbol = 0; symbol < huffman_codes.size(); ++symbol) {
            const auto [code, bits] = huffman_codes[symbol];
            int current = 0;
            for (unsigned bit = bits; bit != 0; --bit) {
                const auto direction = static_cast<unsigned>((code >> (bit - 1)) & 1u);
                if (nodes[static_cast<std::size_t>(current)].child[direction] < 0)
                    nodes[static_cast<std::size_t>(current)].child[direction] = static_cast<int>(used++);
                current = nodes[static_cast<std::size_t>(current)].child[direction];
            }
            nodes[static_cast<std::size_t>(current)].symbol = static_cast<int>(symbol);
        }
        return nodes;
    }();
    int current = 0;
    unsigned pending_bits = 0, padding = 0;
    for (const auto byte : encoded) {
        const auto value = std::to_integer<unsigned>(byte);
        for (int bit = 7; bit >= 0; --bit) {
            const auto direction = (value >> bit) & 1u;
            current = tree[static_cast<std::size_t>(current)].child[direction];
            if (current < 0) return false;
            ++pending_bits;
            padding = (padding << 1 | direction) & 0x7fu;
            const int symbol = tree[static_cast<std::size_t>(current)].symbol;
            if (symbol >= 0) {
                if (symbol == 256 || output.size() == 65536) return false;
                output.push_back(static_cast<char>(symbol));
                current = 0; pending_bits = 0; padding = 0;
            }
        }
    }
    return pending_bits <= 7 && padding == ((1u << pending_bits) - 1);
}

auto qpack_string(std::span<const std::byte> bytes, std::size_t& pos,
                  unsigned bits, unsigned huffman_mask, std::string& value) -> bool
{
    if (pos == bytes.size()) return false;
    const bool huffman = (std::to_integer<unsigned>(bytes[pos]) & huffman_mask) != 0;
    unsigned length {};
    if (!qpack_integer(bytes, pos, bits, length) || length > bytes.size() - pos) return false;
    const auto encoded = bytes.subspan(pos, length);
    pos += length;
    if (huffman) return decode_huffman(encoded, value);
    if (encoded.empty()) value.clear();
    else value.assign(reinterpret_cast<const char*>(encoded.data()), encoded.size());
    return true;
}

auto safe_field(std::string_view value, bool name) -> bool
{
    return std::all_of(value.begin(), value.end(), [name](unsigned char c) {
        return name ? (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) != std::string_view::npos
            : (c >= 0x20 && c != 0x7f) || c == '\t';
    });
}

struct response_headers {
    unsigned status {};
    std::string location;
    std::optional<std::uint64_t> content_length;
    bool informational {};
};

auto decode_headers(std::span<const std::byte> bytes, response_headers& result,
                    bool show_headers, std::FILE* output) -> bool
{
    if (bytes.size() < 3 || bytes[0] != std::byte{} || bytes[1] != std::byte{}) {
        std::cerr << "HTTP/3 dynamic QPACK field section unsupported\n"; return false;
    }
    std::size_t pos = 2, count = 0, decoded_size = 0;
    std::string printed;
    while (pos < bytes.size()) {
        if (++count > 128) { std::cerr << "HTTP/3 response exceeds 128 fields\n"; return false; }
        const auto first = std::to_integer<unsigned>(bytes[pos]);
        unsigned index {};
        std::string name, value;
        if ((first & 0xc0u) == 0xc0u) {
            if (!qpack_integer(bytes, pos, 6, index) || index >= static_fields.size()) return false;
            name = static_fields[index].name; value = static_fields[index].value;
        } else if ((first & 0xd0u) == 0x50u) {
            if (!qpack_integer(bytes, pos, 4, index) || index >= static_fields.size()) return false;
            name = static_fields[index].name;
            if (!qpack_string(bytes, pos, 7, 0x80, value)) return false;
        } else if ((first & 0xe0u) == 0x20u) {
            if (!qpack_string(bytes, pos, 3, 0x08, name) ||
                !qpack_string(bytes, pos, 7, 0x80, value)) return false;
        } else {
            std::cerr << "HTTP/3 dynamic or unsupported QPACK field form\n"; return false;
        }
        if (name.empty() || !safe_field(name, name.front() != ':') || !safe_field(value, false) ||
            name.size() + value.size() > 65536 - decoded_size) return false;
        decoded_size += name.size() + value.size();
        if (name == ":status") {
            if (count != 1 || value.size() != 3 ||
                !std::all_of(value.begin(), value.end(), [](unsigned char c) { return c >= '0' && c <= '9'; }))
                return false;
            result.status = static_cast<unsigned>((value[0] - '0') * 100 + (value[1] - '0') * 10 + value[2] - '0');
            if (result.status < 100 || result.status > 599) return false;
        } else {
            if (name.front() == ':') return false;
            if (name == "location" && result.location.empty()) result.location = value;
            if (name == "content-length") {
                std::uint64_t length {};
                const auto parsed = std::from_chars(value.data(),
                    value.data() + value.size(), length);
                if (value.empty() || parsed.ec != std::errc{} ||
                    parsed.ptr != value.data() + value.size() || result.content_length)
                    return false;
                result.content_length = length;
            }
            if (show_headers) printed += name + ": " + value + "\r\n";
        }
    }
    if (result.status == 0) return false;
    result.informational = result.status < 200;
    if (show_headers) {
        const auto line = "HTTP/3 " + std::to_string(result.status) + "\r\n" + printed + "\r\n";
        if (std::fwrite(line.data(), 1, line.size(), output) != line.size()) return false;
    }
    return true;
}

auto exchange(event_loop& loop, quic_connection& connection, const http_client_example::url_parts& url,
              const request_options& options, std::FILE* output,
              unsigned& final_status, std::string& location) -> task<bool>
{
    (void)loop;
    const std::array<std::byte, 3> settings {std::byte{0}, std::byte{4}, std::byte{0}};
    for (unsigned type = 0; type < 3; ++type) {
        const auto opened = flatten(co_await connection.async_open_stream(quic_stream_direction::unidirectional));
        if (!opened) { std::cerr << "HTTP/3 open control stream failed: " << opened.error().message() << '\n'; co_return false; }
        if (type == 0) {
            const auto written = flatten(co_await connection.async_write(*opened, settings, false));
            if (!written) co_return false;
        } else {
            const std::array<std::byte, 1> kind {static_cast<std::byte>(type + 1)};
            const auto written = flatten(co_await connection.async_write(*opened, kind, false));
            if (!written) co_return false;
        }
    }
    std::vector<std::byte> fields {std::byte{0}, std::byte{0}};
    if (!literal(":method", options.method, fields) || !literal(":scheme", "https", fields) ||
        !literal(":authority", url.host_header, fields) || !literal(":path", url.target, fields) ||
        !literal("user-agent", "wayfarer/0.1", fields)) co_return false;
    std::vector<std::byte> request;
    if (!frame(1, fields, request) || request.size() > 4096) co_return false;
    const auto opened = flatten(co_await connection.async_open_stream(quic_stream_direction::bidirectional));
    if (!opened) { std::cerr << "HTTP/3 open request stream failed: " << opened.error().message() << '\n'; co_return false; }
    const auto written = flatten(co_await connection.async_write(*opened, request, true));
    if (!written) { std::cerr << "HTTP/3 request write failed: " << written.error().message() << '\n'; co_return false; }

    std::array<std::byte, 1024> buffer {};
    std::vector<std::byte> incoming;
    incoming.reserve(8192);
    bool have_status = false, redirect_response = false;
    std::uint64_t body_count = 0;
    std::optional<std::uint64_t> expected_length;
    for (;;) {
        const auto received = flatten(co_await connection.async_read(*opened, buffer));
        if (!received) { std::cerr << "HTTP/3 response read failed: " << received.error().message() << '\n'; co_return false; }
        if (*received == 0) break;
        incoming.insert(incoming.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*received));
        // This limited client retains one complete frame up to 64 KiB, then
        // writes DATA to the output. Total response body is capped at 16 MiB.
        for (;;) {
            std::size_t pos = 0;
            std::uint64_t type {}, length {};
            if (!read_varint(incoming, pos, type) || !read_varint(incoming, pos, length)) break;
            if (length > 65536) { std::cerr << "HTTP/3 frame exceeds 64 KiB probe limit\n"; co_return false; }
            if (incoming.size() < pos + length) break;
            const auto payload = std::span<const std::byte>(incoming).subspan(pos, static_cast<std::size_t>(length));
            if (type == 1) {
                if (have_status) { std::cerr << "HTTP/3 trailers unsupported\n"; co_return false; }
                response_headers headers;
                if (!decode_headers(payload, headers, options.show_headers, output)) {
                    std::cerr << "HTTP/3 response HEADERS unsupported or invalid\n"; co_return false;
                }
                std::cerr << "HTTP/3 " << headers.status << '\n';
                if (!headers.informational) {
                    have_status = true; final_status = headers.status;
                    expected_length = headers.content_length;
                    // 204/304 carry no body; any Content-Length describes the
                    // selected representation rather than the received DATA.
                    if (final_status == 204 || final_status == 304) expected_length.reset();
                    location = std::move(headers.location);
                    redirect_response = options.follow_redirects &&
                        (final_status == 301 || final_status == 302 || final_status == 303 ||
                         final_status == 307 || final_status == 308);
                    if (redirect_response) co_return true;
                    // HEAD has no response body. The final HEADERS block is
                    // enough to finish this one-shot request; closing the
                    // connection below cancels any pending stream read.
                    if (options.method == "HEAD") {
                        if (std::fflush(output) != 0) {
                            std::cerr << "HTTP/3 output flush failed\n"; co_return false;
                        }
                        co_return true;
                    }
                }
            } else if (type == 0) {
                if (!have_status || options.method == "HEAD" || final_status == 204 ||
                    final_status == 304) {
                    std::cerr << "HTTP/3 unexpected response DATA\n"; co_return false;
                }
                if (body_count > 16 * 1024 * 1024 - length) {
                    std::cerr << "HTTP/3 response body exceeds 16 MiB\n"; co_return false;
                }
                body_count += length;
                if (std::fwrite(payload.data(), 1, payload.size(), output) != payload.size()) co_return false;
            }
            incoming.erase(incoming.begin(), incoming.begin() + static_cast<std::ptrdiff_t>(pos + length));
        }
        if (incoming.size() > 65544) { std::cerr << "HTTP/3 response buffer exceeded\n"; co_return false; }
    }
    if (!incoming.empty() || !have_status || std::fflush(output) != 0) {
        std::cerr << "HTTP/3 response incomplete\n"; co_return false;
    }
    if (expected_length && body_count != *expected_length) {
        std::cerr << "HTTP/3 response truncated\n"; co_return false;
    }
    co_return true;
}
auto redirect_http3_url(const url_parts& current, std::string_view location) -> url_parts
{
    if (location.empty()) throw std::invalid_argument("empty redirect Location");
    const std::string scheme = current.secure ? "https:" : "http:";
    const std::string origin = scheme + "//" + current.host_header;
    const auto separator = location.find(':');
    const auto path_start = location.find_first_of("/?#");
    if (separator != std::string_view::npos &&
        (path_start == std::string_view::npos || separator < path_start)) {
        std::string absolute(location);
        std::transform(absolute.begin(), absolute.begin() + separator, absolute.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return http_client_example::parse_url(absolute);
    }
    if (location.starts_with("//"))
        return http_client_example::parse_url(scheme + std::string(location));
    if (location.starts_with('/'))
        return http_client_example::parse_url(origin + std::string(location));
    if (location.starts_with('#'))
        return http_client_example::parse_url(origin + current.target + std::string(location));
    if (location.starts_with('?')) {
        const auto question = current.target.find('?');
        return http_client_example::parse_url(origin + current.target.substr(0, question) + std::string(location));
    }
    const auto question = current.target.find('?');
    const auto path = current.target.substr(0, question);
    const auto slash = path.rfind('/');
    std::string combined = path.substr(0, slash + 1) + std::string(location);
    const auto suffix = combined.find_first_of("?#");
    const std::string path_only = combined.substr(0, suffix);
    std::vector<std::string_view> segments;
    std::string_view remainder(path_only);
    while (!remainder.empty()) {
        const auto separator = remainder.find('/', 1);
        const auto segment = remainder.substr(1, separator == std::string_view::npos
            ? std::string_view::npos : separator - 1);
        if (segment == "..") { if (!segments.empty()) segments.pop_back(); }
        else if (segment != "." && !segment.empty()) segments.push_back(segment);
        if (separator == std::string_view::npos) break;
        remainder.remove_prefix(separator);
    }
    std::string normalized = "/";
    for (const auto segment : segments) {
        if (normalized.size() > 1) normalized += '/';
        normalized += segment;
    }
    if (path_only.ends_with('/') || path_only.ends_with("/.") || path_only.ends_with("/..")) {
        if (!normalized.ends_with('/')) normalized += '/';
    }
    if (suffix != std::string::npos) normalized += combined.substr(suffix);
    return http_client_example::parse_url(origin + normalized);
}

} // namespace

auto fetch_http3(event_loop& loop, const http_client_example::url_parts& url,
                 const request_options& options, std::FILE* output,
                 request_state& state, bool& success, unsigned& final_status) -> task<void>
{
    url_parts current = url;
    std::unordered_set<std::string> visited;
    constexpr std::array<std::uint8_t, 2> alpn {'h', '3'};
    for (unsigned hop = 0; hop <= 10 && !state.expired; ++hop) {
        std::string host = current.hostname;
        std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        const std::string identity = host + ':' + std::to_string(current.port) +
            current.target + '\n' + options.method;
        if (!visited.insert(identity).second) {
            std::cerr << "HTTP/3 redirect loop detected\n"; co_return;
        }
        auto addresses = co_await run_blocking(loop, [host = current.hostname, port = current.port]() noexcept {
            return http_client_example::resolve_addresses(host, port);
        });
        if (!addresses || addresses->error || addresses->count == 0) {
            std::cerr << "HTTP/3 DNS lookup failed\n"; co_return;
        }
        bool exchanged = false;
        std::string location;
        for (std::size_t i = 0; i < addresses->count && !state.expired; ++i) {
            const auto remote = addresses->endpoints[i];
            const auto local = remote.address_family == ip_endpoint::family::ipv4
                ? ip_endpoint::any_v4() : ip_endpoint::any_v6();
            quic_client_options config;
            config.alpn = alpn; config.version = options.quic_version; config.trusted_ca = options.ca_file;
            quic_endpoint endpoint(loop, local, config);
            state.endpoint = &endpoint;
            auto connected = flatten(co_await endpoint.async_connect(remote, current.hostname));
            if (!connected) {
                std::cerr << "HTTP/3 connect failed: " << connected.error().message() << '\n';
                (void)co_await endpoint.async_close(); state.endpoint = nullptr;
                continue;
            }
            auto connection = std::move(*connected);
            const auto done = co_await exchange(loop, connection, current, options, output, final_status, location);
            exchanged = done && *done;
            if (!done) std::cerr << "HTTP/3 request coroutine unavailable or cancelled\n";
            connection.close();
            (void)co_await endpoint.async_close(); state.endpoint = nullptr;
            if (!exchanged) co_return;
            break;
        }
        if (!exchanged) {
            if (!state.expired) std::cerr << "HTTP/3 all connection attempts failed\n";
            co_return;
        }
        if (!options.follow_redirects ||
            (final_status != 301 && final_status != 302 && final_status != 303 &&
             final_status != 307 && final_status != 308)) {
            success = true; co_return;
        }
        if (location.empty()) {
            std::cerr << "HTTP/3 redirect response has no Location\n"; co_return;
        }
        if (hop == 10) {
            std::cerr << "HTTP/3 redirect limit of 10 reached\n"; co_return;
        }
        try {
            current = redirect_http3_url(current, location);
        } catch (const std::exception& error) {
            std::cerr << "HTTP/3 redirect failed: " << error.what() << '\n'; co_return;
        }
        if (!current.secure) {
            std::cerr << "HTTP/3 redirect to non-HTTPS URL is unsupported\n"; co_return;
        }
    }
}
