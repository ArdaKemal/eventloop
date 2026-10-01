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
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace {
using namespace eventloop;

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
    value = std::to_integer<unsigned>(bytes[pos++]) & prefix;
    if (value < prefix) return true;
    unsigned shift = 0;
    while (pos < bytes.size() && shift < 28) {
        const auto byte = std::to_integer<unsigned>(bytes[pos++]);
        value += (byte & 127u) << shift;
        if (!(byte & 128u)) return true;
        shift += 7;
    }
    return false;
}

auto qpack_status(std::span<const std::byte> header) -> unsigned
{
    // Bounded static-table status decoding. Other fields are ignored, and a
    // dynamic reference or arbitrary Huffman value remains unsupported.
    if (header.size() < 3 || header[0] != std::byte{} || header[1] != std::byte{}) return 0;
    std::size_t pos = 2;
    const auto first = std::to_integer<unsigned>(header[pos]);
    unsigned index {};
    if ((first & 0xc0u) == 0xc0u) {
        if (!qpack_integer(header, pos, 6, index)) return 0;
        switch (index) {
        case 25: return 200; case 26: return 304; case 27: return 404;
        case 28: return 503; case 63: return 100; case 64: return 204;
        case 65: return 206; case 66: return 302; case 67: return 400;
        case 68: return 403; case 69: return 421; case 70: return 425;
        case 71: return 500; default: return 0;
        }
    }
    if ((first & 0xf0u) != 0x50u || !qpack_integer(header, pos, 4, index) || index != 24 ||
        pos == header.size()) return 0;
    const bool huffman = (std::to_integer<unsigned>(header[pos]) & 0x80u) != 0;
    unsigned length {};
    if (!qpack_integer(header, pos, 7, length) || length > header.size() - pos) return 0;
    const auto value = header.subspan(pos, length);
    unsigned status = 0;
    if (!huffman) {
        if (value.size() != 3) return 0;
        for (const auto byte : value) {
            const auto digit = std::to_integer<unsigned>(byte);
            if (digit < '0' || digit > '9') return 0;
            status = status * 10 + digit - '0';
        }
    } else {
        // RFC 7541 Appendix B codes for decimal digits. Status has exactly
        // three digits, so the remainder must be all-one padding.
        const std::array<unsigned, 10> codes {0, 1, 2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
        const std::array<unsigned, 10> widths {5, 5, 5, 6, 6, 6, 6, 6, 6, 6};
        std::uint64_t bits = 0;
        if (value.size() > 4) return 0;
        for (auto byte : value) bits = (bits << 8) | std::to_integer<unsigned>(byte);
        unsigned left = static_cast<unsigned>(value.size() * 8);
        for (unsigned i = 0; i < 3; ++i) {
            bool found = false;
            for (unsigned digit = 0; digit < 10; ++digit) {
                if (left < widths[digit]) continue;
                if (((bits >> (left - widths[digit])) & ((1u << widths[digit]) - 1)) == codes[digit]) {
                    status = status * 10 + digit; left -= widths[digit]; found = true; break;
                }
            }
            if (!found) return 0;
        }
        if (left > 7 || (bits & ((1u << left) - 1)) != ((1u << left) - 1)) return 0;
    }
    return status >= 100 && status <= 599 ? status : 0;
}

auto exchange(event_loop& loop, quic_connection& connection, const http_client_example::url_parts& url,
              std::FILE* output, unsigned& final_status) -> task<bool>
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
    if (!literal(":method", "GET", fields) || !literal(":scheme", "https", fields) ||
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
    bool have_status = false;
    std::uint64_t body_count = 0;
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
                const auto status = qpack_status(payload);
                if (!status) {
                    std::cerr << "HTTP/3 QPACK status representation unsupported (prefix";
                    for (auto byte : payload.first(std::min<std::size_t>(payload.size(), 8)))
                        std::cerr << ' ' << std::hex << std::to_integer<unsigned>(byte) << std::dec;
                    std::cerr << ")\n"; co_return false;
                }
                std::cerr << "HTTP/3 " << status << '\n'; have_status = true; final_status = status;
            } else if (type == 0) {
                if (!have_status || body_count > 16 * 1024 * 1024 - length) co_return false;
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
    co_return true;
}
} // namespace

auto fetch_http3(event_loop& loop, const http_client_example::url_parts& url,
                 const request_options& options, std::FILE* output,
                 request_state& state, bool& success, unsigned& final_status) -> task<void>
{
    auto addresses = co_await run_blocking(loop, [host = url.hostname, port = url.port]() noexcept {
        return http_client_example::resolve_addresses(host, port);
    });
    if (!addresses || addresses->error || addresses->count == 0) { std::cerr << "HTTP/3 DNS lookup failed\n"; co_return; }
    constexpr std::array<std::uint8_t, 2> alpn {'h', '3'};
    for (std::size_t i = 0; i < addresses->count && !state.expired; ++i) {
        const auto remote = addresses->endpoints[i];
        const auto local = remote.address_family == ip_endpoint::family::ipv4 ? ip_endpoint::any_v4() : ip_endpoint::any_v6();
        quic_client_options config;
        config.alpn = alpn; config.version = options.quic_version; config.trusted_ca = options.ca_file;
        quic_endpoint endpoint(loop, local, config);
        state.endpoint = &endpoint;
        auto connected = flatten(co_await endpoint.async_connect(remote, url.hostname));
        if (!connected) {
            std::cerr << "HTTP/3 connect failed: " << connected.error().message() << '\n';
            (void)co_await endpoint.async_close(); state.endpoint = nullptr;
            continue;
        }
        auto connection = std::move(*connected);
        const auto done = co_await exchange(loop, connection, url, output, final_status);
        success = done && *done;
        if (!done) std::cerr << "HTTP/3 request coroutine unavailable or cancelled\n";
        connection.close();
        (void)co_await endpoint.async_close(); state.endpoint = nullptr;
        co_return;
    }
}
