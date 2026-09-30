#include "quic/packet_header.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC packet header: " << message << '\n';
    std::exit(1);
}

template<std::size_t N>
constexpr auto bytes(const std::array<std::uint8_t, N>& input)
    -> std::array<std::byte, N>
{
    std::array<std::byte, N> output {};
    for (std::size_t i = 0; i < N; ++i) output[i] = std::byte {input[i]};
    return output;
}

auto long_headers_and_coalescing() -> void
{
    // v1 Initial: two CIDs, a two-byte token, and three protected bytes.
    constexpr auto datagram = bytes(std::array<std::uint8_t, 28> {
        0xc0, 0, 0, 0, 1, 2, 0xaa, 0xbb, 1, 0xcc,
        2, 0xdd, 0xee, 3, 0x01, 0x02, 0x03,
        // v2 Handshake uses type bits 11, versus 10 in v1.
        0xf0, 0x6b, 0x33, 0x43, 0xcf, 0, 0, 3, 0x11, 0x22, 0x33,
    });
    const auto first = parse_packet_header(datagram);
    check(first && first->kind == packet_kind::initial &&
              first->version == version_1 && first->packet_offset == 0 &&
              first->header_end_offset == 14 && first->packet_end_offset == 17,
          "v1 Initial offsets");
    check(first->packet.size() == 17 && first->destination_cid.size() == 2 &&
              first->destination_cid.data() == datagram.data() + 6 &&
              first->source_cid.data() == datagram.data() + 9 &&
              first->token.size() == 2 &&
              first->token.data() == datagram.data() + 11,
          "CID and token borrow input");
    const auto second = parse_packet_header(datagram, first->packet_end_offset);
    check(second && second->kind == packet_kind::handshake &&
              second->version == version_2 &&
              second->packet_offset == 17 &&
              second->header_end_offset == 25 &&
              second->packet_end_offset == datagram.size(),
          "v2 coalesced Handshake offsets");
    check(parse_packet_header(datagram, datagram.size()).error() ==
              packet_header_error::truncated,
          "end of coalesced datagram");

    constexpr auto zero_rtt = bytes(std::array<std::uint8_t, 10> {
        0xd0, 0, 0, 0, 1, 0, 0, 1, 0x44, 0x55,
    });
    const auto parsed = parse_packet_header(zero_rtt);
    check(parsed && parsed->kind == packet_kind::zero_rtt &&
              parsed->header_end_offset == 8 && parsed->packet_end_offset == 9,
          "v1 0-RTT with trailing packet byte");
}

auto terminal_packets() -> void
{
    constexpr auto negotiation = bytes(std::array<std::uint8_t, 17> {
        0x80, 0, 0, 0, 0, 1, 0xa1, 1, 0xb2,
        0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf,
    });
    const auto vn = parse_packet_header(negotiation);
    check(vn && vn->kind == packet_kind::version_negotiation &&
              vn->version_list.size() == 8 &&
              vn->version_list.data() == negotiation.data() + 9 &&
              vn->packet_end_offset == negotiation.size(),
          "Version Negotiation list and arbitrary fixed bit");

    constexpr auto retry = bytes(std::array<std::uint8_t, 27> {
        0xf0, 0, 0, 0, 1, 1, 0x11, 1, 0x22,
        0xaa, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    });
    const auto r = parse_packet_header(retry);
    check(r && r->kind == packet_kind::retry && r->token.size() == 2 &&
              r->retry_integrity_tag.size() == 16 &&
              r->retry_integrity_tag.data() == retry.data() + 11 &&
              r->packet_end_offset == retry.size(),
          "Retry token and tag");

    constexpr auto short_packet = bytes(std::array<std::uint8_t, 5> {
        0x40, 0xa1, 0xa2, 0x11, 0x22,
    });
    const auto s = parse_packet_header(short_packet, 0, 2);
    check(s && s->kind == packet_kind::short_header &&
              s->destination_cid.size() == 2 &&
              s->header_end_offset == 3 &&
              s->packet_end_offset == short_packet.size(),
          "caller-supplied short CID length");
    check(parse_packet_header(short_packet).error() ==
              packet_header_error::invalid_length,
          "short header requires caller-supplied CID length");
}

auto malformed_packets() -> void
{
    constexpr auto initial = bytes(std::array<std::uint8_t, 12> {
        0xc0, 0, 0, 0, 1, 0, 0, 0, 3, 1, 2, 3,
    });
    for (std::size_t size = 0; size < initial.size(); ++size) {
        check(parse_packet_header(std::span(initial).first(size)).error() ==
                  packet_header_error::truncated,
              "every Initial prefix is truncated");
    }
    check(parse_packet_header(initial).has_value(), "complete Initial");

    constexpr auto bad_cid = bytes(std::array<std::uint8_t, 7> {
        0xc0, 0, 0, 0, 1, 21, 0,
    });
    check(parse_packet_header(bad_cid).error() ==
              packet_header_error::invalid_length,
          "v1 CID longer than 20");
    constexpr auto missing_cid = bytes(std::array<std::uint8_t, 7> {
        0xc0, 0, 0, 0, 1, 2, 0,
    });
    check(parse_packet_header(missing_cid).error() ==
              packet_header_error::truncated,
          "CID bytes truncated");
    constexpr auto bad_source_cid = bytes(std::array<std::uint8_t, 7> {
        0xc0, 0, 0, 0, 1, 0, 21,
    });
    check(parse_packet_header(bad_source_cid).error() ==
              packet_header_error::invalid_length,
          "source CID longer than 20");
    constexpr auto bad_token = bytes(std::array<std::uint8_t, 9> {
        0xc0, 0, 0, 0, 1, 0, 0, 4, 0xff,
    });
    check(parse_packet_header(bad_token).error() ==
              packet_header_error::truncated,
          "token length exceeds input");
    constexpr auto huge_token = bytes(std::array<std::uint8_t, 16> {
        0xc0, 0, 0, 0, 1, 0, 0, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0,
    });
    check(parse_packet_header(huge_token).error() ==
              packet_header_error::truncated,
          "large varint token length cannot overflow bounds");
    constexpr auto zero_length = bytes(std::array<std::uint8_t, 9> {
        0xc0, 0, 0, 0, 1, 0, 0, 0, 0,
    });
    check(parse_packet_header(zero_length).error() ==
              packet_header_error::invalid_length,
          "zero protected length");
    constexpr auto unsupported = bytes(std::array<std::uint8_t, 7> {
        0xc0, 0, 0, 0, 3, 0, 0,
    });
    check(parse_packet_header(unsupported).error() ==
              packet_header_error::unsupported_version,
          "unsupported version");
    constexpr auto missing_fixed = bytes(std::array<std::uint8_t, 9> {
        0x80, 0, 0, 0, 1, 0, 0, 1, 0,
    });
    check(parse_packet_header(missing_fixed).error() ==
              packet_header_error::invalid_header,
          "fixed bit on supported long header");
    constexpr auto short_packet = bytes(std::array<std::uint8_t, 3> {
        0x40, 0xaa, 0x11,
    });
    check(parse_packet_header(short_packet, 0, 2).error() ==
              packet_header_error::truncated,
          "short CID must leave a protected byte");
    check(parse_packet_header(short_packet, 0, 21).error() ==
              packet_header_error::invalid_length,
          "short CID length bounded");
    constexpr auto bad_vn = bytes(std::array<std::uint8_t, 10> {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    });
    check(parse_packet_header(bad_vn).error() ==
              packet_header_error::invalid_length,
          "Version Negotiation list multiple of four");
    constexpr auto empty_vn = bytes(std::array<std::uint8_t, 7> {
        0x80, 0, 0, 0, 0, 0, 0,
    });
    check(parse_packet_header(empty_vn).error() ==
              packet_header_error::invalid_length,
          "Version Negotiation list cannot be empty");
    constexpr auto bad_retry = bytes(std::array<std::uint8_t, 22> {
        0xf0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    });
    check(parse_packet_header(bad_retry).error() ==
              packet_header_error::truncated,
          "Retry tag truncated");
}

auto grease_quic_bit() -> void
{
    constexpr auto short_packet = bytes(std::array<std::uint8_t, 3> {
        0x00, 0xaa, 0x11,
    });
    check(parse_packet_header(short_packet, 0, 1).error() ==
              packet_header_error::invalid_header,
          "cleared short QUIC bit requires receive opt-in");
    const auto short_result = parse_packet_header(short_packet, 0, 1, true);
    check(short_result && short_result->kind == packet_kind::short_header &&
              short_result->first_byte == 0 && short_result->header_end_offset == 2,
          "greased short header preserves offsets");
    check(parse_packet_header(short_packet, 0, 21, true).error() ==
              packet_header_error::invalid_length,
          "greasing preserves CID bound");
    check(parse_packet_header(short_packet, 0, 2, true).error() ==
              packet_header_error::truncated,
          "greasing preserves minimum short packet length");
    constexpr auto initial = bytes(std::array<std::uint8_t, 10> {
        0x80, 0, 0, 0, 1, 0, 0, 0, 1, 0,
    });
    check(parse_packet_header(initial).error() == packet_header_error::invalid_header,
          "cleared long QUIC bit requires receive opt-in");
    const auto long_result = parse_packet_header(initial, 0, std::nullopt, true);
    check(long_result && long_result->kind == packet_kind::initial &&
              long_result->header_end_offset == 9 && long_result->packet_end_offset == 10,
          "greased long header preserves offsets");
    check(parse_packet_header(std::span(initial).first(9), 0, std::nullopt, true).error() ==
              packet_header_error::truncated,
          "greasing preserves payload length validation");
    constexpr auto unsupported = bytes(std::array<std::uint8_t, 7> {
        0x80, 0, 0, 0, 3, 0, 0,
    });
    check(parse_packet_header(unsupported, 0, std::nullopt, true).error() ==
              packet_header_error::unsupported_version,
          "greasing preserves supported version validation");
}

} // namespace

auto main() -> int
{
    long_headers_and_coalescing();
    terminal_packets();
    malformed_packets();
    grease_quic_bit();
}
