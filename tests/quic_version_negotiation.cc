#include "quic/version_negotiation.h"

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
    std::cerr << "QUIC Version Negotiation: " << message << '\n';
    std::exit(1);
}

auto construction_and_selection() -> void
{
    constexpr std::array<std::byte, 2> dcid {std::byte {0xa1}, std::byte {0xa2}};
    constexpr std::array<std::byte, 1> scid {std::byte {0xb1}};
    constexpr std::array<std::uint32_t, 2> versions {version_1, version_2};
    constexpr std::array<std::uint32_t, 3> preference {
        version_2, version_1, 0x12345678};
    std::array<std::byte, 32> output {};

    const auto encoded = encode_version_negotiation(
        dcid, scid, versions, 0x00, output);
    check(encoded == 18, "encoded packet size");
    const auto packet = std::span(output).first(*encoded);
    check(output[0] == std::byte {0x80} &&
          output[1] == std::byte {0} && output[4] == std::byte {0},
          "arbitrary fixed bit and zero version");
    const auto parsed = parse_packet_header(packet);
    check(parsed && parsed->kind == packet_kind::version_negotiation &&
          std::equal(parsed->destination_cid.begin(),
                     parsed->destination_cid.end(), scid.begin()) &&
          std::equal(parsed->source_cid.begin(), parsed->source_cid.end(),
                     dcid.begin()) && parsed->version_list.size() == 8 &&
          version_at(parsed->version_list, 0) == version_1 &&
          version_at(parsed->version_list, 1) == version_2,
          "CID echoes and supported versions");
    check(validate_version_negotiation(packet, dcid, scid, 0x12345678,
                                       preference) == version_2,
          "client preference selects v2");

    constexpr std::array<std::uint32_t, 3> reverse_order {
        version_1, 0x1a2a3a4a, version_2};
    check(encode_version_negotiation(dcid, scid, reverse_order, 0x15,
                                     output) == 22 &&
          output[0] == std::byte {0x95} &&
          validate_version_negotiation(std::span(output).first(22), dcid, scid,
                                       0x12345678, preference) == version_2,
          "server list order and unused bits do not change client choice");

    const auto with_fixed_bit = encode_version_negotiation(
        dcid, scid, versions, 0x7f, output);
    check(with_fixed_bit == 18 && output[0] == std::byte {0xff} &&
          validate_version_negotiation(std::span(output).first(*with_fixed_bit),
                                       dcid, scid, 0x12345678,
                                       preference) == version_2,
          "fixed bit one is also accepted");
}

auto malformed_and_spoofed() -> void
{
    constexpr std::array<std::byte, 1> dcid {std::byte {0xa1}};
    constexpr std::array<std::byte, 1> scid {std::byte {0xb1}};
    constexpr std::array<std::uint32_t, 2> preference {
        version_2, 0x12345678};
    constexpr std::array<std::uint32_t, 1> v2 {version_2};
    std::array<std::byte, 32> output {};
    const auto encoded = encode_version_negotiation(dcid, scid, v2, 0, output);
    check(encoded == 13, "single version packet");
    auto packet = std::span(output).first(*encoded);

    check(validate_version_negotiation(packet, dcid, scid, 0x12345678,
                                       preference, true).error() ==
              version_negotiation_error::prior_packet_processed,
          "VN after processed Retry or other packet discarded");
    constexpr std::array<std::byte, 1> wrong_cid {std::byte {0x99}};
    check(validate_version_negotiation(packet, wrong_cid, scid, 0x12345678,
                                       preference).error() ==
              version_negotiation_error::connection_id_mismatch &&
          validate_version_negotiation(packet, dcid, wrong_cid, 0x12345678,
                                       preference).error() ==
              version_negotiation_error::connection_id_mismatch,
          "both echoed CIDs checked");
    check(validate_version_negotiation(packet.first(packet.size() - 1),
                                       dcid, scid, 0x12345678,
                                       preference).error() ==
              version_negotiation_error::invalid_packet,
          "partial version word rejected");
    output[9] = std::byte {0x12};
    output[10] = std::byte {0x34};
    output[11] = std::byte {0x56};
    output[12] = std::byte {0x78};
    check(validate_version_negotiation(packet, dcid, scid, 0x12345678,
                                       preference).error() ==
              version_negotiation_error::offered_version_listed,
          "offered version in VN list discarded");
    output[9] = std::byte {0};
    output[10] = std::byte {0};
    output[11] = std::byte {0};
    output[12] = std::byte {0};
    check(validate_version_negotiation(packet, dcid, scid, 0x12345678,
                                       preference).error() ==
              version_negotiation_error::invalid_version_list,
          "zero list entry rejected");
    output[9] = std::byte {0x6b};
    output[10] = std::byte {0x33};
    output[11] = std::byte {0x43};
    output[12] = std::byte {0xcf};
    output[1] = std::byte {1};
    check(validate_version_negotiation(packet, dcid, scid, 0x12345678,
                                       preference).error() ==
              version_negotiation_error::invalid_packet,
          "nonzero packet version rejected");
    output[1] = std::byte {0};
    constexpr std::array<std::uint32_t, 1> unknown {0x87654321};
    check(encode_version_negotiation(dcid, scid, unknown, 0, output) == 13 &&
          validate_version_negotiation(packet, dcid, scid, 0x12345678,
                                       preference).error() ==
              version_negotiation_error::no_common_version,
          "no mutually supported version");
    constexpr std::array<std::uint32_t, 2> reserved_and_v1 {
        0x1a2a3a4a, version_1};
    constexpr std::array<std::uint32_t, 3> reserved_preference {
        0x1a2a3a4a, version_1, 0x12345678};
    check(encode_version_negotiation(dcid, scid, reserved_and_v1, 0,
                                     output) == 17 &&
          validate_version_negotiation(std::span(output).first(17), dcid, scid,
                                       0x12345678, reserved_preference) ==
              version_1,
          "reserved grease version is never selected");
}

auto output_bounds_and_authentication() -> void
{
    constexpr std::array<std::byte, 1> cid {std::byte {1}};
    constexpr std::array<std::uint32_t, 2> versions {version_1, version_2};
    constexpr std::array<std::uint32_t, 2> duplicate {version_1, version_1};
    constexpr std::array<std::uint32_t, 1> zero {0};
    std::array<std::byte, 16> output;
    output.fill(std::byte {0xaa});
    check(encode_version_negotiation(cid, cid, versions, 0,
                                     output).error() ==
              version_negotiation_error::output_too_small &&
          std::all_of(output.begin(), output.end(),
                      [](std::byte value) { return value == std::byte {0xaa}; }),
          "short output rejected atomically");
    check(encode_version_negotiation(cid, cid, duplicate, 0,
                                     output).error() ==
              version_negotiation_error::invalid_version_list &&
          encode_version_negotiation(cid, cid, zero, 0,
                                     output).error() ==
              version_negotiation_error::invalid_version_list,
          "duplicate and zero versions rejected");
    std::array<std::byte, 256> long_cid {};
    check(encode_version_negotiation(long_cid, cid, versions, 0,
                                     output).error() ==
              version_negotiation_error::invalid_connection_id,
          "CID length field bound");
    std::array<std::byte, 255> maximum_cid {};
    std::array<std::byte, 267> maximum_packet {};
    const auto maximum = encode_version_negotiation(
        maximum_cid, cid, std::array<std::uint32_t, 1> {version_1}, 0,
        maximum_packet);
    check(maximum == maximum_packet.size() &&
          parse_packet_header(maximum_packet)->source_cid.size() == 255,
          "VN accepts maximum 255-byte CID independent of version limits");

    constexpr std::uint32_t original = 0x12345678;
    constexpr std::array<std::uint32_t, 3> preference {
        version_2, version_1, original};
    constexpr std::array<std::uint32_t, 2> available {version_2, version_1};
    constexpr std::array<std::uint32_t, 1> advertised {version_2};
    check(validate_authenticated_version_information(
              original, version_2, version_2, version_2,
              available, advertised, preference).has_value(),
          "authenticated choice confirms VN selection");
    check(validate_authenticated_version_information(
              original, version_2, version_2, version_2,
              std::array<std::uint32_t, 2> {0x1a2a3a4a, version_2},
              advertised,
              std::array<std::uint32_t, 3> {0x1a2a3a4a, version_2,
                                            original}).has_value(),
          "reserved version in authenticated list cannot change selection");
    check(validate_authenticated_version_information(
              original, version_1, version_1, version_1,
              available, std::span(versions), preference).error() ==
              version_negotiation_error::downgrade_detected,
          "authenticated higher preference detects downgrade");
    constexpr std::array<std::uint32_t, 2> original_available {
        original, version_2};
    check(validate_authenticated_version_information(
              original, version_2, version_2, version_2,
              original_available, advertised,
              std::array<std::uint32_t, 3> {original, version_2,
                                            version_1}).error() ==
              version_negotiation_error::downgrade_detected,
          "higher-preference original version detects spoofed VN");
    check(validate_authenticated_version_information(
              original, version_2, version_2, version_2,
              original_available, advertised, preference).has_value(),
          "lower-preference original version does not change selection");
    check(validate_authenticated_version_information(
              original, version_2, version_2, version_1,
              available, std::span(versions), preference).error() ==
              version_negotiation_error::downgrade_detected,
          "chosen version must match negotiated version");
    constexpr std::array<std::uint32_t, 1> compatible_available {version_1};
    check(validate_authenticated_version_information(
              original, version_1, version_2, version_2,
              compatible_available, std::span(versions),
              std::array<std::uint32_t, 3> {version_1, version_2,
                                            original}).has_value(),
          "compatible switch preserves attempted preference");
    check(validate_authenticated_version_information(
              original, version_2, version_2, version_2,
              std::span<const std::uint32_t> {}, advertised,
              preference).error() ==
              version_negotiation_error::downgrade_detected,
          "empty authenticated available list detects downgrade after VN");
    check(validate_authenticated_version_information(
              original, version_1, version_1, version_1,
              std::array<std::uint32_t, 1> {version_1}, advertised,
              preference).error() ==
              version_negotiation_error::downgrade_detected,
          "attempted version must appear in client advertised versions");
}

} // namespace

auto main() -> int
{
    construction_and_selection();
    malformed_and_spoofed();
    output_bounds_and_authentication();
}
