#include "quic/transport_parameters.h"
#include "quic/version.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <span>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC parameters: " << message << '\n';
    std::exit(1);
}

template<std::size_t N>
constexpr auto bytes(const std::array<std::uint8_t, N>& input)
    -> std::array<std::byte, N>
{
    std::array<std::byte, N> result {};
    for (std::size_t i = 0; i < N; ++i) {
        result[i] = static_cast<std::byte>(input[i]);
    }
    return result;
}

auto versions() -> void
{
    check(is_supported_version(version_1) && is_supported_version(version_2),
          "v1 and v2 recognized");
    check(!is_supported_version(0), "version negotiation is not a version");
    for (const auto version : {version_1, version_2}) {
        for (std::uint8_t type = 0; type != 4; ++type) {
            const auto packet = static_cast<long_packet_type>(type);
            const auto bits = long_header_type_bits(version, packet);
            check(decode_long_header_type(version, bits) == packet,
                  "long header packet type round trip");
        }
    }
    check(long_header_type_bits(version_2, long_packet_type::initial) == 1 &&
          long_header_type_bits(version_2, long_packet_type::retry) == 0,
          "v2 long header mapping");
}

auto valid_values() -> void
{
    // ID, length, and value are RFC 9000 Section 18 wire tuples.
    constexpr auto wire = bytes(std::array<std::uint8_t, 21> {
        0x0f, 0x02, 0xaa, 0xbb, // initial_source_connection_id
        0x03, 0x02, 0x44, 0xb0, // max_udp_payload_size = 1200
        0x0a, 0x01, 0x14,       // ack_delay_exponent = 20
        0x0c, 0x00,             // disable_active_migration
        0x40, 0x1b, 0x03, 0x01, 0x02, 0x03, // nonminimal unknown ID 27
        0x20, 0x01, // filled below
    });
    // Last tuple is intentionally truncated.
    check(decode_transport_parameters(wire, parameter_sender::client).error() ==
              parameter_error::truncated,
          "truncated final tuple rejected");

    constexpr auto complete = bytes(std::array<std::uint8_t, 22> {
        0x0f, 0x02, 0xaa, 0xbb,
        0x03, 0x02, 0x44, 0xb0,
        0x0a, 0x01, 0x14,
        0x0c, 0x00,
        0x1b, 0x03, 0x01, 0x02, 0x03,
        0x20, 0x02, 0x44, 0xb0,
    });
    const auto decoded = decode_transport_parameters(complete,
                                                      parameter_sender::client);
    check(decoded && decoded->count == 6, "known and unknown tuples decoded");
    check(decoded->find(0x1b) && decoded->find(0x1b)->value.size() == 3,
          "unknown parameter retained");
    check(parameter_integer(decoded->find(0x03)->value) == 1200,
          "integer value decoded");

    std::array<std::byte, 64> output {};
    const auto encoded = encode_transport_parameters(
        std::span(decoded->entries.data(), decoded->count),
        parameter_sender::client, output);
    check(encoded && *encoded == complete.size(), "encoded size");
    for (std::size_t i = 0; i < complete.size(); ++i) {
        check(output[i] == complete[i], "round trip wire bytes");
    }
    check(encode_transport_parameters(
              std::span(decoded->entries.data(), decoded->count),
              parameter_sender::client, std::span(output.data(), 1)).error() ==
              parameter_error::output_too_small,
          "short output rejected");

    constexpr auto version_wire = bytes(std::array<std::uint8_t, 14> {
        0x11, 0x0c,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01,
        0x6b, 0x33, 0x43, 0xcf,
    });
    check(decode_transport_parameters(version_wire, parameter_sender::client)
              .has_value(), "client version information accepted");

    std::array<std::byte, 44> preferred {};
    preferred[0] = std::byte {0x0d};
    preferred[1] = std::byte {42};
    preferred[26] = std::byte {1}; // CID length after 24 address bytes.
    check(decode_transport_parameters(preferred, parameter_sender::server)
              .has_value(), "server preferred address accepted");
}

auto invalid_values() -> void
{
    std::size_t case_number = 0;
    const auto expect = [&case_number](std::initializer_list<std::uint8_t> data,
                           parameter_sender sender, parameter_error error) {
        std::array<std::byte, 64> input {};
        std::size_t size = 0;
        for (const auto byte : data) input[size++] = static_cast<std::byte>(byte);
        const auto decoded = decode_transport_parameters(
            std::span(input.data(), size), sender);
        ++case_number;
        if (decoded || decoded.error() != error) {
            std::cerr << "invalid tuple case " << case_number << '\n';
            std::exit(1);
        }
    };
    expect({0x01}, parameter_sender::client, parameter_error::truncated);
    expect({0x01, 0x40}, parameter_sender::client, parameter_error::truncated);
    expect({0x01, 0x03, 0x01}, parameter_sender::client,
           parameter_error::truncated);
    expect({0x01, 0x01, 0x00, 0x01, 0x01, 0x00},
           parameter_sender::client, parameter_error::duplicate);
    expect({0x1b, 0x00, 0x1b, 0x00}, parameter_sender::client,
           parameter_error::duplicate);
    expect({0x03, 0x00}, parameter_sender::client,
           parameter_error::invalid_value);
    expect({0x03, 0x01, 0x01}, parameter_sender::client,
           parameter_error::invalid_value);
    expect({0x0a, 0x01, 0x15}, parameter_sender::client,
           parameter_error::invalid_value);
    expect({0x0b, 0x04, 0x80, 0x00, 0x40, 0x00}, parameter_sender::client,
           parameter_error::invalid_value);
    expect({0x0e, 0x01, 0x01}, parameter_sender::client,
           parameter_error::invalid_value);
    expect({0x0c, 0x01, 0x00}, parameter_sender::client,
           parameter_error::invalid_value);
    expect({0x0f, 0x15}, parameter_sender::client,
           parameter_error::truncated);
    expect({0x02, 0x00}, parameter_sender::client,
           parameter_error::forbidden_parameter);
    expect({0x02, 0x00}, parameter_sender::server,
           parameter_error::invalid_value);
    expect({0x11, 0x03, 0x00, 0x00, 0x01}, parameter_sender::client,
           parameter_error::invalid_value);
    expect({0x11, 0x04, 0x00, 0x00, 0x00, 0x00},
           parameter_sender::server, parameter_error::invalid_value);
    expect({0x11, 0x08, 0x00, 0x00, 0x00, 0x01,
            0x6b, 0x33, 0x43, 0xcf},
           parameter_sender::client, parameter_error::invalid_value);
    expect({0x0d, 0x00}, parameter_sender::client,
           parameter_error::forbidden_parameter);
    expect({0x0d, 0x00}, parameter_sender::server,
           parameter_error::invalid_value);
    expect({0x6a, 0xb2, 0x01, 0x00}, parameter_sender::client,
           parameter_error::invalid_value); // grease_quic_bit, nonempty
    expect({0x1d, 0x01, 0x00}, parameter_sender::server,
           parameter_error::invalid_value); // reset_stream_at, nonempty
    const std::array<std::byte, 2> empty_flag {std::byte {0x1d}, std::byte {0x00}};
    const auto flag = decode_transport_parameters(empty_flag, parameter_sender::client);
    check(flag && flag->find(0x1d) != nullptr, "empty reset_stream_at accepted");
}

auto bounds() -> void
{
    std::array<std::byte, transport_parameters::max_encoded_size + 1> oversized {};
    check(decode_transport_parameters(oversized, parameter_sender::client)
              .error() == parameter_error::resource_limit,
          "extension byte limit");

    std::array<std::byte, 128 * 3 + 3> many {};
    for (std::size_t i = 0; i < 129; ++i) {
        // Distinct two-byte unknown IDs, each with an empty value.
        many[3 * i] = std::byte {0x40};
        many[3 * i + 1] = static_cast<std::byte>(0x80 + i);
        many[3 * i + 2] = std::byte {0x00};
    }
    check(decode_transport_parameters(many, parameter_sender::client)
              .error() == parameter_error::resource_limit,
          "entry count limit");
}

} // namespace

auto main() -> int
{
    versions();
    valid_values();
    invalid_values();
    bounds();
}
