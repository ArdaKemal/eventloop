// RFC 9287 QUIC-bit greasing: packet parsing, protected-packet opening, and
// endpoint routing acceptance. Negotiation and randomized sending are covered
// by the in-memory handshake checks in tests/quic_connection_core.cc.
#include "quic/endpoint_router.h"
#include "quic/packet_header.h"
#include "quic/packet_protection.h"
#include "quic/protected_packet.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::fprintf(stderr, "QUIC grease_quic_bit: %.*s\n",
                 static_cast<int>(message.size()), message.data());
    std::abort();
}

struct route_probe {
    bool called {false};
};

auto on_packet(void* argument, std::span<const std::byte>, const packet_header&,
               eventloop::ip_endpoint) noexcept -> bool
{
    static_cast<route_probe*>(argument)->called = true;
    return true;
}

auto parsing_and_opening() -> void
{
    const std::array<std::uint8_t, 8> dcid {1, 2, 3, 4, 5, 6, 7, 8};
    const auto secrets = derive_initial_secrets(version_1, dcid);
    check(secrets.has_value(), "derive Initial secrets");
    const auto initial_keys = derive_aes_128_gcm_keys(version_1, secrets->client);
    check(initial_keys.has_value(), "derive Initial keys");

    std::array<std::uint8_t, 2048> output {};
    std::array<std::uint8_t, 2048> scratch {};
    std::array<std::uint8_t, 256> plaintext {};
    const std::array<std::uint8_t, 1> ping {1};

    // A long header (Initial) with the QUIC bit cleared.
    protected_packet_fields fields;
    fields.kind = packet_kind::initial;
    fields.version = version_1;
    fields.destination_cid = dcid;
    fields.packet_number = 0;
    fields.quic_bit = false;
    const auto built = build_protected_packet(fields, *initial_keys, ping, output,
                                              scratch);
    check(built.has_value(), "build Initial with cleared QUIC bit");

    const auto wire = std::span(output).first(*built);
    const auto datagram = std::as_bytes(wire);
    auto strict = parse_packet_header(datagram, 0, std::nullopt, false);
    check(!strict && strict.error() == packet_header_error::invalid_header,
          "strict parsing rejects a cleared QUIC bit");
    auto greased = parse_packet_header(datagram, 0, std::nullopt, true);
    check(greased && greased->kind == packet_kind::initial,
          "greased parsing accepts a cleared QUIC bit");

    auto strict_open = open_protected_packet(wire, 0, std::nullopt, version_1,
        *initial_keys, std::nullopt, scratch, plaintext, false);
    check(!strict_open && strict_open.error() == protected_packet_error::malformed_packet,
          "strict opening rejects a cleared QUIC bit");
    auto greased_open = open_protected_packet(wire, 0, std::nullopt, version_1,
        *initial_keys, std::nullopt, scratch, plaintext, true);
    check(greased_open && greased_open->kind == packet_kind::initial &&
              greased_open->packet_number == 0 &&
              greased_open->plaintext_size >= ping.size() &&
              plaintext[greased_open->plaintext_size - 1] == ping[0],
          "greased opening accepts a cleared QUIC bit");

    // A short header (1-RTT) with the QUIC bit cleared.
    const std::array<std::uint8_t, 32> application_secret {};
    const auto application_keys =
        derive_aes_128_gcm_keys(version_1, application_secret);
    check(application_keys.has_value(), "derive application keys");
    protected_packet_fields short_fields;
    short_fields.kind = packet_kind::short_header;
    short_fields.version = version_1;
    short_fields.destination_cid = dcid;
    short_fields.packet_number = 0;
    short_fields.quic_bit = false;
    const auto short_built = build_protected_packet(short_fields, *application_keys,
                                                    ping, output, scratch);
    check(short_built.has_value(), "build short header with cleared QUIC bit");
    const auto short_wire = std::span(output).first(*short_built);
    const auto short_datagram = std::as_bytes(short_wire);
    auto short_strict = parse_packet_header(short_datagram, 0, dcid.size(), false);
    check(!short_strict && short_strict.error() == packet_header_error::invalid_header,
          "strict parsing rejects a cleared short-header bit");
    auto short_open = open_protected_packet(short_wire, 0, dcid.size(), version_1,
        *application_keys, std::nullopt, scratch, plaintext, true);
    check(short_open && short_open->kind == packet_kind::short_header,
          "greased opening accepts a cleared short-header bit");

    // A set QUIC bit is always accepted.
    short_fields.quic_bit = true;
    const auto set_built = build_protected_packet(short_fields, *application_keys,
                                                  ping, output, scratch);
    check(set_built.has_value(), "build short header with set QUIC bit");
    auto set_open = open_protected_packet(std::span(output).first(*set_built), 0,
        dcid.size(), version_1, *application_keys, std::nullopt, scratch, plaintext,
        false);
    check(set_open && set_open->kind == packet_kind::short_header,
          "strict opening accepts a set QUIC bit");
}

auto routing() -> void
{
    const std::array<std::byte, 8> cid {std::byte {1}, std::byte {2}, std::byte {3},
        std::byte {4}, std::byte {5}, std::byte {6}, std::byte {7}, std::byte {8}};
    std::array<std::byte, 12> datagram {};
    // Short header, QUIC bit cleared, packet-number length 1.
    datagram[0] = std::byte {0x00};
    std::copy(cid.begin(), cid.end(), datagram.begin() + 1);
    const eventloop::ip_endpoint peer {};

    {
        endpoint_router router {path_endpoint_role::server, 8, true};
        route_probe probe;
        const endpoint_callbacks callbacks {&probe, on_packet, nullptr};
        check(router.add(cid, peer, callbacks, true).has_value(), "add greased route");
        const auto processed = router.dispatch(datagram, peer);
        check(processed.has_value() && *processed == 1 && probe.called,
              "greased router routes a cleared QUIC bit");
    }
    {
        endpoint_router router {path_endpoint_role::server, 8, false};
        route_probe probe;
        const endpoint_callbacks callbacks {&probe, on_packet, nullptr};
        check(router.add(cid, peer, callbacks, true).has_value(), "add strict route");
        const auto processed = router.dispatch(datagram, peer);
        check(!processed && processed.error() == endpoint_error::malformed_packet &&
                  !probe.called,
              "strict router rejects a cleared QUIC bit");
    }
}

} // namespace

auto main() -> int
{
    parsing_and_opening();
    routing();
    std::puts("QUIC grease_quic_bit tests passed");
    return 0;
}
