#include "quic/protected_packet.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>
#include <vector>

using namespace eventloop::quic::detail;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            std::fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__,   \
                         __LINE__, #condition);                                \
            std::abort();                                                       \
        }                                                                       \
    } while (false)

namespace {

auto hex(std::string_view input) -> std::vector<std::uint8_t>
{
    auto nibble = [](char value) -> std::uint8_t {
        if (value >= '0' && value <= '9') return static_cast<std::uint8_t>(value - '0');
        if (value >= 'a' && value <= 'f') return static_cast<std::uint8_t>(value - 'a' + 10);
        CHECK(false);
        return 0;
    };
    std::vector<std::uint8_t> result;
    for (std::size_t i = 0; i < input.size(); i += 2) {
        result.push_back(static_cast<std::uint8_t>(
            (nibble(input[i]) << 4) | nibble(input[i + 1])));
    }
    return result;
}

} // namespace

auto grease_quic_bit_packets() -> void
{
    const std::array<std::uint8_t, 4> cid {1, 2, 3, 4};
    const std::array<std::uint8_t, 3> ping {1, 0, 0};
    std::array<std::uint8_t, 128> packet {}, reference {}, scratch {}, plaintext {}, auth {};
    packet_protection_context context;
    CHECK(context.ready());
    for (const auto version : {version_1, version_2}) {
        const auto secrets = derive_initial_secrets(version, cid);
        CHECK(secrets);
        const auto keys = derive_aes_128_gcm_keys(version, secrets->client);
        CHECK(keys);
        for (const auto kind : {packet_kind::initial, packet_kind::zero_rtt,
                                packet_kind::handshake, packet_kind::short_header}) {
            for (const auto bit : {true, false}) {
                protected_packet_fields fields;
                fields.kind = kind;
                fields.version = version;
                fields.destination_cid = cid;
                fields.packet_number = 7;
                fields.quic_bit = bit;
                fields.spin_bit = fields.key_phase = kind == packet_kind::short_header;
                const auto size = build_protected_packet(context, fields, *keys,
                                                         ping, packet, scratch);
                CHECK(size && ((packet[0] & 0x40) != 0) == bit);
                CHECK(build_protected_packet(fields, *keys, ping, reference, scratch) == size);
                CHECK(std::equal(packet.begin(), packet.begin() + *size, reference.begin()));
                const auto cid_length = kind == packet_kind::short_header
                    ? std::optional<std::size_t>{cid.size()} : std::nullopt;
                const auto strict = open_protected_packet(
                    std::span(packet).first(*size), 0, cid_length, version, *keys,
                    {}, scratch, plaintext);
                CHECK(bit ? strict.has_value() :
                      (!strict && strict.error() == protected_packet_error::malformed_packet));
                const auto opened = open_protected_packet(context,
                    std::span(packet).first(*size), 0, cid_length, version, *keys,
                    {}, scratch, plaintext, auth, true);
                CHECK(opened && opened->kind == kind && opened->packet_number == 7);
                CHECK(opened->key_phase == fields.key_phase && opened->spin_bit == fields.spin_bit);
                CHECK(opened->plaintext_size == ping.size());
                CHECK(std::equal(ping.begin(), ping.end(), plaintext.begin()));
                CHECK(open_protected_packet(std::span(packet).first(*size), 0,
                    cid_length, version, *keys, {}, scratch, plaintext, true).has_value());
                // QUIC bit is not header protected, but remains authenticated AAD.
                packet[0] ^= 0x40;
                plaintext.fill(0xa5);
                const auto tampered = open_protected_packet(context,
                    std::span(packet).first(*size), 0, cid_length, version, *keys,
                    {}, scratch, plaintext, auth, true);
                CHECK(!tampered && tampered.error() == protected_packet_error::authentication_failed);
                CHECK(std::ranges::all_of(plaintext, [](auto value) { return value == 0xa5; }));
            }
        }
    }
    // An authenticated cleared-bit packet still must have zero reserved bits.
    const std::array<std::uint8_t, 32> secret {};
    const auto keys = derive_aes_128_gcm_keys(version_1, secret);
    CHECK(keys);
    packet[0] = 0x08; // short header, QUIC bit zero, reserved bit nonzero, one-byte PN
    packet[1] = 7;
    const auto sealed = seal_payload(context, *keys, 7,
        std::span(packet).first(2), ping, std::span(packet).subspan(2, ping.size() + 16));
    CHECK(sealed);
    const auto size = 2 + *sealed;
    CHECK(apply_aes_header_protection(context, *keys, std::span(packet).first(size), 1, false));
    const auto reserved = open_protected_packet(context, std::span(packet).first(size),
        0, 0, version_1, *keys, {}, scratch, plaintext, auth, true);
    CHECK(!reserved && reserved.error() == protected_packet_error::reserved_bits);
    // Long-header reserved bits are checked only after authentication too.
    for (const bool authentic : {true, false}) {
        packet[0] = 0xe4; // Handshake, reserved bits 01, one-byte PN
        packet[1] = packet[2] = packet[3] = 0; packet[4] = 1; // version 1
        packet[5] = packet[6] = 0; // empty connection IDs
        packet[7] = 0x40; packet[8] = static_cast<std::uint8_t>(1 + ping.size() + 16);
        packet[9] = 7;
        const auto long_sealed = seal_payload(context, *keys, 7,
            std::span(packet).first(10), ping, std::span(packet).subspan(10, ping.size() + 16));
        CHECK(long_sealed);
        const auto long_size = 10 + *long_sealed;
        if (!authentic) packet[long_size - 1] ^= 1;
        CHECK(apply_aes_header_protection(context, *keys, std::span(packet).first(long_size), 9, false));
        const auto long_reserved = open_protected_packet(context,
            std::span(packet).first(long_size), 0, std::nullopt, version_1, *keys, {},
            scratch, plaintext, auth, true);
        CHECK(!long_reserved && long_reserved.error() == (authentic
            ? protected_packet_error::reserved_bits
            : protected_packet_error::authentication_failed));
    }
}

// RFC 9000 17.1/A.2: the sender widens packet numbers with the unacknowledged
// distance, so a receiver that saw nothing since the largest acknowledged
// packet still decodes them.
auto packet_number_lengths() -> void
{
    static_assert(packet_number_length_for(0, std::nullopt) == 1);
    static_assert(packet_number_length_for(127, std::nullopt) == 2);
    static_assert(packet_number_length_for(0xac5c02, 0xabe8b3) == 2);
    static_assert(packet_number_length_for(0xace8fe, 0xabe8b3) == 3);
    static_assert(packet_number_length_for(0x50000000, 0) == 4);
    const std::array<std::uint8_t, 4> cid {1, 2, 3, 4};
    const std::array<std::uint8_t, 3> ping {1, 0, 0};
    std::array<std::uint8_t, 128> packet {}, scratch {}, plaintext {};
    const std::array<std::uint8_t, 32> secret {};
    const auto keys = derive_aes_128_gcm_keys(version_1, secret);
    CHECK(keys);
    // A one-byte encoding of 300 decodes to 44 for a receiver at 0.
    for (const std::uint64_t number : {300u, 70000u}) {
        protected_packet_fields fields;
        fields.kind = packet_kind::short_header;
        fields.destination_cid = cid;
        fields.packet_number = number;
        fields.packet_number_length = packet_number_length_for(number, 0);
        const auto size = build_protected_packet(fields, *keys, ping, packet, scratch);
        CHECK(size);
        const auto opened = open_protected_packet(std::span(packet).first(*size), 0,
            cid.size(), version_1, *keys, 0, scratch, plaintext);
        CHECK(opened && opened->packet_number == number);
    }
}

int main()
{
    grease_quic_bit_packets();
    packet_number_lengths();
    const auto dcid = hex("8394c8f03e515708");
    const auto initial = derive_initial_secrets(version_1, dcid);
    CHECK(initial);
    const auto server = derive_aes_128_gcm_keys(version_1, initial->server);
    CHECK(server);

    // RFC 9001 Appendix A.3: complete protected server Initial packet.
    const auto source_cid = hex("f067a5502a4262b5");
    const auto frames = hex(
        "02000000000600405a020000560303ee"
        "fce7f7b37ba1d1632e96677825ddf739"
        "88cfc79825df566dc5430b9a045a1200"
        "130100002e00330024001d00209d3c94"
        "0d89690b84d08a60993c144eca684d10"
        "81287c834d5311bcf32bb9da1a002b00"
        "020304");
    const auto expected = hex(
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
        "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"
        "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
        "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"
        "2158407dd074ee");
    protected_packet_fields fields;
    fields.kind = packet_kind::initial;
    fields.version = version_1;
    fields.source_cid = source_cid;
    fields.packet_number = 1;
    fields.packet_number_length = 2;
    std::array<std::uint8_t, 1500> packet {};
    std::array<std::uint8_t, 1500> scratch {};
    std::array<std::uint8_t, 1500> plaintext {};
    const auto built = build_protected_packet(fields, *server, frames, packet, scratch);
    CHECK(built && *built == expected.size());
    CHECK(std::equal(expected.begin(), expected.end(), packet.begin()));
    const auto opened = open_protected_packet(
        std::span(packet).first(*built), 0, std::nullopt, version_1,
        *server, std::nullopt, scratch, plaintext);
    CHECK(opened && opened->kind == packet_kind::initial);
    CHECK(opened->packet_number == 1 && opened->plaintext_size == frames.size());
    CHECK(std::equal(frames.begin(), frames.end(), plaintext.begin()));

    // Both version-specific long-header type maps and short-header flags.
    for (const auto version : {version_1, version_2}) {
        const auto secrets = derive_initial_secrets(version, dcid);
        CHECK(secrets);
        const auto keys = derive_aes_128_gcm_keys(version, secrets->client);
        CHECK(keys);
        for (const auto kind : {packet_kind::initial, packet_kind::zero_rtt,
                                packet_kind::handshake, packet_kind::short_header}) {
            fields = {};
            fields.kind = kind;
            fields.version = version;
            fields.destination_cid = dcid;
            fields.packet_number = 0x12345;
            fields.packet_number_length = 2;
            fields.key_phase = kind == packet_kind::short_header;
            fields.spin_bit = kind == packet_kind::short_header;
            const std::array<std::uint8_t, 1> ping {0x01};
            const auto size = build_protected_packet(fields, *keys, ping,
                                                     packet, scratch);
            CHECK(size);
            // One PADDING frame before PING makes room for the HP sample.
            const auto result = open_protected_packet(
                std::span(packet).first(*size), 0,
                kind == packet_kind::short_header
                    ? std::optional<std::size_t>{dcid.size()} : std::nullopt,
                version, *keys, 0x12300, scratch, plaintext);
            CHECK(result && result->kind == kind);
            CHECK(result->packet_number == fields.packet_number);
            CHECK(result->plaintext_size == 2 && plaintext[0] == 0 && plaintext[1] == 1);
            CHECK(result->key_phase == fields.key_phase);
            CHECK(result->spin_bit == fields.spin_bit);
            CHECK(result->packet_end_offset == *size);

            auto damaged = packet;
            damaged[*size - 1] ^= 1;
            std::fill(plaintext.begin(), plaintext.end(), 0xa5);
            CHECK(open_protected_packet(
                std::span(damaged).first(*size), 0,
                kind == packet_kind::short_header
                    ? std::optional<std::size_t>{dcid.size()} : std::nullopt,
                version, *keys, 0x12300, scratch, plaintext).error() ==
                  protected_packet_error::authentication_failed);
            CHECK(plaintext[0] == 0xa5);
        }
    }

    // Each truncated PN width, including the one-byte reconstruction window.
    const auto client = derive_aes_128_gcm_keys(version_1, initial->client);
    CHECK(client);
    const std::array<std::uint8_t, 1> ping {0x01};
    for (std::uint8_t length = 1; length <= 4; ++length) {
        fields = {};
        fields.kind = packet_kind::short_header;
        fields.destination_cid = dcid;
        fields.packet_number = 0x12345;
        fields.packet_number_length = length;
        const auto size = build_protected_packet(fields, *client, ping,
                                                 packet, scratch);
        CHECK(size);
        auto datagram = std::array<std::uint8_t, 1501> {};
        std::copy_n(packet.begin(), *size, datagram.begin() + 1);
        const auto result = open_protected_packet(
            std::span(datagram).first(*size + 1), 1, dcid.size(), version_1,
            *client, 0x12300, scratch, plaintext);
        CHECK(result && result->packet_number == 0x12345);
        CHECK(result->packet_end_offset == *size + 1);
        const auto expected_size = std::max<std::size_t>(1, 4 - length);
        CHECK(result->plaintext_size == expected_size);
        CHECK(std::all_of(plaintext.begin(),
                          plaintext.begin() + static_cast<std::ptrdiff_t>(expected_size - 1),
                          [](std::uint8_t byte) { return byte == 0; }));
        CHECK(plaintext[expected_size - 1] == 1);
    }

    // A STREAM frame without LEN consumes all remaining payload bytes.
    // Prefix padding must not extend its stream data.
    fields = {};
    fields.kind = packet_kind::short_header;
    fields.destination_cid = dcid;
    fields.packet_number_length = 1;
    const std::array<std::uint8_t, 2> empty_lengthless_stream {0x08, 0x00};
    const auto stream_size = build_protected_packet(
        fields, *client, empty_lengthless_stream, packet, scratch);
    CHECK(stream_size);
    const auto stream_result = open_protected_packet(
        std::span(packet).first(*stream_size), 0, dcid.size(), version_1,
        *client, std::nullopt, scratch, plaintext);
    CHECK(stream_result && stream_result->plaintext_size == 3);
    CHECK(plaintext[0] == 0 && plaintext[1] == 0x08 && plaintext[2] == 0x00);

    fields = {};
    fields.destination_cid = dcid;
    fields.packet_number_length = 0;
    CHECK(build_protected_packet(fields, *server, frames, packet, scratch).error() ==
          protected_packet_error::invalid_input);
    fields.packet_number_length = 1;
    fields.version = 0;
    CHECK(build_protected_packet(fields, *server, frames, packet, scratch).error() ==
          protected_packet_error::unsupported_version);
    fields.version = version_1;
    CHECK(build_protected_packet(fields, *server, frames,
          std::span(packet).first(1), scratch).error() ==
          protected_packet_error::output_too_small);
    CHECK(build_protected_packet(fields, *server, frames,
          packet, std::span(scratch).first(1)).error() ==
          protected_packet_error::output_too_small);
    fields.kind = packet_kind::retry;
    CHECK(build_protected_packet(fields, *server, frames, packet, scratch).error() ==
          protected_packet_error::invalid_input);

    // Header protection needs a sample starting four bytes after the PN offset.
    std::array<std::uint8_t, 20> too_short {};
    too_short[0] = 0x40;
    CHECK(open_protected_packet(too_short, 0, 0, version_1, *server,
          std::nullopt, scratch, plaintext).error() ==
          protected_packet_error::malformed_packet);
}
