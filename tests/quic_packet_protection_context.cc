#include "quic/packet_protection.h"
#include "quic/protected_packet.h"
#include <algorithm>
#include <array>
#include <cstdlib>
#include <thread>
using namespace eventloop::quic::detail;
static void check(bool value) { if (!value) std::abort(); }
int main()
{
    packet_protection_context context;
    check(context.ready());
    std::array<std::uint8_t, 32> secret {};
    auto keys = derive_aes_128_gcm_keys(version_1, secret);
    check(keys.has_value());
    std::array<std::uint8_t, 7> header {0x43, 1, 2, 3, 4, 5, 6};
    std::array<std::uint8_t, 31> message {};
    std::array<std::uint8_t, 47> ciphertext {}, reference {};
    std::array<std::uint8_t, 31> output {}, scratch {};
    for (std::uint64_t n = 0; n < 100; ++n) {
        message[0] = static_cast<std::uint8_t>(n);
        check(seal_payload(context, *keys, n, header, message, ciphertext).has_value());
        check(seal_payload(*keys, n, header, message, reference).has_value());
        check(ciphertext == reference);
        check(open_payload(context, *keys, n, header, ciphertext, output, scratch).has_value());
        check(output == message);
        check(std::ranges::all_of(scratch, [](auto v) { return v == 0; }));
        ciphertext.back() ^= 1;
        output.fill(0xcc);
        auto failed = open_payload(context, *keys, n, header, ciphertext, output, scratch);
        check(!failed && failed.error() == protection_error::authentication_failed);
        check(std::ranges::all_of(output, [](auto v) { return v == 0xcc; }));
        check(std::ranges::all_of(scratch, [](auto v) { return v == 0; }));
        ciphertext.back() ^= 1;
        check(open_payload(context, *keys, n, header, ciphertext, output, scratch).has_value());
    }
    auto changed_keys = *keys;
    changed_keys.key[0] ^= 0xff;
    check(seal_payload(context, changed_keys, 100, header, message, ciphertext).has_value());
    check(open_payload(context, changed_keys, 100, header, ciphertext, output, scratch).has_value());
    check(output == message);
    check(seal_payload(context, *keys, 99, header, message, ciphertext).has_value());
    auto small = open_payload(context, *keys, 99, header, ciphertext, output,
                              std::span(scratch).first(30));
    check(!small && small.error() == protection_error::output_too_small);
    small = open_payload(context, *keys, 99, header, ciphertext,
                         std::span(output).first(30), scratch);
    check(!small && small.error() == protection_error::output_too_small);
    small = seal_payload(context, *keys, 99, header, message,
                         std::span(ciphertext).first(46));
    check(!small && small.error() == protection_error::output_too_small);
    small = open_payload(context, *keys, 99, header, ciphertext, output, output);
    check(!small && small.error() == protection_error::invalid_input);
    std::array<std::uint8_t, 64> packet {}, hp_reference {};
    packet[0] = 0x43;
    for (unsigned i = 0; i < 100; ++i) {
        const auto original = packet;
        hp_reference = packet;
        check(apply_aes_header_protection(context, *keys, packet, 1, false).has_value());
        check(apply_aes_header_protection(*keys, hp_reference, 1, false).has_value());
        check(packet == hp_reference);
        check(apply_aes_header_protection(context, *keys, packet, 1, true).has_value());
        check(packet == original);
    }
    std::array<std::uint8_t, 128> packet_scratch {}, auth_scratch {}, build_scratch {}, frames {};
    const std::array<std::uint8_t, 3> ping {1, 0, 0};
    protected_packet_fields fields;
    fields.kind = packet_kind::short_header;
    fields.packet_number = 7;
    auto built = build_protected_packet(context, fields, *keys, ping, packet, build_scratch);
    check(built.has_value());
    auto ref = build_protected_packet(fields, *keys, ping, hp_reference, build_scratch);
    check(ref == built && packet == hp_reference);
    auto opened = open_protected_packet(context, std::span(packet).first(*built), 0, 0,
        version_1, *keys, {}, packet_scratch, frames, auth_scratch);
    check(opened && opened->packet_number == 7 && opened->plaintext_size == 3);
    check(std::equal(ping.begin(), ping.end(), frames.begin()));
    packet[*built - 1] ^= 1;
    frames.fill(0xcc);
    opened = open_protected_packet(context, std::span(packet).first(*built), 0, 0,
        version_1, *keys, {}, packet_scratch, frames, auth_scratch);
    check(!opened && opened.error() == protected_packet_error::authentication_failed);
    check(std::ranges::all_of(frames, [](auto v) { return v == 0xcc; }));
    packet[*built - 1] ^= 1;
    opened = open_protected_packet(context, std::span(packet).first(*built), 0, 0,
        version_1, *keys, {}, packet_scratch, frames, std::span(auth_scratch).first(2));
    check(!opened && opened.error() == protected_packet_error::output_too_small);
    opened = open_protected_packet(context, std::span(packet).first(*built), 0, 0,
        version_1, *keys, {}, packet_scratch, frames, auth_scratch);
    check(opened.has_value());
    std::array<std::uint8_t, 16> empty_cipher {};
    check(seal_payload(context, *keys, 101, {}, {}, empty_cipher).has_value());
    check(open_payload(context, *keys, 101, {}, empty_cipher, {}, {}).has_value());
    bool wrong_thread = false;
    std::thread other([&] { wrong_thread = !context.ready(); });
    other.join();
    check(wrong_thread && context.ready());
}
