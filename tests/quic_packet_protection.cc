#include "quic/packet_protection.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
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

auto hex(std::string_view text) -> std::vector<std::uint8_t>
{
    auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
        CHECK(false);
        return 0;
    };
    std::vector<std::uint8_t> result;
    for (std::size_t i = 0; i < text.size(); i += 2) {
        result.push_back(static_cast<std::uint8_t>(
            (nibble(text[i]) << 4) | nibble(text[i + 1])));
    }
    return result;
}

template<std::size_t N>
auto equal(const std::array<std::uint8_t, N>& bytes, std::string_view expected)
    -> bool
{
    const auto decoded = hex(expected);
    return std::equal(bytes.begin(), bytes.end(), decoded.begin(), decoded.end());
}

} // namespace

int main()
{
    // RFC 9001 Appendix A.1.
    const auto dcid = hex("8394c8f03e515708");
    const auto initial = derive_initial_secrets(version_1, dcid);
    CHECK(initial);
    CHECK(equal(initial->client,
        "c00cf151ca5be075ed0ebfb5c80323c4"
        "2d6b7db67881289af4008f1f6c357aea"));
    CHECK(equal(initial->server,
        "3c199828fd139efd216c155ad844cc81"
        "fb82fa8d7446fa7d78be803acdda951b"));
    const auto client = derive_aes_128_gcm_keys(version_1, initial->client);
    const auto server = derive_aes_128_gcm_keys(version_1, initial->server);
    CHECK(client && server);
    CHECK(equal(client->key, "1f369613dd76d5467730efcbe3b1a22d"));
    CHECK(equal(client->iv, "fa044b2f42a3fd3b46fb255c"));
    CHECK(equal(client->hp, "9f50449e04a0e810283a1e9933adedd2"));
    CHECK(equal(server->key, "cf3a5331653c364c88f0f379b6067e37"));
    CHECK(equal(server->iv, "0ac1493ca1905853b0bba03e"));
    CHECK(equal(server->hp, "c206b8d9b9f0f37644430b490eeaa314"));

    // RFC 9001 Appendix A.3, complete server Initial packet.
    const auto header = hex("c1000000010008f067a5502a4262b50040750001");
    const auto plaintext = hex(
        "02000000000600405a020000560303ee"
        "fce7f7b37ba1d1632e96677825ddf739"
        "88cfc79825df566dc5430b9a045a1200"
        "130100002e00330024001d00209d3c94"
        "0d89690b84d08a60993c144eca684d10"
        "81287c834d5311bcf32bb9da1a002b00"
        "020304");
    const auto protected_packet = hex(
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
        "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"
        "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
        "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"
        "2158407dd074ee");
    std::vector<std::uint8_t> ciphertext(plaintext.size() + 16);
    const auto sealed = seal_payload(*server, 1, header, plaintext, ciphertext);
    CHECK(sealed && *sealed == ciphertext.size());
    auto packet = header;
    packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
    const auto protected_length = apply_aes_header_protection(*server, packet, 18, false);
    CHECK(protected_length && *protected_length == 2);
    CHECK(packet == protected_packet);
    const auto unprotected_length = apply_aes_header_protection(*server, packet, 18, true);
    CHECK(unprotected_length && *unprotected_length == 2);
    CHECK(std::equal(header.begin(), header.end(), packet.begin()));
    std::vector<std::uint8_t> opened(plaintext.size(), 0xa5);
    const auto decrypted = open_payload(
        *server, 1, header, std::span(packet).subspan(header.size()), opened);
    CHECK(decrypted && *decrypted == plaintext.size() && opened == plaintext);

    // Authentication, capacity, sample, version, secret, and number bounds.
    auto tampered = ciphertext;
    tampered.back() ^= 1;
    std::fill(opened.begin(), opened.end(), std::uint8_t{0xa5});
    CHECK(open_payload(*server, 1, header, tampered, opened).error() ==
           protection_error::authentication_failed);
    CHECK(std::all_of(opened.begin(), opened.end(),
                       [](std::uint8_t byte) { return byte == 0xa5; }));
    auto bad_header = header;
    bad_header[5] ^= 1;
    CHECK(open_payload(*server, 1, bad_header, ciphertext, opened).error() ==
           protection_error::authentication_failed);
    CHECK(open_payload(*server, 2, header, ciphertext, opened).error() ==
           protection_error::authentication_failed);
    CHECK(seal_payload(*server, 1, header, plaintext,
                        std::span(ciphertext).first(ciphertext.size() - 1)).error() ==
           protection_error::output_too_small);
    CHECK(open_payload(*server, 1, header, ciphertext,
                        std::span(opened).first(opened.size() - 1)).error() ==
           protection_error::output_too_small);
    CHECK(apply_aes_header_protection(*server,
                                      std::span(packet).first(37), 18, true).error() ==
           protection_error::invalid_input);
    CHECK(apply_aes_header_protection(*server, packet, 0, true).error() ==
           protection_error::invalid_input);
    CHECK(derive_initial_secrets(0, dcid).error() ==
           protection_error::unsupported_version);
    CHECK(derive_aes_128_gcm_keys(version_1,
                                  std::span(initial->client).first(31)).error() ==
           protection_error::invalid_input);
    CHECK(seal_payload(*server, max_packet_number + 1, header,
                        plaintext, ciphertext).error() ==
           protection_error::invalid_input);

    // Empty payloads and associated data still produce and authenticate a tag.
    std::array<std::uint8_t, 16> empty_ciphertext {};
    CHECK(seal_payload(*server, 0, {}, {}, empty_ciphertext).value() == 16);
    CHECK(open_payload(*server, 0, {}, empty_ciphertext, {}).value() == 0);
    empty_ciphertext.back() ^= 1;
    CHECK(open_payload(*server, 0, {}, empty_ciphertext, {}).error() ==
          protection_error::authentication_failed);
    CHECK(derive_initial_secrets(version_1, {}));

    // The maximum protected datagram fits the bounded authentication scratch.
    std::vector<std::uint8_t> maximum_plaintext(65511, 0x5a);
    std::vector<std::uint8_t> maximum_ciphertext(65527);
    std::vector<std::uint8_t> maximum_opened(65511);
    CHECK(seal_payload(*server, max_packet_number, header, maximum_plaintext,
                       maximum_ciphertext).value() == maximum_ciphertext.size());
    CHECK(open_payload(*server, max_packet_number, header, maximum_ciphertext,
                       maximum_opened).value() == maximum_plaintext.size());
    CHECK(maximum_opened == maximum_plaintext);
    std::vector<std::uint8_t> oversized_header(65528);
    CHECK(seal_payload(*server, 0, oversized_header, {}, empty_ciphertext).error() ==
          protection_error::invalid_input);
    CHECK(open_payload(*server, 0, oversized_header, empty_ciphertext, {}).error() ==
          protection_error::invalid_input);

    // RFC 9000 Appendix A.3 and wraparound cases.
    CHECK(reconstruct_packet_number(0x9b32, 2, 0xa82f30ea).value() ==
           0xa82f9b32);
    CHECK(reconstruct_packet_number(0xff, 1, 0xff).value() == 0xff);
    CHECK(reconstruct_packet_number(0, 1, 0xff).value() == 0x100);
    CHECK(reconstruct_packet_number(0, 0, std::nullopt).error() ==
           protection_error::invalid_input);

    // v2 uses a different salt and packet-protection labels (RFC 9369).
    const auto v2 = derive_initial_secrets(version_2, dcid);
    CHECK(v2);
    CHECK(equal(v2->client,
        "14ec9d6eb9fd7af83bf5a668bc17a7e2"
        "83766aade7ecd0891f70f9ff7f4bf47b"));
    CHECK(equal(v2->server,
        "0263db1782731bf4588e7e4d93b74639"
        "07cb8cd8200b5da55a8bd488eafc37c1"));
    const auto v2_keys = derive_aes_128_gcm_keys(version_2, v2->client);
    CHECK(v2_keys);
    CHECK(equal(v2_keys->key, "8b1a0bc121284290a29e0971b5cd045d"));
    CHECK(equal(v2_keys->iv, "91f73e2351d8fa91660e909f"));
    CHECK(equal(v2_keys->hp, "45b95e15235d6f45a6b19cbcb0294ba9"));

    // RFC 9001 A.4 and RFC 9369 A.4 Retry packets.
    const auto retry_v1 = hex(
        "ff000000010008f067a5502a4262b5746f6b656e"
        "04a265ba2eff4d829058fb3f0f2496ba");
    const auto retry_v2 = hex(
        "cf6b3343cf0008f067a5502a4262b5746f6b656e"
        "c8646ce8bfe33952d955543665dcc7b6");
    for (const auto& [version, retry] :
         {std::pair{version_1, retry_v1}, std::pair{version_2, retry_v2}}) {
        const auto body = std::span(retry).first(retry.size() - 16);
        const auto tag = generate_retry_integrity_tag(version, dcid, body);
        CHECK(tag);
        CHECK(std::equal(tag->begin(), tag->end(), retry.end() - 16));
        CHECK(validate_retry_integrity_tag(version, dcid, retry));

        auto damaged_tag = retry;
        damaged_tag.back() ^= 1;
        CHECK(validate_retry_integrity_tag(version, dcid, damaged_tag).error() ==
              protection_error::authentication_failed);
        auto damaged_token = retry;
        damaged_token[retry.size() - 17] ^= 1;
        CHECK(validate_retry_integrity_tag(version, dcid, damaged_token).error() ==
              protection_error::authentication_failed);
        auto wrong_dcid = dcid;
        wrong_dcid[0] ^= 1;
        CHECK(validate_retry_integrity_tag(version, wrong_dcid, retry).error() ==
              protection_error::authentication_failed);
        CHECK(generate_retry_integrity_tag(version, wrong_dcid, body).value() != *tag);
        CHECK(validate_retry_integrity_tag(0, dcid, retry).error() ==
              protection_error::unsupported_version);

        auto wrong_type = retry;
        wrong_type[0] ^= 0x10;
        CHECK(validate_retry_integrity_tag(version, dcid, wrong_type).error() ==
              protection_error::invalid_input);
        auto bad_cid_length = retry;
        bad_cid_length[6] = 21;
        CHECK(validate_retry_integrity_tag(version, dcid, bad_cid_length).error() ==
              protection_error::invalid_input);
        CHECK(validate_retry_integrity_tag(version, dcid,
              std::span(retry).first(16)).error() == protection_error::invalid_input);
        auto oversized_retry = retry;
        oversized_retry.resize(65528, 0);
        CHECK(validate_retry_integrity_tag(version, dcid, oversized_retry).error() ==
              protection_error::invalid_input);
        CHECK(generate_retry_integrity_tag(version,
              std::vector<std::uint8_t>(21), body).error() ==
              protection_error::invalid_input);
    }
}
