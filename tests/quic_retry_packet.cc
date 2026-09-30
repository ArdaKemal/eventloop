#include "quic/retry_packet.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <string_view>
#include <vector>

using namespace eventloop::quic::detail;
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); std::abort(); } } while (false)

auto hex(std::string_view s) -> std::vector<std::uint8_t>
{
    std::vector<std::uint8_t> result;
    for (std::size_t i = 0; i < s.size(); i += 2) {
        const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        result.push_back(static_cast<std::uint8_t>(digit(s[i]) * 16 + digit(s[i + 1])));
    }
    return result;
}

int main()
{
    const auto odcid = hex("8394c8f03e515708");
    const auto scid = hex("f067a5502a4262b5");
    const auto token = hex("746f6b656e");
    const auto v1 = hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
    const auto v2 = hex("cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6");
    std::array<std::uint8_t, 128> scratch {}, output {};
    for (const auto& [version, vector] :
         {std::pair{version_1, v1}, std::pair{version_2, v2}}) {
        const auto parsed = parse_and_validate_retry_packet(vector, version, odcid);
        CHECK(parsed && parsed->token.size() == 5 && parsed->destination_cid.empty());
        CHECK(std::ranges::equal(parsed->source_cid, std::as_bytes(std::span(scid))));
        const auto built = build_retry_packet(version, odcid, {}, scid, token, scratch, output);
        CHECK(built && *built == vector.size());
        CHECK(output[0] == (version == version_1 ? 0xf0 : 0xc0));
        CHECK(parse_and_validate_retry_packet(std::span(output).first(*built), version, odcid));
        CHECK(parse_and_validate_retry_packet(vector, version == version_1 ? version_2 : version_1,
                                              odcid).error() == protection_error::invalid_input);
        auto wrong = odcid;
        wrong[0] ^= 1;
        CHECK(parse_and_validate_retry_packet(vector, version, wrong).error() ==
              protection_error::authentication_failed);
        for (const auto position : {std::size_t{7}, vector.size() - 17, vector.size() - 1}) {
            auto damaged = vector;
            damaged[position] ^= 1;
            CHECK(!parse_and_validate_retry_packet(damaged, version, odcid));
        }
        for (std::size_t n = 0; n < vector.size(); ++n)
            CHECK(!parse_and_validate_retry_packet(std::span(vector).first(n), version, odcid));
        auto wrong_type = vector;
        wrong_type[0] ^= 0x10;
        CHECK(!parse_and_validate_retry_packet(wrong_type, version, odcid));
        auto appended = vector;
        appended.push_back(0);
        CHECK(!parse_and_validate_retry_packet(appended, version, odcid));
    }
    output.fill(0xa5);
    scratch.fill(0xb6);
    const auto saved_output = output;
    const auto saved_scratch = scratch;
    const auto invalid = [&](std::uint32_t version, std::span<const std::uint8_t> original,
                             std::span<const std::uint8_t> client,
                             std::span<const std::uint8_t> server,
                             std::span<const std::uint8_t> opaque) {
        CHECK(!build_retry_packet(version, original, client, server, opaque, scratch, output));
        CHECK(output == saved_output && scratch == saved_scratch);
    };
    std::array<std::uint8_t, 21> long_cid {};
    invalid(0, odcid, {}, scid, token);
    invalid(version_1, long_cid, {}, scid, token);
    invalid(version_1, odcid, long_cid, scid, token);
    invalid(version_1, odcid, {}, long_cid, token);
    invalid(version_1, odcid, {}, odcid, token);
    invalid(version_1, odcid, {}, scid, {});
    invalid(version_1, {}, {}, {}, token);
    CHECK(!build_retry_packet(version_1, odcid, {}, scid, token, scratch,
                              std::span(output).first(35)));
    CHECK(output == saved_output && scratch == saved_scratch);
    CHECK(!build_retry_packet(version_1, odcid, {}, scid, token,
                              std::span(scratch).first(35), output));
    CHECK(!build_retry_packet(version_1, odcid, {}, scid, token, output, output));
    CHECK(!build_retry_packet(version_1, odcid, {}, scid,
                              std::span(scratch).first(5), scratch, output));
    CHECK(!build_retry_packet(version_1, odcid, {}, scid,
                              std::span(output).first(5), scratch, output));
    CHECK(output == saved_output && scratch == saved_scratch);

    std::array<std::uint8_t, 20> cid20 {};
    cid20.fill(3);
    std::vector<std::uint8_t> big_token(65527 - 63, 7);
    std::vector<std::uint8_t> big_scratch(65527), big_output(65527);
    CHECK(build_retry_packet(version_2, odcid, cid20, cid20, big_token,
                              big_scratch, big_output).value() == 65527);
    CHECK(parse_and_validate_retry_packet(big_output, version_2, odcid));
    big_token.push_back(7);
    const auto saved_big = big_output;
    CHECK(!build_retry_packet(version_2, odcid, cid20, cid20, big_token,
                              big_scratch, big_output));
    CHECK(big_output == saved_big);
    big_output.push_back(0);
    CHECK(!parse_and_validate_retry_packet(big_output, version_2, odcid));
    CHECK(!parse_and_validate_retry_packet(v1, 0, odcid));
    CHECK(!parse_and_validate_retry_packet(v1, version_1, long_cid));

    // An otherwise authenticated empty token remains inadmissible.
    auto empty_token = hex("f0000000010008f067a5502a4262b5");
    const auto tag = generate_retry_integrity_tag(version_1, odcid, empty_token);
    CHECK(tag);
    empty_token.insert(empty_token.end(), tag->begin(), tag->end());
    CHECK(!parse_and_validate_retry_packet(empty_token, version_1, odcid));
}
