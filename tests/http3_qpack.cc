#include "http3/qpack.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

using namespace eventloop::http3::detail;
namespace {
auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QPACK: " << message << '\n';
    std::exit(1);
}
auto hex(std::string_view digits) -> std::vector<std::byte>
{
    const auto nibble = [](char c) -> unsigned {
        return c <= '9' ? static_cast<unsigned>(c - '0') : static_cast<unsigned>(c - 'a' + 10);
    };
    std::vector<std::byte> result;
    for (std::size_t i = 0; i < digits.size(); i += 2)
        result.push_back(static_cast<std::byte>((nibble(digits[i]) << 4) | nibble(digits[i + 1])));
    return result;
}
struct decoder_storage {
    std::array<field, qpack_max_fields> fields {};
    std::array<char, qpack_max_field_list_size> strings {};
    auto decode(std::span<const std::byte> block) {
        return qpack_decode(block, fields, strings);
    }
};
auto vectors() -> void
{
    decoder_storage decoded;
    // RFC 9204 B.1, static name-reference literal.
    auto count = decoded.decode(hex("0000510b2f696e6465782e68746d6c"));
    check(count && *count == 1 && decoded.fields[0].name == ":path" &&
        decoded.fields[0].value == "/index.html", "RFC 9204 B.1");
    // HTTP/3 status, content-type and extended static-table indices.
    count = decoded.decode(hex("0000d9f5ff01ff23"));
    check(count && *count == 4 && decoded.fields[0].value == "200" &&
        decoded.fields[1].value == "text/plain" && decoded.fields[2].value == "204" &&
        decoded.fields[3].name == "x-frame-options" && decoded.fields[3].value == "sameorigin",
        "static table entries above six-bit prefix");
    // HPACK RFC 7541 C.4.1 Huffman alphabet reused by QPACK.
    count = decoded.decode(hex("0000508cf1e3c2e5f23a6ba0ab90f4ff"));
    check(count && decoded.fields[0].value == "www.example.com", "Huffman value");
    // RFC 7541 C.4.3 strings in QPACK's literal-name representation.
    count = decoded.decode(hex("00002f0125a849e95ba97d7f8925a849e95bb8e8b4bf"));
    check(count && decoded.fields[0].name == "custom-key" &&
        decoded.fields[0].value == "custom-value", "Huffman name and value");
    // N bits are accepted; nonzero Base is valid for static-only blocks.
    count = decoded.decode(hex("007f007000"));
    check(count && *count == 1 && decoded.fields[0].name == ":authority" &&
        decoded.fields[0].value.empty(), "nonzero base and never-index flag");
    check(decoded.decode(hex("0000")) == 0, "empty field section");
}
auto request_encoding() -> void
{
    const std::array<field, 5> request {{{":method", "GET"}, {":scheme", "https"},
        {":authority", "example.com"}, {":path", "/index.html"}, {"x-custom", "value"}}};
    std::array<std::byte, 1024> buffer {};
    const auto encoded = qpack_encode(request, buffer);
    check(encoded.has_value(), "request encode");
    const auto prefix = hex("0000d1d7500b6578616d706c652e636f6d510b2f696e6465782e68746d6c");
    check(std::equal(prefix.begin(), prefix.end(), buffer.begin()), "independent expected GET bytes");
    decoder_storage decoded;
    const auto count = decoded.decode(std::span(buffer).first(*encoded));
    check(count && *count == request.size(), "request field count");
    for (std::size_t i = 0; i < request.size(); ++i)
        check(decoded.fields[i].name == request[i].name && decoded.fields[i].value == request[i].value,
            "literal request round trip");
    const std::string long_value(300, 'a');
    const std::array<field, 1> long_field {{{"server", long_value}}};
    const auto long_encoded = qpack_encode(long_field, buffer);
    check(long_encoded.has_value(), "multibyte literal integer encoding");
    const auto long_count = decoded.decode(std::span(buffer).first(*long_encoded));
    check(long_count && decoded.fields[0].value == long_value, "multibyte literal integer decode");
    check(!qpack_encode(request, std::span(buffer).first(3)), "short encode storage");
}
auto reject_invalid_and_dynamic() -> void
{
    decoder_storage decoded;
    for (auto digits : {"", "00", "0080", "0000ff24", "00005002ff", "00005081ff",
            "00005084ffffffff", "0000508100", "00005fffffffffffffffffffff7f"})
        check(!decoded.decode(hex(digits)), "malformed/truncated/EOS/padding/overflow input");
    for (auto digits : {"0100d9", "000080", "00004000", "000010", "00000000"}) {
        const auto count = decoded.decode(hex(digits));
        check(!count && count.error() == qpack_error::dynamic_table_disabled,
            "dynamic references and insert count rejected");
    }
    check(qpack_validate_encoder_instructions(hex("2020")).has_value(), "zero capacities accepted");
    for (auto digits : {"21", "3f00", "c000", "4000", "00"}) {
        const auto result = qpack_validate_encoder_instructions(hex(digits));
        check(!result && result.error() == qpack_error::dynamic_table_disabled,
            "state-changing instructions rejected");
    }
    check(!qpack_validate_encoder_instructions(hex("3f")), "truncated instruction");
}
auto limits() -> void
{
    decoder_storage decoded;
    std::vector<std::byte> block {std::byte{0}, std::byte{0}};
    block.insert(block.end(), qpack_max_fields + 1, std::byte{0xd9});
    auto count = decoded.decode(block);
    check(!count && count.error() == qpack_error::limit_exceeded, "field count bound");
    const std::vector<std::byte> oversized_block(qpack_max_block_size + 1);
    count = decoded.decode(oversized_block);
    check(!count && count.error() == qpack_error::limit_exceeded, "block bound");
    const auto literal = hex("0000508cf1e3c2e5f23a6ba0ab90f4ff");
    std::array<char, 4> small {};
    count = qpack_decode(literal, decoded.fields, small);
    check(!count && count.error() == qpack_error::limit_exceeded, "decoded Huffman storage bound");
    count = qpack_decode(hex("0000d9"), {}, decoded.strings);
    check(!count && count.error() == qpack_error::limit_exceeded, "caller field slots bound");
    std::array<std::byte, qpack_max_block_size> wire {};
    // Wire fits the block bound, but per-field 32-byte overhead pushes the
    // decoded field section beyond its independent bound.
    const std::string large_value(qpack_max_field_list_size - 11, 'x');
    const std::array<field, 1> oversized {{{"server", large_value}}};
    check(!qpack_encode(oversized, wire), "encoder field-list overhead bound");
    std::vector<std::byte> large = hex("00005f4d7ff6fe03"); // server value length 65525
    large.insert(large.end(), large_value.size(), std::byte{'x'});
    count = decoded.decode(large);
    check(!count && count.error() == qpack_error::limit_exceeded, "decoder field-list overhead bound");
}
} // namespace
int main()
{
    vectors();
    request_encoding();
    reject_invalid_and_dynamic();
    limits();
    std::cout << "QPACK tests passed\n";
}
