#include "http2/hpack.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

using eventloop::http2::detail::field;
using eventloop::http2::detail::hpack_decoder;
using eventloop::http2::detail::hpack_encode;
using eventloop::http2::detail::hpack_error;
using eventloop::http2::detail::hpack_max_block_size;
using eventloop::http2::detail::hpack_max_fields;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HPACK: " << message << '\n';
    std::exit(1);
}

[[nodiscard]] auto hex(std::string_view digits) -> std::vector<std::byte>
{
    auto nibble = [](char value) -> unsigned {
        if (value >= '0' && value <= '9') return static_cast<unsigned>(value - '0');
        return static_cast<unsigned>(value - 'a' + 10);
    };
    check(digits.size() % 2 == 0, "bad test vector");
    std::vector<std::byte> result;
    for (std::size_t index = 0; index < digits.size(); index += 2) {
        result.push_back(static_cast<std::byte>(
            (nibble(digits[index]) << 4) | nibble(digits[index + 1])));
    }
    return result;
}

auto rfc_request_vectors() -> void
{
    // RFC 7541 Appendix C.4: Huffman literals, static indices, and a
    // persistent dynamic table shared by successive request blocks.
    hpack_decoder decoder;
    std::vector<field> fields;
    const auto first = hex("828684418cf1e3c2e5f23a6ba0ab90f4ff");
    check(decoder.decode(first, fields) == hpack_error::none, "C.4.1 decode");
    check(fields.size() == 4 && fields[0].name == ":method" &&
              fields[0].value == "GET" && fields[3].name == ":authority" &&
              fields[3].value == "www.example.com", "C.4.1 fields");

    const auto second = hex("828684be5886a8eb10649cbf");
    check(decoder.decode(second, fields) == hpack_error::none, "C.4.2 decode");
    check(fields.size() == 5 && fields[3].value == "www.example.com" &&
              fields[4].name == "cache-control" && fields[4].value == "no-cache",
          "C.4.2 dynamic index");

    const auto third = hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf");
    check(decoder.decode(third, fields) == hpack_error::none, "C.4.3 decode");
    check(fields.size() == 5 && fields[1].value == "https" &&
              fields[4].name == "custom-key" && fields[4].value == "custom-value",
          "C.4.3 fields");
}

auto malformed_and_limits() -> void
{
    std::vector<field> fields;
    for (const auto& input : {"80", "ff7f", "00017881fe", "00017884ffffffff"}) {
        hpack_decoder decoder;
        check(decoder.decode(hex(input), fields) == hpack_error::invalid,
              "invalid index or Huffman code accepted");
        check(fields.empty(), "failed decode retained fields");
    }

    hpack_decoder reduced;
    check(reduced.set_table_size_limit(0) == hpack_error::none,
          "set table limit");
    check(reduced.decode(hex("82"), fields) == hpack_error::invalid,
          "missing required table size update");
    hpack_decoder updated;
    check(updated.set_table_size_limit(0) == hpack_error::none,
          "set table limit again");
    check(updated.decode(hex("2082"), fields) == hpack_error::none &&
              fields.size() == 1, "zero-sized table update");
    check(updated.decode(hex("21"), fields) == hpack_error::invalid,
          "oversized table update accepted");

    hpack_decoder bounded;
    std::vector<std::byte> oversized(hpack_max_block_size + 1, std::byte {0});
    check(bounded.decode(oversized, fields) == hpack_error::limit_exceeded,
          "encoded block limit");
    std::vector<std::byte> many(hpack_max_fields + 1, std::byte {0x82});
    check(bounded.decode(many, fields) == hpack_error::limit_exceeded,
          "decoded field count limit");
}

auto encoder_round_trip() -> void
{
    const std::vector<field> source {
        {":status", "200"}, {"content-type", "text/plain"},
    };
    std::vector<std::byte> encoded;
    check(hpack_encode(source, encoded) == hpack_error::none,
          "encode response");
    hpack_decoder decoder;
    std::vector<field> decoded;
    check(decoder.decode(encoded, decoded) == hpack_error::none &&
              decoded.size() == source.size() &&
              decoded[0].name == source[0].name &&
              decoded[1].value == source[1].value,
          "encoder round trip");
    std::vector<field> too_many(hpack_max_fields + 1, field {"x", "y"});
    check(hpack_encode(too_many, encoded) == hpack_error::limit_exceeded,
          "encoder field count limit");
}

} // namespace

int main()
{
    rfc_request_vectors();
    malformed_and_limits();
    encoder_round_trip();
}
