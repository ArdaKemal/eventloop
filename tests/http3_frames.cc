#include "http3/frames.h"

#include <array>
#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {
using namespace eventloop::http3::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP/3 frames: " << message << '\n';
    std::exit(1);
}

auto framing() -> void
{
    std::array<std::byte, 64> output {};
    constexpr std::array payload {std::byte {0x12}, std::byte {0x34}};
    const auto written = encode_frame(headers_frame, payload, output);
    check(written && *written == 4, "HEADERS encoded size");
    check(output[0] == std::byte {1} && output[1] == std::byte {2},
          "type and length wire bytes");
    const auto frame = decode_frame(output, 2);
    check(frame && frame->type == headers_frame && frame->encoded_size == 4 &&
              frame->payload.size() == 2 && frame->payload.data() == output.data() + 2 &&
              frame->payload[1] == payload[1], "borrowed payload and trailing bytes");
    check(decode_frame(output, 1).error() == frame_error::payload_too_large,
          "explicit receive bound");
    for (std::size_t length = 0; length < 4; ++length)
        check(decode_frame(std::span<const std::byte>(output).first(length), 2).error() ==
                  frame_error::incomplete_input, "every truncated frame prefix");

    const auto empty = encode_frame(data_frame, {}, output);
    check(empty && *empty == 2 && decode_frame(output, 0)->payload.empty(),
          "empty DATA");
    const auto extension = encode_frame(0x21, payload, output);
    check(extension && decode_frame(output, 2)->type == 0x21 &&
              !known_frame_type(0x21), "ignorable grease extension");
    check(encode_frame(0x1234, payload, output).has_value() &&
              decode_frame(output, 2)->type == 0x1234,
          "other unknown extension");

    constexpr auto maximum = eventloop::quic::detail::max_varint_value;
    const auto huge = encode_frame_header(maximum, maximum, output);
    check(huge && *huge == 16, "maximum header size");
    const auto header = decode_frame_header(output);
    check(header && header->payload_size == maximum && header->type == maximum,
          "header can be decoded without buffering declared payload");
    check(decode_frame(output, 1024).error() == frame_error::payload_too_large,
          "maximum length checked before narrowing");
    for (std::size_t length = 0; length < 16; ++length)
        check(decode_frame_header(std::span<const std::byte>(output).first(length)).error() ==
                  frame_error::incomplete_input, "truncated multibyte header");

    // QUIC varints need not use their shortest encoding on receive.
    constexpr std::array nonminimal {std::byte {0x40}, std::byte {0x00},
                                    std::byte {0x40}, std::byte {0x00}};
    check(decode_frame(nonminimal, 0)->encoded_size == 4,
          "nonminimal header integers");
    for (const auto type : {2u, 6u, 8u, 9u}) {
        const std::array forbidden {static_cast<std::byte>(type), std::byte {0}};
        check(decode_frame(forbidden, 0).error() == frame_error::forbidden_frame_type,
              "reserved HTTP/2 frame is an error");
    }

    output.fill(std::byte {0xaa});
    const auto saved = output;
    check(encode_frame_header(maximum + 1, 0, output).error() ==
              frame_error::value_out_of_range && output == saved,
          "invalid type preserves output");
    check(encode_frame_header(0, maximum + 1, output).error() ==
              frame_error::value_out_of_range && output == saved,
          "invalid length preserves output");
    check(encode_frame_header(maximum, maximum,
                             std::span<std::byte>(output).first(15)).error() ==
              frame_error::output_too_small && output == saved,
          "short header output is atomic");
    check(encode_frame(headers_frame, payload,
                       std::span<std::byte>(output).first(3)).error() ==
              frame_error::output_too_small && output == saved,
          "short full-frame output is atomic");
    check(encode_frame(2, payload, output).error() ==
              frame_error::forbidden_frame_type && output == saved,
          "forbidden frame encoding is atomic");
    output[0] = payload[0];
    output[1] = payload[1];
    check(encode_frame(data_frame, std::span<const std::byte>(output).first(2), output) &&
              output[2] == payload[0] && output[3] == payload[1],
          "overlapping payload encoding");
}

auto settings() -> void
{
    constexpr std::array entries {setting {qpack_max_table_capacity, 0},
                                 setting {qpack_blocked_streams, 0},
                                 setting {max_field_section_size, 65536},
                                 setting {0x21, 42}, setting {0x1234, 99}};
    std::array<std::byte, 128> output {};
    const auto written = encode_settings(entries, output, entries.size());
    check(written.has_value(), "SETTINGS encode");
    const auto payload = std::span<const std::byte>(output).first(*written);
    const auto valid = validate_settings(payload, entries.size());
    check(valid && *valid == entries.size(), "SETTINGS validate");
    settings_iterator cursor(payload);
    for (const auto expected : entries) {
        const auto item = cursor.next();
        check(item && *item && (**item).identifier == expected.identifier &&
                  (**item).value == expected.value, "SETTINGS iteration");
    }
    const auto end = cursor.next();
    check(end && !*end, "SETTINGS iterator end");
    check(validate_settings({}, 0) && *validate_settings({}, 0) == 0,
          "empty SETTINGS allowed");
    check(validate_settings(payload, entries.size() - 1).error() ==
              frame_error::too_many_settings, "unknown settings count toward bound");
    constexpr std::array odd {std::byte {1}};
    check(validate_settings(odd, 8).error() == frame_error::incomplete_input,
          "missing setting value");
    settings_iterator truncated(odd);
    check(truncated.next().error() == frame_error::incomplete_input &&
              truncated.next().error() == frame_error::incomplete_input,
          "failed iteration does not consume input");
    constexpr std::array incomplete {std::byte {1}, std::byte {0x40}};
    check(validate_settings(incomplete, 8).error() == frame_error::incomplete_input,
          "truncated multibyte setting value");
    constexpr std::array duplicate {std::byte {0x21}, std::byte {0},
                                   std::byte {0x40}, std::byte {0x21}, std::byte {1}};
    check(validate_settings(duplicate, 8).error() == frame_error::duplicate_setting,
          "duplicate unknown identifier with different integer encoding");
    for (const auto id : {2u, 3u, 4u, 5u}) {
        const std::array reserved {static_cast<std::byte>(id), std::byte {0}};
        check(validate_settings(reserved, 8).error() == frame_error::forbidden_setting,
              "reserved HTTP/2 setting is an error");
    }

    output.fill(std::byte {0xaa});
    const auto saved = output;
    const std::array duplicates {setting {0x21, 0}, setting {0x21, 1}};
    check(encode_settings(duplicates, output, 8).error() ==
              frame_error::duplicate_setting && output == saved,
          "duplicate encoding is atomic");
    const std::array forbidden {setting {2, 0}};
    check(encode_settings(forbidden, output, 8).error() ==
              frame_error::forbidden_setting && output == saved,
          "forbidden setting encoding is atomic");
    const std::array invalid {setting {1, eventloop::quic::detail::max_varint_value + 1}};
    check(encode_settings(invalid, output, 8).error() ==
              frame_error::value_out_of_range && output == saved,
          "invalid setting value encoding is atomic");
    check(encode_settings(entries, std::span<std::byte>(output).first(2), 8).error() ==
              frame_error::output_too_small && output == saved,
          "short SETTINGS output is atomic");
    check(encode_settings(entries, output, 1).error() ==
              frame_error::too_many_settings && output == saved,
          "encoding count bound");
}
} // namespace

auto main() -> int
{
    framing();
    settings();
}
