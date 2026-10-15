#include "http3/webtransport_wire.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace {
using namespace eventloop::http3::detail;
using bytes = std::vector<std::byte>;
using parts = std::vector<std::span<const std::byte>>;

constexpr std::uint64_t max_varint = eventloop::quic::detail::max_varint_value;
constexpr std::uint64_t stream_limit = std::uint64_t {1} << 60;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP/3 WebTransport wire: " << message << '\n';
    std::exit(1);
}

auto make(std::initializer_list<unsigned> values) -> bytes
{
    bytes result;
    for (const auto value : values) result.push_back(static_cast<std::byte>(value));
    return result;
}

auto text(std::string_view value) -> bytes
{
    bytes result;
    for (const char c : value) result.push_back(static_cast<std::byte>(c));
    return result;
}

auto append(bytes& target, const bytes& more) -> void
{
    target.insert(target.end(), more.begin(), more.end());
}

auto varint(std::uint64_t value) -> bytes
{
    std::array<std::byte, 8> buffer {};
    const auto size = eventloop::quic::detail::encode_varint(value, buffer);
    check(size.has_value(), "test varint in range");
    return bytes(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*size));
}

auto capsule(std::uint64_t type, const bytes& value) -> bytes
{
    bytes result = varint(type);
    append(result, varint(value.size()));
    append(result, value);
    return result;
}

// Encodes with a caller-supplied encoder into a buffer large enough for any test.
template <typename Encode>
auto encoded(Encode encode) -> bytes
{
    std::array<std::byte, 2048> output {};
    const auto size = encode(std::span<std::byte>(output));
    check(size.has_value(), "encoder accepted value");
    return bytes(output.begin(), output.begin() + static_cast<std::ptrdiff_t>(*size));
}

auto describe(const capsule_event& event) -> std::string
{
    if (const auto* close = std::get_if<wt_close_session>(&event))
        return "close " + std::to_string(close->code) + " " + std::string(close->message);
    if (std::holds_alternative<wt_drain_session>(event)) return "drain";
    if (const auto* data = std::get_if<wt_max_data>(&event))
        return "max_data " + std::to_string(data->maximum);
    if (const auto* data = std::get_if<wt_data_blocked>(&event))
        return "data_blocked " + std::to_string(data->maximum);
    if (const auto* streams = std::get_if<wt_max_streams>(&event))
        return std::string(streams->bidirectional ? "max_streams_bidi " : "max_streams_uni ") +
               std::to_string(streams->maximum);
    if (const auto* streams = std::get_if<wt_streams_blocked>(&event))
        return std::string(streams->bidirectional ? "streams_blocked_bidi "
                                                  : "streams_blocked_uni ") +
               std::to_string(streams->maximum);
    const auto& datagram = std::get<wt_datagram>(event);
    if (datagram.payload.empty()) return "datagram:";
    return "datagram:" + std::string(reinterpret_cast<const char*>(datagram.payload.data()),
                                     datagram.payload.size());
}

struct outcome {
    std::vector<std::string> events;
    std::optional<wt_error> error;

    bool operator==(const outcome&) const = default;
};

auto expect_events(std::vector<std::string> events) -> outcome
{
    return outcome {std::move(events), std::nullopt};
}

auto expect_error(std::vector<std::string> events, wt_error error) -> outcome
{
    return outcome {std::move(events), error};
}

// Drains every event the input yields. Returns false after recording an error.
auto feed(capsule_parser& parser, std::span<const std::byte> part, outcome& result) -> bool
{
    for (;;) {
        auto event = parser.next(part);
        if (!event) {
            result.error = event.error();
            return false;
        }
        if (!*event) return true;
        result.events.push_back(describe(**event));
    }
}

auto run_parts(const parts& pieces, bool flow_control = true,
               std::size_t max_datagram = 1232) -> outcome
{
    capsule_parser parser(flow_control, max_datagram);
    outcome result;
    for (const auto piece : pieces)
        if (!feed(parser, piece, result)) return result;
    if (const auto end = parser.finish(); !end) result.error = end.error();
    return result;
}

auto chunked(const bytes& wire, std::size_t chunk) -> parts
{
    parts result;
    const std::span<const std::byte> all(wire);
    for (std::size_t offset = 0; offset < all.size(); offset += chunk)
        result.push_back(all.subspan(offset, std::min(chunk, all.size() - offset)));
    return result;
}

auto cut_at(const bytes& wire, std::size_t cut) -> parts
{
    const std::span<const std::byte> all(wire);
    return {all.first(cut), all.subspan(cut)};
}

// The same wire bytes must give the same result however they are fragmented:
// whole, every chunk size up to 16, and every two-piece split.
auto check_fragmentation(const bytes& wire, const outcome& want, std::string_view label,
                         bool flow_control = true, std::size_t max_datagram = 1232) -> void
{
    const auto same = [&](const outcome& got) { return got == want; };
    check(same(run_parts(chunked(wire, std::max<std::size_t>(wire.size(), 1)), flow_control,
                         max_datagram)),
          label);
    for (std::size_t chunk = 1; chunk <= std::min<std::size_t>(wire.size(), 16); ++chunk)
        check(same(run_parts(chunked(wire, chunk), flow_control, max_datagram)), label);
    for (std::size_t cut = 0; cut <= wire.size(); ++cut)
        check(same(run_parts(cut_at(wire, cut), flow_control, max_datagram)), label);
}

auto constants() -> void
{
    check(webtransport_uni_stream_type == 0x54 && webtransport_bidi_signal == 0x41,
          "stream type and signal codepoints");
    check(wt_enabled_setting == 0x2c7cf000 && wt_initial_max_data_setting == 0x2b61 &&
              wt_initial_max_streams_uni_setting == 0x2b64 &&
              wt_initial_max_streams_bidi_setting == 0x2b65,
          "WebTransport settings codepoints");
    check(datagram_capsule == 0x00 && wt_close_session_capsule == 0x2843 &&
              wt_drain_session_capsule == 0x78ae && wt_max_data_capsule == 0x190b4d3d &&
              wt_max_stream_data_capsule == 0x190b4d3e &&
              wt_max_streams_bidi_capsule == 0x190b4d3f &&
              wt_max_streams_uni_capsule == 0x190b4d40 &&
              wt_data_blocked_capsule == 0x190b4d41 &&
              wt_stream_data_blocked_capsule == 0x190b4d42 &&
              wt_streams_blocked_bidi_capsule == 0x190b4d43 &&
              wt_streams_blocked_uni_capsule == 0x190b4d44,
          "capsule codepoints");
    check(static_cast<std::uint64_t>(wt_error::h3_datagram_error) == 0x33 &&
              static_cast<std::uint64_t>(wt_error::h3_message_error) == 0x10e &&
              static_cast<std::uint64_t>(wt_error::h3_id_error) == 0x108 &&
              static_cast<std::uint64_t>(wt_error::wt_flow_control_error) == 0x045d4487 &&
              static_cast<std::uint64_t>(wt_error::wt_session_gone) == 0x170d7b68 &&
              static_cast<std::uint64_t>(wt_error::wt_buffered_stream_rejected) == 0x3994bd84 &&
              static_cast<std::uint64_t>(wt_error::wt_alpn_error) == 0x0817b3dd &&
              static_cast<std::uint64_t>(wt_error::wt_requirements_not_met) == 0x212c0d48,
          "error codepoints");
    check(stream_limit == (std::uint64_t {1} << 60) && wt_max_quarter_stream_id == max_varint / 4,
          "stream limits");
}

auto session_ids() -> void
{
    check(valid_session_id(0) && valid_session_id(4) && valid_session_id(64) &&
              valid_session_id((std::uint64_t {1} << 62) - 4),
          "client bidi IDs are valid session IDs");
    check(!valid_session_id(1) && !valid_session_id(2) && !valid_session_id(3) &&
              !valid_session_id(6) && !valid_session_id(7),
          "non-bidi or non-client IDs are invalid");
    check(!valid_session_id(std::uint64_t {1} << 62) && !valid_session_id(max_varint),
          "IDs above the varint range are invalid");
}

auto stream_headers() -> void
{
    std::array<std::byte, 16> output {};
    // 0x54 and 0x41 both exceed 63, so each is a two-byte varint.
    const auto uni = encode_stream_header(true, 0, output);
    check(uni && *uni == 3 && output[0] == std::byte {0x40} && output[1] == std::byte {0x54} &&
              output[2] == std::byte {0x00},
          "unidirectional header bytes");
    const auto bidi = encode_stream_header(false, 4, output);
    check(bidi && *bidi == 3 && output[0] == std::byte {0x40} && output[1] == std::byte {0x41} &&
              output[2] == std::byte {0x04},
          "bidirectional header bytes");
    const auto large = encode_stream_header(true, (std::uint64_t {1} << 62) - 4, output);
    check(large && *large == 2 + 8, "maximum session ID uses eight bytes");
    check(encode_stream_header(true, 2, output).error() ==
              wt_encode_error::invalid_session_id,
          "invalid session ID is rejected");
    check(encode_stream_header(false, std::uint64_t {1} << 62, output).error() ==
              wt_encode_error::invalid_session_id,
          "session ID above varint range is rejected");

    // Type (2 bytes) plus session 0 (1 byte) needs three bytes; two is too few.
    std::array<std::byte, 3> small {};
    small.fill(std::byte {0xaa});
    const auto short_output = encode_stream_header(true, 0, std::span(small).first(2));
    check(short_output.error() == wt_encode_error::output_too_small,
          "stream header reports small output");
    check(small[0] == std::byte {0xaa} && small[1] == std::byte {0xaa} &&
              small[2] == std::byte {0xaa},
          "stream header leaves output unchanged on failure");
}

auto stream_header_parsing() -> void
{
    const std::array<std::uint64_t, 6> ids {0, 4, 64, 16384, std::uint64_t {1} << 30,
                                            (std::uint64_t {1} << 62) - 4};
    for (const auto id : ids) {
        for (const bool unidirectional : {true, false}) {
            std::array<std::byte, 16> header {};
            const auto size = encode_stream_header(unidirectional, id, header);
            check(size.has_value(), "encode header for parsing");
            bytes wire(header.begin(), header.begin() + static_cast<std::ptrdiff_t>(*size));
            // The caller consumed the type or signal (two bytes, as both exceed 63).
            // The parser sees only the session ID that follows.
            const auto prefix = std::size_t {2};
            const auto id_size = wire.size() - prefix;
            append(wire, text("body"));
            const std::span<const std::byte> session_bytes = std::span<const std::byte>(wire).subspan(prefix);

            // One byte at a time: the ID completes on its last byte.
            stream_header_parser bytewise;
            std::optional<std::uint64_t> found;
            for (std::size_t index = 0; index < id_size; ++index) {
                std::span<const std::byte> piece = session_bytes.subspan(index, 1);
                const auto result = bytewise.feed(piece);
                check(result.has_value(), "bytewise header has no error");
                check(piece.empty(), "single byte consumed");
                found = *result;
                check(found.has_value() == (index + 1 == id_size),
                      "ID appears only once the header is complete");
            }
            check(found == id && bytewise.complete() && bytewise.consumed() == id_size,
                  "bytewise header ID and length");

            // Whole buffer: body bytes remain in the caller's span.
            stream_header_parser whole;
            std::span<const std::byte> view = session_bytes;
            const auto result = whole.feed(view);
            check(result && *result == id && whole.consumed() == id_size &&
                      view.size() == 4 && view.front() == std::byte {'b'},
                  "body bytes are left after the header");
            // Feeding a completed parser returns the same ID and consumes nothing.
            std::span<const std::byte> more = session_bytes;
            const auto again = whole.feed(more);
            check(again && *again == id && more.size() == session_bytes.size(),
                  "completed parser consumes nothing further");
        }
    }

    // Non-minimal varint (session 4 in two bytes) is accepted.
    const auto nonminimal = make({0x40, 0x04});
    stream_header_parser parser;
    std::span<const std::byte> view(nonminimal);
    const auto result = parser.feed(view);
    check(result && *result == 4 && parser.consumed() == 2, "non-minimal session ID");


    // A non-bidi or client-invalid session ID is H3_ID_ERROR.
    const auto odd = make({0x01});
    stream_header_parser odd_parser;
    std::span<const std::byte> odd_view(odd);
    check(odd_parser.feed(odd_view).error() == wt_error::h3_id_error,
          "session ID 1 is H3_ID_ERROR");
    const auto two = make({0x40, 0x02});
    stream_header_parser two_parser;
    std::span<const std::byte> first(two.data(), 1);
    const auto partial = two_parser.feed(first);
    check(partial && !*partial && first.empty(), "partial invalid ID waits");
    std::span<const std::byte> rest(two.data() + 1, 1);
    check(two_parser.feed(rest).error() == wt_error::h3_id_error,
          "invalid ID completed bytewise is H3_ID_ERROR");
}

auto datagrams() -> void
{
    const auto payload = text("abc");
    bytes wire = varint(0);
    append(wire, payload);
    const auto zero = parse_http_datagram(wire);
    check(zero && zero->session_id == 0 && zero->payload.size() == 3 &&
              zero->payload.data() == wire.data() + 1,
          "quarter 0 is session 0 and payload borrows input");

    bytes four = varint(1);
    append(four, text("x"));
    const auto one = parse_http_datagram(four);
    check(one && one->session_id == 4 && one->payload.size() == 1,
          "quarter 1 is session 4");

    bytes maximum = varint(stream_limit - 1);
    append(maximum, text("p"));
    const auto top = parse_http_datagram(maximum);
    check(top && top->session_id == (std::uint64_t {1} << 62) - 4 && top->payload.size() == 1,
          "quarter 2^60-1 is accepted");

    check(parse_http_datagram(varint(stream_limit)).error() == wt_error::h3_datagram_error,
          "quarter 2^60 is H3_DATAGRAM_ERROR");
    check(parse_http_datagram(varint(max_varint)).error() == wt_error::h3_datagram_error,
          "largest quarter is H3_DATAGRAM_ERROR");
    check(parse_http_datagram(make({0x80})).error() == wt_error::h3_datagram_error,
          "truncated varint is H3_DATAGRAM_ERROR");
    check(parse_http_datagram({}).error() == wt_error::h3_datagram_error,
          "empty datagram is H3_DATAGRAM_ERROR");

    const auto empty = parse_http_datagram(varint(3));
    check(empty && empty->payload.empty(), "empty payload is valid");

    std::array<std::byte, 8> output {};
    const auto prefix = encode_http_datagram_prefix(4, output);
    check(prefix && *prefix == 1 && output[0] == std::byte {1}, "datagram prefix for session 4");
    check(encode_http_datagram_prefix(2, output).error() == wt_encode_error::invalid_session_id,
          "datagram prefix rejects invalid session");
    std::span<std::byte> none;
    check(encode_http_datagram_prefix(4, none).error() == wt_encode_error::output_too_small,
          "datagram prefix reports small output");
    const auto big = encode_http_datagram_prefix((std::uint64_t {1} << 62) - 4, output);
    check(big && *big == 8, "maximum datagram prefix is eight bytes");
}

auto encoder_round_trips() -> void
{
    check(encoded([](auto out) { return encode_drain_session(out); }) ==
              make({0x80, 0x00, 0x78, 0xae, 0x00}),
          "drain capsule bytes");
    check(encoded([](auto out) { return encode_close_session(1, "a", out); }) ==
              make({0x68, 0x43, 0x05, 0x00, 0x00, 0x00, 0x01, 'a'}),
          "close capsule bytes");

    struct sample {
        bytes wire;
        std::string expected;
    };
    std::vector<sample> samples;
    for (const std::uint64_t value :
         {std::uint64_t {0}, std::uint64_t {1}, std::uint64_t {63}, std::uint64_t {64},
          std::uint64_t {16383}, std::uint64_t {16384}, std::uint64_t {1} << 30,
          max_varint}) {
        samples.push_back({encoded([&](auto out) { return encode_max_data(value, out); }),
                           "max_data " + std::to_string(value)});
        samples.push_back({encoded([&](auto out) { return encode_data_blocked(value, out); }),
                           "data_blocked " + std::to_string(value)});
    }
    for (const std::uint64_t value : {std::uint64_t {0}, std::uint64_t {7}, stream_limit}) {
        samples.push_back({encoded([&](auto out) { return encode_max_streams(true, value, out); }),
                           "max_streams_bidi " + std::to_string(value)});
        samples.push_back({encoded([&](auto out) { return encode_max_streams(false, value, out); }),
                           "max_streams_uni " + std::to_string(value)});
        samples.push_back(
            {encoded([&](auto out) { return encode_streams_blocked(true, value, out); }),
             "streams_blocked_bidi " + std::to_string(value)});
        samples.push_back(
            {encoded([&](auto out) { return encode_streams_blocked(false, value, out); }),
             "streams_blocked_uni " + std::to_string(value)});
    }
    samples.push_back({encoded([](auto out) { return encode_drain_session(out); }), "drain"});
    samples.push_back({encoded([](auto out) { return encode_close_session(0, "", out); }),
                       "close 0 "});
    samples.push_back({encoded([](auto out) {
                           return encode_close_session(0xdeadbeef, "bye", out);
                       }),
                       "close 3735928559 bye"});

    for (const auto& sample : samples)
        check_fragmentation(sample.wire, expect_events({sample.expected}), sample.expected);
}

auto encoder_errors() -> void
{
    std::array<std::byte, 64> output {};
    check(encode_max_data(std::uint64_t {1} << 62, output).error() ==
              wt_encode_error::value_out_of_range,
          "max data above varint range");
    check(encode_max_streams(true, stream_limit + 1, output).error() ==
              wt_encode_error::value_out_of_range,
          "bidi streams above 2^60");
    check(encode_max_streams(false, stream_limit + 1, output).error() ==
              wt_encode_error::value_out_of_range,
          "uni streams above 2^60");
    check(encode_streams_blocked(true, stream_limit + 1, output).error() ==
              wt_encode_error::value_out_of_range,
          "streams blocked above 2^60");
    check(encode_close_session(0, "\xff", output).error() == wt_encode_error::invalid_utf8,
          "close message must be UTF-8");

    std::array<std::byte, 3> small {};
    small.fill(std::byte {0xaa});
    check(encode_max_data(1000, small).error() == wt_encode_error::output_too_small,
          "max data reports small output");
    check(encode_close_session(1, "abc", small).error() == wt_encode_error::output_too_small,
          "close reports small output");
    check(encode_drain_session(std::span<std::byte>(small).first(0)).error() ==
              wt_encode_error::output_too_small,
          "drain reports small output");
    check(encode_capsule_header(0x21, 1, std::span<std::byte>(small).first(1)).error() ==
              wt_encode_error::output_too_small,
          "header reports small output");
    for (const auto byte : small) check(byte == std::byte {0xaa}, "failed encode writes nothing");
}

auto close_message_truncation() -> void
{
    const auto long_ascii = std::string(1100, 'a');
    const auto wire = encoded([&](auto out) { return encode_close_session(7, long_ascii, out); });
    check_fragmentation(wire, expect_events({"close 7 " + std::string(1024, 'a')}), "1024 ASCII cap");

    // 1023 ASCII + a two-byte character: the character cannot be split, so it is dropped.
    const auto split_two = encoded([](auto out) {
        return encode_close_session(7, std::string(1023, 'a') + "\xc3\xa9", out);
    });
    check_fragmentation(split_two, expect_events({"close 7 " + std::string(1023, 'a')}),
                        "two-byte character at the cap");

    // 1022 ASCII + a two-byte character fills the cap exactly.
    const auto exact_two = encoded([](auto out) {
        return encode_close_session(7, std::string(1022, 'a') + "\xc3\xa9", out);
    });
    check_fragmentation(exact_two,
                        expect_events({"close 7 " + std::string(1022, 'a') + "\xc3\xa9"}),
                        "two-byte character fits exactly");

    // 342 three-byte characters (1026 bytes) cut to 341 (1023 bytes).
    std::string euro;
    for (int i = 0; i < 342; ++i) euro += "\xe2\x82\xac";
    const auto cut = encoded([&](auto out) { return encode_close_session(7, euro, out); });
    check_fragmentation(cut, expect_events({[&] {
                                  std::string expected = "close 7 ";
                                  for (int i = 0; i < 341; ++i) expected += "\xe2\x82\xac";
                                  return expected;
                              }()}),
                        "three-byte character cut");
}

auto capsule_errors() -> void
{
    // Errors that are decided from the capsule header alone.
    check_fragmentation(make({0x68, 0x43, 0x03, 0, 0, 0}), expect_error({}, wt_error::h3_message_error),
                        "close shorter than its code");
    check_fragmentation(make({0x68, 0x43, 0x00}), expect_error({}, wt_error::h3_message_error),
                        "empty close");
    bytes oversized_header = varint(wt_close_session_capsule);
    append(oversized_header, varint(4 + 1025));
    check_fragmentation(oversized_header, expect_error({}, wt_error::h3_message_error),
                        "header of oversized close");

    bytes oversized = make({0, 0, 0, 1});
    append(oversized, bytes(1025, std::byte {'a'}));
    check_fragmentation(capsule(wt_close_session_capsule, oversized),
                        expect_error({}, wt_error::h3_message_error), "message over 1024 bytes");
    bytes exact = make({0, 0, 0, 1});
    append(exact, bytes(1024, std::byte {'a'}));
    check_fragmentation(capsule(wt_close_session_capsule, exact),
                        expect_events({"close 1 " + std::string(1024, 'a')}),
                        "message of exactly 1024 bytes");

    // Invalid UTF-8 is only known once the message is complete.
    for (const auto* invalid : {"\xff", "\xc0\xaf", "\xed\xa0\x80", "\xe2\x82", "\xf4\x90\x80\x80"}) {
        bytes value = make({0, 0, 0, 1});
        append(value, text(invalid));
        check_fragmentation(capsule(wt_close_session_capsule, value),
                            expect_error({}, wt_error::h3_message_error), "invalid UTF-8 close");
    }

    // Data after the close capsule resets the stream.
    bytes after = capsule(wt_close_session_capsule, make({0, 0, 0, 1, 'a'}));
    append(after, capsule(wt_drain_session_capsule, {}));
    check_fragmentation(after, expect_error({"close 1 a"}, wt_error::h3_message_error),
                        "data after close");

    // A drain capsule with a length is malformed.
    check_fragmentation(make({0x80, 0x00, 0x78, 0xae, 0x01, 0x00}),
                        expect_error({}, wt_error::h3_message_error), "drain with length");

    // Flow-control values must fill their length exactly.
    check_fragmentation(capsule(wt_max_data_capsule, {}), expect_error({}, wt_error::h3_message_error),
                        "zero-length MAX_DATA");
    check_fragmentation(capsule(wt_max_data_capsule, make({0x05, 0x00})),
                        expect_error({}, wt_error::h3_message_error),
                        "MAX_DATA with padding inside its length");
    check_fragmentation(capsule(wt_data_blocked_capsule, make({0x05, 0x00})),
                        expect_error({}, wt_error::h3_message_error),
                        "DATA_BLOCKED with padded varint");
    check_fragmentation(capsule(wt_max_data_capsule, bytes(9, std::byte {0x01})),
                        expect_error({}, wt_error::h3_message_error), "MAX_DATA longer than a varint");

    // Stream limits above 2^60 are flow-control errors.
    check_fragmentation(capsule(wt_max_streams_bidi_capsule, varint(stream_limit + 1)),
                        expect_error({}, wt_error::wt_flow_control_error),
                        "bidi MAX_STREAMS above 2^60");
    check_fragmentation(capsule(wt_max_streams_uni_capsule, varint(stream_limit + 1)),
                        expect_error({}, wt_error::wt_flow_control_error),
                        "uni MAX_STREAMS above 2^60");
    check_fragmentation(capsule(wt_streams_blocked_uni_capsule, varint(stream_limit + 1)),
                        expect_error({}, wt_error::wt_flow_control_error),
                        "STREAMS_BLOCKED above 2^60");
    check_fragmentation(capsule(wt_streams_blocked_bidi_capsule, varint(stream_limit + 1)),
                        expect_error({}, wt_error::wt_flow_control_error),
                        "bidi STREAMS_BLOCKED above 2^60");

    // Prohibited per-stream capsules are session errors even without flow control.
    check_fragmentation(capsule(wt_max_stream_data_capsule, varint(1)),
                        expect_error({}, wt_error::wt_flow_control_error), "MAX_STREAM_DATA");
    check_fragmentation(capsule(wt_stream_data_blocked_capsule, varint(1)),
                        expect_error({}, wt_error::wt_flow_control_error), "STREAM_DATA_BLOCKED");
    check_fragmentation(capsule(wt_max_stream_data_capsule, varint(1)),
                        expect_error({}, wt_error::wt_flow_control_error),
                        "MAX_STREAM_DATA with flow control disabled");
}

auto capsule_values() -> void
{
    check_fragmentation(capsule(wt_max_streams_bidi_capsule, varint(stream_limit)),
                        expect_events({"max_streams_bidi " + std::to_string(stream_limit)}),
                        "stream limit exactly 2^60");
    check_fragmentation(capsule(wt_max_data_capsule, varint(max_varint)),
                        expect_events({"max_data " + std::to_string(max_varint)}),
                        "maximum data value");
    check_fragmentation(capsule(wt_max_data_capsule, make({0x40, 0x05})),
                        expect_events({"max_data 5"}), "non-minimal varint fills its length");
    bytes nonminimal_zero = varint(wt_max_data_capsule);
    append(nonminimal_zero, varint(2));
    append(nonminimal_zero, make({0x40, 0x00}));
    check_fragmentation(nonminimal_zero, expect_events({"max_data 0"}),
                        "non-minimal zero varint fills its length");
    check_fragmentation(bytes {}, expect_events({}), "empty input");
    check_fragmentation(make({0x80, 0x00, 0x78, 0xae, 0x40, 0x00}), expect_events({"drain"}),
                        "non-minimal zero length of drain");
}

auto skipping() -> void
{
    bytes unknown = capsule(0x21, text("abc"));
    append(unknown, capsule(wt_drain_session_capsule, {}));
    check_fragmentation(unknown, expect_events({"drain"}), "unknown capsule skipped");

    bytes maximal = varint(max_varint);
    append(maximal, varint(0));
    append(maximal, capsule(wt_drain_session_capsule, {}));
    check_fragmentation(maximal, expect_events({"drain"}), "maximal unknown type");

    bytes large = capsule(0x1234, bytes(300, std::byte {'x'}));
    append(large, capsule(wt_drain_session_capsule, {}));
    check_fragmentation(large, expect_events({"drain"}), "300-byte unknown capsule");

    // A huge declared length is skipped as it streams. Nothing is buffered, and the
    // stream is incomplete until the declared length is reached.
    bytes huge = varint(0x21);
    append(huge, varint(std::uint64_t {1} << 40));
    append(huge, bytes(4096, std::byte {0}));
    capsule_parser parser(true);
    std::span<const std::byte> view(huge);
    check(parser.next(view) && !*parser.next(view) && view.empty(),
          "skipping a huge declared length consumes input without events");
    check(parser.finish().error() == wt_error::h3_message_error,
          "FIN partway through a skipped capsule is H3_MESSAGE_ERROR");
}

auto datagram_capsules() -> void
{
    check_fragmentation(capsule(datagram_capsule, text("hello")), expect_events({"datagram:hello"}),
                        "datagram capsule");
    check_fragmentation(capsule(datagram_capsule, {}), expect_events({"datagram:"}),
                        "empty datagram capsule");
    check_fragmentation(capsule(datagram_capsule, bytes(1232, std::byte {'d'})),
                        expect_events({"datagram:" + std::string(1232, 'd')}),
                        "1232-byte datagram");

    // Oversized datagrams are dropped without failing the session.
    bytes oversized = capsule(datagram_capsule, bytes(1233, std::byte {'d'}));
    append(oversized, capsule(wt_drain_session_capsule, {}));
    check_fragmentation(oversized, expect_events({"drain"}), "oversized datagram dropped");

    bytes at_limit = capsule(datagram_capsule, bytes(10, std::byte {'e'}));
    append(at_limit, capsule(datagram_capsule, bytes(11, std::byte {'f'})));
    check_fragmentation(at_limit, expect_events({"datagram:" + std::string(10, 'e')}),
                        "custom datagram limit",
                        true, 10);

    // The limit is clamped to the buffer size.
    bytes clamped = capsule(datagram_capsule, bytes(1300, std::byte {'g'}));
    append(clamped, capsule(datagram_capsule, bytes(1301, std::byte {'h'})));
    check_fragmentation(clamped, expect_events({"datagram:" + std::string(1300, 'g')}),
                        "buffer clamp", true, 5000);
}

auto flow_disabled() -> void
{
    bytes ignored = capsule(wt_max_data_capsule, varint(5));
    append(ignored, capsule(wt_data_blocked_capsule, varint(3)));
    append(ignored, capsule(wt_max_streams_bidi_capsule, varint(2)));
    append(ignored, capsule(wt_streams_blocked_uni_capsule, varint(2)));
    append(ignored, capsule(wt_max_data_capsule, make({0x05, 0x00})));
    append(ignored, capsule(wt_drain_session_capsule, {}));
    check_fragmentation(ignored, expect_events({"drain"}), "flow capsules ignored when disabled",
                        false);

    bytes enabled = capsule(wt_max_data_capsule, varint(5));
    check_fragmentation(enabled, expect_events({"max_data 5"}), "flow capsules when enabled");
}

auto close_then_finish() -> void
{
    check_fragmentation(capsule(wt_close_session_capsule, make({0, 0, 0, 0})),
                        expect_events({"close 0 "}), "clean close");
    // Stream FIN after the close capsule is expected.
    const auto close = capsule(wt_close_session_capsule, make({0, 0, 0, 0}));
    capsule_parser parser(true);
    std::span<const std::byte> view(close);
    const auto event = parser.next(view);
    check(event && *event && std::holds_alternative<wt_close_session>(**event),
          "close capsule is delivered");
    check(parser.finish().has_value(), "FIN after close is valid");
}

auto finish_states() -> void
{
    check_fragmentation(make({0x80}), expect_error({}, wt_error::h3_message_error),
                        "FIN inside a type varint");
    check_fragmentation(make({0x00, 0x40}), expect_error({}, wt_error::h3_message_error),
                        "FIN inside a length varint");
    check_fragmentation(make({0x00, 0x05, 'a', 'b'}), expect_error({}, wt_error::h3_message_error),
                        "FIN inside a datagram value");
    check_fragmentation(make({}), expect_events({}), "FIN at a capsule boundary");
    check_fragmentation(capsule(wt_drain_session_capsule, {}), expect_events({"drain"}),
                        "FIN after a drain capsule");
}

auto utf8_rules() -> void
{
    for (const auto* valid : {"", "a", "\xc2\x80", "\xdf\xbf", "\xe0\xa0\x80", "\xed\x9f\xbf",
                              "\xee\x80\x80", "\xef\xbf\xbf", "\xf0\x90\x80\x80",
                              "\xf4\x8f\xbf\xbf", "\xc3\xa9", "\xe2\x82\xac", "\xf0\x9f\x98\x80"})
        check(valid_utf8(valid), "valid UTF-8 accepted");

    for (const auto* invalid : {"\x80", "\xbf", "\xc0\x80", "\xc1\xbf", "\xe0\x80\x80",
                                "\xe0\x9f\xbf", "\xed\xa0\x80", "\xed\xbf\xbf", "\xf0\x8f\xbf\xbf",
                                "\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xf8\x88\x80\x80\x80",
                                "\xfe", "\xff", "\xc3", "\xe2\x82", "\xf0\x9f\x98", "\xe2\x28\xa1",
                                "\xc3\x28"})
        check(!valid_utf8(invalid), "invalid UTF-8 rejected");

    check(utf8_truncate("abc", 2) == "ab" && utf8_truncate("abc", 3) == "abc" &&
              utf8_truncate("abc", 0).empty(),
          "ASCII truncation");
    check(utf8_truncate("\xc3\xa9", 1).empty() && utf8_truncate("\xc3\xa9", 2) == "\xc3\xa9",
          "two-byte truncation");
    check(utf8_truncate("a\xc3\xa9", 2) == "a" && utf8_truncate("a\xe2\x82\xac", 3) == "a" &&
              utf8_truncate("a\xe2\x82\xac", 4) == "a\xe2\x82\xac",
          "multi-byte truncation keeps boundary");
    check(utf8_truncate("\xe2\x82\xac", 2).empty() && utf8_truncate("\xf0\x9f\x98\x80", 3).empty() &&
              utf8_truncate("\xf0\x9f\x98\x80", 4) == "\xf0\x9f\x98\x80",
          "four-byte truncation");
    check(utf8_truncate("\xf0\x9f\x98\x80x", 4) == "\xf0\x9f\x98\x80" &&
              utf8_truncate("\xf0\x9f\x98\x80x", 5) == "\xf0\x9f\x98\x80x" &&
              utf8_truncate("ab", 10) == "ab",
          "truncation at and above length");
}

auto parsed_protocols(std::string_view field) -> std::optional<std::vector<std::string_view>>
{
    std::array<std::string_view, 16> out {};
    const auto count = parse_available_protocols(field, out);
    if (!count) return std::nullopt;
    return std::vector<std::string_view>(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(*count));
}

auto sf_lists() -> void
{
    using list = std::vector<std::string_view>;
    check(parsed_protocols("") == list {}, "empty field is empty list");
    check(parsed_protocols("   ") == list {}, "space-only field is empty list");
    check(parsed_protocols(R"("a")") == list {"a"}, "single member");
    check(parsed_protocols(R"("a", "b")") == list {"a", "b"}, "two members");
    check(parsed_protocols(R"("a","b")") == list {"a", "b"}, "no spaces around comma");
    check(parsed_protocols(R"(   "a"   ,   "b"   )") == list {"a", "b"}, "surrounding spaces");
    check(parsed_protocols(R"("h3-chat";q=1, "v2")") == list {"h3-chat", "v2"},
          "parameter on first member");
    check(parsed_protocols(R"("a";x;y=2;z="s")") == list {"a"}, "several parameters");
    check(parsed_protocols(R"("a";n=-12.5)") == list {"a"}, "decimal parameter");
    check(parsed_protocols(R"("a";b=?1)") == list {"a"}, "boolean parameter");
    check(parsed_protocols(R"("a";c=:AAEC:)") == list {"a"}, "binary parameter");
    check(parsed_protocols(R"("a";t=tok/en)") == list {"a"}, "token parameter");
    check(parsed_protocols(R"("a";*w=1)") == list {"a"}, "wildcard parameter key");
    check(parsed_protocols(R"("a"; s="x y")") == list {"a"}, "string parameter value with space");
    check(!parsed_protocols(R"("a"; s = "x")"), "whitespace around '=' is a syntax error");
    check(parsed_protocols(R"("a";p="x\"y")") == list {"a"}, "escape in parameter value is valid");

    check(!parsed_protocols(R"("a", b)"), "token member ignores field");
    check(!parsed_protocols(R"("a", 1)"), "integer member ignores field");
    check(!parsed_protocols(R"(?1)"), "boolean member ignores field");
    check(!parsed_protocols(R"(("a"))"), "inner list ignores field");
    check(!parsed_protocols(R"("a", ("b"))"), "inner list after member ignores field");
    check(!parsed_protocols(R"("a", :AA:)"), "binary member ignores field");
    check(!parsed_protocols(R"(-1)"), "negative number ignores field");

    check(!parsed_protocols(R"("a",)"), "trailing comma");
    check(!parsed_protocols(R"(,"a")"), "leading comma");
    check(!parsed_protocols(R"("a" "b")"), "missing comma");
    check(!parsed_protocols(R"("a)"), "unterminated string");
    check(!parsed_protocols(R"("a"x)"), "garbage after member");
    check(!parsed_protocols(R"("a";B=1)"), "uppercase parameter key");
    check(!parsed_protocols(R"("a";k=)"), "parameter missing value");
    check(!parsed_protocols(R"("a";=1)"), "parameter missing key");
    check(!parsed_protocols(R"("a";q=1,)"), "trailing comma after parameter");
    check(!parsed_protocols("\"a\ttab\""), "tab inside string");
    check(!parsed_protocols("\"\xc3\xa9\""), "non-ASCII string");
    check(!parsed_protocols(R"("a\"b")"), "escaped quote is unsupported");
    check(!parsed_protocols(R"("a\\b")"), "escaped backslash is unsupported");
    check(!parsed_protocols(R"("a\x")"), "invalid escape");

    std::array<std::string_view, 2> two {};
    check(parse_available_protocols(R"("a", "b", "c")", two) == std::nullopt,
          "more members than the caller bound");
    check(parse_available_protocols(R"("a", "b")", two) == std::optional<std::size_t> {2},
          "members exactly at the bound");
    std::array<std::string_view, 0> none {};
    check(!parse_available_protocols(R"("a")", none), "zero-capacity output");
    check(parse_available_protocols("", none) == std::optional<std::size_t> {0},
          "empty list with zero-capacity output");
}

auto sf_format() -> void
{
    std::array<char, 32> output {};
    auto written = format_protocol("chat", output);
    check(written && std::string_view(output.data(), *written) == R"("chat")",
          "format plain protocol");
    written = format_protocol(R"(a"b\c)", output);
    check(written && std::string_view(output.data(), *written) == R"("a\"b\\c")",
          "format escapes quote and backslash");
    check(format_protocol("a\nb", output).error() == wt_encode_error::invalid_protocol,
          "newline is not printable");
    check(format_protocol("\x7f", output).error() == wt_encode_error::invalid_protocol,
          "DEL is not printable");
    check(format_protocol("\xc3\xa9", output).error() == wt_encode_error::invalid_protocol,
          "non-ASCII is rejected");

    std::array<char, 3> small {};
    small.fill('#');
    check(format_protocol("chat", small).error() == wt_encode_error::output_too_small,
          "format reports small output");
    check(small[0] == '#' && small[2] == '#', "format leaves output unchanged on failure");

    written = format_protocol("h3-chat", output);
    check(written && parsed_protocols(std::string_view(output.data(), *written)) ==
                         std::vector<std::string_view> {"h3-chat"},
          "format then parse round trip");
    written = format_protocol(R"(a"b)", output);
    check(written && !parsed_protocols(std::string_view(output.data(), *written)),
          "escaped protocol is not parsed back (escapes unsupported)");
}

auto session_send_credit() -> void
{
    session_flow flow(true, {.data = 100, .streams = {4, 4}}, {.data = 10, .streams = {2, 1}});
    check(flow.reserve_send(4) == 4, "send within credit");
    check(flow.reserve_send(10) == 6, "send clipped to credit");
    check(flow.take_data_blocked() == std::optional<std::uint64_t> {10}, "blocked reported");
    check(!flow.take_data_blocked(), "blocked reported once per limit");
    check(flow.reserve_send(1) == 0, "no credit left");
    check(!flow.take_data_blocked(), "same limit not reported again");
    check(flow.reserve_send(0) == 0 && !flow.take_data_blocked(), "zero send is not blocked");

    check(!flow.on_max_data(10) && !flow.on_max_data(9),
          "WT_MAX_DATA must increase");
    check(flow.on_max_data(15).has_value(), "WT_MAX_DATA increase accepted");
    check(flow.reserve_send(10) == 5, "credit after increase");
    check(flow.reserve_send(1) == 0 && flow.take_data_blocked() ==
              std::optional<std::uint64_t> {15},
          "new limit reported once");

    session_flow exact(true, {.data = 100, .streams = {4, 4}}, {.data = 10, .streams = {2, 1}});
    check(exact.reserve_send(10) == 10 && !exact.take_data_blocked(),
          "exact credit is not blocked");

    // A short QUIC write returns the unsent part: only the 4 accepted bytes of each
    // 10-byte reservation count as sent, so 88 of 100 remain after three writes.
    session_flow short_writes(true, {.data = 100, .streams = {4, 4}}, {.data = 100, .streams = {2, 1}});
    for (int i = 0; i < 3; ++i) {
        check(short_writes.reserve_send(10) == 10, "credit reserved for the write");
        short_writes.release_send(6);
    }
    check(short_writes.reserve_send(100) == 88, "unsent credit returned after short writes");

    session_flow streams(true, {.data = 100, .streams = {4, 4}}, {.data = 10, .streams = {2, 1}});
    check(streams.open_stream(true) && streams.open_stream(true), "two bidi streams open");
    check(!streams.open_stream(true), "third bidi stream refused");
    check(streams.take_streams_blocked(true) == std::optional<std::uint64_t> {2},
          "bidi streams blocked reported");
    check(!streams.take_streams_blocked(true), "streams blocked reported once");
    check(!streams.take_streams_blocked(false), "uni not blocked");
    check(streams.open_stream(false) && !streams.open_stream(false),
          "one uni stream allowed");
    check(streams.take_streams_blocked(false) == std::optional<std::uint64_t> {1},
          "uni streams blocked reported");

    check(!streams.on_max_streams(true, 2) && !streams.on_max_streams(true, 1),
          "WT_MAX_STREAMS must increase");
    check(streams.on_max_streams(true, 3) && streams.open_stream(true),
          "raised bidi limit allows a stream");
    check(!streams.open_stream(true) && streams.take_streams_blocked(true) ==
              std::optional<std::uint64_t> {3},
          "raised limit then blocked again");
    check(streams.on_max_streams(false, stream_limit).has_value() &&
              !streams.on_max_streams(false, stream_limit),
          "maximum stream count accepted, then must increase");
    check(!streams.on_max_streams(true, stream_limit + 1), "stream count above 2^60 is rejected");
}

auto session_receive_credit() -> void
{
    session_flow data(true, {.data = 100, .streams = {2, 1}}, {.data = 10, .streams = {2, 1}});
    check(data.on_peer_data(100).has_value(), "exactly the advertised limit");
    check(!data.on_peer_data(1).has_value(), "one byte beyond the limit");

    session_flow overflow(true, {.data = 100, .streams = {2, 1}}, {.data = 10, .streams = {2, 1}});
    check(!overflow.on_peer_data(std::numeric_limits<std::uint64_t>::max()).has_value(),
          "huge byte count cannot overflow");

    session_flow opened(true, {.data = 100, .streams = {2, 1}}, {.data = 10, .streams = {2, 1}});
    check(opened.on_peer_stream_opened(true) && opened.on_peer_stream_opened(true),
          "two bidi streams");
    check(!opened.on_peer_stream_opened(true), "third bidi stream exceeds limit");
    check(opened.on_peer_stream_opened(false).has_value(), "one uni stream");
    check(!opened.on_peer_stream_opened(false), "second uni stream exceeds limit");

    session_flow no_uni(true, {.data = 100, .streams = {2, 0}}, {.data = 10, .streams = {2, 1}});
    check(!no_uni.on_peer_stream_opened(false), "zero uni limit refuses the first stream");
}

auto session_renewal() -> void
{
    session_flow data(true, {.data = 100, .streams = {4, 4}}, {.data = 10, .streams = {2, 1}});
    check(data.on_peer_data(60).has_value(), "peer sent 60");
    check(!data.take_max_data_update(), "no renewal before the application consumes");
    data.on_data_consumed(60);
    check(data.take_max_data_update() == std::optional<std::uint64_t> {160},
          "renewal is consumed plus the window");
    check(!data.take_max_data_update(), "renewal sent once per window");
    check(data.on_peer_data(100).has_value(), "peer may use the renewed window");
    check(!data.on_peer_data(1).has_value(), "beyond the renewed window");

    session_flow idle(true, {.data = 100, .streams = {4, 4}}, {.data = 10, .streams = {2, 1}});
    check(idle.on_peer_data(10).has_value(), "peer sent 10");
    idle.on_data_consumed(10);
    check(!idle.take_max_data_update(), "no renewal while most of the window remains");

    session_flow clamp(true, {.data = 100, .streams = {4, 4}}, {.data = 10, .streams = {2, 1}});
    check(clamp.on_peer_data(10).has_value(), "peer sent 10");
    clamp.on_data_consumed(1000);
    check(!clamp.take_max_data_update(), "consumption capped at received bytes");
    check(clamp.on_peer_data(90).has_value(), "peer uses the rest of the window");
    check(clamp.take_max_data_update() == std::optional<std::uint64_t> {110},
          "renewal after capped consumption");

    session_flow streams(true, {.data = 100, .streams = {4, 4}}, {.data = 10, .streams = {2, 1}});
    check(streams.on_peer_stream_opened(true) && streams.on_peer_stream_opened(true) &&
              streams.on_peer_stream_opened(true),
          "three peer streams");
    check(!streams.take_max_streams_update(true), "no renewal until closures");
    streams.on_peer_stream_closed(true);
    streams.on_peer_stream_closed(true);
    check(streams.take_max_streams_update(true) == std::optional<std::uint64_t> {6},
          "stream renewal is closed plus the window");
    check(!streams.take_max_streams_update(true), "stream renewal sent once");
    streams.on_peer_stream_closed(false);
    check(!streams.take_max_streams_update(false), "closure without an open is ignored");
}

auto session_disabled() -> void
{
    session_flow flow(false, {}, {});
    check(!flow.enabled(), "disabled flag");
    check(flow.reserve_send(1000) == 1000, "disabled send is unrestricted");
    check(flow.open_stream(true) && flow.open_stream(true) && flow.open_stream(false),
          "disabled streams are unrestricted");
    check(!flow.take_data_blocked() && !flow.take_streams_blocked(true),
          "disabled never reports blocked");
    check(flow.on_max_data(0).has_value() && flow.on_max_streams(true, 0).has_value(),
          "disabled ignores flow-control capsules");
    check(flow.on_peer_data(std::numeric_limits<std::uint64_t>::max()).has_value(),
          "disabled ignores received data");
    check(flow.on_peer_stream_opened(true).has_value() && flow.on_peer_stream_opened(true).has_value(),
          "disabled ignores peer streams");
    check(!flow.take_max_data_update() && !flow.take_max_streams_update(true),
          "disabled sends no updates");
}

} // namespace

int main()
{
    constants();
    session_ids();
    stream_headers();
    stream_header_parsing();
    datagrams();
    encoder_round_trips();
    encoder_errors();
    close_message_truncation();
    capsule_errors();
    capsule_values();
    skipping();
    datagram_capsules();
    flow_disabled();
    close_then_finish();
    finish_states();
    utf8_rules();
    sf_lists();
    sf_format();
    session_send_credit();
    session_receive_credit();
    session_renewal();
    session_disabled();
    std::cout << "HTTP/3 WebTransport wire: all checks passed\n";
    return 0;
}
