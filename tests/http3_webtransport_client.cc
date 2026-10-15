// Self-test for the WebTransport test client's encoders and decoders. It runs
// without a server: each encoder output is parsed back by the library's codecs.
#include "fixtures/webtransport_client.h"

#include "http3/frames.h"
#include "http3/qpack.h"
#include "http3/webtransport_wire.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string_view>
#include <variant>

namespace {

namespace h3 = eventloop::http3::detail;
namespace wire = eventloop::http3::detail;
using namespace eventloop::webtransport_fixture;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::fprintf(stderr, "webtransport client self-test: %.*s\n",
                 static_cast<int>(message.size()), message.data());
    std::abort();
}

// Strips the HEADERS frame header and returns its QPACK block.
auto headers_block(std::span<const std::byte> frame) -> std::span<const std::byte>
{
    const auto view = h3::decode_frame(frame, frame.size());
    check(view.has_value(), "frame decodes");
    check(view->type == h3::headers_frame, "HEADERS frame type");
    return view->payload;
}

auto field_value(const std::array<h3::field, 32>& fields, std::size_t count, std::string_view name)
    -> std::optional<std::string_view>
{
    for (std::size_t i = 0; i < count; ++i)
        if (fields[i].name == name) return fields[i].value;
    return std::nullopt;
}

auto connect_request_round_trip() -> void
{
    std::array<std::byte, 512> frame {};
    request_options request;
    request.origin = "https://example.test";
    request.available_protocols = "\"echo/1\", \"chat\"";
    const auto size = encode_request(request, frame);
    check(size.has_value(), "encode CONNECT request");
    const auto block = headers_block(std::span<const std::byte>(frame).first(*size));

    std::array<h3::field, 32> fields {};
    std::array<char, 1024> strings {};
    const auto count = h3::qpack_decode(block, fields, strings);
    check(count.has_value(), "CONNECT HEADERS decode through qpack");
    check(field_value(fields, *count, ":method") == "CONNECT", ":method is CONNECT");
    check(field_value(fields, *count, ":protocol") == "webtransport-h3", ":protocol");
    check(field_value(fields, *count, ":scheme") == "https", ":scheme");
    check(field_value(fields, *count, ":authority") == "localhost", ":authority");
    check(field_value(fields, *count, ":path") == "/echo", ":path");
    check(field_value(fields, *count, "origin") == "https://example.test", "origin");
    check(field_value(fields, *count, "wt-available-protocols") == "\"echo/1\", \"chat\"",
          "wt-available-protocols");
}

auto get_request_omits_webtransport_fields() -> void
{
    std::array<std::byte, 512> frame {};
    request_options request;
    request.method = "GET";
    request.protocol = {};
    request.path = "/";
    const auto size = encode_request(request, frame);
    check(size.has_value(), "encode GET request");
    std::array<h3::field, 32> fields {};
    std::array<char, 1024> strings {};
    const auto count = h3::qpack_decode(headers_block(std::span<const std::byte>(frame).first(*size)),
                                        fields, strings);
    check(count.has_value(), "GET HEADERS decode");
    check(!field_value(fields, *count, ":protocol").has_value(), "GET has no :protocol");
    check(!field_value(fields, *count, "origin").has_value(), "GET has no origin");
}

auto settings_round_trip() -> void
{
    std::array<std::byte, 128> frame {};
    const auto size = encode_settings_frame(client_settings {}, frame);
    check(size.has_value(), "encode SETTINGS");
    const auto view = h3::decode_frame(std::span<const std::byte>(frame).first(*size), 128);
    check(view.has_value() && view->type == h3::settings_frame, "SETTINGS frame");

    bool connect = false, datagram = false, enabled = false;
    std::uint64_t max_data = 0, bidi = 0, uni = 0;
    h3::settings_iterator cursor(view->payload);
    for (;;) {
        const auto item = cursor.next();
        check(item.has_value(), "SETTINGS entry decodes");
        if (!*item) break;
        switch ((**item).identifier) {
        case 0x08: connect = (**item).value == 1; break;
        case 0x33: datagram = (**item).value == 1; break;
        case wire::wt_enabled_setting: enabled = (**item).value == 1; break;
        case wire::wt_initial_max_data_setting: max_data = (**item).value; break;
        case wire::wt_initial_max_streams_bidi_setting: bidi = (**item).value; break;
        case wire::wt_initial_max_streams_uni_setting: uni = (**item).value; break;
        default: break;
        }
    }
    check(connect && datagram && enabled, "client advertises CONNECT, H3_DATAGRAM and WT_ENABLED");
    check(max_data == 1024 * 1024 && bidi == 16 && uni == 16, "client advertises WT_INITIAL_* values");

    client_settings bare;
    bare.h3_datagram = false;
    bare.wt_enabled = false;
    bare.initial_max_data.reset();
    bare.initial_max_streams_bidi.reset();
    bare.initial_max_streams_uni.reset();
    const auto omitted = encode_settings_frame(bare, frame);
    check(omitted.has_value(), "encode bare SETTINGS");
    const auto bare_view = h3::decode_frame(std::span<const std::byte>(frame).first(*omitted), 128);
    check(bare_view.has_value(), "bare SETTINGS frame");
    h3::settings_iterator bare_cursor(bare_view->payload);
    for (;;) {
        const auto item = bare_cursor.next();
        check(item.has_value(), "bare SETTINGS entry decodes");
        if (!*item) break;
        check((**item).identifier == 0x08, "only ENABLE_CONNECT_PROTOCOL remains");
    }
}

auto response_decodes_status_and_protocol() -> void
{
    std::array<h3::field, 2> fields {h3::field {":status", "200"},
                                     h3::field {"wt-protocol", "\"echo/1\""}};
    std::array<std::byte, 128> block {};
    const auto size = h3::qpack_encode(fields, block);
    check(size.has_value(), "encode response fields");
    const auto response = decode_response(std::span<const std::byte>(block).first(*size));
    check(response.has_value(), "response decodes");
    check(response->status == 200, "response status");
    check(response->wt_protocol == std::optional<std::string>("\"echo/1\""), "wt-protocol value");

    std::array<h3::field, 1> missing {h3::field {"server", "x"}};
    const auto missing_size = h3::qpack_encode(missing, block);
    check(missing_size.has_value(), "encode response without status");
    check(!decode_response(std::span<const std::byte>(block).first(*missing_size)).has_value(),
          "response without :status is rejected");
}

auto stream_header_round_trip() -> void
{
    for (const bool unidirectional : {true, false}) {
        std::array<std::byte, 16> header {};
        const auto size = wire::encode_stream_header(unidirectional, 8, header);
        check(size.has_value(), "encode WT stream header");
        // The caller reads the stream type varint (0x54 or 0x41 is two bytes); the
        // parser takes the session ID that follows.
        auto input = std::span<const std::byte>(header).first(*size);
        h3::varint_accumulator type_bits;
        const auto type = type_bits.feed(input);
        check(type.has_value() && *type == (unidirectional ? wire::webtransport_uni_stream_type
                                                           : wire::webtransport_bidi_signal),
              "WT stream type");
        wire::stream_header_parser parser;
        const auto id = parser.feed(input);
        check(id.has_value() && id->has_value() && **id == 8, "WT stream header session ID");
        check(input.empty() && type_bits.partial() == false, "WT stream header length");
    }
    std::array<std::byte, 8> bad {};
    const auto bad_size = wire::encode_stream_header(false, 5, bad);
    check(!bad_size.has_value(), "session ID must be a client bidi stream ID");
}

auto datagram_prefix_round_trip() -> void
{
    std::array<std::byte, 16> packet {};
    const auto prefix = wire::encode_http_datagram_prefix(12, packet);
    check(prefix.has_value(), "encode quarter stream ID");
    packet[*prefix] = std::byte {0x5a};
    const auto parsed = wire::parse_http_datagram(std::span<const std::byte>(packet).first(*prefix + 1));
    check(parsed.has_value() && parsed->session_id == 12, "datagram session ID");
    check(parsed->payload.size() == 1 && parsed->payload[0] == std::byte {0x5a}, "datagram payload");
}

auto capsule_round_trip() -> void
{
    std::array<std::byte, 64> capsule {};
    const auto size = wire::encode_close_session(7, "bye", capsule);
    check(size.has_value(), "encode WT_CLOSE_SESSION");
    auto input = std::span<const std::byte>(capsule).first(*size);
    wire::capsule_parser parser(true);
    const auto event = parser.next(input);
    check(event.has_value() && event->has_value(), "WT_CLOSE_SESSION parses");
    const auto* close = std::get_if<wire::wt_close_session>(&**event);
    check(close != nullptr && close->code == 7 && close->message == "bye", "close code and message");
}

} // namespace

auto main() -> int
{
    connect_request_round_trip();
    get_request_omits_webtransport_fields();
    settings_round_trip();
    response_decodes_status_and_protocol();
    stream_header_round_trip();
    datagram_prefix_round_trip();
    capsule_round_trip();
    std::puts("webtransport client self-test passed");
}
