#include "http3/peer_streams.h"

#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <string_view>
#include <vector>

namespace {
using namespace eventloop::http3::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP/3 peer streams: " << message << '\n';
    std::exit(1);
}

auto bytes(std::initializer_list<unsigned> values) -> std::vector<std::byte>
{
    std::vector<std::byte> result;
    for (auto value : values) result.push_back(static_cast<std::byte>(value));
    return result;
}

// Feeds input whole and one octet at a time; both must agree.
auto run(std::span<const std::byte> input, peer_critical_streams critical = {})
    -> std::optional<h3_error>
{
    std::optional<h3_error> whole, split;
    {
        auto streams = critical;
        peer_uni_stream stream;
        if (auto result = stream.receive(input, streams); !result) whole = result.error();
    }
    {
        auto streams = critical;
        peer_uni_stream stream;
        for (std::size_t i = 0; i < input.size(); ++i)
            if (auto result = stream.receive(input.subspan(i, 1), streams); !result) {
                split = result.error();
                break;
            }
    }
    check(whole == split, "split delivery changes the verdict");
    return whole;
}

auto run(std::initializer_list<unsigned> values, peer_critical_streams critical = {})
{
    const auto input = bytes(values);
    return run(std::span<const std::byte>(input), critical);
}

auto stream_types() -> void
{
    check(run({0x01}) == h3_error::stream_creation_error, "client push stream");
    check(run({0x00, 0x04, 0x00}, {.control = true}) == h3_error::stream_creation_error,
          "duplicate control stream");
    check(run({0x02}, {.qpack_encoder = true}) == h3_error::stream_creation_error,
          "duplicate QPACK encoder stream");
    check(run({0x03}, {.qpack_decoder = true}) == h3_error::stream_creation_error,
          "duplicate QPACK decoder stream");
    // Reserved type 0x21 in a two-octet varint, followed by arbitrary bytes.
    check(!run({0x40, 0x21, 0xff, 0x01, 0x00}), "unknown stream types are ignored");

    peer_critical_streams critical;
    peer_uni_stream encoder, decoder, control;
    check(encoder.receive(bytes({0x02}), critical).has_value() &&
          decoder.receive(bytes({0x03}), critical).has_value() &&
          control.receive(bytes({0x00, 0x04, 0x00}), critical).has_value(),
          "one stream of each critical type");
    check(critical.control && critical.qpack_encoder && critical.qpack_decoder,
          "critical streams are recorded");
    for (auto* stream : {&encoder, &decoder, &control})
        check(stream->finish().error() == h3_error::closed_critical_stream,
              "critical stream closure");

    peer_uni_stream pending, unknown;
    check(pending.finish().has_value(), "stream closed before its type");
    check(unknown.receive(bytes({0x21}), critical).has_value() &&
          unknown.finish().has_value(), "unknown stream may close");
}

auto control_stream() -> void
{
    // SETTINGS: QPACK capacity 0, blocked 0, GREASE id 0x21 with value 7.
    check(!run({0x00, 0x04, 0x06, 0x01, 0x00, 0x07, 0x00, 0x21, 0x07}), "valid SETTINGS");
    check(!run({0x00, 0x04, 0x00}), "empty SETTINGS");
    check(run({0x00, 0x07, 0x01, 0x00}) == h3_error::missing_settings,
          "GOAWAY before SETTINGS");
    check(run({0x00, 0x21, 0x00}) == h3_error::missing_settings,
          "extension frame before SETTINGS");
    check(run({0x00, 0x04, 0x00, 0x04, 0x00}) == h3_error::frame_unexpected,
          "second SETTINGS");
    for (unsigned type : {0x00u, 0x01u, 0x05u, 0x02u, 0x06u, 0x08u, 0x09u})
        check(run({0x00, 0x04, 0x00, type, 0x00}) == h3_error::frame_unexpected,
              "request or HTTP/2 frame on control stream");
    check(!run({0x00, 0x04, 0x00, 0x21, 0x03, 0xaa, 0xbb, 0xcc, 0x07, 0x01, 0x00}),
          "frame after a skipped extension frame");

    check(run({0x00, 0x04, 0x02, 0x02, 0x00}) == h3_error::settings_error,
          "HTTP/2-only setting");
    check(!run({0x00, 0x04, 0x04, 0x08, 0x01, 0x33, 0x00}), "boolean settings at 0 and 1");
    check(run({0x00, 0x04, 0x02, 0x08, 0x02}) == h3_error::settings_error,
          "ENABLE_CONNECT_PROTOCOL above 1");
    check(run({0x00, 0x04, 0x02, 0x33, 0x02}) == h3_error::settings_error,
          "H3_DATAGRAM above 1");
    check(!run({0x00, 0x04, 0x02, 0x06, 0x3f}), "other settings take any value");
    check(run({0x00, 0x04, 0x04, 0x01, 0x00, 0x01, 0x00}) == h3_error::settings_error,
          "duplicate setting");
    check(run({0x00, 0x04, 0x01, 0x01}) == h3_error::frame_error,
          "setting identifier without value");
    check(run({0x00, 0x04, 0x02, 0x01, 0x40, 0x00}) == h3_error::frame_error,
          "setting value crosses frame end");

    std::vector<std::byte> many = bytes({0x00, 0x04, 0x40, 0x00});
    for (unsigned id = 0; id <= peer_uni_stream::max_settings; ++id)
        for (auto octet : {0x40u, 0x40u + id, 0x00u}) many.push_back(static_cast<std::byte>(octet));
    many[3] = static_cast<std::byte>(many.size() - 4);
    check(run(std::span<const std::byte>(many)) == h3_error::excessive_load,
          "SETTINGS identifier bound");
}

auto push_ids() -> void
{
    check(!run({0x00, 0x04, 0x00, 0x0d, 0x01, 0x05, 0x0d, 0x01, 0x05, 0x03, 0x01, 0x05}),
          "MAX_PUSH_ID then CANCEL_PUSH within limit");
    check(run({0x00, 0x04, 0x00, 0x0d, 0x01, 0x05, 0x0d, 0x01, 0x04}) == h3_error::id_error,
          "decreasing MAX_PUSH_ID");
    check(run({0x00, 0x04, 0x00, 0x03, 0x01, 0x00}) == h3_error::id_error,
          "CANCEL_PUSH without MAX_PUSH_ID");
    check(run({0x00, 0x04, 0x00, 0x0d, 0x01, 0x05, 0x03, 0x01, 0x06}) == h3_error::id_error,
          "CANCEL_PUSH above MAX_PUSH_ID");
    check(!run({0x00, 0x04, 0x00, 0x07, 0x01, 0x05, 0x07, 0x01, 0x05, 0x07, 0x01, 0x02}),
          "nonincreasing GOAWAY");
    check(run({0x00, 0x04, 0x00, 0x07, 0x01, 0x02, 0x07, 0x01, 0x03}) == h3_error::id_error,
          "increasing GOAWAY");
    check(run({0x00, 0x04, 0x00, 0x07, 0x00}) == h3_error::frame_error, "empty GOAWAY");
    check(run({0x00, 0x04, 0x00, 0x07, 0x02, 0x01, 0x00}) == h3_error::frame_error,
          "GOAWAY with trailing payload");
    check(run({0x00, 0x04, 0x00, 0x07, 0x01, 0x40, 0x00}) == h3_error::frame_error,
          "GOAWAY varint crosses frame end");
    check(run({0x00, 0x04, 0x00, 0x0d, 0x09}) == h3_error::frame_error,
          "oversized MAX_PUSH_ID payload");
}

auto qpack_streams() -> void
{
    check(!run({0x02, 0x20, 0x20}), "encoder sets zero capacity");
    check(run({0x02, 0x21}) == h3_error::qpack_encoder_stream_error,
          "encoder sets nonzero capacity");
    check(run({0x02, 0x3f, 0x00}) == h3_error::qpack_encoder_stream_error,
          "encoder capacity with continuation");
    check(run({0x02, 0xc0, 0x00}) == h3_error::qpack_encoder_stream_error,
          "encoder insert with static name reference");
    check(run({0x02, 0x41, 0x61, 0x00}) == h3_error::qpack_encoder_stream_error,
          "encoder insert with literal name");
    check(run({0x02, 0x00}) == h3_error::qpack_encoder_stream_error, "encoder duplicate");

    check(!run({0x03, 0x40, 0x44, 0x7f, 0x80, 0x01, 0x7f, 0x00}),
          "decoder stream cancellations, including multi-octet IDs");
    check(run({0x03, 0x84}) == h3_error::qpack_decoder_stream_error,
          "section acknowledgment without dynamic references");
    check(run({0x03, 0x01}) == h3_error::qpack_decoder_stream_error,
          "insert count increment without insertions");
    check(run({0x03, 0x00}) == h3_error::qpack_decoder_stream_error,
          "zero insert count increment");
    check(run({0x03, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}) ==
          h3_error::qpack_decoder_stream_error, "unbounded stream ID continuation");

    check(make_error_code(h3_error::closed_critical_stream).value() == 0x104 &&
          make_error_code(h3_error::closed_critical_stream).message() ==
              "H3_CLOSED_CRITICAL_STREAM", "error code values");
}
} // namespace

auto main() -> int
{
    stream_types();
    control_stream();
    push_ids();
    qpack_streams();
}
