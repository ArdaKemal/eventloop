#include "http3/peer_streams.h"

#include <algorithm>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <string_view>
#include <utility>
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
    check(run({0x00, 0x04, 0x00, 0x0d, 0x01, 0x05, 0x03, 0x01, 0x05}) == h3_error::id_error,
          "CANCEL_PUSH for an unpromised ID");
    check(run({0x00, 0x04, 0x00, 0x0d, 0x01, 0x05, 0x0d, 0x01, 0x04}) == h3_error::id_error,
          "decreasing MAX_PUSH_ID");
    check(run({0x00, 0x04, 0x00, 0x03, 0x01, 0x00}) == h3_error::id_error,
          "CANCEL_PUSH without MAX_PUSH_ID");
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

// QUIC varint, minimal encoding.
auto append_varint(std::vector<std::byte>& out, std::uint64_t value) -> void
{
    const unsigned length = value < 64 ? 1 : value < 16384 ? 2 : value < (1ull << 30) ? 4 : 8;
    const unsigned prefix = length == 1 ? 0 : length == 2 ? 1 : length == 4 ? 2 : 3;
    const auto start = out.size();
    for (unsigned i = length; i-- > 0;)
        out.push_back(static_cast<std::byte>((value >> (8 * i)) & 0xff));
    out[start] |= static_cast<std::byte>(prefix << 6);
}

// Control stream: type 0, then one SETTINGS frame with the given pairs.
auto settings_stream(const std::vector<std::pair<std::uint64_t, std::uint64_t>>& pairs)
    -> std::vector<std::byte>
{
    std::vector<std::byte> payload;
    for (const auto& [identifier, value] : pairs) {
        append_varint(payload, identifier);
        append_varint(payload, value);
    }
    std::vector<std::byte> stream = bytes({0x00, 0x04});
    append_varint(stream, payload.size());
    stream.insert(stream.end(), payload.begin(), payload.end());
    return stream;
}

struct settings_probe {
    int calls {0};
};

auto count_settings(void* context) noexcept -> void
{
    ++static_cast<settings_probe*>(context)->calls;
}

auto settings_recording() -> void
{
    const auto stream_bytes = settings_stream({{enable_connect_protocol_setting, 1},
        {h3_datagram_setting, 1}, {wt_enabled_setting, 1},
        {wt_initial_max_streams_uni_setting, 5}, {wt_initial_max_streams_bidi_setting, 7},
        {wt_initial_max_data_setting, 1000}, {0x21, 7}});
    const auto check_recorded = [](const peer_critical_streams& critical, std::string_view when) {
        check(critical.settings_received && critical.h3_datagram && critical.connect_protocol &&
              critical.wt_enabled, when);
        check(critical.wt_initial_max_streams_uni == 5 &&
              critical.wt_initial_max_streams_bidi == 7 &&
              critical.wt_initial_max_data == 1000, "initial WebTransport limits");
    };

    {
        settings_probe probe;
        peer_critical_streams critical {.on_settings = count_settings, .settings_context = &probe};
        peer_uni_stream stream;
        check(stream.receive(stream_bytes, critical).has_value(), "SETTINGS with WebTransport");
        check_recorded(critical, "whole SETTINGS recorded");
        check(probe.calls == 1, "hook fires once for whole SETTINGS");
    }
    {
        // Octet by octet: nothing is visible and the hook stays silent until the
        // final octet completes the frame.
        settings_probe probe;
        peer_critical_streams critical {.on_settings = count_settings, .settings_context = &probe};
        peer_uni_stream stream;
        for (std::size_t i = 0; i < stream_bytes.size(); ++i) {
            const auto octet = std::span<const std::byte>(stream_bytes).subspan(i, 1);
            check(stream.receive(octet, critical).has_value(), "fragmented SETTINGS parses");
            const bool last = i + 1 == stream_bytes.size();
            check(critical.settings_received == last, "settings_received only when complete");
            check(probe.calls == (last ? 1 : 0), "hook only after the full payload");
            if (!last)
                check(!critical.wt_enabled && !critical.h3_datagram && !critical.connect_protocol &&
                      critical.wt_initial_max_data == 0, "no partial SETTINGS values visible");
        }
        check_recorded(critical, "fragmented SETTINGS recorded");
    }
    {
        // An empty SETTINGS frame completes at its header.
        settings_probe probe;
        peer_critical_streams critical {.on_settings = count_settings, .settings_context = &probe};
        peer_uni_stream stream;
        const auto empty = bytes({0x00, 0x04, 0x00});
        check(stream.receive(empty, critical).has_value() && critical.settings_received &&
              probe.calls == 1 && !critical.wt_enabled, "empty SETTINGS completes");
    }
    {
        peer_critical_streams critical;
        peer_uni_stream stream;
        const auto frame = settings_stream({{wt_max_sessions_draft07_setting, 1}});
        for (std::size_t i = 0; i < frame.size(); ++i) {
            check(stream.receive(std::span(frame).subspan(i, 1), critical).has_value(),
                  "fragmented draft-07 SETTINGS accepted");
            check(critical.wt_max_sessions_draft07 == (i + 1 == frame.size() ? 1u : 0u),
                  "draft-07 setting committed only when complete");
        }
        check(!critical.wt_enabled, "draft-07 does not enable draft-16");
    }
    {
        // Values of SETTINGS_WT_ENABLED other than 1 mean not enabled. A server
        // does not reject them here.
        for (const std::uint64_t value : {0ull, 2ull, 3ull}) {
            peer_critical_streams critical;
            peer_uni_stream stream;
            const auto frame = settings_stream({{wt_enabled_setting, value}});
            check(stream.receive(frame, critical).has_value(), "WT_ENABLED value accepted");
            check(critical.settings_received && !critical.wt_enabled,
                  "WT_ENABLED other than 1 is not enabled");
        }
    }
    {
        // Unknown identifiers and a non-boolean flag still behave as before.
        peer_critical_streams critical;
        peer_uni_stream stream;
        check(stream.receive(settings_stream({{0x21, 0}, {0x2b64, 1}}), critical).has_value() &&
              critical.wt_initial_max_streams_uni == 1 && !critical.wt_enabled,
              "unknown identifiers ignored; WebTransport limit recorded alone");
        peer_critical_streams other;
        peer_uni_stream bad;
        check(bad.receive(settings_stream({{wt_enabled_setting, 1}, {wt_enabled_setting, 1}}),
                          other) == std::unexpected(h3_error::settings_error),
              "duplicate WT_ENABLED is a settings error");
    }
    {
        // The 32-identifier cap counts WebTransport identifiers too.
        std::vector<std::pair<std::uint64_t, std::uint64_t>> pairs {{wt_enabled_setting, 1}};
        for (std::uint64_t id = 0x21; pairs.size() < peer_uni_stream::max_settings; ++id)
            pairs.push_back({id, 0});
        peer_critical_streams critical;
        peer_uni_stream stream;
        check(stream.receive(settings_stream(pairs), critical).has_value(),
              "32 identifiers including WebTransport are accepted");
        pairs.push_back({wt_initial_max_data_setting, 1});
        peer_critical_streams over;
        peer_uni_stream overflow;
        check(overflow.receive(settings_stream(pairs), over) == std::unexpected(h3_error::excessive_load),
              "33rd identifier is excessive load");
    }
}

// Feeds input in steps of `step` octets, stopping once the session ID is known as
// the caller would. Returns the body offset or the error.
struct wt_uni_result {
    std::optional<h3_error> error;
    std::optional<std::uint64_t> session;
    std::size_t body_offset {0};
    peer_uni_stream::kind stream_kind {peer_uni_stream::kind::pending};
    auto operator==(const wt_uni_result&) const -> bool = default;
};

auto feed_uni(std::span<const std::byte> input, bool enabled, std::size_t step) -> wt_uni_result
{
    peer_uni_stream stream(enabled);
    peer_critical_streams critical;
    wt_uni_result result;
    std::size_t offset = 0;
    while (offset < input.size() && !stream.session_id()) {
        const auto chunk = input.subspan(offset, std::min(step, input.size() - offset));
        if (const auto parsed = stream.receive(chunk, critical); !parsed) {
            result.error = parsed.error();
            break;
        }
        offset += stream.bytes_consumed();
    }
    result.session = stream.session_id();
    result.body_offset = offset;
    result.stream_kind = stream.stream_kind();
    return result;
}

auto run_uni(std::span<const std::byte> input, bool enabled = true) -> wt_uni_result
{
    const auto whole = feed_uni(input, enabled, input.empty() ? 1 : input.size());
    check(whole == feed_uni(input, enabled, 1), "split delivery changes the WebTransport verdict");
    return whole;
}

auto webtransport_streams() -> void
{
    // Stream type 0x54 is 84, a two-octet varint (0x40 0x54) on the wire.
    // Enabled: then session ID 4; the body octets are not consumed.
    {
        const auto input = bytes({0x40, 0x54, 0x04, 0x61, 0x62});
        const auto result = run_uni(input);
        check(!result.error && result.session == 4 && result.body_offset == 3 &&
              result.stream_kind == peer_uni_stream::kind::webtransport,
              "WebTransport stream session ID and body offset");
    }
    {
        // A session ID fragmented across reads, and a body in the same read.
        const auto input = bytes({0x40, 0x54, 0x52, 0x34, 0x7a});
        check(run_uni(input) == wt_uni_result {{}, 0x1234, 4,
              peer_uni_stream::kind::webtransport}, "two-octet session ID across reads");
    }
    {
        std::vector<std::byte> input = bytes({0x40, 0x54});
        append_varint(input, 1ull << 40);
        input.push_back(std::byte {0x78});
        check(run_uni(input) == wt_uni_result {{}, 1ull << 40, 10,
              peer_uni_stream::kind::webtransport}, "eight-octet session ID");
    }
    {
        // The stream stops at the session ID even if more input arrives later.
        peer_uni_stream stream(true);
        peer_critical_streams critical;
        const auto head = bytes({0x40, 0x54, 0x04});
        check(stream.receive(head, critical).has_value() && stream.bytes_consumed() == 3,
              "head consumed exactly");
        const auto body = bytes({0x61, 0x62});
        check(stream.receive(body, critical).has_value() && stream.bytes_consumed() == 0 &&
              stream.session_id() == 4, "no bytes consumed after the session ID");
        check(!critical.control && !critical.wt_enabled, "WebTransport stream leaves SETTINGS alone");
    }
    {
        // A FIN before the session ID completes is not a connection error.
        peer_uni_stream type_only(true), partial(true);
        peer_critical_streams critical;
        check(type_only.receive(bytes({0x40, 0x54}), critical).has_value() &&
              type_only.finish().has_value() && !type_only.session_id(),
              "FIN after the stream type");
        check(partial.receive(bytes({0x40, 0x54, 0x52}), critical).has_value() &&
              partial.finish().has_value() && !partial.session_id() &&
              partial.stream_kind() == peer_uni_stream::kind::webtransport,
              "FIN inside the session ID");
    }
    {
        // Disabled: 0x54 is an unknown stream type, consumed whole.
        const auto input = bytes({0x40, 0x54, 0x04, 0x61});
        const auto result = run_uni(input, false);
        check(!result.error && !result.session && result.body_offset == 4 &&
              result.stream_kind == peer_uni_stream::kind::unknown,
              "disabled 0x54 is unknown");
        check(!run({0x40, 0x54, 0x04, 0x61}), "default constructor leaves 0x54 unknown");
    }
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
    settings_recording();
    webtransport_streams();
}
