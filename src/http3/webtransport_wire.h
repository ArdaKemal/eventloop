#pragma once

#include "frames.h"
#include "peer_streams.h"
#include "quic/varint.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <variant>

namespace eventloop::http3::detail {

// WebTransport over HTTP/3 (draft-ietf-webtrans-http3-16) wire formats: stream
// headers, HTTP Datagram prefixes, capsules, UTF-8 and Structured Fields helpers,
// and session flow-control bookkeeping. Nothing here performs I/O or allocates.
// Parsers report the HTTP/3 or WebTransport code the session or stream must be
// reset with; encoders report caller mistakes as wt_encode_error and never write
// to their output on failure.

inline constexpr std::uint64_t webtransport_uni_stream_type = 0x54;
inline constexpr std::uint64_t webtransport_bidi_signal = 0x41;

// The SETTINGS identifiers (SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_H3_DATAGRAM,
// and the WT_ENABLED and WT_INITIAL_* settings) are defined by peer_streams.h,
// which this header includes.

inline constexpr std::uint64_t datagram_capsule = 0x00;
inline constexpr std::uint64_t wt_close_session_capsule = 0x2843;
inline constexpr std::uint64_t wt_drain_session_capsule = 0x78ae;
inline constexpr std::uint64_t wt_max_data_capsule = 0x190b4d3d;
inline constexpr std::uint64_t wt_max_stream_data_capsule = 0x190b4d3e; // prohibited
inline constexpr std::uint64_t wt_max_streams_bidi_capsule = 0x190b4d3f;
inline constexpr std::uint64_t wt_max_streams_uni_capsule = 0x190b4d40;
inline constexpr std::uint64_t wt_data_blocked_capsule = 0x190b4d41;
inline constexpr std::uint64_t wt_stream_data_blocked_capsule = 0x190b4d42; // prohibited
inline constexpr std::uint64_t wt_streams_blocked_bidi_capsule = 0x190b4d43;
inline constexpr std::uint64_t wt_streams_blocked_uni_capsule = 0x190b4d44;

// Largest Maximum Streams value; stream IDs cannot exceed 2^62-1.
inline constexpr std::uint64_t wt_max_stream_count = std::uint64_t {1} << 60;
// Largest quarter stream ID carried in an HTTP Datagram (RFC 9297).
inline constexpr std::uint64_t wt_max_quarter_stream_id = (std::uint64_t {1} << 60) - 1;
inline constexpr std::size_t wt_max_close_message = 1024;
// Largest value buffered for any capsule: WT_CLOSE_SESSION (code + message).
inline constexpr std::size_t wt_capsule_buffer_size = 1300;

// Error codes the codec reports. Values are the HTTP/3 or WebTransport codes.
enum class wt_error : std::uint64_t {
    h3_id_error = 0x108,
    h3_message_error = 0x10e,
    h3_datagram_error = 0x33,
    wt_buffered_stream_rejected = 0x3994bd84,
    wt_session_gone = 0x170d7b68,
    wt_flow_control_error = 0x045d4487,
    wt_alpn_error = 0x0817b3dd,
    wt_requirements_not_met = 0x212c0d48,
};

enum class wt_encode_error {
    output_too_small,
    value_out_of_range,
    invalid_session_id,
    invalid_utf8,
    invalid_protocol,
};

// Client-initiated bidirectional stream IDs are multiples of four. Session IDs
// are CONNECT stream IDs, so only those values are valid.
[[nodiscard]] constexpr auto valid_session_id(std::uint64_t id) noexcept -> bool
{
    return id % 4 == 0 && id <= quic::detail::max_varint_value;
}

// Strict RFC 3629 UTF-8: rejects overlong forms, surrogates, and values above
// U+10FFFF.
[[nodiscard]] constexpr auto valid_utf8(std::string_view text) noexcept -> bool
{
    std::size_t index = 0;
    while (index < text.size()) {
        const auto lead = static_cast<unsigned char>(text[index]);
        if (lead < 0x80) {
            ++index;
            continue;
        }
        std::size_t length = 0;
        unsigned char second_low = 0x80;
        unsigned char second_high = 0xbf;
        if (lead >= 0xc2 && lead <= 0xdf) {
            length = 2;
        } else if (lead >= 0xe0 && lead <= 0xef) {
            length = 3;
            if (lead == 0xe0) second_low = 0xa0; // no overlong three-byte forms
            if (lead == 0xed) second_high = 0x9f; // no UTF-16 surrogates
        } else if (lead >= 0xf0 && lead <= 0xf4) {
            length = 4;
            if (lead == 0xf0) second_low = 0x90; // no overlong four-byte forms
            if (lead == 0xf4) second_high = 0x8f; // nothing above U+10FFFF
        } else {
            return false;
        }
        if (text.size() - index < length) return false;
        for (std::size_t offset = 1; offset < length; ++offset) {
            const auto byte = static_cast<unsigned char>(text[index + offset]);
            const auto low = offset == 1 ? second_low : static_cast<unsigned char>(0x80);
            const auto high = offset == 1 ? second_high : static_cast<unsigned char>(0xbf);
            if (byte < low || byte > high) return false;
        }
        index += length;
    }
    return true;
}

// Longest prefix of at most max bytes that does not end inside a UTF-8 sequence.
// Input that is not valid UTF-8 is cut on a best-effort basis.
[[nodiscard]] constexpr auto utf8_truncate(std::string_view text, std::size_t max) noexcept
    -> std::string_view
{
    if (text.size() <= max) return text;
    std::size_t cut = max;
    while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xc0) == 0x80) --cut;
    return text.substr(0, cut);
}

// ---- Stream headers -------------------------------------------------------

// Writes the stream type (0x54) or bidi signal (0x41) followed by the session
// ID. The returned length is the reliable size for RESET_STREAM_AT.
[[nodiscard]] inline auto encode_stream_header(
    bool unidirectional, std::uint64_t session_id, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, wt_encode_error>
{
    if (!valid_session_id(session_id)) return std::unexpected(wt_encode_error::invalid_session_id);
    const auto type = unidirectional ? webtransport_uni_stream_type : webtransport_bidi_signal;
    const auto type_size = quic::detail::varint_size(type);
    const auto id_size = quic::detail::varint_size(session_id);
    if (output.size() < type_size + id_size) return std::unexpected(wt_encode_error::output_too_small);
    (void)quic::detail::encode_varint(type, output);
    (void)quic::detail::encode_varint(session_id, output.subspan(type_size));
    return type_size + id_size;
}

// Consumes the session ID that follows an already-classified stream type or
// signal. Bytes after the header stay in the caller's span as body. Holds at most
// one partial varint.
class stream_header_parser {
public:
    // Returns the session ID once the header is complete, nullopt if more input is
    // needed. A session ID that is not a client-initiated bidirectional stream ID
    // is H3_ID_ERROR.
    [[nodiscard]] auto feed(std::span<const std::byte>& input) noexcept
        -> std::expected<std::optional<std::uint64_t>, wt_error>
    {
        if (done_) return std::optional<std::uint64_t> {session_id_};
        const auto before = input.size();
        const auto id = varint_.feed(input);
        consumed_ += before - input.size();
        if (!id) return std::optional<std::uint64_t> {};
        if (!valid_session_id(*id)) return std::unexpected(wt_error::h3_id_error);
        done_ = true;
        session_id_ = *id;
        return std::optional<std::uint64_t> {session_id_};
    }

    [[nodiscard]] auto complete() const noexcept -> bool { return done_; }
    // Header bytes consumed so far; the wire length even for non-minimal varints.
    [[nodiscard]] auto consumed() const noexcept -> std::size_t { return consumed_; }

private:
    varint_accumulator varint_ {};
    std::uint64_t session_id_ {0};
    std::size_t consumed_ {0};
    bool done_ {false};
};

// ---- HTTP Datagram prefix (RFC 9297, WebTransport section "Datagrams") -----

struct http_datagram {
    std::uint64_t session_id;
    std::span<const std::byte> payload;
};

// Splits a QUIC DATAGRAM payload into its session ID and body. The payload view
// borrows input. A quarter stream ID above 2^60-1 or a truncated varint is
// H3_DATAGRAM_ERROR.
[[nodiscard]] inline auto parse_http_datagram(std::span<const std::byte> input) noexcept
    -> std::expected<http_datagram, wt_error>
{
    const auto quarter = quic::detail::decode_varint(input);
    if (!quarter || quarter->value > wt_max_quarter_stream_id)
        return std::unexpected(wt_error::h3_datagram_error);
    return http_datagram {quarter->value * 4, input.subspan(quarter->encoded_size)};
}

// Writes the Quarter Stream ID that prefixes a datagram payload.
[[nodiscard]] inline auto encode_http_datagram_prefix(
    std::uint64_t session_id, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, wt_encode_error>
{
    if (!valid_session_id(session_id)) return std::unexpected(wt_encode_error::invalid_session_id);
    const auto quarter = session_id / 4;
    const auto size = quic::detail::varint_size(quarter);
    if (output.size() < size) return std::unexpected(wt_encode_error::output_too_small);
    (void)quic::detail::encode_varint(quarter, output);
    return size;
}

// ---- Capsules -------------------------------------------------------------

// Bare capsule header (type, length). The caller writes the value after it.
[[nodiscard]] constexpr auto capsule_header_size(std::uint64_t type, std::uint64_t length) noexcept
    -> std::size_t
{
    const auto type_size = quic::detail::varint_size(type);
    const auto length_size = quic::detail::varint_size(length);
    return type_size == 0 || length_size == 0 ? 0 : type_size + length_size;
}

[[nodiscard]] inline auto encode_capsule_header(
    std::uint64_t type, std::uint64_t length, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, wt_encode_error>
{
    const auto size = capsule_header_size(type, length);
    if (size == 0) return std::unexpected(wt_encode_error::value_out_of_range);
    if (output.size() < size) return std::unexpected(wt_encode_error::output_too_small);
    (void)quic::detail::encode_varint(type, output);
    (void)quic::detail::encode_varint(length, output.subspan(quic::detail::varint_size(type)));
    return size;
}

struct wt_close_session {
    std::uint32_t code;
    std::string_view message; // valid until the next parser call
};
struct wt_drain_session {};
struct wt_max_data {
    std::uint64_t maximum;
};
struct wt_data_blocked {
    std::uint64_t maximum;
};
struct wt_max_streams {
    bool bidirectional;
    std::uint64_t maximum;
};
struct wt_streams_blocked {
    bool bidirectional;
    std::uint64_t maximum;
};
struct wt_datagram {
    std::span<const std::byte> payload; // valid until the next parser call
};

using capsule_event = std::variant<wt_close_session, wt_drain_session, wt_max_data,
                                   wt_max_streams, wt_data_blocked, wt_streams_blocked,
                                   wt_datagram>;

// Incremental parser for the capsule stream carried on the CONNECT stream. Input
// may be split at any byte. Only the capsule being parsed is held; unknown
// capsules and oversized DATAGRAM payloads are skipped as they stream past.
//
// Only one event is returned per call, and event views stay valid until the next
// call. Each call consumes input up to the event or the end of input. nullopt
// means the input is exhausted without completing an event.
class capsule_parser {
    using event_result = std::expected<std::optional<capsule_event>, wt_error>;
    enum class phase : std::uint8_t { type, length, value, skip, closed };

public:
    // flow_control: when false, the four flow-control capsules are skipped unread,
    // since an endpoint must ignore them without flow control. Prohibited capsules
    // are always errors. max_datagram_payload bounds buffered DATAGRAM payloads;
    // larger datagrams are dropped (datagrams are unreliable). Values above
    // wt_capsule_buffer_size are reduced to it.
    explicit capsule_parser(bool flow_control, std::size_t max_datagram_payload = 1232) noexcept
        : flow_control_(flow_control),
          max_datagram_(std::min(max_datagram_payload, wt_capsule_buffer_size)) {}

    // Errors are fatal to the session and map to the code the CONNECT stream
    // must be reset with:
    //   WT_CLOSE_SESSION: length < 4, message > 1024 bytes, invalid UTF-8 -> H3_MESSAGE_ERROR
    //   WT_DRAIN_SESSION with nonzero length, malformed flow-control value,
    //   data after WT_CLOSE_SESSION -> H3_MESSAGE_ERROR
    //   WT_MAX_STREAMS / WT_STREAMS_BLOCKED value > 2^60, WT_MAX_STREAM_DATA,
    //   WT_STREAM_DATA_BLOCKED -> WT_FLOW_CONTROL_ERROR
    [[nodiscard]] auto next(std::span<const std::byte>& input) noexcept -> event_result
    {
        if (phase_ == phase::closed) {
            if (!input.empty()) return std::unexpected(wt_error::h3_message_error);
            return std::optional<capsule_event> {};
        }
        for (;;) {
            switch (phase_) {
            case phase::type: {
                const auto type = type_varint_.feed(input);
                if (!type) return std::optional<capsule_event> {};
                type_value_ = *type;
                phase_ = phase::length;
                break;
            }
            case phase::length: {
                const auto length = length_varint_.feed(input);
                if (!length) return std::optional<capsule_event> {};
                auto event = begin_value(*length);
                if (!event) return std::unexpected(event.error());
                if (*event) return std::move(*event);
                break;
            }
            case phase::value: {
                const auto take = static_cast<std::size_t>(
                    std::min<std::uint64_t>(remaining_, input.size()));
                std::copy_n(input.data(), take, buffer_.data() + fill_);
                fill_ += take;
                remaining_ -= take;
                input = input.subspan(take);
                if (remaining_ != 0) return std::optional<capsule_event> {};
                return complete();
            }
            case phase::skip: {
                const auto take = static_cast<std::size_t>(
                    std::min<std::uint64_t>(remaining_, input.size()));
                input = input.subspan(take);
                remaining_ -= take;
                if (remaining_ != 0) return std::optional<capsule_event> {};
                phase_ = phase::type;
                break;
            }
            case phase::closed:
                return std::optional<capsule_event> {};
            }
        }
    }

    // End of the CONNECT stream. A FIN inside a capsule is H3_MESSAGE_ERROR; a FIN
    // after WT_CLOSE_SESSION is expected.
    [[nodiscard]] auto finish() const noexcept -> std::expected<void, wt_error>
    {
        if (phase_ == phase::closed || (phase_ == phase::type && !type_varint_.partial()))
            return {};
        return std::unexpected(wt_error::h3_message_error);
    }

private:
    // Classifies a capsule once its length is known. Returns an event immediately
    // for zero-length capsules that need no value bytes.
    auto begin_value(std::uint64_t length) noexcept -> event_result
    {
        remaining_ = length;
        fill_ = 0;
        phase_ = phase::value;
        switch (type_value_) {
        case datagram_capsule:
            if (length > max_datagram_) phase_ = phase::skip;
            break;
        case wt_close_session_capsule:
            if (length < 4 || length > 4 + wt_max_close_message)
                return std::unexpected(wt_error::h3_message_error);
            break;
        case wt_drain_session_capsule:
            if (length != 0) return std::unexpected(wt_error::h3_message_error);
            phase_ = phase::type;
            return std::optional<capsule_event> {wt_drain_session {}};
        case wt_max_data_capsule:
        case wt_max_streams_bidi_capsule:
        case wt_max_streams_uni_capsule:
        case wt_data_blocked_capsule:
        case wt_streams_blocked_bidi_capsule:
        case wt_streams_blocked_uni_capsule:
            if (!flow_control_) {
                phase_ = phase::skip;
                break;
            }
            // A varint value must fill the capsule exactly; checked in complete().
            if (length > 8) return std::unexpected(wt_error::h3_message_error);
            break;
        case wt_max_stream_data_capsule:
        case wt_stream_data_blocked_capsule:
            return std::unexpected(wt_error::wt_flow_control_error);
        default:
            phase_ = phase::skip;
            break;
        }
        if (phase_ == phase::value && length == 0) return complete();
        return std::optional<capsule_event> {};
    }

    auto complete() noexcept -> event_result
    {
        const std::span<const std::byte> value(buffer_.data(), fill_);
        phase_ = phase::type;
        if (type_value_ == datagram_capsule)
            return std::optional<capsule_event> {wt_datagram {value}};
        if (type_value_ == wt_close_session_capsule) {
            const auto text = std::string_view(
                reinterpret_cast<const char*>(value.data() + 4), value.size() - 4);
            if (!valid_utf8(text)) return std::unexpected(wt_error::h3_message_error);
            phase_ = phase::closed;
            const auto code = (std::to_integer<std::uint32_t>(value[0]) << 24) |
                              (std::to_integer<std::uint32_t>(value[1]) << 16) |
                              (std::to_integer<std::uint32_t>(value[2]) << 8) |
                              std::to_integer<std::uint32_t>(value[3]);
            return std::optional<capsule_event> {wt_close_session {code, text}};
        }

        const auto decoded = quic::detail::decode_varint(value);
        if (!decoded || decoded->encoded_size != value.size())
            return std::unexpected(wt_error::h3_message_error);
        const auto number = decoded->value;
        switch (type_value_) {
        case wt_max_data_capsule:
            return std::optional<capsule_event> {wt_max_data {number}};
        case wt_data_blocked_capsule:
            return std::optional<capsule_event> {wt_data_blocked {number}};
        case wt_max_streams_bidi_capsule:
        case wt_max_streams_uni_capsule:
            if (number > wt_max_stream_count)
                return std::unexpected(wt_error::wt_flow_control_error);
            return std::optional<capsule_event> {
                wt_max_streams {type_value_ == wt_max_streams_bidi_capsule, number}};
        case wt_streams_blocked_bidi_capsule:
        case wt_streams_blocked_uni_capsule:
            if (number > wt_max_stream_count)
                return std::unexpected(wt_error::wt_flow_control_error);
            return std::optional<capsule_event> {
                wt_streams_blocked {type_value_ == wt_streams_blocked_bidi_capsule, number}};
        default:
            return std::unexpected(wt_error::h3_message_error);
        }
    }

    bool flow_control_;
    std::size_t max_datagram_;
    phase phase_ {phase::type};
    varint_accumulator type_varint_ {};
    varint_accumulator length_varint_ {};
    std::uint64_t type_value_ {0};
    std::uint64_t remaining_ {0};
    std::size_t fill_ {0};
    std::array<std::byte, wt_capsule_buffer_size> buffer_ {};
};

// Capsule encoders write the bare capsule (type, length, value). Framing as HTTP
// DATA frames or stream placement is the caller's responsibility.

[[nodiscard]] inline auto encode_varint_capsule(
    std::uint64_t type, std::uint64_t value, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, wt_encode_error>
{
    const auto value_size = quic::detail::varint_size(value);
    if (value_size == 0) return std::unexpected(wt_encode_error::value_out_of_range);
    const auto header = capsule_header_size(type, value_size);
    if (header == 0) return std::unexpected(wt_encode_error::value_out_of_range);
    if (output.size() < header + value_size)
        return std::unexpected(wt_encode_error::output_too_small);
    (void)encode_capsule_header(type, value_size, output);
    (void)quic::detail::encode_varint(value, output.subspan(header));
    return header + value_size;
}

// The message is truncated to 1024 bytes at a UTF-8 boundary. Invalid UTF-8 is
// rejected rather than sent.
[[nodiscard]] inline auto encode_close_session(
    std::uint32_t code, std::string_view message, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, wt_encode_error>
{
    if (!valid_utf8(message)) return std::unexpected(wt_encode_error::invalid_utf8);
    const auto text = utf8_truncate(message, wt_max_close_message);
    const auto length = 4 + text.size();
    const auto header = capsule_header_size(wt_close_session_capsule, length);
    if (output.size() < header + length)
        return std::unexpected(wt_encode_error::output_too_small);
    (void)encode_capsule_header(wt_close_session_capsule, length, output);
    for (std::size_t index = 0; index < 4; ++index)
        output[header + index] = static_cast<std::byte>((code >> (24 - 8 * index)) & 0xff);
    if (!text.empty())
        std::memcpy(output.data() + header + 4, text.data(), text.size());
    return header + length;
}

[[nodiscard]] inline auto encode_drain_session(std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, wt_encode_error>
{
    return encode_capsule_header(wt_drain_session_capsule, 0, output);
}

[[nodiscard]] inline auto encode_max_data(std::uint64_t maximum, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, wt_encode_error>
{
    return encode_varint_capsule(wt_max_data_capsule, maximum, output);
}

[[nodiscard]] inline auto encode_data_blocked(std::uint64_t maximum, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, wt_encode_error>
{
    return encode_varint_capsule(wt_data_blocked_capsule, maximum, output);
}

[[nodiscard]] inline auto encode_max_streams(
    bool bidirectional, std::uint64_t maximum, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, wt_encode_error>
{
    if (maximum > wt_max_stream_count)
        return std::unexpected(wt_encode_error::value_out_of_range);
    return encode_varint_capsule(
        bidirectional ? wt_max_streams_bidi_capsule : wt_max_streams_uni_capsule, maximum, output);
}

[[nodiscard]] inline auto encode_streams_blocked(
    bool bidirectional, std::uint64_t maximum, std::span<std::byte> output) noexcept
    -> std::expected<std::size_t, wt_encode_error>
{
    if (maximum > wt_max_stream_count)
        return std::unexpected(wt_encode_error::value_out_of_range);
    return encode_varint_capsule(
        bidirectional ? wt_streams_blocked_bidi_capsule : wt_streams_blocked_uni_capsule,
        maximum, output);
}

// ---- Structured Fields (RFC 9651) for WT-Available-Protocols / WT-Protocol ---

namespace wt_sf {

[[nodiscard]] constexpr auto is_alpha(char c) noexcept -> bool
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
[[nodiscard]] constexpr auto is_lcalpha(char c) noexcept -> bool { return c >= 'a' && c <= 'z'; }
[[nodiscard]] constexpr auto is_digit(char c) noexcept -> bool { return c >= '0' && c <= '9'; }
[[nodiscard]] constexpr auto is_tchar(char c) noexcept -> bool
{
    return is_alpha(c) || is_digit(c) || std::string_view("!#$%&'*+-.^_`|~").find(c) !=
                                              std::string_view::npos;
}

constexpr auto skip_spaces(std::string_view input, std::size_t& index) noexcept -> void
{
    while (index < input.size() && input[index] == ' ') ++index;
}

// sf-string. escaped reports whether a backslash escape was present.
[[nodiscard]] constexpr auto string(std::string_view input, std::size_t& index,
                                    std::string_view& value, bool& escaped) noexcept -> bool
{
    if (index >= input.size() || input[index] != '"') return false;
    const auto start = ++index;
    escaped = false;
    while (index < input.size()) {
        const char c = input[index];
        if (c == '"') {
            value = input.substr(start, index - start);
            ++index;
            return true;
        }
        if (c == '\\') {
            if (index + 1 >= input.size()) return false;
            const char next = input[index + 1];
            if (next != '"' && next != '\\') return false;
            escaped = true;
            index += 2;
            continue;
        }
        if (c < 0x20 || c > 0x7e) return false;
        ++index;
    }
    return false;
}

// sf-integer or sf-decimal.
[[nodiscard]] constexpr auto number(std::string_view input, std::size_t& index) noexcept -> bool
{
    if (index < input.size() && input[index] == '-') ++index;
    const auto digits_start = index;
    while (index < input.size() && is_digit(input[index])) ++index;
    const auto integer_digits = index - digits_start;
    if (integer_digits == 0) return false;
    if (index < input.size() && input[index] == '.') {
        if (integer_digits > 12) return false;
        ++index;
        const auto fraction_start = index;
        while (index < input.size() && is_digit(input[index])) ++index;
        const auto fraction_digits = index - fraction_start;
        return fraction_digits >= 1 && fraction_digits <= 3;
    }
    return integer_digits <= 15;
}

// Any sf-bare-item; used only for parameter values, which are ignored.
[[nodiscard]] constexpr auto bare_item(std::string_view input, std::size_t& index) noexcept -> bool
{
    if (index >= input.size()) return false;
    const char c = input[index];
    if (c == '-' || is_digit(c)) return number(input, index);
    if (c == '"') {
        std::string_view value;
        bool escaped = false;
        return string(input, index, value, escaped);
    }
    if (c == '?') {
        if (index + 1 < input.size() && (input[index + 1] == '0' || input[index + 1] == '1')) {
            index += 2;
            return true;
        }
        return false;
    }
    if (c == ':') {
        ++index;
        while (index < input.size() && (is_alpha(input[index]) || is_digit(input[index]) ||
                                        input[index] == '+' || input[index] == '/' ||
                                        input[index] == '=')) ++index;
        if (index < input.size() && input[index] == ':') {
            ++index;
            return true;
        }
        return false;
    }
    if (is_alpha(c) || c == '*') {
        ++index;
        while (index < input.size() && (is_tchar(input[index]) || input[index] == ':' ||
                                        input[index] == '/')) ++index;
        return true;
    }
    return false;
}

// Parameters: *( ";" *SP key [ "=" bare-item ] ). Syntax is validated, values ignored.
[[nodiscard]] constexpr auto parameters(std::string_view input, std::size_t& index) noexcept -> bool
{
    while (index < input.size() && input[index] == ';') {
        ++index;
        skip_spaces(input, index);
        if (index >= input.size() || !(is_lcalpha(input[index]) || input[index] == '*'))
            return false;
        ++index;
        while (index < input.size() && (is_lcalpha(input[index]) || is_digit(input[index]) ||
                                        input[index] == '_' || input[index] == '-' ||
                                        input[index] == '.' || input[index] == '*')) ++index;
        if (index < input.size() && input[index] == '=') {
            ++index;
            if (!bare_item(input, index)) return false;
        }
    }
    return true;
}

} // namespace wt_sf

// Parses an sf-list whose members must all be sf-strings. Parameters are
// validated and ignored. Returned views borrow field_value.
//
// Returns nullopt, meaning "ignore the whole field", for any syntax error, any
// non-string member (token, number, boolean, binary, or inner list), any member
// containing a backslash escape (escapes are unsupported here), or more members
// than out holds. An empty or all-space field is an empty list.
[[nodiscard]] constexpr auto parse_available_protocols(
    std::string_view field_value, std::span<std::string_view> out) noexcept
    -> std::optional<std::size_t>
{
    std::size_t index = 0;
    std::size_t count = 0;
    wt_sf::skip_spaces(field_value, index);
    if (index == field_value.size()) return std::size_t {0};
    for (;;) {
        std::string_view value;
        bool escaped = false;
        if (!wt_sf::string(field_value, index, value, escaped) || escaped) return std::nullopt;
        if (count == out.size()) return std::nullopt;
        out[count++] = value;
        if (!wt_sf::parameters(field_value, index)) return std::nullopt;
        wt_sf::skip_spaces(field_value, index);
        if (index == field_value.size()) return count;
        if (field_value[index] != ',') return std::nullopt;
        ++index;
        wt_sf::skip_spaces(field_value, index);
    }
}

// Writes protocol as an sf-string item, escaping '"' and '\'. Printable ASCII only.
// The output is untouched on failure.
[[nodiscard]] constexpr auto format_protocol(std::string_view protocol, std::span<char> output) noexcept
    -> std::expected<std::size_t, wt_encode_error>
{
    std::size_t needed = 2;
    for (const char c : protocol) {
        if (c < 0x20 || c > 0x7e) return std::unexpected(wt_encode_error::invalid_protocol);
        needed += (c == '"' || c == '\\') ? 2 : 1;
    }
    if (output.size() < needed) return std::unexpected(wt_encode_error::output_too_small);
    std::size_t at = 0;
    output[at++] = '"';
    for (const char c : protocol) {
        if (c == '"' || c == '\\') output[at++] = '\\';
        output[at++] = c;
    }
    output[at++] = '"';
    return at;
}

// ---- Session flow control -------------------------------------------------

// Stream-count limits are indexed by stream_index(bidirectional).
[[nodiscard]] constexpr auto stream_index(bool bidirectional) noexcept -> std::size_t
{
    return bidirectional ? 0 : 1;
}

struct flow_limits {
    std::uint64_t data {0};
    std::array<std::uint64_t, 2> streams {0, 0};
};

// Pure session-level flow control (WebTransport section "Flow Control"). Two
// views are kept: what this endpoint has advertised to the peer (local) and what
// the peer advertised to us (peer). The caller reports body bytes and stream
// opens or closes in order, and sends the WT_* capsules this class asks for.
//
// When disabled, every check passes, nothing is tracked, and no capsule is
// requested.
class session_flow {
public:
    // local: initial limits this endpoint advertised. Renewals use them as the
    // window size. peer: initial limits from the peer's SETTINGS.
    session_flow(bool enabled, flow_limits local, flow_limits peer) noexcept
        : enabled_(enabled), window_(local), local_(local), peer_(peer) {}

    [[nodiscard]] auto enabled() const noexcept -> bool { return enabled_; }

    // ---- Sending (our limits from the peer) ----

    // Body bytes we may send now, at most wanted. Records them as sent.
    [[nodiscard]] auto reserve_send(std::uint64_t wanted) noexcept -> std::uint64_t
    {
        if (!enabled_) return wanted;
        const auto allowed = std::min(wanted, peer_.data - sent_data_);
        sent_data_ += allowed;
        if (allowed < wanted) data_blocked_pending_ = true;
        return allowed;
    }

    // Gives back credit that reserve_send counted but the write did not send (a short
    // or failed QUIC write). The peer counts only bytes it received, so keeping it
    // reserved would leak window it can never renew.
    auto release_send(std::uint64_t unsent) noexcept -> void
    {
        if (!enabled_) return;
        sent_data_ -= std::min(unsent, sent_data_);
    }

    // WT_DATA_BLOCKED value to send after reserve_send was short. Reported once per
    // peer limit value.
    [[nodiscard]] auto take_data_blocked() noexcept -> std::optional<std::uint64_t>
    {
        if (!data_blocked_pending_) return std::nullopt;
        data_blocked_pending_ = false;
        if (last_data_blocked_ == peer_.data) return std::nullopt;
        last_data_blocked_ = peer_.data;
        return peer_.data;
    }

    // Whether we may open one more stream of this type. Counts the stream when true.
    [[nodiscard]] auto open_stream(bool bidirectional) noexcept -> bool
    {
        if (!enabled_) return true;
        const auto index = stream_index(bidirectional);
        if (local_opened_[index] >= peer_.streams[index]) {
            streams_blocked_pending_[index] = true;
            return false;
        }
        ++local_opened_[index];
        return true;
    }

    // Roll back a reservation when QUIC refused to create the stream.
    auto release_stream(bool bidirectional) noexcept -> void
    {
        if (enabled_) --local_opened_[stream_index(bidirectional)];
    }

    // WT_STREAMS_BLOCKED value to send after open_stream was refused. Reported
    // once per peer limit value.
    [[nodiscard]] auto take_streams_blocked(bool bidirectional) noexcept
        -> std::optional<std::uint64_t>
    {
        const auto index = stream_index(bidirectional);
        if (!streams_blocked_pending_[index]) return std::nullopt;
        streams_blocked_pending_[index] = false;
        if (last_streams_blocked_[index] == peer_.streams[index]) return std::nullopt;
        last_streams_blocked_[index] = peer_.streams[index];
        return peer_.streams[index];
    }

    // Peer's WT_MAX_DATA. Must increase the previous value (or the SETTINGS value).
    [[nodiscard]] auto on_max_data(std::uint64_t maximum) noexcept -> std::expected<void, wt_error>
    {
        if (!enabled_) return {};
        if (maximum <= peer_.data) return std::unexpected(wt_error::wt_flow_control_error);
        peer_.data = maximum;
        return {};
    }

    // Peer's WT_MAX_STREAMS. Must increase and must not exceed 2^60.
    [[nodiscard]] auto on_max_streams(bool bidirectional, std::uint64_t maximum) noexcept
        -> std::expected<void, wt_error>
    {
        if (!enabled_) return {};
        if (maximum > wt_max_stream_count) return std::unexpected(wt_error::wt_flow_control_error);
        auto& limit = peer_.streams[stream_index(bidirectional)];
        if (maximum <= limit) return std::unexpected(wt_error::wt_flow_control_error);
        limit = maximum;
        return {};
    }

    // ---- Receiving (our advertised limits) ----

    // Body bytes received from the peer, excluding stream headers. Exceeding the
    // advertised limit is WT_FLOW_CONTROL_ERROR. Include the final size of reset
    // streams.
    [[nodiscard]] auto on_peer_data(std::uint64_t bytes) noexcept -> std::expected<void, wt_error>
    {
        if (!enabled_) return {};
        if (bytes > local_.data - received_data_)
            return std::unexpected(wt_error::wt_flow_control_error);
        received_data_ += bytes;
        return {};
    }

    // A peer-initiated stream was opened in this session. Exceeding the advertised
    // stream limit is WT_FLOW_CONTROL_ERROR.
    [[nodiscard]] auto on_peer_stream_opened(bool bidirectional) noexcept
        -> std::expected<void, wt_error>
    {
        if (!enabled_) return {};
        const auto index = stream_index(bidirectional);
        if (peer_opened_[index] >= local_.streams[index])
            return std::unexpected(wt_error::wt_flow_control_error);
        ++peer_opened_[index];
        return {};
    }

    // A peer-initiated stream finished (both directions done or reset).
    auto on_peer_stream_closed(bool bidirectional) noexcept -> void
    {
        if (!enabled_) return;
        const auto index = stream_index(bidirectional);
        if (peer_closed_[index] < peer_opened_[index]) ++peer_closed_[index];
    }

    // The application consumed body bytes from the peer.
    auto on_data_consumed(std::uint64_t bytes) noexcept -> void
    {
        if (!enabled_) return;
        consumed_data_ += std::min(bytes, received_data_ - consumed_data_);
    }

    // New WT_MAX_DATA value to send, once the peer has used half of the window.
    // The new limit is consumed bytes plus the window, and it must increase.
    [[nodiscard]] auto take_max_data_update() noexcept -> std::optional<std::uint64_t>
    {
        const auto window = window_.data;
        if (!enabled_ || window == 0 || local_.data - received_data_ > window / 2)
            return std::nullopt;
        const auto next = std::min(consumed_data_ + window, quic::detail::max_varint_value);
        if (next <= local_.data) return std::nullopt;
        local_.data = next;
        return next;
    }

    // New WT_MAX_STREAMS value to send, once the peer has used half of the window.
    // The new limit is closed streams plus the window, capped at 2^60.
    [[nodiscard]] auto take_max_streams_update(bool bidirectional) noexcept
        -> std::optional<std::uint64_t>
    {
        const auto index = stream_index(bidirectional);
        const auto window = window_.streams[index];
        if (!enabled_ || window == 0 ||
            local_.streams[index] - peer_opened_[index] > window / 2)
            return std::nullopt;
        const auto next = std::min(peer_closed_[index] + window, wt_max_stream_count);
        if (next <= local_.streams[index]) return std::nullopt;
        local_.streams[index] = next;
        return next;
    }

private:
    bool enabled_;
    flow_limits window_;
    flow_limits local_;
    flow_limits peer_;
    std::uint64_t sent_data_ {0};
    std::uint64_t received_data_ {0};
    std::uint64_t consumed_data_ {0};
    std::array<std::uint64_t, 2> local_opened_ {0, 0};
    std::array<std::uint64_t, 2> peer_opened_ {0, 0};
    std::array<std::uint64_t, 2> peer_closed_ {0, 0};
    bool data_blocked_pending_ {false};
    std::optional<std::uint64_t> last_data_blocked_;
    std::array<bool, 2> streams_blocked_pending_ {false, false};
    std::array<std::optional<std::uint64_t>, 2> last_streams_blocked_ {};
};

} // namespace eventloop::http3::detail
