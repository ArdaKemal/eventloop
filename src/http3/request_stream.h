#pragma once

#include "errors.h"
#include "frames.h"
#include "qpack.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>

namespace eventloop::http3::detail {

constexpr std::uint64_t max_stream_data = (std::uint64_t {1} << 62) - 1;

// WebTransport over HTTP/3 (draft-16, "Bidirectional Streams"): the WT_STREAM
// signal 0x41 is a frame type that is valid only as the first varint of a
// client-initiated bidirectional stream.
inline constexpr std::uint64_t wt_stream_signal = 0x41;

// Incremental parser for a client request stream (RFC 9114 4.1 and 7.1):
// HEADERS, then DATA frames, then at most one trailing HEADERS. Unknown and
// reserved extension frames may appear anywhere and are skipped by length.
// HEADERS payloads are copied into caller storage that must outlive the
// parser. DATA payloads are delivered as views of the input and counted. No
// other input is buffered.
//
// With set_webtransport(true), a stream whose first frame type is 0x41 yields
// event::webtransport_stream once its session ID varint is complete. Input
// after that point is stream data rather than HTTP/3 framing: the caller takes
// over at the first body byte, and later receive() calls consume nothing and
// return need_input. A 0x41 frame type anywhere else is H3_FRAME_ERROR.
//
// Errors are RFC codes; stream_scoped() tells whether to reset the stream or
// close the connection.
class request_frames {
public:
    enum class event { need_input, header_block, data, webtransport_stream };

    explicit request_frames(std::span<std::byte> block_storage) noexcept
        : storage_(block_storage) {}

    // Consumes input until a complete header block or some DATA payload is
    // available, leaving input positioned after it, or until input is
    // exhausted. The block stays valid until the next call; data() views the
    // payload bytes in input.
    [[nodiscard]] auto receive(std::span<const std::byte>& input) noexcept
        -> std::expected<event, h3_error>
    {
        while (!input.empty()) {
            switch (state_) {
            case state::frame_type: {
                const auto type = varint_.feed(input);
                if (!type) break;
                const bool first = !frame_started_;
                frame_started_ = true;
                frame_type_ = *type;
                if (webtransport_ && *type == wt_stream_signal) {
                    if (!first) return std::unexpected(h3_error::frame_error);
                    state_ = state::wt_session_id;
                    break;
                }
                state_ = state::frame_length;
                break;
            }
            case state::wt_session_id: {
                const auto id = varint_.feed(input);
                if (!id) break;
                session_id_ = *id;
                state_ = state::wt_body;
                return event::webtransport_stream;
            }
            case state::wt_body:
                // Stream data belongs to the caller; nothing is consumed here.
                return event::need_input;
            case state::frame_length: {
                const auto length = varint_.feed(input);
                if (!length) break;
                remaining_ = *length;
                if (const auto started = begin_frame(); !started)
                    return std::unexpected(started.error());
                if (state_ == state::header_payload && remaining_ == 0)
                    return complete_block();
                break;
            }
            case state::header_payload: {
                const auto count = take(input);
                std::copy_n(input.begin(), count, storage_.begin() + static_cast<std::ptrdiff_t>(block_size_));
                block_size_ += count;
                input = input.subspan(count);
                if (remaining_ == 0) return complete_block();
                break;
            }
            case state::skip_payload:
                input = input.subspan(take(input));
                if (remaining_ == 0) state_ = state::frame_type;
                break;
            case state::data_payload: {
                const auto count = take(input);
                data_ = input.first(count);
                input = input.subspan(count);
                if (remaining_ == 0) state_ = state::frame_type;
                return event::data;
            }
            }
        }
        return event::need_input;
    }

    // Peer FIN. A truncated frame is a connection error (RFC 9114 7.1); a
    // stream ending before its request HEADERS is incomplete (4.1).
    [[nodiscard]] auto finish() const noexcept -> std::expected<void, h3_error>
    {
        // A WebTransport stream that ends before its session ID is incomplete;
        // after it, the stream data may end at any point.
        if (state_ == state::wt_session_id) return std::unexpected(h3_error::request_incomplete);
        if (state_ == state::wt_body) return {};
        if (state_ != state::frame_type || varint_.partial())
            return std::unexpected(h3_error::frame_error);
        if (phase_ == phase::request_headers)
            return std::unexpected(h3_error::request_incomplete);
        if (content_length_too_large_ || (content_length_ && data_received_ != *content_length_))
            return std::unexpected(h3_error::message_error);
        return {};
    }

    // Declared request content length; DATA must sum to it exactly (4.1.2).
    // A decimal above the QUIC stream limit cannot match even at FIN.
    auto set_content_length(std::optional<std::uint64_t> length, bool too_large = false) noexcept -> void
    { content_length_ = length; content_length_too_large_ = too_large; }

    auto accept_connect() noexcept -> void
    { tunnel_ = true; content_length_.reset(); content_length_too_large_ = false; }

    // Recognizes WT_STREAM (0x41) as the first frame of this stream. Off by
    // default, in which case 0x41 is an unknown frame type.
    auto set_webtransport(bool enabled) noexcept -> void { webtransport_ = enabled; }
    // Session ID of a webtransport_stream event; meaningless for other events.
    [[nodiscard]] auto session_id() const noexcept -> std::uint64_t { return session_id_; }

    [[nodiscard]] auto block() const noexcept -> std::span<const std::byte>
    { return std::span<const std::byte>(storage_).first(block_size_); }
    // The DATA payload bytes of the last data event.
    [[nodiscard]] auto data() const noexcept -> std::span<const std::byte> { return data_; }
    // Storage for later HEADERS payloads (trailers), for example once the
    // request section has been decoded and its storage is in use elsewhere.
    auto set_block_storage(std::span<std::byte> storage) noexcept -> void { storage_ = storage; }
    // DATA frames may still follow.
    [[nodiscard]] auto in_body() const noexcept -> bool { return phase_ == phase::body; }
    [[nodiscard]] auto trailers() const noexcept -> bool
    { return phase_ == phase::complete; }
    [[nodiscard]] auto data_received() const noexcept -> std::uint64_t
    { return data_received_; }

private:
    enum class state : std::uint8_t {
        frame_type, frame_length, header_payload, skip_payload, data_payload,
        wt_session_id, wt_body,
    };
    enum class phase : std::uint8_t { request_headers, body, complete };

    auto take(std::span<const std::byte> input) noexcept -> std::size_t
    {
        const auto count = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining_, input.size()));
        remaining_ -= count;
        return count;
    }

    auto begin_frame() noexcept -> std::expected<void, h3_error>
    {
        if (frame_type_ == headers_frame) {
            if (tunnel_ || phase_ == phase::complete) return std::unexpected(h3_error::frame_unexpected);
            if (remaining_ > storage_.size()) return std::unexpected(h3_error::excessive_load);
            block_size_ = 0;
            state_ = state::header_payload;
            return {};
        }
        if (frame_type_ == data_frame) {
            if (phase_ != phase::body) return std::unexpected(h3_error::frame_unexpected);
            if (remaining_ > max_stream_data - data_received_)
                return std::unexpected(h3_error::message_error);
            data_received_ += remaining_;
            if (content_length_ && data_received_ > *content_length_)
                return std::unexpected(h3_error::message_error);
            state_ = remaining_ == 0 ? state::frame_type : state::data_payload;
            return {};
        } else if (known_frame_type(frame_type_) || forbidden_frame_type(frame_type_)) {
            // Control-stream frames, PUSH_PROMISE from a client, and reserved
            // HTTP/2 types are invalid on a request stream (7.2).
            return std::unexpected(h3_error::frame_unexpected);
        }
        state_ = remaining_ == 0 ? state::frame_type : state::skip_payload;
        return {};
    }

    auto complete_block() noexcept -> std::expected<event, h3_error>
    {
        state_ = state::frame_type;
        phase_ = phase_ == phase::request_headers ? phase::body : phase::complete;
        return event::header_block;
    }

    std::span<std::byte> storage_;
    std::span<const std::byte> data_;
    std::optional<std::uint64_t> content_length_;
    std::uint64_t frame_type_ {0};
    std::uint64_t remaining_ {0};
    std::uint64_t data_received_ {0};
    std::size_t block_size_ {0};
    std::uint64_t session_id_ {0};
    varint_accumulator varint_ {};
    state state_ {state::frame_type};
    phase phase_ {phase::request_headers};
    bool tunnel_ {false};
    bool content_length_too_large_ {false};
    bool webtransport_ {false};
    bool frame_started_ {false};
};

// HTTP field names, methods, and Extended CONNECT protocol values are tokens.
[[nodiscard]] constexpr auto valid_token(std::string_view text) noexcept -> bool
{
    if (text.empty()) return false;
    for (unsigned char c : text)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) !=
                  std::string_view::npos)) return false;
    return true;
}

// RFC 9110 5.5: field-vchar at either end, with SP/HTAB allowed internally.
[[nodiscard]] constexpr auto valid_field_value(std::string_view value) noexcept -> bool
{
    if (!value.empty() && (value.front() == ' ' || value.front() == '\t' ||
                           value.back() == ' ' || value.back() == '\t')) return false;
    for (unsigned char c : value)
        if ((c < 0x20 && c != '\t') || c == 0x7f) return false;
    return true;
}

// ASCII case-insensitive matching against a lowercase comparison string.
[[nodiscard]] constexpr auto ascii_equal(std::string_view text,
                                       std::string_view name) noexcept -> bool
{
    if (text.size() != name.size()) return false;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const auto c = static_cast<unsigned char>(text[i]);
        if ((c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c) != name[i]) return false;
    }
    return true;
}

// Field rules shared by request headers and trailers (RFC 9114 4.2 and
// 4.1.2): lowercase token names, valid field values, no connection-
// specific fields, and TE limited to "trailers".
[[nodiscard]] constexpr auto valid_regular_field(const field& f) noexcept -> bool
{
    if (!valid_token(f.name)) return false;
    for (unsigned char c : f.name)
        if (c >= 'A' && c <= 'Z') return false;
    if (!valid_field_value(f.value)) return false;
    if (f.name == "connection" || f.name == "keep-alive" || f.name == "proxy-connection" ||
        f.name == "transfer-encoding" || f.name == "upgrade") return false;
    return f.name != "te" || ascii_equal(f.value, "trailers");
}

// URI schemes are an ASCII letter followed by letters, digits, '+', '-', or '.'.
[[nodiscard]] constexpr auto valid_scheme(std::string_view scheme) noexcept -> bool
{
    const auto alpha = [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    };
    if (scheme.empty() || !alpha(scheme.front())) return false;
    for (unsigned char c : scheme)
        if (!alpha(c) && !(c >= '0' && c <= '9') && c != '+' && c != '-' && c != '.')
            return false;
    return true;
}

[[nodiscard]] constexpr auto uri_hex_digit(unsigned char c) noexcept -> bool
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

// RFC 3986 unreserved / sub-delims, shared by reg-name and IPvFuture.
[[nodiscard]] constexpr auto uri_name_char(unsigned char c) noexcept -> bool
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           std::string_view("-._~!$&'()*+,;=").find(static_cast<char>(c)) != std::string_view::npos;
}

[[nodiscard]] constexpr auto valid_ipv4_tail(std::string_view address) noexcept -> bool
{
    for (unsigned i = 0; i < 4; ++i) {
        const auto dot = address.find('.');
        const auto octet = address.substr(0, dot);
        if (octet.empty() || octet.size() > 3 || (octet.size() > 1 && octet.front() == '0'))
            return false;
        unsigned value = 0;
        for (unsigned char c : octet) {
            if (c < '0' || c > '9') return false;
            value = value * 10 + static_cast<unsigned>(c - '0');
        }
        if (value > 255) return false;
        if (i == 3) return dot == std::string_view::npos;
        if (dot == std::string_view::npos) return false;
        address.remove_prefix(dot + 1);
    }
    return false;
}

// RFC 3986 3.2.2: IPv6address or IPvFuture, without constructing an address.
[[nodiscard]] constexpr auto valid_ip_literal(std::string_view address) noexcept -> bool
{
    if (address.empty()) return false;
    if (address.front() == 'v' || address.front() == 'V') {
        address.remove_prefix(1);
        const auto dot = address.find('.');
        if (dot == 0 || dot == std::string_view::npos) return false;
        for (unsigned char c : address.substr(0, dot))
            if (!uri_hex_digit(c)) return false;
        address.remove_prefix(dot + 1);
        if (address.empty()) return false;
        for (unsigned char c : address)
            if (!uri_name_char(c) && c != ':') return false;
        return true;
    }
    unsigned groups = 0;
    bool compressed = address.starts_with("::");
    if (compressed) address.remove_prefix(2);
    while (!address.empty()) {
        const auto colon = address.find(':');
        const auto group = address.substr(0, colon);
        if (group.empty()) return false;
        if (group.find('.') != std::string_view::npos) {
            if (colon != std::string_view::npos || !valid_ipv4_tail(group)) return false;
            groups += 2;
            break;
        }
        if (group.size() > 4) return false;
        for (unsigned char c : group)
            if (!uri_hex_digit(c)) return false;
        if (++groups > 8) return false;
        if (colon == std::string_view::npos) break;
        address.remove_prefix(colon + 1);
        if (address.starts_with(':')) {
            if (compressed) return false;
            compressed = true;
            address.remove_prefix(1);
        } else if (address.empty()) return false;
    }
    return compressed ? groups < 8 : groups == 8;
}

// CONNECT requires a nonempty numeric port; HTTP(S) permits no or empty port.
[[nodiscard]] constexpr auto valid_authority(std::string_view authority,
                                            bool require_port = false) noexcept -> bool
{
    if (authority.empty()) return false;
    const bool bracketed = authority.front() == '[';
    auto end = authority.find(bracketed ? ']' : ':');
    if (bracketed && end == std::string_view::npos) return false;
    if (end == std::string_view::npos) end = authority.size();
    const auto host = authority.substr(bracketed ? 1 : 0, end - (bracketed ? 1 : 0));
    if (host.empty()) return false;
    if (bracketed && !valid_ip_literal(host)) return false;
    for (std::size_t i = 0; !bracketed && i < host.size(); ++i) {
        const auto c = static_cast<unsigned char>(host[i]);
        if (c == '%') {
            if (host.size() - i < 3 || !uri_hex_digit(host[i + 1]) ||
                !uri_hex_digit(host[i + 2])) return false;
            i += 2;
        } else if (!uri_name_char(c)) return false;
    }
    if (bracketed) ++end;
    if (end == authority.size()) return !require_port;
    if (authority[end] != ':') return false;
    const auto port = authority.substr(end + 1);
    if (require_port && port.empty()) return false;
    for (unsigned char c : port)
        if (c < '0' || c > '9') return false;
    return true;
}

// RFC 9114 4.3.1 (erratum 7014): absolute-path (RFC 9110 4.1) and optional
// query (RFC 3986 3.4), or '*' for OPTIONS. Check escapes without decoding.
[[nodiscard]] constexpr auto valid_request_path(std::string_view path,
                                               std::string_view method) noexcept -> bool
{
    if (path == "*") return method == "OPTIONS";
    if (path.empty() || path.front() != '/') return false;
    for (std::size_t i = 0; i < path.size(); ++i) {
        const auto c = static_cast<unsigned char>(path[i]);
        if (c == '%') {
            if (path.size() - i < 3 || !uri_hex_digit(path[i + 1]) ||
                !uri_hex_digit(path[i + 2])) return false;
            i += 2;
        } else if (!uri_name_char(c) && c != ':' && c != '@' && c != '/' && c != '?')
            return false;
    }
    return true;
}

struct request_head {
    std::string_view method;
    std::string_view scheme;
    std::string_view authority; // :authority, or Host when it is absent
    std::string_view path;
    std::string_view connect_protocol;
    std::optional<std::uint64_t> content_length;
    bool content_length_too_large {false}; // Declared length cannot fit a QUIC stream.
};

// Validates a decoded request field section. Any violation makes the request
// malformed, which is a stream error of type H3_MESSAGE_ERROR (4.1.2).
[[nodiscard]] constexpr auto validate_request(std::span<const field> fields,
                                              bool enable_extended_connect = false) noexcept
    -> std::expected<request_head, h3_error>
{
    const auto malformed = std::unexpected(h3_error::message_error);
    request_head head;
    bool have_method = false, have_scheme = false, have_path = false, have_authority = false;
    bool have_protocol = false;
    bool regular = false;
    std::optional<std::string_view> host;
    std::optional<std::string_view> declared_length;
    for (const auto& f : fields) {
        if (!f.name.empty() && f.name.front() == ':') {
            if (regular) return malformed;
            const auto take = [&](bool& seen, std::string_view& target) {
                if (seen) return false;
                seen = true;
                target = f.value;
                return true;
            };
            bool ok = false;
            if (f.name == ":method") ok = take(have_method, head.method);
            else if (f.name == ":scheme") ok = take(have_scheme, head.scheme);
            else if (f.name == ":path") ok = take(have_path, head.path);
            else if (f.name == ":authority") ok = take(have_authority, head.authority);
            else if (f.name == ":protocol" && enable_extended_connect)
                ok = take(have_protocol, head.connect_protocol);
            if (!ok) return malformed;
            if (!valid_field_value(f.value)) return malformed;
            continue;
        }
        regular = true;
        if (!valid_regular_field(f)) return malformed;
        if (f.name == "host") {
            if (host) return malformed;
            host = f.value;
        } else if (f.name == "content-length") {
            if (f.value.empty()) return malformed;
            for (char c : f.value)
                if (c < '0' || c > '9') return malformed;
            const auto first = f.value.find_first_not_of('0');
            const auto normalized = first == std::string_view::npos ? std::string_view {}
                                                                    : f.value.substr(first);
            if (declared_length && *declared_length != normalized) return malformed;
            declared_length = normalized;
            constexpr std::string_view limit = "4611686018427387903"; // max_stream_data
            head.content_length_too_large = normalized.size() > limit.size() ||
                (normalized.size() == limit.size() && normalized > limit);
            if (!head.content_length_too_large) {
                std::uint64_t value = 0;
                for (char c : normalized) value = value * 10 + static_cast<unsigned>(c - '0');
                head.content_length = value;
            }
        }
    }
    if (!have_method || !valid_token(head.method)) return malformed;
    if (host && !valid_authority(*host)) return malformed;
    if (have_protocol) {
        if (head.method != "CONNECT" || !valid_token(head.connect_protocol) ||
            !have_scheme || head.scheme.empty() || !have_path ||
            !have_authority || head.authority.empty()) return malformed;
    } else if (head.method == "CONNECT") {
        // Plain CONNECT names only an authority (4.4).
        if (have_scheme || have_path || !have_authority || !valid_authority(head.authority, true))
            return malformed;
        return head;
    }
    if (!have_scheme || !valid_scheme(head.scheme) || !have_path ||
        !valid_request_path(head.path, head.method)) return malformed;
    if (ascii_equal(head.scheme, "http") || ascii_equal(head.scheme, "https")) {
        if (have_authority && host && *host != head.authority) return malformed;
        if (!have_authority) {
            if (!host) return malformed;
            head.authority = *host;
        }
        if (!valid_authority(head.authority)) return malformed;
    }
    return head;
}

// Trailers carry no pseudo-header fields (4.1.2).
[[nodiscard]] constexpr auto validate_trailers(std::span<const field> fields) noexcept
    -> std::expected<void, h3_error>
{
    for (const auto& f : fields)
        if (!valid_regular_field(f)) return std::unexpected(h3_error::message_error);
    return {};
}

// QPACK decode failures: a static-only decoder rejects every dynamic
// reference as QPACK_DECOMPRESSION_FAILED (RFC 9204 2.2); a section beyond
// the fixed decode storage only fails this request.
[[nodiscard]] constexpr auto qpack_failure(qpack_error error) noexcept -> h3_error
{
    return error == qpack_error::limit_exceeded ? h3_error::excessive_load
                                                : h3_error::qpack_decompression_failed;
}

} // namespace eventloop::http3::detail
