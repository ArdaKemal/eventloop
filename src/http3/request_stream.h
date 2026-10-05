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

// Incremental parser for a client request stream (RFC 9114 4.1 and 7.1):
// HEADERS, then DATA frames, then at most one trailing HEADERS. Unknown and
// reserved extension frames may appear anywhere and are skipped by length.
// HEADERS payloads are copied into caller storage that must outlive the
// parser. DATA payloads are delivered as views of the input and counted. No
// other input is buffered.
//
// Errors are RFC codes; stream_scoped() tells whether to reset the stream or
// close the connection.
class request_frames {
public:
    enum class event { need_input, header_block, data };

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
                frame_type_ = *type;
                state_ = state::frame_length;
                break;
            }
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
        if (state_ != state::frame_type || varint_.partial())
            return std::unexpected(h3_error::frame_error);
        if (phase_ == phase::request_headers)
            return std::unexpected(h3_error::request_incomplete);
        if (content_length_ && data_received_ != *content_length_)
            return std::unexpected(h3_error::message_error);
        return {};
    }

    // Declared request content length; DATA must sum to it exactly (4.1.2).
    auto set_content_length(std::optional<std::uint64_t> length) noexcept -> void
    { content_length_ = length; }

    auto accept_connect() noexcept -> void { tunnel_ = true; content_length_.reset(); }

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
            if (remaining_ > max_varint - data_received_)
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

    static constexpr std::uint64_t max_varint = (std::uint64_t {1} << 62) - 1;
    std::span<std::byte> storage_;
    std::span<const std::byte> data_;
    std::optional<std::uint64_t> content_length_;
    std::uint64_t frame_type_ {0};
    std::uint64_t remaining_ {0};
    std::uint64_t data_received_ {0};
    std::size_t block_size_ {0};
    varint_accumulator varint_ {};
    state state_ {state::frame_type};
    phase phase_ {phase::request_headers};
    bool tunnel_ {false};
};

// Field rules shared by request headers and trailers (RFC 9114 4.2 and
// 4.1.2): lowercase token names, no NUL/CR/LF in values, no connection-
// specific fields, and TE limited to "trailers".
[[nodiscard]] constexpr auto valid_regular_field(const field& f) noexcept -> bool
{
    if (f.name.empty()) return false;
    for (unsigned char c : f.name)
        if (c <= 0x20 || c >= 0x7f || (c >= 'A' && c <= 'Z') || c == ':') return false;
    for (unsigned char c : f.value)
        if (c == 0 || c == '\r' || c == '\n' || c == 0x7f) return false;
    if (f.name == "connection" || f.name == "keep-alive" || f.name == "proxy-connection" ||
        f.name == "transfer-encoding" || f.name == "upgrade") return false;
    return f.name != "te" || f.value == "trailers";
}

struct request_head {
    std::string_view method;
    std::string_view scheme;
    std::string_view authority; // :authority, or Host when it is absent
    std::string_view path;
    std::string_view connect_protocol;
    std::optional<std::uint64_t> content_length;
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
            for (unsigned char c : f.value)
                if (c == 0 || c == '\r' || c == '\n' || c == 0x7f) return malformed;
            continue;
        }
        regular = true;
        if (!valid_regular_field(f)) return malformed;
        if (f.name == "host") {
            if (host) return malformed;
            host = f.value;
        } else if (f.name == "content-length") {
            if (f.value.empty() || f.value.size() > 19) return malformed;
            std::uint64_t value = 0;
            for (char c : f.value) {
                if (c < '0' || c > '9') return malformed;
                value = value * 10 + static_cast<std::uint64_t>(c - '0');
            }
            if (head.content_length && *head.content_length != value) return malformed;
            head.content_length = value;
        }
    }
    if (!have_method || head.method.empty()) return malformed;
    if (have_protocol) {
        if (head.method != "CONNECT" || head.connect_protocol.empty() ||
            !have_scheme || head.scheme.empty() || !have_path || head.path.empty() ||
            head.path.front() != '/' || head.path.find('#') != std::string_view::npos ||
            !have_authority || head.authority.empty()) return malformed;
        for (unsigned char c : head.connect_protocol)
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') ||
                  std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) !=
                      std::string_view::npos)) return malformed;
    } else if (head.method == "CONNECT") {
        // Plain CONNECT names only an authority (4.4).
        if (have_scheme || have_path || !have_authority || head.authority.empty())
            return malformed;
        return head;
    }
    if (!have_scheme || !have_path) return malformed;
    if (head.scheme == "http" || head.scheme == "https") {
        if (head.path.empty()) return malformed;
        if (have_authority && host && *host != head.authority) return malformed;
        if (!have_authority) {
            if (!host) return malformed;
            head.authority = *host;
        }
        if (head.authority.empty()) return malformed;
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
