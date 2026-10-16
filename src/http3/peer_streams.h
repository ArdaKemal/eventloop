#pragma once

#include "errors.h"
#include "frames.h"
#include "qpack.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace eventloop::http3::detail {

inline constexpr std::uint64_t enable_connect_protocol_setting = 0x08;
inline constexpr std::uint64_t h3_datagram_setting = 0x33;
inline constexpr std::uint64_t wt_enabled_setting = 0x2c7cf000; // draft-16 codepoint
inline constexpr std::uint64_t wt_max_sessions_draft07_setting = 0x2b603742;
inline constexpr std::uint64_t wt_initial_max_streams_uni_setting = 0x2b64;
inline constexpr std::uint64_t wt_initial_max_streams_bidi_setting = 0x2b65;
inline constexpr std::uint64_t wt_initial_max_data_setting = 0x2b61;
inline constexpr std::uint64_t control_stream_type = 0x00;
inline constexpr std::uint64_t push_stream_type = 0x01;
inline constexpr std::uint64_t qpack_encoder_stream_type = 0x02;
inline constexpr std::uint64_t qpack_decoder_stream_type = 0x03;
inline constexpr std::uint64_t webtransport_stream_type = 0x54; // draft-16 "Unidirectional streams"

// Connection-wide record of the peer's critical streams (RFC 9114 6.2.1,
// RFC 9204 4.2). A second stream of the same type is a connection error.
// Also carries the peer's SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114 4.2.2).
//
// max_field_section_size is written as each setting arrives. The fields after
// it are written only when the whole SETTINGS frame has been parsed.
// settings_received then becomes true and on_settings is invoked once, so a
// consumer that waits on the hook never sees a partial SETTINGS. Until then
// they keep their defaults. wt_enabled is true only for
// the value 1. A server receiving a larger value treats WebTransport as not
// enabled rather than raising H3_SETTINGS_ERROR; the draft's "MUST be
// H3_SETTINGS_ERROR" rule applies to clients receiving the setting.
struct peer_critical_streams {
    bool control {false};
    bool qpack_encoder {false};
    bool qpack_decoder {false};
    std::uint64_t max_field_section_size {UINT64_MAX};

    bool settings_received {false};
    bool h3_datagram {false};      // SETTINGS_H3_DATAGRAM == 1 (RFC 9297 2.1.1)
    bool connect_protocol {false}; // SETTINGS_ENABLE_CONNECT_PROTOCOL == 1
    bool wt_enabled {false};       // SETTINGS_WT_ENABLED == 1 (draft-16)
    std::uint64_t wt_max_sessions_draft07 {0};
    std::uint64_t wt_initial_max_streams_bidi {0};
    std::uint64_t wt_initial_max_streams_uni {0};
    std::uint64_t wt_initial_max_data {0};

    // Called with settings_context once SETTINGS completes. Both may be null.
    void (*on_settings)(void* context) noexcept {nullptr};
    void* settings_context {nullptr};
};

// Incremental validator for one client-initiated unidirectional stream as
// seen by a server that advertises a zero-capacity QPACK dynamic table and
// never pushes. State is fixed-size (about 300 bytes) so the stream's reader
// coroutine stays in a small frame class; nothing is buffered beyond one
// partial varint, and unknown frame payloads are skipped by length.
//
// Feed received bytes in order with receive(); report a FIN or peer reset
// with finish(). Any error is a connection error to close with.
//
// With WebTransport enabled, a 0x54 stream is kind::webtransport. Its session
// ID is parsed and then parsing stops: receive() never consumes bytes past the
// session ID, and the rest of the stream is application data for the caller.
// The caller reads bytes_consumed() to find where that data begins and feeds
// no further input to this parser.
class peer_uni_stream {
public:
    // Distinct SETTINGS identifiers accepted, including GREASE entries.
    static constexpr std::size_t max_settings = 32;

    enum class kind { pending, control, qpack_encoder, qpack_decoder, unknown, webtransport };

    // webtransport enables stream type 0x54. When disabled, 0x54 is unknown.
    explicit peer_uni_stream(bool webtransport = false) noexcept
        : webtransport_(webtransport) {}

    [[nodiscard]] auto stream_kind() const noexcept -> kind { return kind_; }

    // Session ID of a kind::webtransport stream, once its varint is complete.
    [[nodiscard]] auto session_id() const noexcept -> std::optional<std::uint64_t>
    { return session_id_; }

    // Bytes of the input passed to the last receive() call that were consumed.
    [[nodiscard]] auto bytes_consumed() const noexcept -> std::size_t { return consumed_; }

    [[nodiscard]] auto receive(std::span<const std::byte> input,
                               peer_critical_streams& critical) noexcept
        -> std::expected<void, h3_error>
    {
        const auto size = input.size();
        const auto parsed = parse(input, critical);
        consumed_ = size - input.size();
        return parsed;
    }

    // Critical streams must stay open for the connection's lifetime. Other
    // streams, including ones closed before their type arrived, may end. A
    // WebTransport stream may end anywhere, including before its session ID.
    [[nodiscard]] auto finish() const noexcept -> std::expected<void, h3_error>
    {
        if (kind_ == kind::control || kind_ == kind::qpack_encoder ||
            kind_ == kind::qpack_decoder)
            return std::unexpected(h3_error::closed_critical_stream);
        return {};
    }

private:
    enum class control_state : std::uint8_t {
        frame_type, frame_length, setting_identifier, setting_value,
        push_id, skip_payload,
    };

    // SETTINGS values held until the frame completes (see peer_critical_streams).
    struct settings_values {
        bool h3_datagram {false};
        bool connect_protocol {false};
        bool wt_enabled {false};
        std::uint64_t wt_max_sessions_draft07 {0};
        std::uint64_t wt_initial_max_streams_bidi {0};
        std::uint64_t wt_initial_max_streams_uni {0};
        std::uint64_t wt_initial_max_data {0};
    };

    auto parse(std::span<const std::byte>& input, peer_critical_streams& critical) noexcept
        -> std::expected<void, h3_error>
    {
        while (!input.empty()) {
            switch (kind_) {
            case kind::pending: {
                const auto type = varint_.feed(input);
                if (!type) break;
                if (const auto claimed = claim(*type, critical); !claimed) return claimed;
                break;
            }
            case kind::control:
                if (const auto parsed = control(input, critical); !parsed) return parsed;
                break;
            case kind::qpack_encoder: {
                // With our advertised capacity of zero, the only valid encoder
                // instruction is Set Dynamic Table Capacity 0: the single octet
                // 0x20. Every instruction is complete in one octet, so chunks
                // can be validated independently without reassembly.
                if (!qpack_validate_encoder_instructions(input))
                    return std::unexpected(h3_error::qpack_encoder_stream_error);
                input = {};
                break;
            }
            case kind::qpack_decoder:
                if (const auto parsed = decoder(input); !parsed) return parsed;
                break;
            case kind::unknown:
                input = {};
                break;
            case kind::webtransport:
                // Once the session ID is known, leave the remaining input for
                // the caller: it is stream data, not HTTP/3 framing.
                if (session_id_) return {};
                if (const auto id = varint_.feed(input)) session_id_ = *id;
                break;
            }
        }
        return {};
    }

    auto claim(std::uint64_t type, peer_critical_streams& critical) noexcept
        -> std::expected<void, h3_error>
    {
        const auto take = [](bool& seen) noexcept {
            if (seen) return false;
            seen = true;
            return true;
        };
        if (type == push_stream_type)
            return std::unexpected(h3_error::stream_creation_error);
        if (type == control_stream_type) {
            if (!take(critical.control)) return std::unexpected(h3_error::stream_creation_error);
            kind_ = kind::control;
        } else if (type == qpack_encoder_stream_type) {
            if (!take(critical.qpack_encoder)) return std::unexpected(h3_error::stream_creation_error);
            kind_ = kind::qpack_encoder;
        } else if (type == qpack_decoder_stream_type) {
            if (!take(critical.qpack_decoder)) return std::unexpected(h3_error::stream_creation_error);
            kind_ = kind::qpack_decoder;
        } else if (type == webtransport_stream_type && webtransport_) {
            kind_ = kind::webtransport;
        } else {
            // Reserved and unknown types are ignored (RFC 9114 6.2.3).
            kind_ = kind::unknown;
        }
        return {};
    }

    // Bytes consumed from the current frame's declared payload.
    auto consume_payload(std::span<const std::byte> before,
                         std::span<const std::byte> after) noexcept -> bool
    {
        const auto used = before.size() - after.size();
        if (used > payload_remaining_) return false;
        payload_remaining_ -= used;
        return true;
    }

    auto control(std::span<const std::byte>& input, peer_critical_streams& critical) noexcept
        -> std::expected<void, h3_error>
    {
        switch (control_state_) {
        case control_state::frame_type: {
            const auto type = varint_.feed(input);
            if (!type) return {};
            frame_type_ = *type;
            control_state_ = control_state::frame_length;
            return {};
        }
        case control_state::frame_length: {
            const auto length = varint_.feed(input);
            if (!length) return {};
            payload_remaining_ = *length;
            return begin_frame(critical);
        }
        case control_state::setting_identifier:
        case control_state::setting_value: {
            const auto before = input;
            const auto value = varint_.feed(input);
            if (!consume_payload(before, input))
                return std::unexpected(h3_error::frame_error);
            if (!value) {
                // The frame ended inside a varint.
                if (payload_remaining_ == 0) return std::unexpected(h3_error::frame_error);
                return {};
            }
            if (control_state_ == control_state::setting_identifier) {
                if (forbidden_setting(*value)) return std::unexpected(h3_error::settings_error);
                for (std::size_t i = 0; i < setting_count_; ++i)
                    if (settings_[i] == *value) return std::unexpected(h3_error::settings_error);
                if (setting_count_ == settings_.size())
                    return std::unexpected(h3_error::excessive_load);
                settings_[setting_count_++] = *value;
                if (payload_remaining_ == 0) return std::unexpected(h3_error::frame_error);
                control_state_ = control_state::setting_value;
            } else {
                // SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441 3, RFC 9220 3)
                // and SETTINGS_H3_DATAGRAM (RFC 9297 2.1.1) are booleans.
                const auto identifier = settings_[setting_count_ - 1];
                if ((identifier == enable_connect_protocol_setting ||
                     identifier == h3_datagram_setting) && *value > 1)
                    return std::unexpected(h3_error::settings_error);
                if (identifier == max_field_section_size) critical.max_field_section_size = *value;
                if (identifier == wt_enabled_setting) pending_.wt_enabled = *value == 1;
                else if (identifier == wt_max_sessions_draft07_setting)
                    pending_.wt_max_sessions_draft07 = *value;
                else if (identifier == wt_initial_max_streams_bidi_setting)
                    pending_.wt_initial_max_streams_bidi = *value;
                else if (identifier == wt_initial_max_streams_uni_setting)
                    pending_.wt_initial_max_streams_uni = *value;
                else if (identifier == wt_initial_max_data_setting)
                    pending_.wt_initial_max_data = *value;
                else if (identifier == enable_connect_protocol_setting)
                    pending_.connect_protocol = *value == 1;
                else if (identifier == h3_datagram_setting) pending_.h3_datagram = *value == 1;
                if (payload_remaining_ == 0) commit_settings(critical);
                control_state_ = payload_remaining_ == 0 ? control_state::frame_type
                                                         : control_state::setting_identifier;
            }
            return {};
        }
        case control_state::push_id: {
            const auto before = input;
            const auto value = varint_.feed(input);
            if (!consume_payload(before, input))
                return std::unexpected(h3_error::frame_error);
            if (!value) {
                if (payload_remaining_ == 0) return std::unexpected(h3_error::frame_error);
                return {};
            }
            // The push ID must fill the payload exactly (RFC 9114 7.1).
            if (payload_remaining_ != 0) return std::unexpected(h3_error::frame_error);
            control_state_ = control_state::frame_type;
            return push_id(*value);
        }
        case control_state::skip_payload: {
            const auto skipped = static_cast<std::size_t>(
                std::min<std::uint64_t>(payload_remaining_, input.size()));
            input = input.subspan(skipped);
            payload_remaining_ -= skipped;
            if (payload_remaining_ == 0) control_state_ = control_state::frame_type;
            return {};
        }
        }
        return {};
    }

    // Publishes the staged SETTINGS. Only one control stream exists per
    // connection and a second SETTINGS frame is rejected, so this runs once.
    auto commit_settings(peer_critical_streams& critical) noexcept -> void
    {
        critical.h3_datagram = pending_.h3_datagram;
        critical.connect_protocol = pending_.connect_protocol;
        critical.wt_enabled = pending_.wt_enabled;
        critical.wt_max_sessions_draft07 = pending_.wt_max_sessions_draft07;
        critical.wt_initial_max_streams_bidi = pending_.wt_initial_max_streams_bidi;
        critical.wt_initial_max_streams_uni = pending_.wt_initial_max_streams_uni;
        critical.wt_initial_max_data = pending_.wt_initial_max_data;
        critical.settings_received = true;
        if (critical.on_settings) critical.on_settings(critical.settings_context);
    }

    auto begin_frame(peer_critical_streams& critical) noexcept -> std::expected<void, h3_error>
    {
        const bool first = !settings_started_;
        if (first && frame_type_ != settings_frame)
            return std::unexpected(h3_error::missing_settings);
        if (frame_type_ == settings_frame) {
            if (!first) return std::unexpected(h3_error::frame_unexpected);
            settings_started_ = true;
            // An empty SETTINGS frame is complete as soon as it begins.
            if (payload_remaining_ == 0) commit_settings(critical);
            control_state_ = payload_remaining_ == 0 ? control_state::frame_type
                                                     : control_state::setting_identifier;
            return {};
        }
        if (frame_type_ == goaway_frame || frame_type_ == max_push_id_frame ||
            frame_type_ == cancel_push_frame) {
            if (payload_remaining_ == 0 || payload_remaining_ > 8)
                return std::unexpected(h3_error::frame_error);
            control_state_ = control_state::push_id;
            return {};
        }
        // DATA, HEADERS, PUSH_PROMISE, and reserved HTTP/2 types are not
        // permitted on a control stream (RFC 9114 7.2 and 7.2.8).
        if (known_frame_type(frame_type_) || forbidden_frame_type(frame_type_))
            return std::unexpected(h3_error::frame_unexpected);
        control_state_ = payload_remaining_ == 0 ? control_state::frame_type
                                                 : control_state::skip_payload;
        return {};
    }

    auto push_id(std::uint64_t id) noexcept -> std::expected<void, h3_error>
    {
        if (frame_type_ == max_push_id_frame) {
            // MAX_PUSH_ID must not decrease (RFC 9114 7.2.7).
            if (max_push_id_received_ && id < max_push_id_)
                return std::unexpected(h3_error::id_error);
            max_push_id_ = id;
            max_push_id_received_ = true;
        } else if (frame_type_ == cancel_push_frame) {
            // This server never sends PUSH_PROMISE, so every peer cancellation
            // refers to an unpromised ID (RFC 9114 7.2.3).
            return std::unexpected(h3_error::id_error);
        } else {
            // A client GOAWAY carries a push ID and must not increase (5.2).
            if (goaway_received_ && id > goaway_id_)
                return std::unexpected(h3_error::id_error);
            goaway_id_ = id;
            goaway_received_ = true;
        }
        return {};
    }

    // RFC 9204 4.4. This server never emits dynamic references, so Section
    // Acknowledgment and Insert Count Increment are always errors. Stream
    // Cancellation (01xxxxxx, 6-bit prefix stream ID) is the only valid form.
    auto decoder(std::span<const std::byte>& input) noexcept
        -> std::expected<void, h3_error>
    {
        while (!input.empty()) {
            const auto octet = std::to_integer<unsigned>(input.front());
            input = input.subspan(1);
            if (!in_integer_) {
                if ((octet & 0xc0u) != 0x40u)
                    return std::unexpected(h3_error::qpack_decoder_stream_error);
                // A prefix below 63 completes the instruction in one octet.
                in_integer_ = (octet & 0x3fu) == 0x3fu;
                continuation_ = 0;
                continue;
            }
            // Stream IDs are below 2^62; nine continuation octets suffice.
            if (++continuation_ > 9)
                return std::unexpected(h3_error::qpack_decoder_stream_error);
            if ((octet & 0x80u) == 0) in_integer_ = false;
        }
        return {};
    }

    std::array<std::uint64_t, max_settings> settings_ {};
    settings_values pending_ {};
    std::optional<std::uint64_t> session_id_;
    std::size_t consumed_ {0};
    std::uint64_t frame_type_ {0};
    std::uint64_t payload_remaining_ {0};
    std::uint64_t max_push_id_ {0};
    std::uint64_t goaway_id_ {0};
    varint_accumulator varint_ {};
    std::uint8_t setting_count_ {0};
    std::uint8_t continuation_ {0};
    kind kind_ {kind::pending};
    control_state control_state_ {control_state::frame_type};
    bool webtransport_ {false};
    bool settings_started_ {false};
    bool max_push_id_received_ {false};
    bool goaway_received_ {false};
    bool in_integer_ {false};
};

} // namespace eventloop::http3::detail
