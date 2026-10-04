#pragma once

#include <cstdint>
#include <string>
#include <system_error>

namespace eventloop::http3::detail {

// RFC 9114 section 8.1 and RFC 9204 section 6 application error codes.
enum class h3_error : std::uint64_t {
    no_error = 0x0100,
    general_protocol_error = 0x0101,
    internal_error = 0x0102,
    stream_creation_error = 0x0103,
    closed_critical_stream = 0x0104,
    frame_unexpected = 0x0105,
    frame_error = 0x0106,
    excessive_load = 0x0107,
    id_error = 0x0108,
    settings_error = 0x0109,
    missing_settings = 0x010a,
    request_rejected = 0x010b,
    request_cancelled = 0x010c,
    request_incomplete = 0x010d,
    message_error = 0x010e,
    qpack_decompression_failed = 0x0200,
    qpack_encoder_stream_error = 0x0201,
    qpack_decoder_stream_error = 0x0202,
};

// Errors this server raises against one request stream (reset plus
// STOP_SENDING); every other code closes the connection.
[[nodiscard]] constexpr auto stream_scoped(h3_error error) noexcept -> bool
{
    return error == h3_error::message_error || error == h3_error::request_incomplete ||
           error == h3_error::request_rejected || error == h3_error::request_cancelled ||
           error == h3_error::internal_error || error == h3_error::excessive_load;
}

[[nodiscard]] inline auto h3_category() noexcept -> const std::error_category&
{
    class category final : public std::error_category {
    public:
        [[nodiscard]] auto name() const noexcept -> const char* override { return "http3"; }
        [[nodiscard]] auto message(int value) const -> std::string override
        {
            switch (static_cast<h3_error>(value)) {
            case h3_error::no_error: return "H3_NO_ERROR";
            case h3_error::general_protocol_error: return "H3_GENERAL_PROTOCOL_ERROR";
            case h3_error::internal_error: return "H3_INTERNAL_ERROR";
            case h3_error::stream_creation_error: return "H3_STREAM_CREATION_ERROR";
            case h3_error::closed_critical_stream: return "H3_CLOSED_CRITICAL_STREAM";
            case h3_error::frame_unexpected: return "H3_FRAME_UNEXPECTED";
            case h3_error::frame_error: return "H3_FRAME_ERROR";
            case h3_error::excessive_load: return "H3_EXCESSIVE_LOAD";
            case h3_error::id_error: return "H3_ID_ERROR";
            case h3_error::settings_error: return "H3_SETTINGS_ERROR";
            case h3_error::missing_settings: return "H3_MISSING_SETTINGS";
            case h3_error::request_rejected: return "H3_REQUEST_REJECTED";
            case h3_error::request_cancelled: return "H3_REQUEST_CANCELLED";
            case h3_error::request_incomplete: return "H3_REQUEST_INCOMPLETE";
            case h3_error::message_error: return "H3_MESSAGE_ERROR";
            case h3_error::qpack_decompression_failed: return "QPACK_DECOMPRESSION_FAILED";
            case h3_error::qpack_encoder_stream_error: return "QPACK_ENCODER_STREAM_ERROR";
            case h3_error::qpack_decoder_stream_error: return "QPACK_DECODER_STREAM_ERROR";
            }
            return "unknown HTTP/3 error";
        }
    };
    static const category instance;
    return instance;
}

[[nodiscard]] inline auto make_error_code(h3_error value) noexcept -> std::error_code
{ return {static_cast<int>(value), h3_category()}; }

} // namespace eventloop::http3::detail

template<>
struct std::is_error_code_enum<eventloop::http3::detail::h3_error> : std::true_type {};
