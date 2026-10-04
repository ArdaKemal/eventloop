#pragma once

#include "eventloop/http/request.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace eventloop::http::detail {

inline constexpr std::size_t max_headers = 32;
inline constexpr std::size_t max_target_size = 2048;
inline constexpr std::size_t max_message_size = 4096;

// HTTP/1.1 request head and body views into the parsed input.
struct parsed_request {
    method_type method {method_type::unknown};
    std::string_view method_name;
    std::string_view target;
    std::string_view host;
    std::string_view body;
    std::array<header, max_headers> headers {};
    std::size_t header_count {0};
    std::size_t content_length {0};
    bool content_length_seen {false};
    bool close_after_response {false};
    bool trailers_accepted {false};
    bool expect_continue {false};
    bool chunked {false};

    [[nodiscard]] auto header_value(std::string_view name) const noexcept
        -> std::optional<std::string_view>;
    [[nodiscard]] auto header_occurrences(std::string_view name) const noexcept
        -> std::size_t;
    // Comma-joins every matching field into storage when there is more than one
    // and returns a view of the result; otherwise returns a view of the single
    // value (or an empty view) without touching storage.
    [[nodiscard]] auto joined_header_value(std::string_view name,
                                           std::string& storage) const
        -> std::string_view;
};

enum class parse_status {
    complete,
    incomplete,
    bad_request,
    target_too_long,
    headers_too_large,
    payload_too_large,
    unsupported_transfer_encoding,
    unsupported_version,
};

struct parse_result {
    parse_status status;
    std::size_t consumed {0};
};

// Parses the request head only. On complete, consumed is the head size and
// content_length holds the declared body size, or chunked is set; body is
// empty.
[[nodiscard]] auto parse_request_head(std::string_view input, parsed_request& output) noexcept
    -> parse_result;
// Parses the head and requires the whole body within max_message_size.
[[nodiscard]] auto parse_request(std::string_view input, parsed_request& output) noexcept
    -> parse_result;

[[nodiscard]] auto ascii_equal(std::string_view left, std::string_view right) noexcept -> bool;

// Incremental decoder for a chunked request body (RFC 9112 7.1). Line endings
// must be CRLF. Chunk extensions are skipped; trailer fields are checked for
// a name and colon and then dropped. Size lines, including extensions, are
// limited to max_line bytes and the trailer section to max_trailers bytes.
class chunked_decoder {
public:
    static constexpr std::size_t max_line = 1024;
    static constexpr std::size_t max_trailers = 8 * 1024;
    enum class status { need_input, data, done, error };

    // Consumes input until up to max_data payload bytes are available
    // (returned in data as a view of input), the body ends, or input runs
    // out. input advances past everything consumed.
    [[nodiscard]] auto feed(std::span<const std::byte>& input, std::size_t max_data,
                            std::span<const std::byte>& data) noexcept -> status;
    [[nodiscard]] auto done() const noexcept -> bool { return state_ == state::done; }

private:
    enum class state : std::uint8_t {
        size, extension, size_lf, data, data_cr, data_lf,
        trailer_start, trailer, trailer_lf, final_lf, done, error,
    };
    std::uint64_t remaining_ {0};
    std::size_t line_ {0};
    std::size_t trailers_ {0};
    unsigned digits_ {0};
    bool trailer_colon_ {false};
    state state_ {state::size};
};

} // namespace eventloop::http::detail
