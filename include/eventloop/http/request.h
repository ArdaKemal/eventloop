#pragma once

#include <array>
#include <cstddef>
#include <optional>
#include <string_view>

namespace http {

inline constexpr std::size_t max_headers = 32;
inline constexpr std::size_t max_target_size = 2048;
inline constexpr std::size_t max_message_size = 16 * 1024;

enum class method_type {
    get,
    head,
    post,
    put,
    delete_,
    options,
    trace,
    connect,
    patch,
    unknown,
};

struct header {
    std::string_view name;
    std::string_view value;
};

struct request {
    method_type method {method_type::unknown};
    std::string_view target;
    std::string_view body;
    std::array<header, max_headers> headers {};
    std::size_t header_count {0};
    bool close_after_response {false};

    [[nodiscard]] auto header_value(std::string_view name) const noexcept
        -> std::optional<std::string_view>;
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

[[nodiscard]] auto parse_request(std::string_view input, request& output) noexcept
    -> parse_result;

} // namespace http
