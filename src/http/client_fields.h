#pragma once

#include "eventloop/http/client.h"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>

// Field rules shared by the HTTP/2 and HTTP/3 clients (RFC 9110, RFC 9113
// section 8.2, RFC 9114 section 4.2).
namespace eventloop::http::detail {

inline constexpr std::size_t client_max_body = 4 * 1024 * 1024;
inline constexpr std::uint64_t client_max_streamed_body = std::uint64_t {1} << 40;

[[nodiscard]] inline auto token_character(unsigned char c) -> bool
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           std::string_view("!#$%&'*+-.^_`|~").contains(char(c));
}

// A lowercase token; pseudo-header names are rejected.
[[nodiscard]] inline auto valid_field_name(std::string_view name) -> bool
{
    if (name.empty()) return false;
    for (unsigned char c : name) if (!token_character(c)) return false;
    return true;
}

[[nodiscard]] inline auto valid_method(std::string_view method) -> bool
{
    if (method.empty()) return false;
    for (unsigned char c : method)
        if (!token_character(c) && !(c >= 'A' && c <= 'Z')) return false;
    return true;
}

[[nodiscard]] inline auto valid_field_value(std::string_view value) -> bool
{
    if (!value.empty() && (value.front() == ' ' || value.front() == '\t' ||
                           value.back() == ' ' || value.back() == '\t'))
        return false;
    for (unsigned char c : value)
        if (c == 0x7f || (c < 0x20 && c != '\t')) return false;
    return true;
}

[[nodiscard]] inline auto valid_target(std::string_view value) -> bool
{
    if (value.empty() || value.front() != '/' || value.contains('#'))
        return false;
    for (unsigned char c : value) if (c <= 0x20 || c == 0x7f) return false;
    return true;
}

// TE is allowed only in requests, as "trailers".
[[nodiscard]] inline auto connection_specific(std::string_view name) -> bool
{
    return name == "connection" || name == "upgrade" || name == "keep-alive" ||
           name == "proxy-connection" || name == "transfer-encoding";
}

// Every content-length field must hold the same decimal value. Absent returns
// an empty optional; a malformed or conflicting value returns protocol_error.
[[nodiscard]] inline auto content_length(std::span<const client_header> headers)
    -> std::expected<std::optional<std::uint64_t>, std::error_code>
{
    std::optional<std::uint64_t> length;
    for (const auto& item : headers) {
        if (item.name != "content-length") continue;
        std::uint64_t value = 0;
        const auto* end = item.value.data() + item.value.size();
        const auto parsed = std::from_chars(item.value.data(), end, value);
        if (parsed.ec != std::errc {} || parsed.ptr != end || (length && *length != value))
            return std::unexpected(std::make_error_code(std::errc::protocol_error));
        length = value;
    }
    return length;
}

// Validates a request before any I/O and returns its declared Content-Length.
// authority is the value :authority will carry; max_fields excludes the four
// request pseudo-header fields.
[[nodiscard]] inline auto validate_client_request(const client_request& request,
                                                  std::string_view authority,
                                                  std::size_t max_fields)
    -> std::expected<std::optional<std::uint64_t>, std::error_code>
{
    const auto failure = [](std::errc code) { return std::unexpected(std::make_error_code(code)); };
    if (!valid_target(request.target) || authority.empty() ||
        !valid_field_value(authority) || !valid_method(request.method) ||
        (request.body_source && !request.body.empty()))
        return failure(std::errc::invalid_argument);
    // A CONNECT tunnel does not fit one buffered exchange.
    if (request.method == "CONNECT") return failure(std::errc::operation_not_supported);
    if (request.body.size() > client_max_body || request.headers.size() > max_fields)
        return failure(std::errc::message_size);
    for (const auto& item : request.headers) {
        // A Host field must repeat :authority.
        if (!valid_field_name(item.name) || !valid_field_value(item.value) ||
            connection_specific(item.name) || (item.name == "te" && item.value != "trailers") ||
            (item.name == "host" && item.value != authority))
            return failure(std::errc::invalid_argument);
    }
    // A declared request length must match the owned body, or the source total.
    const auto length = content_length(request.headers);
    if (!length || (*length && !request.body_source && **length != request.body.size()))
        return failure(std::errc::invalid_argument);
    return *length;
}

} // namespace eventloop::http::detail
