#include "eventloop/http/request.h"

#include <charconv>

namespace eventloop::http {
namespace {

[[nodiscard]] constexpr auto ascii_lower(char value) noexcept -> char
{
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
}

[[nodiscard]] auto ascii_equal(std::string_view left, std::string_view right) noexcept -> bool
{
    if (left.size() != right.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (ascii_lower(left[index]) != ascii_lower(right[index])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] auto contains_token(std::string_view value, std::string_view token) noexcept -> bool
{
    while (!value.empty()) {
        const auto comma = value.find(',');
        auto part = value.substr(0, comma);
        while (!part.empty() && (part.front() == ' ' || part.front() == '\t')) {
            part.remove_prefix(1);
        }
        while (!part.empty() && (part.back() == ' ' || part.back() == '\t')) {
            part.remove_suffix(1);
        }
        if (ascii_equal(part, token)) {
            return true;
        }
        if (comma == std::string_view::npos) {
            return false;
        }
        value.remove_prefix(comma + 1);
    }
    return false;
}

[[nodiscard]] auto valid_header_name(std::string_view name) noexcept -> bool
{
    if (name.empty()) {
        return false;
    }
    for (const unsigned char value : name) {
        const bool alpha_numeric =
            (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9');
        if (!alpha_numeric && std::string_view("!#$%&'*+-.^_`|~").find(
                                  static_cast<char>(value)) == std::string_view::npos) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] auto valid_target(std::string_view target) noexcept -> bool
{
    for (const unsigned char value : target) {
        if (value <= 0x20 || value == 0x7f) return false;
    }
    return true;
}

[[nodiscard]] auto valid_header_value(std::string_view value) noexcept -> bool
{
    for (const unsigned char character : value) {
        if ((character < 0x20 && character != '\t') || character == 0x7f) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] auto parse_method(std::string_view value) noexcept -> method_type
{
    if (value == "GET") return method_type::get;
    if (value == "HEAD") return method_type::head;
    if (value == "POST") return method_type::post;
    if (value == "PUT") return method_type::put;
    if (value == "DELETE") return method_type::delete_;
    if (value == "OPTIONS") return method_type::options;
    if (value == "TRACE") return method_type::trace;
    if (value == "CONNECT") return method_type::connect;
    if (value == "PATCH") return method_type::patch;
    return method_type::unknown;
}

} // namespace

auto request::header_value(std::string_view name) const noexcept
    -> std::optional<std::string_view>
{
    for (std::size_t index = 0; index < header_count; ++index) {
        if (ascii_equal(headers[index].name, name)) {
            return headers[index].value;
        }
    }
    return std::nullopt;
}

auto parse_request(std::string_view input, request& output) noexcept -> parse_result
{
    output = {};
    const auto header_end = input.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        return {input.size() >= max_message_size ? parse_status::headers_too_large
                                                 : parse_status::incomplete};
    }

    const auto first_line_end = input.find("\r\n");
    if (first_line_end == std::string_view::npos || first_line_end == 0) {
        return {parse_status::bad_request};
    }
    const auto first_line = input.substr(0, first_line_end);
    const auto first_space = first_line.find(' ');
    const auto second_space = first_space == std::string_view::npos
        ? std::string_view::npos
        : first_line.find(' ', first_space + 1);
    if (first_space == std::string_view::npos || second_space == std::string_view::npos ||
        first_line.find(' ', second_space + 1) != std::string_view::npos) {
        return {parse_status::bad_request};
    }

    output.method = parse_method(first_line.substr(0, first_space));
    output.target = first_line.substr(first_space + 1, second_space - first_space - 1);
    if (output.method == method_type::unknown || output.target.empty() ||
        output.target.front() != '/' || !valid_target(output.target)) {
        return {parse_status::bad_request};
    }
    if (output.target.size() > max_target_size) {
        return {parse_status::target_too_long};
    }
    if (first_line.substr(second_space + 1) != "HTTP/1.1") {
        return {parse_status::unsupported_version};
    }

    bool host_seen = false;
    bool content_length_seen = false;
    std::size_t content_length = 0;
    std::size_t position = first_line_end + 2;
    while (position < header_end) {
        const auto line_end = input.find("\r\n", position);
        if (line_end == std::string_view::npos || line_end > header_end) {
            return {parse_status::bad_request};
        }
        if (output.header_count == output.headers.size()) {
            return {parse_status::headers_too_large};
        }

        const auto line = input.substr(position, line_end - position);
        const auto colon = line.find(':');
        if (colon == std::string_view::npos) {
            return {parse_status::bad_request};
        }
        auto name = line.substr(0, colon);
        auto value = line.substr(colon + 1);
        if (!valid_header_name(name) || !valid_header_value(value)) {
            return {parse_status::bad_request};
        }
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
            value.remove_prefix(1);
        }
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
            value.remove_suffix(1);
        }

        output.headers[output.header_count++] = {.name = name, .value = value};
        if (ascii_equal(name, "Host")) {
            if (host_seen || value.empty()) {
                return {parse_status::bad_request};
            }
            host_seen = true;
        } else if (ascii_equal(name, "Content-Length")) {
            std::size_t parsed = 0;
            const auto [end, error] = std::from_chars(
                value.data(), value.data() + value.size(), parsed);
            if (error != std::errc {} || end != value.data() + value.size() ||
                (content_length_seen && parsed != content_length)) {
                return {parse_status::bad_request};
            }
            content_length = parsed;
            content_length_seen = true;
        } else if (ascii_equal(name, "Transfer-Encoding") &&
                   !ascii_equal(value, "identity")) {
            return {parse_status::unsupported_transfer_encoding};
        } else if (ascii_equal(name, "Connection") && contains_token(value, "close")) {
            output.close_after_response = true;
        }
        position = line_end + 2;
    }

    if (!host_seen) {
        return {parse_status::bad_request};
    }
    const std::size_t body_start = header_end + 4;
    if (body_start > max_message_size ||
        content_length > max_message_size - body_start) {
        return {parse_status::payload_too_large};
    }
    if (input.size() < body_start + content_length) {
        return {parse_status::incomplete};
    }
    output.body = input.substr(body_start, content_length);
    return {.status = parse_status::complete,
            .consumed = body_start + content_length};
}

} // namespace eventloop::http
