#pragma once

#include <array>
#include <string>
#include <optional>
#include <string_view>

constexpr std::size_t HTTP_MAX_HEADERS = 64;

enum class http_method_t {
    GET,
    PUT,
    HEAD,
    POST,
    DELETE,
    OPTIONS,
};

struct http_header {
    std::string_view name;
    std::string_view value;
};

struct http_request {
    http_method_t method;
    std::string_view uri;
    std::string_view version;
    std::size_t header_count;
    std::array<http_header, HTTP_MAX_HEADERS> headers;
    std::size_t raw_size;

    static constexpr std::size_t MAX_HEADERS = 64;
};

std::optional<http_request> http_parse_request(std::string_view buffer);
