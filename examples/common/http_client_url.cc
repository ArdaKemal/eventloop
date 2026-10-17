#include "http_client_url.h"

#include <algorithm>
#include <charconv>
#include <stdexcept>

namespace http_client_example {
namespace {
[[nodiscard]] auto parse_port(std::string_view text) -> std::uint16_t
{
    unsigned int value = 0;
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), value);
    if (text.empty() || error != std::errc {} ||
        end != text.data() + text.size() || value == 0 || value > 65535) {
        throw std::invalid_argument("URL port must be between 1 and 65535");
    }
    return static_cast<std::uint16_t>(value);
}

[[nodiscard]] auto safe_http_text(std::string_view text) -> bool
{
    return std::all_of(text.begin(), text.end(), [](unsigned char ch) {
        return ch > 0x20 && ch != 0x7f;
    });
}
} // namespace

auto parse_url(std::string_view url) -> url_parts
{
    url_parts parsed;
    if (url.starts_with("https://")) {
        parsed.secure = true;
        parsed.port = 443;
        url.remove_prefix(8);
    } else if (url.starts_with("http://")) {
        parsed.port = 80;
        url.remove_prefix(7);
    } else {
        throw std::invalid_argument("URL must start with http:// or https://");
    }

    const auto authority_end = url.find_first_of("/?#");
    const auto authority = url.substr(0, authority_end);
    auto remainder = authority_end == std::string_view::npos
                         ? std::string_view {}
                         : url.substr(authority_end);
    if (authority.empty() || authority.contains('@')) {
        throw std::invalid_argument("URL needs a host without user information");
    }

    std::string_view host;
    std::string_view port_text;
    if (authority.front() == '[') {
        const auto closing = authority.find(']');
        if (closing == std::string_view::npos) {
            throw std::invalid_argument("invalid bracketed IPv6 host");
        }
        host = authority.substr(1, closing - 1);
        const auto suffix = authority.substr(closing + 1);
        if (!suffix.empty()) {
            if (suffix.front() != ':') {
                throw std::invalid_argument("invalid URL authority");
            }
            port_text = suffix.substr(1);
        }
        parsed.host_header = std::string(authority.substr(0, closing + 1));
    } else {
        const auto separator = authority.find(':');
        host = authority.substr(0, separator);
        if (separator != std::string_view::npos) {
            port_text = authority.substr(separator + 1);
        }
        parsed.host_header = std::string(host);
    }
    if (host.empty() || !safe_http_text(host) ||
        host.find_first_of("[]\\") != std::string_view::npos) {
        throw std::invalid_argument("invalid URL host");
    }
    parsed.hostname = host;
    if (!port_text.empty() || authority.ends_with(':')) {
        parsed.port = parse_port(port_text);
        parsed.host_header += ':';
        parsed.host_header += port_text;
    }

    if (const auto fragment = remainder.find('#');
        fragment != std::string_view::npos) {
        remainder = remainder.substr(0, fragment);
    }
    if (remainder.empty()) {
        parsed.target = "/";
    } else if (remainder.front() == '?') {
        parsed.target = '/';
        parsed.target += remainder;
    } else {
        parsed.target = remainder;
    }
    if (!safe_http_text(parsed.target)) {
        throw std::invalid_argument("URL target contains an invalid character");
    }
    return parsed;
}

} // namespace http_client_example
