#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace http_client_example {

struct url_parts {
    bool secure {false};
    std::string hostname;
    std::string host_header;
    std::string target;
    std::uint16_t port {0};
};

[[nodiscard]] auto parse_url(std::string_view url) -> url_parts;

} // namespace http_client_example
