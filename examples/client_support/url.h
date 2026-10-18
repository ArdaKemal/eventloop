#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace client_support {

struct url_parts {
    bool secure {false};
    std::string hostname;
    std::string host_header;
    std::string target;
    std::uint16_t port {0};
};

[[nodiscard]] auto parse_url(std::string_view url) -> url_parts;

} // namespace client_support
