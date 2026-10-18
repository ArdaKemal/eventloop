#pragma once

#include "eventloop/ip_endpoint.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace client_support {

struct resolved_addresses {
    std::array<eventloop::ip_endpoint, 16> endpoints {};
    std::size_t count {0};
    int error {0};
};

// Call only from run_blocking's bounded worker.
[[nodiscard]] auto resolve_addresses(const std::string& host,
                                     std::uint16_t port) noexcept
    -> resolved_addresses;

} // namespace client_support
