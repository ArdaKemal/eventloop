#pragma once

#include "eventloop/util/arg_parser.h"

#include <charconv>
#include <cstdint>
#include <stdexcept>
#include <string_view>

namespace basics {

// An arg_parser handler that stores a port in 1..65535 and throws
// std::invalid_argument for anything else.
[[nodiscard]] inline auto port_argument(std::uint16_t& port) -> eventloop::arg_parser::value_handler
{
    return [&port](std::string_view text) {
        unsigned value = 0;
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
        if (error != std::errc {} || end != text.data() + text.size() || value == 0 ||
            value > 65535)
            throw std::invalid_argument("port must be between 1 and 65535");
        port = static_cast<std::uint16_t>(value);
    };
}

} // namespace basics
