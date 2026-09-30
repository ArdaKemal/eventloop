#pragma once

#include "eventloop/quic.h"

#include <expected>
#include <string_view>
#include <system_error>

namespace http3_client_example {

// Performs one GET on an established, hostname-verified connection with ALPN
// h3. Status and fields go to stderr; the streamed response body goes to stdout.
[[nodiscard]] auto perform_get(eventloop::event_loop& loop,
    eventloop::quic_connection& connection,
    std::string_view authority, std::string_view path)
    -> eventloop::task<std::expected<void, std::error_code>>;

} // namespace http3_client_example
