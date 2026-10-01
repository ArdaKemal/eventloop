#pragma once

#include "eventloop/quic.h"

#include <expected>
#include <cstdio>
#include <span>
#include <string_view>
#include <system_error>

namespace http3_client_example {

inline constexpr std::size_t max_requests = 32;

struct get_request {
    std::string_view path;
    std::FILE* output;
};

// Sends up to 32 concurrent GETs on one connection. Caller-owned paths and
// output files remain valid until completion; each response has its own sink.
[[nodiscard]] auto perform_gets(eventloop::event_loop& loop,
    eventloop::quic_connection& connection,
    std::string_view authority, std::span<const get_request> requests)
    -> eventloop::task<std::expected<void, std::error_code>>;

// Performs one GET on an established, hostname-verified connection with ALPN
// h3. Status and fields go to stderr; the streamed response body goes to stdout.
[[nodiscard]] auto perform_get(eventloop::event_loop& loop,
    eventloop::quic_connection& connection,
    std::string_view authority, std::string_view path)
    -> eventloop::task<std::expected<void, std::error_code>>;

} // namespace http3_client_example
