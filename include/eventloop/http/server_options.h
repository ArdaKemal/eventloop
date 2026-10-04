#pragma once

#include "eventloop/http/router.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>

namespace eventloop::http {

// Options shared by server, https_server and http3_server. At least one of
// routes and document_root is required; otherwise construction throws
// std::invalid_argument. Routed requests run first; unmatched paths serve
// static files from document_root, or answer 404 without one.
struct server_options {
    std::shared_ptr<const router> routes {};
    std::filesystem::path document_root {};
    bool directory_listing {false};
    // TCP servers only.
    bool reuse_port {false};
    // https_server only: advertise h2 next to http/1.1.
    bool enable_http2 {true};
    // A routed request declaring a larger body answers 413.
    std::uint64_t max_request_body {std::uint64_t {1} << 20};
    // http3_server only. Connection capacity is 1..256; request capacity is
    // 1..8192, or four per connection when zero. The UDP payload size is
    // clamped to 1200..8192.
    std::size_t connection_capacity {8};
    std::size_t request_capacity {0};
    std::size_t max_udp_payload_size {1472};
};

} // namespace eventloop::http
