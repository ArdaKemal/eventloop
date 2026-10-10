#pragma once

#include "eventloop/http/router.h"

#include <chrono>
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
    // Static files: keep up to this many regular files open, per server and
    // event loop, instead of opening them on every request; 0 disables the
    // cache, and the limit is 65536. A cached file is checked again through
    // the document root at most once per second, so for up to a second a
    // changed, replaced, or deleted file can still be served as it was;
    // replace files atomically. Each entry holds a file descriptor.
    // HTTP/1.1 bodies of 11 KiB or more are sent with sendfile from a
    // duplicate descriptor. See docs/api-contract.md.
    std::size_t open_file_cache_capacity {0};
    // TCP servers only.
    bool reuse_port {false};
    // TCP servers only; zero disables either. A connection is closed when its
    // TLS handshake and first request head take longer than header_timeout
    // from accept, or when the next request head does not arrive within
    // idle_timeout of the previous response. Handlers bound their own body
    // reads and response writes.
    std::chrono::milliseconds header_timeout {std::chrono::seconds {30}};
    std::chrono::milliseconds idle_timeout {std::chrono::seconds {60}};
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
