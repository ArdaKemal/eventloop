#pragma once

#include "eventloop/http/router.h"
#include "eventloop/http/webtransport.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <vector>

namespace eventloop { class event_loop; class quic_worker_group; }

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
    // SO_REUSEPORT, so one server per loop can share a port. For HTTP/3, see
    // docs/quic.md for how datagrams reach the owning server.
    bool reuse_port {false};
    // TCP servers only: the loops that serve accepted connections in turn;
    // empty means the listener's loop. Each must outlive the listener's run()
    // task. See docs/http.md.
    std::vector<event_loop*> serving_loops {};
    // TCP servers only; redirect_server uses header_timeout only. Zero
    // disables either. A connection is closed when its TLS handshake and
    // first request head take longer than header_timeout from accept, or when
    // the next request head does not arrive within idle_timeout of the
    // previous response. Handlers bound their own body reads and response
    // writes.
    std::chrono::milliseconds header_timeout {std::chrono::seconds {30}};
    std::chrono::milliseconds idle_timeout {std::chrono::seconds {60}};
    // https_server only: advertise h2 next to http/1.1.
    bool enable_http2 {true};
    // https_server only: static file responses carry
    // `Alt-Svc: h3=":<port>"; ma=86400`; 0 (default) sends none. The caller
    // runs the http3_server on that UDP port.
    std::uint16_t advertise_http3_port {0};
    // A routed request declaring a larger body answers 413.
    std::uint64_t max_request_body {std::uint64_t {1} << 20};
    // http3_server only. Connection capacity is 1..256; request capacity is
    // 1..8192, or ten per connection when zero. The UDP payload size is
    // clamped to 1200..8192.
    std::size_t connection_capacity {8};
    std::size_t request_capacity {0};
    std::size_t max_udp_payload_size {8192};
    // http3_server only: see quic_server_options::worker_index and
    // worker_group.
    std::optional<std::uint8_t> worker_index {};
    std::shared_ptr<quic_worker_group> worker_group {};
    // http3_server only, and only with routes: Extended CONNECT
    // webtransport-h3 sessions. Enabling it raises the QUIC datagram and
    // reset_stream_at transport parameters and the HTTP/3 SETTINGS listed in
    // docs/webtransport.md. See request::async_accept_webtransport().
    webtransport_options webtransport {};
};

} // namespace eventloop::http
