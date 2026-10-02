#pragma once

#include "eventloop/ip_endpoint.h"
#include "eventloop/quic.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string_view>

namespace eventloop::http {

// Static-file HTTP/3 server. Construct, run and close on one event-loop thread.
// The listener owns its UDP endpoint and document-root descriptor. The caller
// keeps the listener alive until run() and async_close() finish. With
// `directory_listing`, a directory without an index.html renders a bounded
// directory listing; otherwise it is forbidden. Connection capacity is 1..256.
// Request capacity is 1..8192, or four per connection when zero. Both pools
// reserve storage at construction; exhaustion closes the affected connection.
class http3_server final {
public:
    // `max_udp_payload_size` is clamped to 1200..8192 and negotiated down to
    // the peer's advertised limit. The default is the standard Ethernet payload
    // because path MTU discovery is not implemented.
    http3_server(event_loop& loop, ip_endpoint local, std::string_view root,
                 std::filesystem::path certificate_chain,
                 std::filesystem::path private_key,
                 bool directory_listing = false,
                 std::size_t connection_capacity = 8,
                 std::size_t request_capacity = 0,
                 std::size_t max_udp_payload_size = 1472);
    ~http3_server();
    http3_server(const http3_server&) = delete;
    auto operator=(const http3_server&) -> http3_server& = delete;

    [[nodiscard]] auto local_endpoint() const noexcept -> ip_endpoint;
    [[nodiscard]] auto run() -> task<void>;
    [[nodiscard]] auto async_close() -> task<void>;
    auto close() noexcept -> void;

private:
    static auto run_loop(event_loop& loop, http3_server& server) -> task<void>;
    static auto close_loop(event_loop& loop, http3_server& server) -> task<void>;
    class implementation;
    std::unique_ptr<implementation> implementation_;
};

} // namespace eventloop::http
