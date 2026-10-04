#pragma once

#include "eventloop/http/server_options.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/quic.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string_view>

namespace eventloop::http {

// HTTP/3 server. Construct, run and close on one event-loop thread. The
// listener owns its UDP endpoint and document-root descriptor. The caller
// keeps the listener alive until run() and async_close() finish. Connection
// and request pools reserve storage at construction. A connection beyond
// capacity is closed; a request without free storage is refused with
// H3_REQUEST_REJECTED on its stream. Path MTU discovery is not implemented,
// so max_udp_payload_size defaults to the standard Ethernet payload and is
// negotiated down to the peer's advertised limit.
class http3_server final {
public:
    http3_server(event_loop& loop, ip_endpoint local,
                 std::filesystem::path certificate_chain,
                 std::filesystem::path private_key, server_options options);
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
