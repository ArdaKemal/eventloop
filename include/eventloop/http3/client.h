#pragma once

#include "eventloop/event_loop.h"
#include "eventloop/http/client.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/quic.h"
#include "eventloop/task.h"

#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>

namespace eventloop::http3 {

using header = http::client_header;
using http::client_request;
using http::client_response;
using http::request_body_source;
using http::response_header_sink;
using http::response_sink;

struct client_options {
    std::filesystem::path trusted_ca; // empty uses the system trust store
    quic_version version {quic_version::v1};
};

// One QUIC connection with ALPN h3 that carries sequential requests on
// client bidirectional streams (RFC 9114). The connection owns its client
// quic_endpoint, bound to the unspecified address of the peer's family.
// Construct, use, and close it on the loop thread, and keep it alive and
// unmoved while an operation is pending. Once async_connect() has been called,
// async_close() must complete before destruction; destroying it earlier
// terminates. Only one of async_connect(), async_request(), and async_close()
// may be pending: another returns device_or_resource_busy. A request before
// connecting, after close(), failure, or a peer GOAWAY returns not_connected.
// Any request failure other than argument validation, including cancellation,
// closes the QUIC connection; a peer GOAWAY that excludes the request's stream
// returns connection_reset, meaning the server did not process it.
//
// Limits: 64 KiB and 128 fields per field section, 4 MiB owned request and
// buffered response bodies, 1 TiB through a source or sink. A sink leaves
// response.body empty. Callbacks run synchronously on the loop thread. A
// request Content-Length must match the body or source total, otherwise
// invalid_argument. Resource limits report message_size; malformed protocol,
// including a response Content-Length mismatch or content on a HEAD, 204, or
// 304 response, reports protocol_error. QPACK uses no dynamic table and
// server push is refused.
class client_connection {
public:
    // The hostname selects certificate verification, SNI, and the default
    // :authority. No I/O starts until async_connect().
    client_connection(event_loop& loop, ip_endpoint endpoint, std::string hostname,
                      client_options options = {});
    client_connection(const client_connection&) = delete;
    auto operator=(const client_connection&) -> client_connection& = delete;
    ~client_connection();

    // Opens the endpoint, handshakes with ALPN h3, and opens the control and
    // QPACK streams. Connecting twice returns already_connected.
    [[nodiscard]] auto async_connect() -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] auto async_request(client_request request, response_sink sink = {},
                                     response_header_sink header_sink = {})
        -> task<std::expected<client_response, std::error_code>>;
    // Closes the connection and endpoint without waiting, so a pending
    // operation fails promptly; for deadlines. async_close() is still required.
    auto close() noexcept -> void;
    // Closes with H3_NO_ERROR and resolves once the endpoint has retired.
    [[nodiscard]] auto async_close() -> task<std::expected<void, std::error_code>>;

private:
    struct state;
    std::unique_ptr<state> state_;
};

} // namespace eventloop::http3
