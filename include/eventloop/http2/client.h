#pragma once

#include "eventloop/event_loop.h"
#include "eventloop/http/client.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/task.h"
#include "eventloop/tls_context.h"

#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>

namespace eventloop::http2 {

using header = http::client_header;
using http::client_request;
using http::client_response;
using http::request_body_source;
using http::response_header_sink;
using http::response_sink;

// One HTTPS connection with ALPN h2 that carries sequential requests on
// streams 1, 3, 5, and so on (RFC 9113 section 9.1.1). The connection
// owns its loop-owned TLS transport; construct, use, and destroy it on the
// loop thread, and keep it alive and unmoved while an operation is pending.
// Destroy it before the loop shuts down. Destruction closes an open transport
// without GOAWAY; async_close() sends GOAWAY first. Requests have the limits
// and errors of async_request below; an empty authority uses hostname. Only
// one operation may be pending: another returns device_or_resource_busy.
// A request before connecting, after close, failure, or a peer GOAWAY returns
// not_connected. Any request failure other than argument validation,
// including cancellation, closes the connection; a peer GOAWAY that excludes
// the request's stream returns connection_reset, meaning the server did not
// process it.
class client_connection {
public:
    // The hostname selects certificate verification, SNI, and the default
    // :authority. No I/O starts until async_connect().
    client_connection(event_loop& loop, ip_endpoint endpoint,
                      std::shared_ptr<tls_context> context, std::string hostname);
    client_connection(const client_connection&) = delete;
    auto operator=(const client_connection&) -> client_connection& = delete;
    ~client_connection();

    // Connects, handshakes, and requires ALPN h2 (otherwise
    // protocol_not_supported). Connecting twice returns already_connected.
    [[nodiscard]] auto async_connect() -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] auto async_request(client_request request, response_sink sink = {},
                                     response_header_sink header_sink = {})
        -> task<std::expected<client_response, std::error_code>>;
    // True when the connection is open, has not seen GOAWAY, was made to
    // endpoint, and its verified certificate is valid for hostname under the
    // checks a new connection would apply. Such a connection may carry
    // requests for hostname at endpoint's port. A server that is not
    // authoritative for a request answers 421; retry it on a new connection.
    [[nodiscard]] auto can_reuse_for(std::string_view hostname,
                                     const ip_endpoint& endpoint) const -> bool;
    // Sends GOAWAY (NO_ERROR, last stream 0) after any request, then closes.
    [[nodiscard]] auto async_close() -> task<std::expected<void, std::error_code>>;

private:
    struct state;
    friend auto async_request(event_loop&, ip_endpoint, std::shared_ptr<tls_context>,
                              std::string, client_request, response_sink,
                              response_header_sink)
        -> task<std::expected<client_response, std::error_code>>;
    std::unique_ptr<state> state_;
};

// Performs one request on one owned TLS connection. The numeric endpoint
// is caller supplied; hostname selects certificate verification, SNI and the
// default :authority. All request strings are owned by the task. Response
// strings and body bytes are owned by the caller after completion. Requests
// and callbacks are move-only; move named values into this operation. Owned
// callback captures live with the task through completion, including cancellation.
// Limits:
// 64 KiB and 128 fields per header block, 16 KiB frame, 4 MiB owned request
// and buffered response bodies. A source or sink streams up to 1 TiB; a sink
// leaves response.body empty. Callbacks run synchronously on the loop thread.
// A request Content-Length must match the body or source total, otherwise
// invalid_argument. Resource limits report message_size; malformed protocol,
// including a response Content-Length mismatch or content on a HEAD, 204, or
// 304 response, reports protocol_error. Cancellation closes the connection
// and pending I/O.
[[nodiscard]] auto async_request(event_loop& loop, ip_endpoint endpoint,
                                 std::shared_ptr<tls_context> context,
                                 std::string hostname, client_request request,
                                 response_sink sink = {},
                                 response_header_sink header_sink = {})
    -> task<std::expected<client_response, std::error_code>>;

} // namespace eventloop::http2
