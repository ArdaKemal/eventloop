#pragma once

#include "eventloop/event_loop.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/task.h"
#include "eventloop/tls_context.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace eventloop::http2 {

struct header {
    std::string name;
    std::string value;
};

// Called on the owning loop thread with a writable borrowed chunk of at most
// 16 KiB. Return 0 for EOF, a byte count within the span, or an error. Any
// captured descriptor or buffer must remain valid until task completion.
// Sources are move-only and may own captured resources exclusively.
using request_body_source =
    std::move_only_function<std::expected<std::size_t, std::error_code>(std::span<std::byte>)>;

struct client_request {
    std::string method {"GET"};
    std::string target {"/"};
    // Empty uses hostname. Include the port here when it is not the HTTPS default.
    std::string authority;
    std::vector<header> headers;
    std::vector<std::byte> body;
    request_body_source body_source;
};

struct client_response {
    unsigned status = 0;
    std::vector<header> headers;
    std::vector<std::byte> body;
};

// Called on the owning loop thread. The borrowed chunk is valid only during
// the call. A nonzero error aborts the request and is returned to the caller.
using response_sink = std::move_only_function<std::error_code(std::span<const std::byte>)>;
// Called once for each complete header block before subsequent DATA. Status
// is 1xx for informational headers, the final status for final headers, and
// zero for trailers. The fields span is valid only during the call.
using response_header_sink =
    std::move_only_function<std::error_code(unsigned, std::span<const header>)>;

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
