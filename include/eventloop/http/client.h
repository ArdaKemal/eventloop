#pragma once

#include <cstddef>
#include <expected>
#include <functional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace eventloop::http {

// Request and response values shared by the HTTP/2 and HTTP/3 clients
// (eventloop/http2/client.h, eventloop/http3/client.h). Each client documents
// its own limits and errors.
struct client_header {
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
    std::vector<client_header> headers;
    std::vector<std::byte> body;
    request_body_source body_source;
};

// Trailers, when present, follow the final header fields in headers.
struct client_response {
    unsigned status = 0;
    std::vector<client_header> headers;
    std::vector<std::byte> body;
};

// Called on the owning loop thread. The borrowed chunk is valid only during
// the call. A nonzero error aborts the request and is returned to the caller.
using response_sink = std::move_only_function<std::error_code(std::span<const std::byte>)>;
// Called once for each complete header block before subsequent DATA. Status
// is 1xx for informational headers, the final status for final headers, and
// zero for trailers. The fields span is valid only during the call.
using response_header_sink =
    std::move_only_function<std::error_code(unsigned, std::span<const client_header>)>;

} // namespace eventloop::http
