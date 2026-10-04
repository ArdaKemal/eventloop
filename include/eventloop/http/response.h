#pragma once

#include "eventloop/http/request.h"
#include "eventloop/task.h"
#include "eventloop/unique_fd.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>

namespace eventloop::http {

// The response to a routed request, owned by the server. Header and body
// spans are borrowed until the operation completes. One operation may be
// pending at a time; another returns operation_in_progress.
//
// Field names must be lowercase tokens. Connection-specific fields
// (connection, keep-alive, proxy-connection, transfer-encoding, upgrade, te)
// are rejected with invalid_argument. The server adds a date field when
// absent. A declared content-length is enforced: writing past it is
// invalid_argument, and finishing short is invalid_argument and abandons the
// response. Without content-length, HTTP/1.1 uses chunked transfer coding.
// Status 204 and 304 carry no body. A response to HEAD sends the same status
// and fields, and body writes are accepted and discarded.
//
// If the handler returns before async_start, the server sends 500. If it
// returns after async_start but before async_finish, the response is
// abandoned: HTTP/1.1 closes the connection.
class response {
public:
    response(const response&) = delete;
    auto operator=(const response&) -> response& = delete;

    // status must be 200 to 599.
    [[nodiscard]] auto async_start(unsigned status, std::span<const header> headers)
        -> task<std::expected<void, std::error_code>>;
    // Completes once the bytes are accepted by the connection.
    [[nodiscard]] auto async_write(std::span<const std::byte> data)
        -> task<std::expected<void, std::error_code>>;
    // Trailers are sent only on chunked HTTP/1.1 responses to requests that
    // sent TE: trailers; otherwise they are dropped.
    [[nodiscard]] auto async_finish(std::span<const header> trailers = {})
        -> task<std::expected<void, std::error_code>>;
    // Start with content-length set to body.size(), write, and finish. headers
    // must not contain content-length.
    [[nodiscard]] auto async_send(unsigned status, std::span<const header> headers,
                                  std::span<const std::byte> body = {})
        -> task<std::expected<void, std::error_code>>;
    // Sends size bytes of file from offset with content-length set. The file
    // is owned through completion, including cancellation.
    [[nodiscard]] auto async_send_file(unsigned status, std::span<const header> headers,
                                       unique_fd file, std::uint64_t offset,
                                       std::uint64_t size)
        -> task<std::expected<void, std::error_code>>;

private:
    friend struct detail::request_access;
    response() = default;

    detail::exchange* exchange_ {nullptr};
};

} // namespace eventloop::http
