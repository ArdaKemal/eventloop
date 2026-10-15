#pragma once

#include "eventloop/task.h"
#include "eventloop/http/webtransport.h"
#include "eventloop/http/websocket_stream.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>

namespace eventloop::http {

enum class method_type {
    get,
    head,
    post,
    put,
    delete_,
    options,
    trace,
    connect,
    patch,
    unknown,
};

enum class protocol { http1_1, http2, http3 };

struct header {
    std::string_view name;
    std::string_view value;
};

namespace detail {
class exchange;
struct request_access;
} // namespace detail

// A request delivered to a route handler. Every view stays valid until the
// handler task completes. The server owns this object.
class request {
public:
    request(const request&) = delete;
    auto operator=(const request&) -> request& = delete;

    [[nodiscard]] auto method() const noexcept -> method_type { return method_; }
    [[nodiscard]] auto method_name() const noexcept -> std::string_view { return method_name_; }
    // The target before '?', not percent-decoded.
    [[nodiscard]] auto path() const noexcept -> std::string_view { return path_; }
    // The target after '?', or empty.
    [[nodiscard]] auto query() const noexcept -> std::string_view { return query_; }
    // :authority, or Host on HTTP/1.1.
    [[nodiscard]] auto authority() const noexcept -> std::string_view { return authority_; }
    [[nodiscard]] auto protocol() const noexcept -> http::protocol { return protocol_; }
    // Extended CONNECT :protocol, or empty on ordinary requests.
    [[nodiscard]] auto connect_protocol() const noexcept -> std::string_view
    { return connect_protocol_; }
    [[nodiscard]] auto headers() const noexcept -> std::span<const header> { return headers_; }
    // First field with this name, compared case-insensitively.
    [[nodiscard]] auto header_value(std::string_view name) const noexcept
        -> std::optional<std::string_view>;
    [[nodiscard]] auto content_length() const noexcept -> std::optional<std::uint64_t>
    {
        return content_length_;
    }
    // The context pointer registered with the matched route.
    [[nodiscard]] auto route_context() const noexcept -> void* { return route_context_; }

    // Reads up to buffer.size() body bytes; 0 is the end of the body. The
    // buffer is borrowed until completion. One read may be pending at a time;
    // another returns operation_in_progress. A peer reset or connection loss
    // returns connection_reset.
    [[nodiscard]] auto async_read_body(std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;

    // Accept RFC 8441/9220 WebSocket version 13 before reading the body or
    // starting a response. A selected subprotocol must have been offered.
    // No extensions are negotiated. The handler applies Origin/auth policy.
    // Invalid handshakes return invalid_argument without a response; HTTP/1.1
    // returns operation_not_supported. The returned stream cannot outlive
    // this handler. Ordinary HTTP I/O is invalid after acceptance.
    [[nodiscard]] auto async_accept_websocket(std::string_view subprotocol = {})
        -> task<std::expected<websocket_stream, std::error_code>>;

    // Accept an Extended CONNECT whose :protocol is webtransport-h3 before
    // starting the response or reading the body, on an http3_server with
    // server_options::webtransport enabled. The session borrows this handler:
    // keep it inside the handler, and returning ends it. The first
    // WT-Available-Protocols member, in client order, that appears in
    // protocols is selected and returned as WT-Protocol; with no match, the
    // session has no protocol. Invalid requests (not CONNECT, other
    // :protocol, already accepted or started) return invalid_argument without
    // a response. HTTP/1.1 and HTTP/2 return operation_not_supported.
    [[nodiscard]] auto async_accept_webtransport(std::span<const std::string_view> protocols = {})
        -> task<std::expected<webtransport_session, std::error_code>>;

private:
    friend struct detail::request_access;
    request() = default;

    detail::exchange* exchange_ {nullptr};
    std::span<const header> headers_;
    std::string_view method_name_;
    std::string_view path_;
    std::string_view query_;
    std::string_view authority_;
    std::string_view connect_protocol_;
    std::optional<std::uint64_t> content_length_;
    void* route_context_ {nullptr};
    method_type method_ {method_type::unknown};
    http::protocol protocol_ {http::protocol::http1_1};
};

} // namespace eventloop::http
