#pragma once

#include "eventloop/task.h"

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

private:
    friend struct detail::request_access;
    request() = default;

    detail::exchange* exchange_ {nullptr};
    std::span<const header> headers_;
    std::string_view method_name_;
    std::string_view path_;
    std::string_view query_;
    std::string_view authority_;
    std::optional<std::uint64_t> content_length_;
    void* route_context_ {nullptr};
    method_type method_ {method_type::unknown};
    http::protocol protocol_ {http::protocol::http1_1};
};

} // namespace eventloop::http
