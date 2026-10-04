#pragma once

#include "eventloop/http/request.h"
#include "eventloop/http/response.h"
#include "eventloop/http/router.h"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>

namespace eventloop::http::detail {

using void_result = std::expected<void, std::error_code>;
using size_result = std::expected<std::size_t, std::error_code>;

// One routed request and its response on some protocol. The public request
// and response forward here. Implementations return tasks from static
// coroutines whose first parameter is the event loop.
class exchange {
public:
    virtual auto read_body(std::span<std::byte> buffer) -> task<size_result> = 0;
    // length, when set, is emitted as content-length and enforced.
    virtual auto start(unsigned status, std::span<const header> headers,
                       std::optional<std::uint64_t> length) -> task<void_result> = 0;
    virtual auto write(std::span<const std::byte> data) -> task<void_result> = 0;
    virtual auto finish(std::span<const header> trailers) -> task<void_result> = 0;
    virtual auto send_file(unsigned status, std::span<const header> headers, unique_fd file,
                           std::uint64_t offset, std::uint64_t size) -> task<void_result> = 0;
    // Each implementation owns the loop its tasks run on.
    [[nodiscard]] virtual auto loop() noexcept -> event_loop& = 0;

protected:
    ~exchange() = default;
};

struct request_fields {
    std::span<const header> headers;
    std::string_view method_name;
    std::string_view target;
    std::string_view authority;
    std::optional<std::uint64_t> content_length;
    method_type method {method_type::unknown};
    http::protocol protocol {http::protocol::http1_1};
};

struct request_access {
    static auto bind(request& value, exchange& owner, const request_fields& fields,
                     void* context) noexcept -> void;
    static auto bind(response& value, exchange& owner) noexcept -> void;
    [[nodiscard]] static auto make_request() noexcept -> request { return {}; }
    [[nodiscard]] static auto make_response() noexcept -> response { return {}; }
};

// Bitmask of method_type values.
using method_set = std::uint16_t;

[[nodiscard]] constexpr auto method_bit(method_type method) noexcept -> method_set
{
    return static_cast<method_set>(1u << static_cast<unsigned>(method));
}

struct route_match {
    handler function {nullptr};
    void* context {nullptr};
    // Methods routed for the request path, including implied HEAD and
    // OPTIONS. Zero when no route matches the path.
    method_set allowed {0};
};

struct router_access {
    [[nodiscard]] static auto match(const router& routes, method_type method,
                                    std::string_view path) noexcept -> route_match;
};

// Writes "GET, HEAD, ..." for allowed into output and returns its length.
[[nodiscard]] auto format_allow(method_set allowed, std::span<char> output) noexcept
    -> std::size_t;

// Lowercase token, not a pseudo-header or connection-specific field.
[[nodiscard]] auto valid_response_field(std::string_view name, std::string_view value) noexcept
    -> bool;

// Parses a decimal content-length value.
[[nodiscard]] auto parse_length(std::string_view value) noexcept -> std::optional<std::uint64_t>;

} // namespace eventloop::http::detail
