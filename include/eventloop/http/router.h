#pragma once

#include "eventloop/event_loop.h"
#include "eventloop/http/request.h"
#include "eventloop/http/response.h"
#include "eventloop/task.h"

#include <array>
#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <system_error>

namespace eventloop::http {

// A route handler. It is a free coroutine function: the event_loop& first
// parameter selects the bounded coroutine frame pool. An exception it throws
// is handled like returning; see response.
using handler = task<void> (*)(event_loop&, request&, response&);

namespace detail { struct router_access; }

// A bounded route table, built before a server takes it. Servers share it
// read-only through std::shared_ptr<const router>.
//
// Paths start with '/' and contain no '?' or '#'. add() matches the path
// exactly; add_prefix() matches requests whose path starts with the prefix.
// Among routes for the request path, an exact route wins over a prefix and a
// longer prefix over a shorter one; the first of them registered for the
// method runs. HEAD without a HEAD route runs a GET route, and OPTIONS
// without an OPTIONS route answers 204 with Allow. A path matched only for
// other methods answers 405 with Allow. Unmatched paths go to static files
// when the server has a document root, and otherwise answer 404.
//
// add() copies the path, so building a router may allocate; matching does
// not. A duplicate method and path returns file_exists, an invalid path
// returns invalid_argument, and more than max_routes returns
// no_buffer_space. context is passed through request::route_context() and
// must outlive every server that uses the router.
class router {
public:
    static constexpr std::size_t max_routes = 64;

    [[nodiscard]] auto add(method_type method, std::string_view path, handler function,
                           void* context = nullptr) -> std::expected<void, std::error_code>;
    [[nodiscard]] auto add_prefix(method_type method, std::string_view prefix,
                                  handler function, void* context = nullptr)
        -> std::expected<void, std::error_code>;

private:
    friend struct detail::router_access;

    struct route {
        std::string path;
        handler function {nullptr};
        void* context {nullptr};
        method_type method {method_type::unknown};
        bool prefix {false};
    };

    auto insert(method_type method, std::string_view path, handler function,
                void* context, bool prefix) -> std::expected<void, std::error_code>;

    std::array<route, max_routes> routes_ {};
    std::size_t size_ {0};
};

} // namespace eventloop::http
