// HTTP/1.1 connection input: request heads, pipelining, routed bodies
// (Content-Length and chunked), and static responses. The first input byte
// picks how many bytes arrive per read; the rest is the connection's input.
#include "fuzz_support.h"

#include "http/session.h"

#include "eventloop/http/router.h"

#include <algorithm>
#include <cstring>
#include <memory>

namespace {

using namespace eventloop;

auto unused(event_loop&, http::request&, http::response&) -> task<void> { co_return; }

auto routes() -> const http::router&
{
    static const auto table = [] {
        auto value = std::make_unique<http::router>();
        for (const auto method : {http::method_type::get, http::method_type::post,
                                  http::method_type::put})
            (void)value->add_prefix(method, "/api/", unused);
        return value;
    }();
    return *table;
}

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int
{
    if (size == 0) return 0;
    const auto piece = fuzz::piece_size(data[0]);
    auto input = fuzz::bytes(data + 1, size - 1);

    http::detail::route_state routing;
    routing.routes = &routes();
    routing.max_request_body = 4096;
    http::detail::session state(fuzz::document_root(), true, &routing);
    while (!state.closed()) {
        while (state.has_response()) {
            (void)state.response();
            (void)state.take_file();
            state.finish_response();
        }
        // A routed request: its handler would read the body, then release it.
        if (state.routed()) {
            state.consume_buffered_body(state.buffered_body().size());
            state.finish_routed(input.size() % 2 == 0);
            continue;
        }
        if (input.empty()) break;
        const auto space = state.read_space();
        if (space.empty()) break;
        const auto count = std::min({piece, space.size(), input.size()});
        std::memcpy(space.data(), input.data(), count);
        input = input.subspan(count);
        state.commit_read(count);
    }
    state.shutdown();
    return 0;
}
