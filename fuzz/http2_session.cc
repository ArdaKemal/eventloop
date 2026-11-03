// HTTP/2 connection input after the client preface and an empty SETTINGS
// frame, which this harness supplies: frames, HPACK, flow control, priority,
// static requests, and routed streams with bodies. The first input byte
// picks how many bytes arrive per read.
#include "fuzz_support.h"

#include "http2/session.h"

#include "eventloop/http/router.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <string_view>
#include <vector>

namespace {

using namespace eventloop;
using namespace std::literals;

auto unused(event_loop&, http::request&, http::response&) -> task<void> { co_return; }

auto routes() -> const http::router&
{
    static const auto table = [] {
        auto value = std::make_unique<http::router>();
        for (const auto method : {http::method_type::get, http::method_type::post,
                                  http::method_type::connect})
            (void)value->add_prefix(method, "/api/", unused);
        return value;
    }();
    return *table;
}

// Answers what the session has decoded and takes all of its output, as
// the connection task does between reads.
auto serve(http2::detail::session& state, std::vector<std::uint32_t>& routed) -> void
{
    http2::detail::request request;
    while (state.pop_request(request)) {
        static constexpr std::string_view text = "body";
        const std::array<http::header, 1> fields {{{"content-type", "text/plain"}}};
        (void)state.respond(request.stream_id, request.method == "HEAD" ? 204 : 200, fields,
            std::vector<std::byte>(reinterpret_cast<const std::byte*>(text.data()),
                                   reinterpret_cast<const std::byte*>(text.data()) + text.size()));
    }
    http2::detail::routed_request incoming;
    while (state.pop_routed(incoming)) {
        routed.push_back(incoming.stream_id);
        state.recycle_fields(std::move(incoming.fields));
    }
    std::array<std::byte, 512> body {};
    std::erase_if(routed, [&](std::uint32_t id) {
        auto status = http2::detail::session::body_state::data;
        std::size_t count = 0;
        while (status == http2::detail::session::body_state::data)
            status = state.read_body(id, body, count);
        if (status == http2::detail::session::body_state::waiting) return false;
        // Odd streams get a response; others are reset, as an abandoned
        // handler would.
        if (id % 4 == 1 && state.start_streamed(id, 200, {}))
            (void)state.finish_streamed(id, {});
        else
            state.abandon(id, 8);
        return true;
    });
    if (state.input_paused()) state.resume_input();
    for (int round = 0; round < 64; ++round) {
        if (auto file = state.take_file_send(true)) {
            if (!file->prefix.empty()) state.consume_output(file->prefix.size());
            state.complete_file_send(std::move(file->file));
            continue;
        }
        const auto output = state.output();
        if (output.empty()) break;
        state.consume_output(output.size());
    }
}

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int
{
    if (size == 0) return 0;
    static constexpr std::string_view preface =
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\4\0\0\0\0\0"sv;
    std::vector<std::byte> stream(reinterpret_cast<const std::byte*>(preface.data()),
                                  reinterpret_cast<const std::byte*>(preface.data()) + preface.size());
    const auto rest = fuzz::bytes(data + 1, size - 1);
    stream.insert(stream.end(), rest.begin(), rest.end());
    const auto piece = fuzz::piece_size(data[0]);

    http2::detail::session state(false, &routes(), 4096);
    std::vector<std::uint32_t> routed;
    auto input = std::span<const std::byte>(stream);
    while (!input.empty() && !state.closed()) {
        const auto space = state.read_buffer();
        if (space.empty()) {
            serve(state, routed);
            if (state.read_buffer().empty()) break;
            continue;
        }
        const auto count = std::min({piece, space.size(), input.size()});
        std::memcpy(space.data(), input.data(), count);
        input = input.subspan(count);
        state.commit_read(count);
        serve(state, routed);
    }
    return 0;
}
