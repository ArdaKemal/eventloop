#include "connection.h"

#include "eventloop/http/directory_listing.h"
#include "eventloop/http/mime_types.h"
#include "../http/resource.h"
#include "../http/file_operations.h"
#include "session.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <expected>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace eventloop::http2::detail {
namespace {

[[nodiscard]] auto status_fields(std::uint64_t length,
                                 std::string_view content_type = {})
    -> std::array<field, 2>
{
    auto length_text = std::to_string(length);
    auto type_text = std::string(content_type);
    return {field {"content-length", std::move(length_text)},
            field {"content-type", std::move(type_text)}};
}

auto respond_empty(session& state, std::uint32_t stream_id,
                   unsigned status) -> void
{
    if (status == 405) {
        const std::array<field, 2> headers {
            field {"content-length", "0"},
            field {"allow", "GET, HEAD, OPTIONS"}};
        (void)state.respond(stream_id, status, headers, {});
    } else {
        const std::array<field, 1> headers {field {"content-length", "0"}};
        (void)state.respond(stream_id, status, headers, {});
    }
}

[[nodiscard]] auto path_without_suffix(std::string_view target) noexcept
    -> std::string_view
{
    return target.substr(0, target.find_first_of("?#"));
}

[[nodiscard]] auto make_redirect(std::string_view target) -> std::string
{
    const auto path = path_without_suffix(target);
    const auto suffix = target.substr(path.size());
    std::string location;
    location.reserve(target.size() + 1);
    location.append(path);
    location.push_back('/');
    location.append(suffix);
    return location;
}

auto serve_request(session& state, request incoming, native_socket root,
                   bool directory_listing) -> void
{
    if (incoming.method == "OPTIONS") {
        const std::array<field, 1> headers {
            field {"allow", "GET, HEAD, OPTIONS"}};
        (void)state.respond(incoming.stream_id, 204, headers, {});
        return;
    }
    if (incoming.method != "GET" && incoming.method != "HEAD") {
        respond_empty(state, incoming.stream_id, 405);
        return;
    }

    const bool headers_only = incoming.method == "HEAD";
    auto opened = http::detail::open_resource(root, incoming.target);
    if (!opened) {
        const auto status = opened.error() == http::detail::resource_error::invalid_target
            ? 400u : opened.error() == http::detail::resource_error::target_too_long
                ? 414u : 404u;
        respond_empty(state, incoming.stream_id, status);
        return;
    }
    auto descriptor = std::move(*opened);
    auto info = http::detail::get_file_info(descriptor.get());
    if (!info || (info->kind != http::detail::file_info::type::regular &&
                  info->kind != http::detail::file_info::type::directory)) {
        respond_empty(state, incoming.stream_id, 404);
        return;
    }

    if (info->kind == http::detail::file_info::type::regular) {
        const auto size = info->size;
        const auto fields = status_fields(size,
            http::mime_type_from_path(incoming.target));
        (void)state.respond_file(incoming.stream_id, 200, fields,
                                 std::move(descriptor), size, !headers_only);
        return;
    }

    const auto raw_path = path_without_suffix(incoming.target);
    if (raw_path.empty() || raw_path.back() != '/') {
        const auto location = make_redirect(incoming.target);
        const std::array<field, 2> headers {
            field {"content-length", "0"}, field {"location", location}};
        (void)state.respond(incoming.stream_id, 308, headers, {});
        return;
    }

    unique_fd index = http::detail::open_child(descriptor.get(), "index.html", false);
    auto index_info = index ? http::detail::get_file_info(index.get()) : std::nullopt;
    if (index_info && index_info->kind == http::detail::file_info::type::regular) {
        const auto size = index_info->size;
        const auto fields = status_fields(size,
            http::mime_type_from_path("index.html"));
        (void)state.respond_file(incoming.stream_id, 200, fields,
                                 std::move(index), size, !headers_only);
        return;
    }

    if (!directory_listing) {
        respond_empty(state, incoming.stream_id, 403);
        return;
    }
    try {
        auto listing = http::make_directory_listing(descriptor.release());
        if (!listing) {
            respond_empty(state, incoming.stream_id, 500);
            return;
        }
        const auto size = listing->size();
        const auto fields = status_fields(size, "text/html; charset=utf-8");
        if (headers_only) {
            (void)state.respond(incoming.stream_id, 200, fields, {});
            return;
        }
        std::vector<std::byte> body(listing->size());
        if (!body.empty()) {
            std::memcpy(body.data(), listing->data(), listing->size());
        }
        if (!state.respond(incoming.stream_id, 200, fields, std::move(body))) {
            respond_empty(state, incoming.stream_id, 503);
        }
    } catch (...) {
        respond_empty(state, incoming.stream_id, 500);
    }
}

template<typename T>
[[nodiscard]] auto operation_result(
    std::expected<std::expected<T, std::error_code>, task_result> result)
    noexcept -> std::expected<T, std::error_code>
{
    if (!result) {
        return std::unexpected(std::make_error_code(
            result.error() == task_result::frame_allocation_failure
                ? std::errc::not_enough_memory
                : std::errc::operation_canceled));
    }
    return std::move(*result);
}

} // namespace

auto serve([[maybe_unused]] event_loop& loop, tls_stream& peer,
           std::shared_ptr<unique_fd> document_root,
           bool directory_listing) -> task<bool>
{
    try {
        auto state = std::make_unique<session>();
        for (;;) {
            request incoming;
            while (state->pop_request(incoming)) {
                serve_request(*state, std::move(incoming), document_root->get(),
                              directory_listing);
            }

            while (!state->output().empty()) {
                auto written = operation_result(
                    co_await peer.async_write_some(state->output()));
                if (!written || *written == 0) co_return false;
                state->consume_output(*written);
                if (state->closed()) co_return true;
            }
            if (state->closed()) co_return true;

            auto received = operation_result(
                co_await peer.async_read_some(state->read_buffer()));
            if (!received || *received == 0) co_return false;
            state->commit_read(*received);
        }
    } catch (...) {
        // A failed bounded-state allocation retires only this connection.
        co_return false;
    }
}

} // namespace eventloop::http2::detail
