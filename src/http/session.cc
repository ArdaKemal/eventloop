#include "eventloop/http/session.h"

#include "eventloop/http/directory_listing.h"
#include "eventloop/http/mime_types.h"
#include "resource.h"
#include "file_operations.h"
#include "file_response.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace eventloop::http {
namespace {

constexpr std::string_view bad_request =
    "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view not_found =
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view forbidden =
    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view internal_error =
    "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view method_not_allowed =
    "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD, OPTIONS\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view payload_too_large =
    "HTTP/1.1 413 Content Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view uri_too_long =
    "HTTP/1.1 414 URI Too Long\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view headers_too_large =
    "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view version_not_supported =
    "HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view not_implemented =
    "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view options_response =
    "HTTP/1.1 204 No Content\r\nAllow: GET, HEAD, OPTIONS\r\nContent-Length: 0\r\n\r\n";
constexpr std::size_t sendfile_min_size = 11 * 1024;

} // namespace

session::session(native_socket root_descriptor, bool directory_listing) noexcept
    : root_descriptor_(root_descriptor), directory_listing_(directory_listing)
{
}

auto session::input_data() noexcept -> char*
{
    return expanded_input_ ? expanded_input_.get() : input_.data();
}

auto session::expand_input() -> void
{
    auto expanded = std::make_unique<char[]>(max_message_size);
    std::memcpy(expanded.get(), input_.data(), input_size_);
    expanded_input_ = std::move(expanded);
}

auto session::read_space() -> std::span<std::byte>
{
    if (!expanded_input_ && input_size_ == input_.size()) expand_input();
    const auto capacity = expanded_input_ ? max_message_size : input_.size();
    return std::as_writable_bytes(
        std::span {input_data() + input_size_, capacity - input_size_});
}

auto session::receive(std::span<const std::byte> data) -> void
{
    if (data.empty() || closed_) return;
    if (data.size() > max_message_size - input_size_) {
        if (responding_) closed_ = true;
        else send_error(parse_status::payload_too_large);
        return;
    }

    if (!expanded_input_ && data.size() > input_.size() - input_size_) {
        expand_input();
    }
    std::memcpy(input_data() + input_size_, data.data(), data.size());
    input_size_ += data.size();
    if (!responding_) process_requests();
}

auto session::commit_read(std::size_t size) -> void
{
    const auto capacity = expanded_input_ ? max_message_size : input_.size();
    if (size > capacity - input_size_) {
        closed_ = true;
        return;
    }
    input_size_ += size;
    if (!responding_) process_requests();
}

auto session::shutdown() -> void
{
    close_after_response_ = true;
    if (!responding_) closed_ = true;
}

auto session::response() const noexcept -> std::span<const char>
{
    if (!responding_) return {};
    if (!static_response_.empty()) return {static_response_.data(), static_response_.size()};
    if (file_output_) return {file_output_.get(), file_output_size_};
    return output_;
}

auto session::process_requests() -> void
{
    if (responding_ || input_size_ == 0) return;

    request parsed;
    const auto result = parse_request(
        std::string_view {input_data(), input_size_}, parsed);
    if (result.status == parse_status::incomplete) return;
    if (result.status != parse_status::complete) {
        request_size_ = 0;
        send_error(result.status);
        return;
    }

    request_size_ = result.consumed;
    close_after_response_ = parsed.close_after_response;
    if (parsed.method == method_type::get ||
        parsed.method == method_type::head) {
        serve_resource(parsed, parsed.method == method_type::head);
    } else {
        handle_request(parsed);
    }
}

auto session::handle_request(const request& parsed) -> void
{
    if (parsed.method == method_type::options) send_options();
    else send_static_response(method_not_allowed);
}

auto session::serve_resource(const request& parsed, bool headers_only) -> void
{
    auto opened = detail::open_resource(root_descriptor_, parsed.target);
    if (!opened && opened.error() == detail::resource_error::target_too_long) {
        send_error(parse_status::target_too_long);
        return;
    }
    if (!opened && opened.error() == detail::resource_error::invalid_target) {
        send_error(parse_status::bad_request);
        return;
    }
    auto descriptor = opened ? std::move(*opened) : unique_fd {};
    if (!descriptor) {
        send_static_response(not_found);
        return;
    }

    auto info = detail::get_file_info(descriptor.get());
    if (!info || (info->kind != detail::file_info::type::regular &&
                  info->kind != detail::file_info::type::directory)) {
        descriptor.reset();
        send_static_response(not_found);
        return;
    }
    if (info->kind == detail::file_info::type::regular) {
        serve_file(parsed, std::move(descriptor), *info, headers_only, parsed.target);
        return;
    }

    const auto raw_path = parsed.target.substr(
        0, parsed.target.find_first_of("?#"));
    if (raw_path.empty() || raw_path.back() != '/') {
        descriptor.reset();
        send_directory_redirect(parsed.target);
        return;
    }

    unique_fd index = detail::open_child(descriptor.get(), "index.html", false);
    auto index_info = index ? detail::get_file_info(index.get()) : std::nullopt;
    if (index_info && index_info->kind == detail::file_info::type::regular) {
        descriptor.reset();
        serve_file(parsed, std::move(index), *index_info, headers_only, "index.html");
        return;
    }
    index.reset();

    if (!directory_listing_) {
        descriptor.reset();
        send_static_response(forbidden);
        return;
    }
    serve_directory(std::move(descriptor), headers_only);
}

auto session::serve_file(const request& parsed, unique_fd descriptor, const detail::file_info& info,
                         bool headers_only, std::string_view mime_path) -> void
{
    if (info.size > (std::numeric_limits<std::size_t>::max)()) {
        descriptor.reset();
        close_after_response_ = true;
        send_static_response(internal_error);
        return;
    }

    std::array<char, 64> date {};
    std::string joined_none_match;
    const auto selection = detail::choose_file_response(info, {
        parsed.joined_header_value("If-None-Match", joined_none_match),
        parsed.header_value("If-Modified-Since").value_or(std::string_view {}),
        parsed.header_occurrences("Range") > 1
            ? std::string_view {}
            : parsed.header_value("Range").value_or(std::string_view {})});
    const auto date_size = detail::format_http_time(std::time(nullptr), date);
    const auto mime = mime_type_from_path(mime_path);
    std::array<char, 1024> header {};
    const auto status_text = selection.status == 304 ? "304 Not Modified" :
        selection.status == 206 ? "206 Partial Content" :
        selection.status == 416 ? "416 Range Not Satisfiable" : "200 OK";
    const int header_size = std::snprintf(
        header.data(), header.size(),
        "HTTP/1.1 %s\r\nDate: %.*s\r\nLast-Modified: %.*s\r\n"
        "ETag: %.*s\r\nAccept-Ranges: bytes\r\n"
        "Content-Length: %llu\r\nContent-Type: %.*s\r\n%s%.*s%s"
        "Connection: %s\r\n\r\n",
        status_text,
        static_cast<int>(date_size), date.data(),
        static_cast<int>(selection.modified_size), selection.modified.data(),
        static_cast<int>(selection.etag_size), selection.etag.data(),
        static_cast<unsigned long long>(selection.length),
        static_cast<int>(mime.size()), mime.data(),
        selection.content_range_size == 0 ? "" : "Content-Range: ",
        static_cast<int>(selection.content_range_size), selection.content_range.data(),
        selection.content_range_size == 0 ? "" : "\r\n",
        close_after_response_ ? "close" : "keep-alive");
    if (header_size < 0 || static_cast<std::size_t>(header_size) >= header.size()) {
        descriptor.reset();
        send_error(parse_status::headers_too_large);
        return;
    }

    const auto body_size = headers_only ? std::size_t {0}
                                        : static_cast<std::size_t>(selection.length);
    const auto header_length = static_cast<std::size_t>(header_size);
    if (body_size > (std::numeric_limits<std::size_t>::max)() - header_length) {
        descriptor.reset();
        close_after_response_ = true;
        send_static_response(internal_error);
        return;
    }

    const auto response_size = header_length + body_size;
    if (!headers_only && body_size >= sendfile_min_size) {
        send_response(std::span {header}.first(header_length));
        file_ = std::move(descriptor);
        file_size_ = body_size;
        file_offset_ = selection.offset;
        return;
    }

    try {
        auto response = allocate_response(response_size);
        std::memcpy(response.data(), header.data(), header_length);
        if (!headers_only && !detail::read_file_at(descriptor.get(), selection.offset,
                std::as_writable_bytes(response.subspan(header_length, body_size)))) {
            descriptor.reset();
            file_output_.reset();
            file_output_size_ = 0;
            close_after_response_ = true;
            send_static_response(internal_error);
            return;
        }
    } catch (const std::bad_alloc&) {
        descriptor.reset();
        close_after_response_ = true;
        send_static_response(internal_error);
        return;
    } catch (const std::length_error&) {
        descriptor.reset();
        close_after_response_ = true;
        send_static_response(internal_error);
        return;
    }
    descriptor.reset();
    start_large_response();
}

auto session::serve_directory(unique_fd descriptor, bool headers_only) -> void
{
    try {
        auto listing = detail::render_directory_listing(std::move(descriptor));
        if (!listing) {
            close_after_response_ = true;
            send_static_response(internal_error);
            return;
        }

        const auto body_size = listing->size();
        std::array<char, 512> header {};
        const int header_size = std::snprintf(
            header.data(), header.size(),
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
            "Content-Length: %zu\r\nConnection: %s\r\n\r\n",
            body_size, close_after_response_ ? "close" : "keep-alive");
        if (header_size < 0 ||
            static_cast<std::size_t>(header_size) >= header.size()) {
            send_error(parse_status::headers_too_large);
            return;
        }

        const auto header_length = static_cast<std::size_t>(header_size);
        if (headers_only) {
            send_response(std::span {header}.first(header_length));
            return;
        }
        if (body_size > (std::numeric_limits<std::size_t>::max)() - header_length) {
            throw std::length_error("directory listing is too large");
        }

        listing->insert(listing->begin(), header.begin(), header.begin() +
                            static_cast<std::ptrdiff_t>(header_length));
        output_ = std::move(*listing);
        static_response_ = {};
        start_large_response();
    } catch (const std::bad_alloc&) {
        close_after_response_ = true;
        send_static_response(internal_error);
    } catch (const std::length_error&) {
        close_after_response_ = true;
        send_static_response(internal_error);
    }
}

auto session::send_directory_redirect(std::string_view target) -> void
{
    const auto marker = target.find_first_of("?#");
    const auto path = target.substr(0, marker);
    const auto suffix = marker == std::string_view::npos
        ? std::string_view {}
        : target.substr(marker);
    std::array<char, 4096> response {};
    const int size = std::snprintf(
        response.data(), response.size(),
        "HTTP/1.1 308 Permanent Redirect\r\nLocation: %.*s/%.*s\r\n"
        "Content-Length: 0\r\nConnection: %s\r\n\r\n",
        static_cast<int>(path.size()), path.data(),
        static_cast<int>(suffix.size()), suffix.data(),
        close_after_response_ ? "close" : "keep-alive");
    if (size < 0 || static_cast<std::size_t>(size) >= response.size()) {
        send_error(parse_status::headers_too_large);
        return;
    }
    send_response(std::span {response}.first(static_cast<std::size_t>(size)));
}

auto session::send_options() -> void
{
    send_static_response(options_response);
}

auto session::send_error(parse_status status) -> void
{
    close_after_response_ = true;
    switch (status) {
    case parse_status::target_too_long: send_static_response(uri_too_long); break;
    case parse_status::headers_too_large: send_static_response(headers_too_large); break;
    case parse_status::payload_too_large: send_static_response(payload_too_large); break;
    case parse_status::unsupported_transfer_encoding:
        send_static_response(not_implemented);
        break;
    case parse_status::unsupported_version:
        send_static_response(version_not_supported);
        break;
    default: send_static_response(bad_request); break;
    }
}

auto session::send_static_response(std::string_view response) -> void
{
    output_.clear();
    file_output_.reset();
    file_output_size_ = 0;
    static_response_ = response;
    responding_ = true;
}

auto session::send_response(std::span<const char> response) -> void
{
    output_.assign(response.begin(), response.end());
    file_output_.reset();
    file_output_size_ = 0;
    static_response_ = {};
    responding_ = true;
}

auto session::start_large_response() -> void
{
    responding_ = true;
}

auto session::finish_response() -> void
{
    responding_ = false;
    std::vector<char> {}.swap(output_);
    file_output_.reset();
    file_output_size_ = 0;
    static_response_ = {};
    file_.reset();
    file_size_ = 0;
    file_offset_ = 0;
    if (close_after_response_) {
        closed_ = true;
        return;
    }

    consume_request(request_size_);
    request_size_ = 0;
    process_requests();
}

auto session::consume_request(std::size_t size) -> void
{
    const auto remaining = input_size_ - size;
    std::memmove(input_data(), input_data() + size, remaining);
    input_size_ = remaining;
    if (expanded_input_ && remaining <= input_.size()) {
        std::memcpy(input_.data(), expanded_input_.get(), remaining);
        expanded_input_.reset();
    }
}

auto session::allocate_response(std::size_t size) -> std::span<char>
{
    file_output_ = std::make_unique_for_overwrite<char[]>(size);
    file_output_size_ = size;
    static_response_ = {};
    return {file_output_.get(), size};
}

} // namespace eventloop::http
