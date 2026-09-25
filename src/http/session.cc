#include "eventloop/http/session.h"

#include "eventloop/http/directory_listing.h"
#include "eventloop/http/mime_types.h"
#include "eventloop/tcp_stream.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <limits>
#include <stdexcept>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

namespace http {
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
constexpr std::size_t buffer_size = 4096;
constexpr std::size_t sendfile_min_size = 11 * 1024;
constexpr std::size_t write_size = 16 * 1024;

[[nodiscard]] constexpr auto hex_value(char value) noexcept -> int
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

auto format_http_time(std::time_t value, std::span<char> output) noexcept
    -> std::size_t
{
    std::tm time {};
    if (gmtime_r(&value, &time) == nullptr) return 0;
    return std::strftime(output.data(), output.size(),
                         "%a, %d %b %Y %H:%M:%S GMT", &time);
}

[[nodiscard]] auto open_beneath(int root, std::span<char> path) noexcept
    -> unique_fd
{
    std::size_t start = 0;
    int parent = root;
    unique_fd owned_parent;

    while (start < path.size()) {
        while (start < path.size() && path[start] == '/') ++start;
        if (start == path.size()) break;

        auto end = start;
        while (end < path.size() && path[end] != '/') ++end;
        const char saved = end < path.size() ? path[end] : '\0';
        if (end < path.size()) path[end] = '\0';
        const int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
                          (end < path.size() ? O_DIRECTORY : 0);
        unique_fd next(openat(parent, path.data() + start, flags));
        if (end < path.size()) path[end] = saved;
        if (!next) {
            const int error = errno;
            owned_parent.reset();
            errno = error;
            return {};
        }
        owned_parent = std::move(next);
        parent = owned_parent.get();
        start = end + 1;
    }

    if (owned_parent) return owned_parent;
    return unique_fd(openat(root, ".", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
}

auto read_file(int descriptor, std::span<std::byte> output) noexcept -> bool
{
    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto size = ::read(descriptor, output.data() + offset,
                                 output.size() - offset);
        if (size > 0) {
            offset += static_cast<std::size_t>(size);
        } else if (size == -1 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

} // namespace

session::session(byte_stream& stream, int root_descriptor,
                 bool directory_listing, tcp_stream* file_stream) noexcept
    : stream_(stream), file_stream_(file_stream), root_descriptor_(root_descriptor),
      directory_listing_(directory_listing)
{
}

auto session::receive(std::span<const std::byte> data) -> void
{
    if (data.empty()) return;
    if (data.size() > input_.size() - input_size_) {
        if (responding_) stream_.close();
        else send_error(parse_status::payload_too_large);
        return;
    }

    std::memcpy(input_.data() + input_size_, data.data(), data.size());
    input_size_ += data.size();
    if (!responding_) process_requests();
}

auto session::write_drained() -> void
{
    if (!responding_) return;
    if (output_ && output_offset_ < output_size_) write_next();
    else finish_response();
}

auto session::closed() -> void
{
    responding_ = false;
    output_.reset();
    output_size_ = 0;
    output_offset_ = 0;
}

auto session::failed(std::error_code) -> void
{
    closed();
}

auto session::shutdown() -> void
{
    close_after_response_ = true;
    if (!responding_) {
        stream_.close();
    }
}

auto session::process_requests() -> void
{
    if (responding_ || input_size_ == 0) return;

    const auto result = parse_request(
        std::string_view {input_.data(), input_size_}, request_);
    if (result.status == parse_status::incomplete) return;
    if (result.status != parse_status::complete) {
        request_size_ = 0;
        send_error(result.status);
        return;
    }

    request_size_ = result.consumed;
    close_after_response_ = request_.close_after_response;
    if (request_.method == method_type::get ||
        request_.method == method_type::head) {
        serve_resource(request_.method == method_type::head);
    } else {
        handle_request();
    }
}

auto session::handle_request() -> void
{
    if (request_.method == method_type::options) send_options();
    else send_response(method_not_allowed);
}

auto session::serve_resource(bool headers_only) -> void
{
    std::array<char, 4096> path {};
    std::size_t path_size = 0;
    const auto result = prepare_path(request_.target, path, path_size);
    if (result == path_result::too_long) {
        send_error(parse_status::target_too_long);
        return;
    }
    if (result == path_result::invalid) {
        send_error(parse_status::bad_request);
        return;
    }

    auto descriptor = open_beneath(root_descriptor_,
                                   std::span {path}.first(path_size));
    if (!descriptor) {
        send_response(not_found);
        return;
    }

    struct stat info {};
    if (fstat(descriptor.get(), &info) == -1 ||
        (!S_ISREG(info.st_mode) && !S_ISDIR(info.st_mode))) {
        descriptor.reset();
        send_response(not_found);
        return;
    }
    if (S_ISREG(info.st_mode)) {
        serve_file(std::move(descriptor), info, headers_only, request_.target);
        return;
    }

    const auto raw_path = request_.target.substr(
        0, request_.target.find_first_of("?#"));
    if (raw_path.empty() || raw_path.back() != '/') {
        descriptor.reset();
        send_directory_redirect();
        return;
    }

    unique_fd index(openat(descriptor.get(), "index.html",
                           O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    struct stat index_info {};
    if (index && fstat(index.get(), &index_info) == 0 &&
        S_ISREG(index_info.st_mode)) {
        descriptor.reset();
        serve_file(std::move(index), index_info, headers_only, "index.html");
        return;
    }
    index.reset();

    if (!directory_listing_) {
        descriptor.reset();
        send_response(forbidden);
        return;
    }
    serve_directory(std::move(descriptor), headers_only);
}

auto session::serve_file(unique_fd descriptor, const struct ::stat& info,
                         bool headers_only, std::string_view mime_path) -> void
{
    if (info.st_size < 0 ||
        static_cast<std::uintmax_t>(info.st_size) >
            std::numeric_limits<std::size_t>::max()) {
        descriptor.reset();
        close_after_response_ = true;
        send_response(internal_error);
        return;
    }

    std::array<char, 64> date {};
    std::array<char, 64> modified {};
    const auto date_size = format_http_time(std::time(nullptr), date);
    const auto modified_size = format_http_time(info.st_mtime, modified);
    const auto mime = mime_type_from_path(mime_path);
    std::array<char, 1024> header {};
    const int header_size = std::snprintf(
        header.data(), header.size(),
        "HTTP/1.1 200 OK\r\nDate: %.*s\r\nLast-Modified: %.*s\r\n"
        "Content-Length: %jd\r\nContent-Type: %.*s\r\n"
        "Connection: %s\r\n\r\n",
        static_cast<int>(date_size), date.data(),
        static_cast<int>(modified_size), modified.data(),
        static_cast<std::intmax_t>(info.st_size),
        static_cast<int>(mime.size()), mime.data(),
        close_after_response_ ? "close" : "keep-alive");
    if (header_size < 0 || static_cast<std::size_t>(header_size) >= header.size()) {
        descriptor.reset();
        send_error(parse_status::headers_too_large);
        return;
    }

    const auto body_size = headers_only ? std::size_t {0}
                                        : static_cast<std::size_t>(info.st_size);
    const auto header_length = static_cast<std::size_t>(header_size);
    if (body_size > std::numeric_limits<std::size_t>::max() - header_length) {
        descriptor.reset();
        close_after_response_ = true;
        send_response(internal_error);
        return;
    }

    const auto response_size = header_length + body_size;
    if (!headers_only && file_stream_ != nullptr &&
        body_size >= sendfile_min_size) {
        responding_ = true;
        file_stream_->send_file(
            std::as_bytes(std::span {header}.first(header_length)),
            std::move(descriptor), body_size);
        return;
    }

    if (response_size <= buffer_size) {
        std::array<char, buffer_size> response {};
        std::memcpy(response.data(), header.data(), header_length);
        const bool read = headers_only || read_file(
            descriptor.get(),
            std::as_writable_bytes(std::span {response}.subspan(header_length,
                                                                 body_size)));
        descriptor.reset();
        if (!read) {
            close_after_response_ = true;
            send_response(internal_error);
            return;
        }
        send_response(std::span {response}.first(response_size));
        return;
    }

    try {
        auto response = allocate_response(response_size);
        std::memcpy(response.data(), header.data(), header_length);
        if (!read_file(descriptor.get(), std::as_writable_bytes(
                response.subspan(header_length, body_size)))) {
            descriptor.reset();
            output_.reset();
            close_after_response_ = true;
            send_response(internal_error);
            return;
        }
    } catch (const std::bad_alloc&) {
        descriptor.reset();
        close_after_response_ = true;
        send_response(internal_error);
        return;
    } catch (const std::length_error&) {
        descriptor.reset();
        close_after_response_ = true;
        send_response(internal_error);
        return;
    }
    descriptor.reset();
    start_large_response();
}

auto session::serve_directory(unique_fd descriptor, bool headers_only) -> void
{
    try {
        auto listing = make_directory_listing(descriptor.release());
        if (!listing) {
            close_after_response_ = true;
            send_response(internal_error);
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
        if (body_size > std::numeric_limits<std::size_t>::max() - header_length) {
            throw std::length_error("directory listing is too large");
        }

        const auto response_size = header_length + body_size;
        if (response_size <= buffer_size) {
            std::array<char, buffer_size> response {};
            std::memcpy(response.data(), header.data(), header_length);
            std::memcpy(response.data() + header_length, listing->data(), body_size);
            send_response(std::span {response}.first(response_size));
            return;
        }

        auto response = allocate_response(response_size);
        std::memcpy(response.data(), header.data(), header_length);
        std::memcpy(response.data() + header_length, listing->data(), body_size);
        start_large_response();
    } catch (const std::bad_alloc&) {
        close_after_response_ = true;
        send_response(internal_error);
    } catch (const std::length_error&) {
        close_after_response_ = true;
        send_response(internal_error);
    }
}

auto session::send_directory_redirect() -> void
{
    const auto marker = request_.target.find_first_of("?#");
    const auto path = request_.target.substr(0, marker);
    const auto suffix = marker == std::string_view::npos
        ? std::string_view {}
        : request_.target.substr(marker);
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
    send_response(std::string_view {response.data(), static_cast<std::size_t>(size)});
}

auto session::send_options() -> void
{
    send_response(options_response);
}

auto session::send_error(parse_status status) -> void
{
    close_after_response_ = true;
    switch (status) {
    case parse_status::target_too_long: send_response(uri_too_long); break;
    case parse_status::headers_too_large: send_response(headers_too_large); break;
    case parse_status::payload_too_large: send_response(payload_too_large); break;
    case parse_status::unsupported_transfer_encoding:
        send_response(not_implemented);
        break;
    case parse_status::unsupported_version:
        send_response(version_not_supported);
        break;
    default: send_response(bad_request); break;
    }
}

auto session::send_response(std::string_view response) -> void
{
    send_response(std::span {response.data(), response.size()});
}

auto session::send_response(std::span<const char> response) -> void
{
    responding_ = true;
    stream_.write(std::as_bytes(response));
}

auto session::start_large_response() -> void
{
    responding_ = true;
    write_next();
}

auto session::write_next() -> void
{
    const auto size = std::min(write_size, output_size_ - output_offset_);
    const auto chunk = std::span {output_.get() + output_offset_, size};
    output_offset_ += size;
    stream_.write(std::as_bytes(chunk));
}

auto session::finish_response() -> void
{
    responding_ = false;
    output_.reset();
    output_size_ = 0;
    output_offset_ = 0;
    if (close_after_response_) {
        stream_.close();
        return;
    }

    consume_request(request_size_);
    request_size_ = 0;
    request_ = {};
    process_requests();
}

auto session::consume_request(std::size_t size) -> void
{
    const auto remaining = input_size_ - size;
    std::memmove(input_.data(), input_.data() + size, remaining);
    input_size_ = remaining;
}

auto session::prepare_path(std::string_view target, std::span<char> output,
                           std::size_t& size) const noexcept -> path_result
{
    target = target.substr(0, target.find_first_of("?#"));
    if (target.empty() || target.front() != '/') return path_result::invalid;

    size = 0;
    for (std::size_t input = 1; input < target.size(); ++input) {
        char value = target[input];
        if (value == '%') {
            if (input + 2 >= target.size()) return path_result::invalid;
            const int high = hex_value(target[input + 1]);
            const int low = hex_value(target[input + 2]);
            if (high < 0 || low < 0) return path_result::invalid;
            value = static_cast<char>((high << 4) | low);
            input += 2;
        }
        if (value == '\0' || value == '\\' ||
            static_cast<unsigned char>(value) < 0x20) {
            return path_result::invalid;
        }
        if (size == output.size()) return path_result::too_long;
        output[size++] = value;
    }

    const std::string_view decoded {output.data(), size};
    std::size_t segment_start = 0;
    while (segment_start <= decoded.size()) {
        const auto slash = decoded.find('/', segment_start);
        const auto segment = decoded.substr(
            segment_start, slash == std::string_view::npos
                ? decoded.size() - segment_start
                : slash - segment_start);
        if (segment == "..") return path_result::invalid;
        if (slash == std::string_view::npos) break;
        segment_start = slash + 1;
    }

    if (size == 0) output[size++] = '.';
    return path_result::valid;
}

auto session::allocate_response(std::size_t size) -> std::span<char>
{
    output_ = std::make_unique_for_overwrite<char[]>(size);
    output_size_ = size;
    output_offset_ = 0;
    return {output_.get(), size};
}

} // namespace http
