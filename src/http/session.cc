#include "eventloop/http/session.h"

#include "eventloop/http/directory_listing.h"
#include "eventloop/http/mime_types.h"

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
constexpr std::size_t sendfile_min_size = 11 * 1024;

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

session::session(int root_descriptor, bool directory_listing) noexcept
    : root_descriptor_(root_descriptor), directory_listing_(directory_listing)
{
}

auto session::receive(std::span<const std::byte> data) -> void
{
    if (data.empty() || closed_) return;
    if (data.size() > input_.size() - input_size_) {
        if (responding_) closed_ = true;
        else send_error(parse_status::payload_too_large);
        return;
    }

    std::memcpy(input_.data() + input_size_, data.data(), data.size());
    input_size_ += data.size();
    if (!responding_) process_requests();
}

auto session::commit_read(std::size_t size) -> void
{
    if (size > input_.size() - input_size_) {
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
        std::string_view {input_.data(), input_size_}, parsed);
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
    std::array<char, 4096> path {};
    std::size_t path_size = 0;
    const auto result = prepare_path(parsed.target, path, path_size);
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
        send_static_response(not_found);
        return;
    }

    struct stat info {};
    if (fstat(descriptor.get(), &info) == -1 ||
        (!S_ISREG(info.st_mode) && !S_ISDIR(info.st_mode))) {
        descriptor.reset();
        send_static_response(not_found);
        return;
    }
    if (S_ISREG(info.st_mode)) {
        serve_file(std::move(descriptor), info, headers_only, parsed.target);
        return;
    }

    const auto raw_path = parsed.target.substr(
        0, parsed.target.find_first_of("?#"));
    if (raw_path.empty() || raw_path.back() != '/') {
        descriptor.reset();
        send_directory_redirect(parsed.target);
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
        send_static_response(forbidden);
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
        send_static_response(internal_error);
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
        send_static_response(internal_error);
        return;
    }

    const auto response_size = header_length + body_size;
    if (!headers_only && body_size >= sendfile_min_size) {
        send_response(std::span {header}.first(header_length));
        file_ = std::move(descriptor);
        file_size_ = body_size;
        return;
    }

    try {
        auto response = allocate_response(response_size);
        std::memcpy(response.data(), header.data(), header_length);
        if (!headers_only && !read_file(descriptor.get(), std::as_writable_bytes(
                response.subspan(header_length, body_size)))) {
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
        auto listing = make_directory_listing(descriptor.release());
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
        if (body_size > std::numeric_limits<std::size_t>::max() - header_length) {
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
    file_output_ = std::make_unique_for_overwrite<char[]>(size);
    file_output_size_ = size;
    static_response_ = {};
    return {file_output_.get(), size};
}

} // namespace http
