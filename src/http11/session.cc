#include "eventloop/http/session.h"

#include "eventloop/http/mime_types.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string_view>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace http {
namespace {

constexpr std::string_view bad_request =
    "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
constexpr std::string_view not_found =
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
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

[[nodiscard]] constexpr auto hex_value(char value) noexcept -> int
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

auto format_http_time(std::time_t value, std::span<char> output) noexcept -> std::size_t
{
    std::tm time {};
    if (gmtime_r(&value, &time) == nullptr) {
        return 0;
    }
    return std::strftime(output.data(), output.size(),
                         "%a, %d %b %Y %H:%M:%S GMT", &time);
}

} // namespace

session::session(byte_stream& stream, int root_descriptor) noexcept
    : stream_(stream), root_descriptor_(root_descriptor)
{
}

session::~session()
{
    if (file_descriptor_ != -1) {
        ::close(file_descriptor_);
    }
}

auto session::receive(std::span<const std::byte> data) -> void
{
    if (data.size() > input_.size() - input_size_) {
        if (responding_) {
            stream_.close();
        } else {
            send_error(parse_status::payload_too_large);
        }
        return;
    }
    std::memcpy(input_.data() + input_size_, data.data(), data.size());
    input_size_ += data.size();
    if (!responding_) {
        process_requests();
    }
}

auto session::write_drained() -> void
{
    if (file_descriptor_ != -1) {
        pump_file();
    } else if (responding_) {
        finish_response();
    }
}

auto session::closed() -> void
{
    if (file_descriptor_ != -1) {
        ::close(file_descriptor_);
        file_descriptor_ = -1;
    }
}

auto session::failed(std::error_code) -> void
{
    closed();
}

auto session::process_requests() -> void
{
    while (!responding_ && input_size_ != 0) {
        const auto result = parse_request(
            std::string_view {input_.data(), input_size_}, request_);
        if (result.status == parse_status::incomplete) {
            return;
        }
        if (result.status != parse_status::complete) {
            send_error(result.status);
            return;
        }

        close_after_response_ = request_.close_after_response;
        if (request_.method == method_type::get || request_.method == method_type::head) {
            const auto path_status = prepare_path(request_.target);
            consume_request(result.consumed);
            if (path_status == path_result::too_long) {
                send_error(parse_status::target_too_long);
            } else if (path_status == path_result::invalid) {
                send_error(parse_status::bad_request);
            } else {
                serve_file(request_.method == method_type::head);
            }
        } else {
            consume_request(result.consumed);
            handle_request();
        }
    }
}

auto session::handle_request() -> void
{
    if (request_.method == method_type::options) {
        send_options();
    } else {
        send_response(method_not_allowed);
    }
}

auto session::serve_file(bool headers_only) -> void
{
    file_descriptor_ = openat(root_descriptor_, path_.data(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (file_descriptor_ == -1) {
        send_response(not_found);
        return;
    }

    struct stat info {};
    if (fstat(file_descriptor_, &info) == -1) {
        ::close(file_descriptor_);
        file_descriptor_ = -1;
        send_response(not_found);
        return;
    }
    if (S_ISDIR(info.st_mode)) {
        ::close(file_descriptor_);
        file_descriptor_ = -1;
        const auto length = std::strlen(path_.data());
        constexpr std::string_view index = "/index.html";
        if (length + index.size() >= path_.size()) {
            send_error(parse_status::target_too_long);
            return;
        }
        std::memcpy(path_.data() + length, index.data(), index.size());
        path_[length + index.size()] = '\0';
        file_descriptor_ = openat(
            root_descriptor_, path_.data(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (file_descriptor_ == -1 || fstat(file_descriptor_, &info) == -1 ||
            !S_ISREG(info.st_mode)) {
            if (file_descriptor_ != -1) ::close(file_descriptor_);
            file_descriptor_ = -1;
            send_response(not_found);
            return;
        }
    } else if (!S_ISREG(info.st_mode)) {
        ::close(file_descriptor_);
        file_descriptor_ = -1;
        send_response(not_found);
        return;
    }

    std::array<char, 64> date {};
    std::array<char, 64> modified {};
    const auto now = std::time(nullptr);
    const auto date_size = format_http_time(now, date);
    const auto modified_size = format_http_time(info.st_mtime, modified);
    const auto mime = mime_type_from_path(path_.data());
    const int response_size = std::snprintf(
        response_.data(), response_.size(),
        "HTTP/1.1 200 OK\r\n"
        "Date: %.*s\r\n"
        "Last-Modified: %.*s\r\n"
        "Content-Length: %jd\r\n"
        "Content-Type: %.*s\r\n"
        "Connection: %s\r\n\r\n",
        static_cast<int>(date_size), date.data(),
        static_cast<int>(modified_size), modified.data(),
        static_cast<std::intmax_t>(info.st_size),
        static_cast<int>(mime.size()), mime.data(),
        close_after_response_ ? "close" : "keep-alive");
    if (response_size < 0 || static_cast<std::size_t>(response_size) >= response_.size()) {
        ::close(file_descriptor_);
        file_descriptor_ = -1;
        send_error(parse_status::headers_too_large);
        return;
    }

    if (headers_only) {
        ::close(file_descriptor_);
        file_descriptor_ = -1;
    }
    responding_ = true;
    stream_.write(std::as_bytes(std::span {response_}.first(
        static_cast<std::size_t>(response_size))));
}

auto session::send_options() -> void
{
    send_response(options_response);
}

auto session::send_error(parse_status status) -> void
{
    close_after_response_ = true;
    switch (status) {
    case parse_status::target_too_long:
        send_response(uri_too_long);
        break;
    case parse_status::headers_too_large:
        send_response(headers_too_large);
        break;
    case parse_status::payload_too_large:
        send_response(payload_too_large);
        break;
    case parse_status::unsupported_transfer_encoding:
        send_response(not_implemented);
        break;
    case parse_status::unsupported_version:
        send_response(version_not_supported);
        break;
    default:
        send_response(bad_request);
        break;
    }
}

auto session::send_response(std::string_view response) -> void
{
    responding_ = true;
    stream_.write(std::as_bytes(std::span {response.data(), response.size()}));
}

auto session::pump_file() -> void
{
    while (file_descriptor_ != -1 && !stream_.write_pending()) {
        const auto size = ::read(file_descriptor_, file_buffer_.data(), file_buffer_.size());
        if (size > 0) {
            stream_.write(std::span {file_buffer_}.first(static_cast<std::size_t>(size)));
            continue;
        }
        if (size == -1 && errno == EINTR) {
            continue;
        }
        ::close(file_descriptor_);
        file_descriptor_ = -1;
        if (size == 0) {
            finish_response();
        } else {
            stream_.close();
        }
    }
}

auto session::finish_response() -> void
{
    responding_ = false;
    if (close_after_response_) {
        stream_.close();
        return;
    }
    process_requests();
}

auto session::consume_request(std::size_t size) -> void
{
    const auto remaining = input_size_ - size;
    std::memmove(input_.data(), input_.data() + size, remaining);
    input_size_ = remaining;
}

auto session::prepare_path(std::string_view target) noexcept -> path_result
{
    target = target.substr(0, target.find_first_of("?#"));
    if (target.empty() || target.front() != '/') {
        return path_result::invalid;
    }

    std::size_t output = 0;
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
        if (output + 1 >= path_.size()) return path_result::too_long;
        path_[output++] = value;
    }

    std::string_view decoded {path_.data(), output};
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

    if (output == 0) {
        constexpr std::string_view index = "index.html";
        std::memcpy(path_.data(), index.data(), index.size());
        output = index.size();
    } else if (path_[output - 1] == '/') {
        constexpr std::string_view index = "index.html";
        if (output + index.size() >= path_.size()) return path_result::too_long;
        std::memcpy(path_.data() + output, index.data(), index.size());
        output += index.size();
    }
    path_[output] = '\0';
    return path_result::valid;
}

} // namespace http
