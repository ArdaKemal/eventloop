#include "eventloop/http/session.h"

#include "eventloop/http/mime_types.h"

#include <algorithm>
#include <charconv>
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
constexpr std::string_view forbidden =
    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
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
constexpr std::size_t response_header_capacity = 4096;
constexpr std::size_t chunk_prefix_size = 16;
constexpr std::string_view directory_start =
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>Index</title>"
    "</head><body><h1>Index</h1><ul>\n";
constexpr std::string_view directory_end = "</ul></body></html>\n";

class buffer_writer {
public:
    explicit buffer_writer(std::span<char> buffer) : buffer_(buffer) {}

    auto append(std::string_view value) noexcept -> bool
    {
        if (value.size() > buffer_.size() - size_) return false;
        std::memcpy(buffer_.data() + size_, value.data(), value.size());
        size_ += value.size();
        return true;
    }

    auto append(char value) noexcept -> bool
    {
        if (size_ == buffer_.size()) return false;
        buffer_[size_++] = value;
        return true;
    }

    [[nodiscard]] auto size() const noexcept -> std::size_t { return size_; }

private:
    std::span<char> buffer_;
    std::size_t size_ {0};
};

[[nodiscard]] constexpr auto url_safe(unsigned char value) noexcept -> bool
{
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') || value == '-' || value == '.' ||
           value == '_' || value == '~';
}

auto append_url_encoded(buffer_writer& output, std::string_view value) noexcept -> bool
{
    constexpr char hex[] = "0123456789ABCDEF";
    for (const unsigned char byte : value) {
        if (url_safe(byte)) {
            if (!output.append(static_cast<char>(byte))) return false;
        } else if (!output.append('%') || !output.append(hex[byte >> 4]) ||
                   !output.append(hex[byte & 0x0f])) {
            return false;
        }
    }
    return true;
}

auto append_html_escaped(buffer_writer& output, std::string_view value) noexcept -> bool
{
    for (const char byte : value) {
        std::string_view escaped;
        switch (byte) {
        case '&': escaped = "&amp;"; break;
        case '<': escaped = "&lt;"; break;
        case '>': escaped = "&gt;"; break;
        case '"': escaped = "&quot;"; break;
        case '\'': escaped = "&#39;"; break;
        default:
            if (!output.append(byte)) return false;
            continue;
        }
        if (!output.append(escaped)) return false;
    }
    return true;
}

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

session::session(byte_stream& stream, int root_descriptor,
                 bool directory_listing) noexcept
    : stream_(stream), root_descriptor_(root_descriptor),
      directory_listing_(directory_listing)
{
}

session::~session()
{
    if (file_descriptor_ != -1) {
        ::close(file_descriptor_);
    }
    if (directory_ != nullptr) {
        ::closedir(directory_);
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
    } else if (directory_ != nullptr) {
        pump_directory();
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
    if (directory_ != nullptr) {
        ::closedir(directory_);
        directory_ = nullptr;
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
    file_descriptor_ = open_path();
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
    if (!S_ISDIR(info.st_mode) && !S_ISREG(info.st_mode)) {
        ::close(file_descriptor_);
        file_descriptor_ = -1;
        send_response(not_found);
        return;
    }

    if (S_ISDIR(info.st_mode)) {
        if (url_path_size_ == 0 || url_path_[url_path_size_ - 1] != '/') {
            ::close(file_descriptor_);
            file_descriptor_ = -1;
            send_directory_redirect();
            return;
        }

        const int directory_descriptor = file_descriptor_;
        const int index_descriptor = openat(
            directory_descriptor, "index.html", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat index_info {};
        if (index_descriptor != -1 && fstat(index_descriptor, &index_info) == 0 &&
            S_ISREG(index_info.st_mode)) {
            ::close(directory_descriptor);
            file_descriptor_ = index_descriptor;
            const auto length = std::strlen(path_.data());
            const std::string_view index =
                length != 0 && path_[length - 1] == '/' ? "index.html"
                                                        : "/index.html";
            if (length + index.size() >= path_.size()) {
                ::close(file_descriptor_);
                file_descriptor_ = -1;
                send_error(parse_status::target_too_long);
                return;
            }
            std::memcpy(path_.data() + length, index.data(), index.size());
            path_[length + index.size()] = '\0';
            serve_open_file(index_info, headers_only);
            return;
        }
        if (index_descriptor != -1) ::close(index_descriptor);

        if (!directory_listing_) {
            ::close(directory_descriptor);
            file_descriptor_ = -1;
            send_response(forbidden);
            return;
        }

        directory_ = fdopendir(directory_descriptor);
        if (directory_ == nullptr) {
            ::close(directory_descriptor);
            file_descriptor_ = -1;
            send_response(not_found);
            return;
        }
        file_descriptor_ = -1;
        serve_directory(headers_only);
        return;
    }

    serve_open_file(info, headers_only);
}

auto session::serve_open_file(const struct ::stat& info, bool headers_only) -> void
{
    std::array<char, 64> date {};
    std::array<char, 64> modified {};
    const auto now = std::time(nullptr);
    const auto date_size = format_http_time(now, date);
    const auto modified_size = format_http_time(info.st_mtime, modified);
    const auto mime = mime_type_from_path(path_.data());
    const int response_size = std::snprintf(
        response_.data(), response_header_capacity,
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
    if (response_size < 0 ||
        static_cast<std::size_t>(response_size) >= response_header_capacity) {
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
    const auto header_size = static_cast<std::size_t>(response_size);
    while (file_descriptor_ != -1) {
        const auto size = ::read(file_descriptor_, response_.data() + header_size,
                                 response_.size() - header_size);
        if (size > 0) {
            stream_.write(std::as_bytes(std::span {response_}.first(
                header_size + static_cast<std::size_t>(size))));
            return;
        }
        if (size == -1 && errno == EINTR) {
            continue;
        }
        ::close(file_descriptor_);
        file_descriptor_ = -1;
        if (size == -1) {
            stream_.close();
            return;
        }
    }
    stream_.write(std::as_bytes(std::span {response_}.first(header_size)));
}

auto session::serve_directory(bool headers_only) -> void
{
    std::array<char, 64> date {};
    const auto date_size = format_http_time(std::time(nullptr), date);
    const int response_size = std::snprintf(
        response_.data(), response_header_capacity,
        "HTTP/1.1 200 OK\r\n"
        "Date: %.*s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "%s"
        "Connection: %s\r\n\r\n",
        static_cast<int>(date_size), date.data(),
        headers_only ? "" : "Transfer-Encoding: chunked\r\n",
        close_after_response_ ? "close" : "keep-alive");
    if (response_size < 0 ||
        static_cast<std::size_t>(response_size) >= response_header_capacity) {
        ::closedir(directory_);
        directory_ = nullptr;
        send_error(parse_status::headers_too_large);
        return;
    }

    if (headers_only) {
        ::closedir(directory_);
        directory_ = nullptr;
    } else {
        directory_started_ = false;
    }
    responding_ = true;
    stream_.write(std::as_bytes(std::span {response_}.first(
        static_cast<std::size_t>(response_size))));
}

auto session::pump_directory() -> void
{
    auto payload = std::span {response_}.subspan(
        chunk_prefix_size, response_.size() - chunk_prefix_size - 7);
    buffer_writer output(payload);
    bool finished = false;

    if (!directory_started_) {
        directory_started_ = true;
        (void)output.append(directory_start);
    } else {
        errno = 0;
        dirent* entry = nullptr;
        do {
            entry = readdir(directory_);
        } while (entry != nullptr &&
                 (std::strcmp(entry->d_name, ".") == 0 ||
                  std::strcmp(entry->d_name, "..") == 0));

        if (entry == nullptr) {
            if (errno != 0) {
                ::closedir(directory_);
                directory_ = nullptr;
                stream_.close();
                return;
            }
            (void)output.append(directory_end);
            ::closedir(directory_);
            directory_ = nullptr;
            finished = true;
        } else {
            bool is_directory = entry->d_type == DT_DIR;
            if (entry->d_type == DT_UNKNOWN) {
                struct stat info {};
                is_directory = fstatat(dirfd(directory_), entry->d_name, &info,
                                       AT_SYMLINK_NOFOLLOW) == 0 &&
                               S_ISDIR(info.st_mode);
            }
            const std::string_view name {entry->d_name};
            if (!output.append("<li><a href=\"") ||
                !append_url_encoded(output, name) ||
                (is_directory && !output.append('/')) ||
                !output.append("\">") ||
                !append_html_escaped(output, name) ||
                (is_directory && !output.append('/')) ||
                !output.append("</a></li>\n")) {
                ::closedir(directory_);
                directory_ = nullptr;
                stream_.close();
                return;
            }
        }
    }

    std::array<char, chunk_prefix_size> prefix {};
    const auto [end, error] = std::to_chars(
        prefix.data(), prefix.data() + prefix.size() - 2, output.size(), 16);
    if (error != std::errc {}) {
        stream_.close();
        return;
    }
    *end = '\r';
    *(end + 1) = '\n';
    const auto prefix_size = static_cast<std::size_t>(end + 2 - prefix.data());
    const auto output_start = chunk_prefix_size - prefix_size;
    std::memcpy(response_.data() + output_start, prefix.data(), prefix_size);
    auto output_size = chunk_prefix_size + output.size();
    std::memcpy(response_.data() + output_size, "\r\n", 2);
    output_size += 2;
    if (finished) {
        std::memcpy(response_.data() + output_size, "0\r\n\r\n", 5);
        output_size += 5;
    }
    stream_.write(std::as_bytes(std::span {response_}.subspan(
        output_start, output_size - output_start)));
}

auto session::send_directory_redirect() -> void
{
    const int response_size = std::snprintf(
        response_.data(), response_.size(),
        "HTTP/1.1 308 Permanent Redirect\r\n"
        "Location: %.*s/\r\n"
        "Content-Length: 0\r\n"
        "Connection: %s\r\n\r\n",
        static_cast<int>(url_path_size_), url_path_.data(),
        close_after_response_ ? "close" : "keep-alive");
    if (response_size < 0 ||
        static_cast<std::size_t>(response_size) >= response_.size()) {
        send_error(parse_status::headers_too_large);
        return;
    }
    send_response(std::string_view {
        response_.data(), static_cast<std::size_t>(response_size)});
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
        const auto size = ::read(file_descriptor_, response_.data(), response_.size());
        if (size > 0) {
            stream_.write(std::as_bytes(
                std::span {response_}.first(static_cast<std::size_t>(size))));
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

auto session::open_path() noexcept -> int
{
    const auto length = std::strlen(path_.data());
    std::size_t start = 0;
    int parent = root_descriptor_;
    int owned_parent = -1;

    while (start < length) {
        while (start < length && path_[start] == '/') ++start;
        if (start == length) break;

        auto end = start;
        while (end < length && path_[end] != '/') ++end;
        const char saved = path_[end];
        path_[end] = '\0';
        const int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
                          (end < length ? O_DIRECTORY : 0);
        const int next = openat(parent, path_.data() + start, flags);
        path_[end] = saved;
        if (next == -1) {
            const int error = errno;
            if (owned_parent != -1) ::close(owned_parent);
            errno = error;
            return -1;
        }
        if (owned_parent != -1) ::close(owned_parent);
        owned_parent = next;
        parent = next;
        start = end + 1;
    }

    if (owned_parent != -1) return owned_parent;
    return openat(root_descriptor_, ".", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
}

auto session::prepare_path(std::string_view target) noexcept -> path_result
{
    target = target.substr(0, target.find_first_of("?#"));
    if (target.empty() || target.front() != '/') {
        return path_result::invalid;
    }
    if (target.size() > url_path_.size()) {
        return path_result::too_long;
    }
    std::memcpy(url_path_.data(), target.data(), target.size());
    url_path_size_ = target.size();

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
        path_[output++] = '.';
    }
    path_[output] = '\0';
    return path_result::valid;
}

} // namespace http
