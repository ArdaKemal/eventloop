#include "http_client.h"

#include "mime_types.h"

#include <ctime>
#include <cstdio>
#include <string>
#include <sstream>
#include <charconv>
#include <algorithm>

#include <dirent.h>

std::string http_client::ROOT_PATH = {};
std::shared_ptr<route_manager> http_client::ROUTES = {};

static const std::string_view BAD_REQUEST =
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";

static const std::string_view NOT_FOUND =
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

static const std::string_view URI_TOO_LONG =
    "HTTP/1.1 414 URI Too Long\r\nContent-Length: 0\r\n\r\n";

static const std::string_view NOT_IMPLEMENTED =
    "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n";

auto http_client::set_root_path(const std::string &path) -> void
{
    ROOT_PATH = path;
}

auto http_client::set_route_manager(std::shared_ptr<route_manager> routes)
    -> void
{
    ROUTES = routes;
}

auto http_client::start() -> void
{
    socket_.async_read(in_buffer_,
        std::bind_front(&http_client::on_read, this));
}

auto http_client::serve_file(const struct stat &info) -> void
{
    static thread_local std::array<char, 128> time_buffer;

    const std::size_t time_len = std::strftime(
        time_buffer.data(), time_buffer.size(),
        "%a, %e %b %Y %T %Z", std::gmtime(&info.st_mtime));

    const long buffer_size = std::snprintf(
        out_buffer_.data(), out_buffer_.size(),
        "HTTP/1.1 200 OK\r\n"
        "Connection: Keep-Alive\r\n"
        "Last-Modified: %.*s\n"
        "Content-Length: %zu\r\n"
        "Content-Type: %s\r\n\r\n",
        static_cast<int>(time_len), time_buffer.data(),
        static_cast<std::size_t>(info.st_size),
        mime_type_from_path(request_->uri).data());

    std::string_view buffer{
        out_buffer_.begin(), out_buffer_.begin() + buffer_size };

    socket_.async_write(buffer, true,
        std::bind_front(&http_client::on_write, this));

    socket_.async_sendfile(path_buffer_.data(),
        static_cast<std::size_t>(info.st_size),
        std::bind_front(&http_client::on_write, this));
}

auto http_client::serve_file_size(std::size_t size) -> void
{
    const long buffer_size = std::snprintf(
        out_buffer_.data(), out_buffer_.size(),
        "HTTP/1.1 200 OK\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Length: %zu\r\n"
        "Content-Type: %s\r\n\r\n",
        size, mime_type_from_path(request_->uri).data());

    std::string_view buffer{
        out_buffer_.begin(), out_buffer_.begin() + buffer_size };

    socket_.async_write(buffer, std::bind_front(&http_client::on_write, this));
}

auto http_client::serve_directory() -> void
{
    const auto last_modified = [](const std::time_t *time) {
        std::string str = std::asctime(std::localtime(time));
        str.pop_back();
        return str;
    };

    std::ostringstream html;
    html
        << "<!DOCKTYPE html><head><title>Index</title></head><body>"sv
        << "<h1>Index of "sv << request_->uri << "</h1><hr><pre>"sv;

    std::string path = ROOT_PATH;
    path += request_->uri;

    DIR *dir = opendir(path.c_str());

    struct stat64 s;
    dirent64 *entry;

    std::string entry_path;
    entry_path.reserve(PATH_MAX);

    while ((entry = readdir64(dir))) {
        entry_path += path;
        entry_path += entry->d_name;

        html
            << "<a href="sv << request_->uri << '/' << entry->d_name << '>'
            << entry->d_name << "</a>\t\t\t\t\t\t\t\t"sv
            << last_modified(static_cast<const std::time_t*>(&s.st_mtime));

        if (entry->d_type == DT_REG)
            html << "\t\t\t\t"sv << s.st_size << "\n";
        else
            html << "\t\t\t\t-\n"sv;

        entry_path.clear();
    }
    html << "</pre><hr></body></html>"sv;

    closedir(dir);

    body_buffer_ = html.str();

    const long buffer_size = std::snprintf(
            std::data(out_buffer_), std::size(out_buffer_),
            "HTTP/1.1 200 OK\r\nContent-Length:%zu\r\n"
            "Content-Type: text/html\r\n\r\n", body_buffer_.size());

    std::string_view buffer{
        out_buffer_.begin(), out_buffer_.begin() + buffer_size };

    socket_.async_write(buffer, true,
        std::bind_front(&http_client::on_write, this));

    socket_.async_write(body_buffer_,
        std::bind_front(&http_client::on_write, this));
}

auto http_client::handle_request(std::size_t bytes_received) -> void
{
    request_ = http_parse_request({ in_buffer_.data(), bytes_received });
    if (!request_) {
        socket_.async_write(BAD_REQUEST,
            std::bind_front(&http_client::on_write, this));
        return;
    }

    if ((ROOT_PATH.size() + request_->uri.size()) >= path_buffer_.size()) {
        socket_.async_write(URI_TOO_LONG,
            std::bind_front(&http_client::on_write, this));
        return;
    }

    std::copy(ROOT_PATH.begin(), ROOT_PATH.end(), path_buffer_.begin());
    std::copy(request_->uri.begin(), request_->uri.end(),
        path_buffer_.begin() + ROOT_PATH.size());
    path_buffer_.at(ROOT_PATH.size() + request_->uri.size()) = '\0';

    struct stat info {};
    const bool found = ::stat(path_buffer_.data(), &info) == 0;

    switch (request_->method) {
        case http_method_t::GET:
            if (!found) {
                socket_.async_write(NOT_FOUND,
                    std::bind_front(&http_client::on_write, this));

                break;
            }

            if (S_ISREG(info.st_mode)) {
                serve_file(info);
            }
            else if (S_ISDIR(info.st_mode)) {
                serve_directory();
            }
            else {
                socket_.async_write(NOT_FOUND,
                    std::bind_front(&http_client::on_write, this));
            }

            break;
        case http_method_t::HEAD:
            if (!found || !S_ISREG(info.st_mode)) {
                socket_.async_write(NOT_FOUND,
                    std::bind_front(&http_client::on_write, this));
            }
            else {
                serve_file_size(static_cast<std::size_t>(info.st_size));
            }

            break;
        default:
            socket_.async_write(NOT_IMPLEMENTED,
                std::bind_front(&http_client::on_write, this));
            break;
    }
}

auto http_client::on_read(std::size_t bytes_received, std::errc ec) -> void
{
    if (bytes_received == 0 || ec != std::errc()) {
        parent_.erase(shared_from_this());
        return;
    }

    handle_request(bytes_received);
}

auto http_client::on_write(std::size_t, std::errc ec) -> void
{
    if (ec != std::errc()) {
        parent_.erase(shared_from_this());
        return;
    }

    start();
}
