#pragma once

#include "http_parser.h"
#include "route_manager.h"
#include "../io/tcp_socket.h"

#include <array>
#include <memory>
#include <unordered_set>

#include <sys/stat.h>

class http_client
    : public std::enable_shared_from_this<http_client>
{
public:
    using client_list = std::unordered_set<std::shared_ptr<http_client>>;

    http_client(tcp_socket &&socket, client_list &parent)
        : socket_(std::move(socket)), parent_(parent)
    {}

    http_client(http_client&) = delete;
    http_client(const http_client&) = delete;

    auto start() -> void;

    static auto set_root_path(const std::string &path) -> void;

    static auto set_route_manager(
            std::shared_ptr<route_manager> routes) -> void;

private:
    enum class connection_state {
        waiting,
        waiting_body,
    };

    auto handle_request(std::size_t bytes_received) -> void;

    auto serve_file(const struct stat &info) -> void;
    auto serve_file_size(std::size_t size) -> void;
    auto serve_directory() -> void;

    auto on_read(std::size_t bytes_received, std::errc ec) -> void;
    auto on_write(std::size_t bytes_received, std::errc ec) -> void;

    tcp_socket socket_;
    client_list &parent_;
    connection_state state_ { connection_state::waiting };

    std::array<char, 1024> in_buffer_;
    std::array<char, 1024> out_buffer_;
    std::array<char, 3072> path_buffer_;

    std::string body_buffer_;
    std::optional<http_request> request_;

    static std::string ROOT_PATH;
    static std::shared_ptr<route_manager> ROUTES;
};
