#pragma once

#include "../common.h"
#include "../io/tcp_socket.h"

#include "http_client.h"

#include <memory>

using client_list = std::unordered_set<std::shared_ptr<http_client>>;

class http_server {
    NONCOPYABLE(http_server)

public:
    http_server(uint16_t port, client_list &clients, std::shared_ptr<event_loop> ev);

    auto start() -> void;

private:
    auto on_accept(int peer, std::errc ec) -> void;
    
    tcp_socket socket_;
    client_list &clients_;
};
