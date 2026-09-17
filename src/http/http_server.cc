#include "http_server.h"

#include <stdexcept>

http_server::http_server(uint16_t port,
                         client_list &clients,
                         std::shared_ptr<event_loop> ev)
    : socket_(-1, ev)
    , clients_(clients)
{
    if (socket_.bind(port) != std::errc())
        throw std::runtime_error("bind");
}

auto http_server::start() -> void
{
    socket_.async_accept(
        std::bind_front(&http_server::on_accept, this));
}

auto http_server::on_accept(int peer, std::errc ec) -> void
{
    if (ec == std::errc()) {
        socket_utils::set_nodelay(peer);
        socket_utils::set_nonblocking(peer);

        tcp_socket socket{ peer, socket_.ev() };

        auto client =
            std::make_shared<http_client>(std::move(socket), clients_);

        client->start();

        clients_.insert(std::move(client));
    }

    start();
}
