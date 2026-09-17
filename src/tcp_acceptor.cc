#include "eventloop/tcp_acceptor.h"

#include <cerrno>
#include <stdexcept>
#include <string>
#include <system_error>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
[[nodiscard]] auto system_error(const char* operation) -> std::system_error
{
    return {errno, std::system_category(), operation};
}
} // namespace

tcp_acceptor::tcp_acceptor(event_loop& loop, std::uint16_t port,
                           std::string_view address)
    : loop_(loop)
{
    descriptor_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (descriptor_ == -1) {
        throw system_error("socket");
    }

    try {
        const int enabled = 1;
        if (setsockopt(descriptor_, SOL_SOCKET, SO_REUSEADDR, &enabled,
                       sizeof(enabled)) == -1) {
            throw system_error("setsockopt");
        }

        sockaddr_in endpoint {};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons(port);
        const std::string address_text {address};
        if (inet_pton(AF_INET, address_text.c_str(), &endpoint.sin_addr) != 1) {
            throw std::invalid_argument("invalid IPv4 address");
        }
        if (bind(descriptor_, reinterpret_cast<const sockaddr*>(&endpoint),
                 sizeof(endpoint)) == -1) {
            throw system_error("bind");
        }
        if (listen(descriptor_, SOMAXCONN) == -1) {
            throw system_error("listen");
        }
    } catch (...) {
        ::close(descriptor_);
        throw;
    }
}

tcp_acceptor::~tcp_acceptor()
{
    ::close(descriptor_);
}

auto tcp_acceptor::descriptor() const noexcept -> int
{
    return descriptor_;
}

auto tcp_acceptor::owner() noexcept -> event_loop&
{
    return loop_;
}

auto tcp_acceptor::on_read() -> void
{
    for (;;) {
        const int client = accept4(
            descriptor_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client >= 0) {
            on_accept(client);
            continue;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        throw system_error("accept4");
    }
}

auto tcp_acceptor::on_error() -> void
{
    throw std::runtime_error("listening socket failed");
}
