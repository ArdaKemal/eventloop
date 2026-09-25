#include "eventloop/tcp_acceptor.h"

#include <cerrno>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
constexpr std::size_t max_accepts_per_event = 64;

[[nodiscard]] auto system_error(const char* operation) -> std::system_error
{
    return {errno, std::system_category(), operation};
}

[[nodiscard]] constexpr auto transient_accept_error(int error) noexcept -> bool
{
    switch (error) {
    case ECONNABORTED:
    case ENETDOWN:
    case EPROTO:
    case ENOPROTOOPT:
    case EHOSTDOWN:
    case ENONET:
    case EHOSTUNREACH:
    case EOPNOTSUPP:
    case ENETUNREACH:
        return true;
    default:
        return false;
    }
}
} // namespace

tcp_acceptor::tcp_acceptor(event_loop& loop, std::uint16_t port,
                           std::string_view address, bool reuse_port)
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
        if (reuse_port &&
            setsockopt(descriptor_, SOL_SOCKET, SO_REUSEPORT, &enabled,
                       sizeof(enabled)) == -1) {
            throw system_error("setsockopt(SO_REUSEPORT)");
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
    for (std::size_t attempt = 0; attempt < max_accepts_per_event; ++attempt) {
        unique_fd client(accept4(
            descriptor_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
        if (client) {
            const int enabled = 1;
            if (setsockopt(client.get(), IPPROTO_TCP, TCP_NODELAY, &enabled,
                           sizeof(enabled)) == -1) {
                continue;
            }
            on_accept_owned(std::move(client));
            continue;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        if (transient_accept_error(errno)) {
            continue;
        }
        if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS ||
            errno == ENOMEM) {
            return;
        }
        throw system_error("accept4");
    }
}

auto tcp_acceptor::on_accept_owned(unique_fd descriptor) -> void
{
    on_accept(descriptor.release());
}

auto tcp_acceptor::on_error() -> void
{
    throw std::runtime_error("listening socket failed");
}

auto tcp_acceptor::on_shutdown() -> void
{
    loop_.remove(descriptor_);
}
