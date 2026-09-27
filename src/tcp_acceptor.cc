#include "eventloop/tcp_acceptor.h"

#include <cerrno>
#include <cstddef>
#include <exception>
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

[[nodiscard]] auto code(int error) noexcept -> std::error_code
{
    return {error, std::generic_category()};
}

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

[[nodiscard]] auto accept_one(int listener)
    -> std::expected<unique_fd, std::error_code>
{
    for (std::size_t attempt = 0; attempt < max_accepts_per_event; ++attempt) {
        unique_fd client(::accept4(listener, nullptr, nullptr,
                                   SOCK_NONBLOCK | SOCK_CLOEXEC));
        if (client) {
            const int enabled = 1;
            if (::setsockopt(client.get(), IPPROTO_TCP, TCP_NODELAY, &enabled,
                             sizeof(enabled)) == -1) {
                return std::unexpected(code(errno));
            }
            return client;
        }
        if (errno == EINTR || transient_accept_error(errno)) continue;
        return std::unexpected(code(errno));
    }
    return std::unexpected(code(EAGAIN));
}
} // namespace

tcp_acceptor::tcp_acceptor(event_loop& loop, std::uint16_t port,
                           std::string_view address, bool reuse_port)
    : loop_(loop)
{
    descriptor_.reset(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (!descriptor_) {
        throw system_error("socket");
    }

    const int enabled = 1;
    if (setsockopt(descriptor_.get(), SOL_SOCKET, SO_REUSEADDR, &enabled,
                   sizeof(enabled)) == -1) {
        throw system_error("setsockopt");
    }
    if (reuse_port &&
        setsockopt(descriptor_.get(), SOL_SOCKET, SO_REUSEPORT, &enabled,
                   sizeof(enabled)) == -1) {
        throw system_error("setsockopt(SO_REUSEPORT)");
    }

    sockaddr_in endpoint {};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(port);
    if (address.find('\0') != std::string_view::npos) {
        throw std::invalid_argument("invalid IPv4 address");
    }
    const std::string address_text {address};
    if (inet_pton(AF_INET, address_text.c_str(), &endpoint.sin_addr) != 1) {
        throw std::invalid_argument("invalid IPv4 address");
    }
    if (bind(descriptor_.get(), reinterpret_cast<const sockaddr*>(&endpoint),
             sizeof(endpoint)) == -1) {
        throw system_error("bind");
    }
    if (listen(descriptor_.get(), SOMAXCONN) == -1) {
        throw system_error("listen");
    }
}

tcp_acceptor::~tcp_acceptor()
{
    if (waiter_ != nullptr) std::terminate();
}

auto tcp_acceptor::descriptor() const noexcept -> int
{
    return descriptor_.get();
}

auto tcp_acceptor::owner() noexcept -> event_loop&
{
    return loop_;
}

auto tcp_acceptor::close() -> void
{
    fail_and_close(code(ECANCELED));
}

auto tcp_acceptor::fail_and_close(std::error_code error) -> void
{
    event_loop::handler_call_scope scope(loop_);
    if (closed_) return;
    closed_ = true;
    complete_accept({}, error);
    loop_.remove(descriptor_.get());
}

auto tcp_acceptor::complete_accept(unique_fd descriptor,
                                   std::error_code error) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* waiter = std::exchange(waiter_, nullptr);
    if (waiter == nullptr) return;
    eventloop_detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
    if (!closed_) {
        try {
            loop_.set_io_interest(descriptor_.get(), false, false);
        } catch (...) {
            std::terminate();
        }
    }
    waiter->finish(std::move(descriptor), error);
}

auto tcp_acceptor::on_read() -> void
{
    if (waiter_ == nullptr || closed_) return;
    auto accepted = accept_one(descriptor_.get());
    if (!accepted && accepted.error().value() == EAGAIN) return;
    if (accepted) complete_accept(std::move(*accepted), {});
    else complete_accept({}, accepted.error());
}

auto tcp_acceptor::on_error() -> void
{
    int error = 0;
    socklen_t length = sizeof(error);
    if (::getsockopt(descriptor_.get(), SOL_SOCKET, SO_ERROR, &error,
                     &length) == -1) error = errno;
    if (error == 0) error = ECONNRESET;
    fail_and_close(code(error));
}

auto tcp_acceptor::on_shutdown() -> void
{
    close();
}

tcp_acceptor::accept_awaiter::accept_awaiter(tcp_acceptor& owner) noexcept
    : owner_(owner)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
}

tcp_acceptor::accept_awaiter::~accept_awaiter()
{
    if (owner_.waiter_ == this) std::terminate();
}

auto tcp_acceptor::accept_awaiter::suspend(
    std::coroutine_handle<> handle,
    eventloop_detail::coroutine_cancellation_state& state) -> bool
{
    if (owner_.closed_) {
        result_ = std::unexpected(code(EBADF));
        return false;
    }
    if (owner_.waiter_ != nullptr) {
        result_ = std::unexpected(code(EBUSY));
        return false;
    }
    if (state.requested) {
        result_ = std::unexpected(code(ECANCELED));
        return false;
    }
    auto accepted = accept_one(owner_.descriptor_.get());
    if (accepted) {
        result_ = std::move(*accepted);
        return false;
    }
    if (accepted.error().value() != EAGAIN) {
        result_ = std::unexpected(accepted.error());
        return false;
    }
    continuation_ = handle;
    if (!eventloop_detail::coroutine_frame_access::attach_cancellation(
            state, cancellation_)) {
        result_ = std::unexpected(code(ECANCELED));
        return false;
    }
    owner_.waiter_ = this;
    try {
        owner_.loop_.set_io_interest(owner_.descriptor_.get(), true, false);
    } catch (const std::system_error& error) {
        owner_.waiter_ = nullptr;
        eventloop_detail::coroutine_frame_access::detach_cancellation(
            cancellation_);
        result_ = std::unexpected(error.code());
        return false;
    }
    return true;
}

auto tcp_acceptor::accept_awaiter::cancel(
    eventloop_detail::coroutine_cancellation_node& node) noexcept -> void
{
    auto& self = *static_cast<accept_awaiter*>(node.operation);
    self.owner_.complete_accept({}, code(ECANCELED));
}

auto tcp_acceptor::accept_awaiter::finish(unique_fd descriptor,
                                           std::error_code error) noexcept -> void
{
    if (error) result_ = std::unexpected(error);
    else result_ = std::move(descriptor);
    continuation_.resume();
}

auto tcp_acceptor::accept_awaiter::await_resume() noexcept
    -> std::expected<unique_fd, std::error_code>
{
    return std::move(result_);
}
