#include "eventloop/tcp_acceptor.h"
#include "ip_endpoint_native.h"
#include "socket_operations.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <system_error>
#include <utility>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace eventloop {

namespace {
#ifndef _WIN32
constexpr std::size_t max_accepts_per_event = 64;
#endif
[[nodiscard]] auto code(int error) noexcept -> std::error_code
{
    return {error, std::generic_category()};
}
#ifndef _WIN32
[[nodiscard]] constexpr auto transient_accept_error(int error) noexcept -> bool
{
    switch (error) {
    case ECONNABORTED: case ENETDOWN: case EPROTO: case ENOPROTOOPT:
    case EHOSTDOWN: case ENONET: case EHOSTUNREACH: case EOPNOTSUPP:
    case ENETUNREACH: return true;
    default: return false;
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
#endif
} // namespace

tcp_acceptor::tcp_acceptor(event_loop& loop, ip_endpoint bind_endpoint,
                           bool reuse_port)
#ifdef _WIN32
    : loop_(loop), family_(detail::socket_family(bind_endpoint))
#else
    : loop_(loop)
#endif
{
    descriptor_.reset(detail::socket_operations::create(
        detail::socket_family(bind_endpoint), SOCK_STREAM, 0));
#ifdef _WIN32
    registered_descriptor_ = descriptor_.get();
#endif
    detail::socket_operations::prepare_listener(descriptor_.get(),
                                                bind_endpoint, reuse_port);
}

tcp_acceptor::~tcp_acceptor()
{
    if (waiter_ != nullptr) std::terminate();
}

auto tcp_acceptor::descriptor() const noexcept -> native_socket
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
#ifdef _WIN32
    if (waiter_ != nullptr && waiter_->operation_.pending_completion) {
        waiter_->cancelled_ = true;
        detail::socket_operations::cancel(descriptor_.get(), waiter_->operation_);
        descriptor_.reset();
        return;
    }
    complete_accept({}, error);
    loop_.remove(registered_descriptor_);
#else
    complete_accept({}, error);
    loop_.remove(descriptor_.get());
#endif
}

auto tcp_acceptor::set_read_interest(bool enabled) -> void
{
    if (read_interest_enabled_ == enabled) return;
    loop_.set_io_interest(descriptor_.get(), enabled, false);
    read_interest_enabled_ = enabled;
}

auto tcp_acceptor::complete_accept(unique_fd descriptor,
                                   std::error_code error) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* waiter = std::exchange(waiter_, nullptr);
    if (waiter == nullptr) return;
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
#ifdef _WIN32
    if (closed_) loop_.remove(registered_descriptor_);
#endif
    waiter->finish(std::move(descriptor), error);
    if (!closed_) {
        try {
            // Resumption may immediately wait for another connection. Keep
            // the listener armed in that case and avoid a disable/re-enable
            // pair on every accepted connection.
            set_read_interest(waiter_ != nullptr);
        } catch (...) {
            std::terminate();
        }
    }
}

auto tcp_acceptor::on_read() -> void
{
    if (waiter_ == nullptr || closed_) return;
#ifdef _WIN32
    auto result = detail::socket_operations::start_accept(
        descriptor_.get(), family_, waiter_->accept_addresses_,
        waiter_->operation_);
    if (result.pending) return;
    complete_accept(unique_fd(result.accepted), result.error);
#else
    auto accepted = accept_one(descriptor_.get());
    if (!accepted && accepted.error().value() == EAGAIN) return;
    if (accepted) complete_accept(std::move(*accepted), {});
    else complete_accept({}, accepted.error());
#endif
}

auto tcp_acceptor::on_error() -> void
{
#ifdef _WIN32
    fail_and_close(detail::socket_operations::pending_error(
        descriptor_.get(), ECONNRESET));
#else
    int error = 0;
    socklen_t length = sizeof(error);
    if (::getsockopt(descriptor_.get(), SOL_SOCKET, SO_ERROR, &error,
                     &length) == -1) error = errno;
    if (error == 0) error = ECONNRESET;
    fail_and_close(code(error));
#endif
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
#ifdef _WIN32
    operation_.context = this;
    operation_.complete = [](detail::socket_operation& operation,
                             std::size_t, int error) noexcept {
        auto& self = *static_cast<accept_awaiter*>(operation.context);
        std::error_code result;
        if (self.cancelled_ || self.owner_.closed_)
            result = code(ECANCELED);
        else if (error != 0)
            result = {error, std::system_category()};
        else
            result = detail::socket_operations::finish_accept(
                self.owner_.descriptor_.get(), self.accepted_.get());
        unique_fd accepted = std::move(self.accepted_);
        if (result) accepted.reset();
        self.owner_.complete_accept(std::move(accepted), result);
    };
#endif
}

tcp_acceptor::accept_awaiter::~accept_awaiter()
{
    if (owner_.waiter_ == this) std::terminate();
}

auto tcp_acceptor::accept_awaiter::suspend(
    std::coroutine_handle<> handle,
    detail::coroutine_cancellation_state& state) -> bool
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
#ifndef _WIN32
    auto accepted = accept_one(owner_.descriptor_.get());
    if (accepted) {
        result_ = std::move(*accepted);
        return false;
    }
    if (accepted.error().value() != EAGAIN) {
        result_ = std::unexpected(accepted.error());
        return false;
    }
#endif
    continuation_ = handle;
    if (!detail::coroutine_frame_access::attach_cancellation(
            state, cancellation_)) {
        result_ = std::unexpected(code(ECANCELED));
        return false;
    }
    owner_.waiter_ = this;
#ifdef _WIN32
    const auto result = detail::socket_operations::start_accept(
        owner_.descriptor_.get(), owner_.family_, accept_addresses_, operation_);
    if (!result.pending) {
        owner_.waiter_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(cancellation_);
        if (result.error) result_ = std::unexpected(result.error);
        else result_ = unique_fd(result.accepted);
        return false;
    }
    if (result.accepted != static_cast<native_socket>(-1))
        accepted_.reset(result.accepted);
#endif
    try {
        owner_.set_read_interest(true);
    } catch (const std::system_error& error) {
        owner_.waiter_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(
            cancellation_);
        result_ = std::unexpected(error.code());
        return false;
    }
    return true;
}

auto tcp_acceptor::accept_awaiter::cancel(
    detail::coroutine_cancellation_node& node) noexcept -> void
{
    auto& self = *static_cast<accept_awaiter*>(node.operation);
#ifdef _WIN32
    detail::coroutine_frame_access::detach_cancellation(self.cancellation_);
    if (self.operation_.pending_completion) self.owner_.close();
    else self.owner_.complete_accept({}, code(ECANCELED));
#else
    self.owner_.complete_accept({}, code(ECANCELED));
#endif
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

} // namespace eventloop
