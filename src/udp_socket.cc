#include "eventloop/udp_socket.h"
#include "socket_operations.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <exception>
#include <limits>
#include <stdexcept>
#include <utility>

#if defined(__linux__)
#include <netinet/in.h>
#include <sys/socket.h>
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
#endif


namespace eventloop {

namespace {
[[nodiscard]] auto error_code(int result) noexcept -> std::error_code
{
    return {-result, std::generic_category()};
}
} // namespace

udp_socket::udp_socket(event_loop& loop, ip_endpoint endpoint,
                       bool reuse_port)
    : loop_(loop)
{
    descriptor_.reset(detail::socket_operations::create_datagram(endpoint));
    detail::socket_operations::datagram_register(*this);
    detail::socket_operations::prepare_datagram(descriptor_.get(), endpoint,
                                                reuse_port);
}

udp_socket::~udp_socket()
{
    // Removing a socket with an active awaiter would leave a coroutine with a
    // dangling socket reference. Cancel its task before removing the handler.
    if (receive_ != nullptr || send_ != nullptr ||
        detail::socket_operations::datagram_pending(*this))
        std::terminate();
    descriptor_.reset();
    auto* context = std::exchange(lifetime_observer_context_, nullptr);
    const auto observer = std::exchange(lifetime_observer_, nullptr);
    if (observer != nullptr) observer(context);
}

auto udp_socket::set_lifetime_observer(
    void* context, void (*observer)(void*) noexcept) noexcept -> void
{
    if ((context == nullptr) != (observer == nullptr)) std::terminate();
    lifetime_observer_context_ = context;
    lifetime_observer_ = observer;
}

auto udp_socket::descriptor() const noexcept -> native_socket
{
    return descriptor_.get();
}

auto udp_socket::local_endpoint() const -> ip_endpoint
{
    return detail::socket_operations::local_endpoint(descriptor_.get());
}

auto udp_socket::enable_receive_coalescing() noexcept -> void
{
#if defined(__linux__)
    // Opt-in UDP_GRO for the QUIC endpoint only; the public API keeps one
    // datagram per receive. Best-effort: failure keeps single-datagram reads.
    const int enabled = 1;
    (void)::setsockopt(descriptor_.get(), IPPROTO_UDP, UDP_GRO,
                       &enabled, sizeof(enabled));
#endif
}

auto udp_socket::close() -> void
{
    event_loop::handler_call_scope scope(loop_);
    if (closing_) return;
    closing_ = true;
    const bool receive_kernel = receive_ != nullptr &&
        detail::socket_operations::datagram_cancel(*this, receive_->operation_);
    const bool send_kernel = send_ != nullptr &&
        detail::socket_operations::datagram_cancel(*this, send_->operation_);
    if (!receive_kernel && !send_kernel) complete_pending(-ECANCELED);
    else {
        if (!receive_kernel) complete_receive(-ECANCELED);
        if (!send_kernel) complete_send(-ECANCELED);
    }
    detail::socket_operations::datagram_close(*this);
}

auto udp_socket::async_receive_from(std::span<std::byte> buffer) noexcept
    -> receive_awaiter
{
    return {*this, buffer};
}

auto udp_socket::async_send_to(std::span<const std::byte> buffer,
                               ip_endpoint destination) noexcept -> send_awaiter
{
    return {*this, buffer, destination};
}

auto udp_socket::send_batch(std::span<const std::byte> buffer,
                            std::size_t segment_size,
                            ip_endpoint destination) noexcept
    -> std::expected<std::size_t, std::error_code>
{
    if (closing_)
        return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    if (buffer.empty() || segment_size == 0 || segment_size > buffer.size())
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    if (send_ != nullptr)
        return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
#if defined(__linux__)
    if (!gso_disabled_) {
        detail::socket_operation operation {};
        const auto result = detail::socket_operations::start_send_segments(
            descriptor_.get(), buffer.data(), buffer.size(), segment_size,
            destination, operation);
        if (!result.pending && !result.error)
            return static_cast<std::size_t>(result.transferred);
        if (result.pending)
            return std::unexpected(
                std::make_error_code(std::errc::resource_unavailable_try_again));
        const auto value = result.error.value();
        if (value != EINVAL && value != ENOPROTOOPT && value != EOPNOTSUPP)
            return std::unexpected(result.error);
        gso_disabled_ = true;
    }
#endif
    std::size_t total = 0;
    for (std::size_t offset = 0; offset < buffer.size(); offset += segment_size) {
        const auto length = std::min(segment_size, buffer.size() - offset);
        const auto result = detail::socket_operations::try_send_to(
            descriptor_.get(), buffer.data() + offset, length, destination);
        if (result.error) return std::unexpected(result.error);
        if (result.pending)
            return std::unexpected(
                std::make_error_code(std::errc::resource_unavailable_try_again));
        total += result.transferred;
    }
    return total;
}

udp_socket::receive_awaiter::receive_awaiter(
    udp_socket& socket, std::span<std::byte> buffer) noexcept
    : socket_(socket), buffer_(buffer)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
    detail::socket_operations::datagram_bind(*this);
}

auto udp_socket::receive_awaiter::start(
    std::coroutine_handle<> continuation,
    detail::coroutine_cancellation_state& cancellation) noexcept -> bool
{
    if (cancellation.requested || socket_.closing_) {
        result_ = -ECANCELED;
        return false;
    }
    if (socket_.receive_ != nullptr) {
        result_ = -EBUSY;
        return false;
    }
    continuation_ = continuation;
    if (!detail::coroutine_frame_access::attach_cancellation(
            cancellation, cancellation_)) {
        result_ = -ECANCELED;
        return false;
    }
    socket_.receive_ = this;
    const auto result = detail::socket_operations::datagram_receive(socket_, *this);
    if (!result.pending) {
        socket_.receive_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(cancellation_);
        result_ = detail::socket_operations::datagram_result(result);
        source_ = result.source;
        socket_.receive_segment_ = result.segment_size;
        return false;
    }
    detail::socket_operations::datagram_submitted(socket_, operation_);
    bool armed = false;
    try {
        socket_.update_interest();
        armed = true;
    } catch (const std::system_error& error) {
        result_ = -error.code().value();
    } catch (...) {
        result_ = -EIO;
    }
    if (armed) return true;
    socket_.receive_ = nullptr;
    detail::coroutine_frame_access::detach_cancellation(cancellation_);
    return false;
}

auto udp_socket::receive_awaiter::await_resume() const noexcept
    -> std::expected<udp_datagram, std::error_code>
{
    if (result_ < 0) return std::unexpected(error_code(result_));
    return udp_datagram {static_cast<std::size_t>(result_), source_};
}

auto udp_socket::receive_awaiter::cancel(
    detail::coroutine_cancellation_node& node) noexcept -> void
{
    auto& self = *static_cast<receive_awaiter*>(node.operation);
    detail::coroutine_frame_access::detach_cancellation(self.cancellation_);
    if (detail::socket_operations::datagram_cancel(
            self.socket_, self.operation_)) self.socket_.close();
    else self.socket_.complete_receive(-ECANCELED);
}

udp_socket::send_awaiter::send_awaiter(
    udp_socket& socket, std::span<const std::byte> buffer,
    ip_endpoint destination) noexcept
    : socket_(socket), buffer_(buffer), destination_(destination)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
    detail::socket_operations::datagram_bind(*this);
}

auto udp_socket::send_awaiter::start(
    std::coroutine_handle<> continuation,
    detail::coroutine_cancellation_state& cancellation) noexcept -> bool
{
    if (cancellation.requested || socket_.closing_) {
        result_ = -ECANCELED;
        return false;
    }
    if (socket_.send_ != nullptr) {
        result_ = -EBUSY;
        return false;
    }
    continuation_ = continuation;
    if (!detail::coroutine_frame_access::attach_cancellation(
            cancellation, cancellation_)) {
        result_ = -ECANCELED;
        return false;
    }
    socket_.send_ = this;
    const auto result = detail::socket_operations::datagram_send(socket_, *this);
    if (!result.pending) {
        socket_.send_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(cancellation_);
        result_ = detail::socket_operations::datagram_result(result);
        return false;
    }
    detail::socket_operations::datagram_submitted(socket_, operation_);
    bool armed = false;
    try {
        socket_.update_interest();
        armed = true;
    } catch (const std::system_error& error) {
        result_ = -error.code().value();
    } catch (...) {
        result_ = -EIO;
    }
    if (armed) return true;
    socket_.send_ = nullptr;
    detail::coroutine_frame_access::detach_cancellation(cancellation_);
    return false;
}

auto udp_socket::send_awaiter::await_resume() const noexcept
    -> std::expected<std::size_t, std::error_code>
{
    if (result_ < 0) return std::unexpected(error_code(result_));
    return static_cast<std::size_t>(result_);
}

auto udp_socket::send_awaiter::cancel(
    detail::coroutine_cancellation_node& node) noexcept -> void
{
    auto& self = *static_cast<send_awaiter*>(node.operation);
    detail::coroutine_frame_access::detach_cancellation(self.cancellation_);
    if (detail::socket_operations::datagram_cancel(
            self.socket_, self.operation_)) self.socket_.close();
    else self.socket_.complete_send(-ECANCELED);
}

auto udp_socket::update_interest() -> void
{
    const bool receive = receive_ != nullptr;
    const bool send = send_ != nullptr;
    if (receive_interest_ == receive && send_interest_ == send) return;
    loop_.set_io_interest(descriptor_.get(), receive, send);
    receive_interest_ = receive;
    send_interest_ = send;
}

// Completions call this after resuming, as tcp_stream does, so a continuation
// that starts the next receive or send keeps its interest armed. The loop
// defers handler removal while a completion runs; closing removes the socket.
auto udp_socket::refresh_interest() noexcept -> void
{
    if (closing_) return;
    try {
        update_interest();
    } catch (...) {
        std::terminate();
    }
}

auto udp_socket::complete_receive(int result, ip_endpoint source,
                                  std::size_t segment) noexcept
    -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* operation = std::exchange(receive_, nullptr);
    if (operation == nullptr) return;
    detail::socket_operations::datagram_retire(*this, operation->operation_);
    detail::coroutine_frame_access::detach_cancellation(
        operation->cancellation_);
    operation->result_ = result;
    operation->source_ = source;
    receive_segment_ = segment;
    const auto continuation = operation->continuation_;
    continuation.resume();
    refresh_interest();
}

auto udp_socket::complete_send(int result) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* operation = std::exchange(send_, nullptr);
    if (operation == nullptr) return;
    detail::socket_operations::datagram_retire(*this, operation->operation_);
    detail::coroutine_frame_access::detach_cancellation(
        operation->cancellation_);
    operation->result_ = result;
    const auto continuation = operation->continuation_;
    continuation.resume();
    refresh_interest();
}

auto udp_socket::complete_pending(int result) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* receiving = std::exchange(receive_, nullptr);
    auto* sending = std::exchange(send_, nullptr);
    if (receiving == nullptr && sending == nullptr) return;
    std::coroutine_handle<> receive_continuation;
    std::coroutine_handle<> send_continuation;
    if (receiving != nullptr) {
        detail::coroutine_frame_access::detach_cancellation(
            receiving->cancellation_);
        receiving->result_ = result;
        receive_continuation = receiving->continuation_;
    }
    if (sending != nullptr) {
        detail::coroutine_frame_access::detach_cancellation(
            sending->cancellation_);
        sending->result_ = result;
        send_continuation = sending->continuation_;
    }
    if (receive_continuation) receive_continuation.resume();
    if (send_continuation) send_continuation.resume();
    refresh_interest();
}

auto udp_socket::on_read() -> void
{
    if (receive_ == nullptr) return;
    const auto result = detail::socket_operations::datagram_receive(*this, *receive_);
    if (!result.pending) complete_receive(
        detail::socket_operations::datagram_result(result), result.source,
        result.segment_size);
}

auto udp_socket::on_write() -> void
{
    if (send_ == nullptr) return;
    const auto result = detail::socket_operations::datagram_send(*this, *send_);
    if (!result.pending) complete_send(
        detail::socket_operations::datagram_result(result));
}

auto udp_socket::on_error() -> void
{
    const auto error = detail::socket_operations::pending_error(
        descriptor_.get(), EIO);
    detail::socket_operations::datagram_error(*this, -error.value());
}

auto udp_socket::on_shutdown() -> void
{
    event_loop::handler_call_scope scope(loop_);
    close();
}

} // namespace eventloop
