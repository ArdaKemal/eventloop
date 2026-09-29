#include "eventloop/udp_socket.h"
#include "ip_endpoint_native.h"
#include "socket_operations.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <exception>
#include <limits>
#include <stdexcept>
#include <utility>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace eventloop {

namespace {
[[nodiscard]] auto numeric_result(const detail::socket_result& result) noexcept
    -> int
{
    if (!result.error) return static_cast<int>(result.transferred);
#ifdef _WIN32
    if (result.error.value() == WSAEMSGSIZE) return -EMSGSIZE;
    if (result.error.value() == ERROR_OPERATION_ABORTED) return -ECANCELED;
    return -EIO;
#else
    return -result.error.value();
#endif
}

[[nodiscard]] auto error_code(int result) noexcept -> std::error_code
{
    return {-result, std::generic_category()};
}
} // namespace

udp_socket::udp_socket(event_loop& loop, ip_endpoint endpoint,
                       bool reuse_port)
    : loop_(loop)
{
    descriptor_.reset(detail::socket_operations::create(
        detail::socket_family(endpoint), SOCK_DGRAM, 0));
    registered_descriptor_ = descriptor_.get();
    detail::socket_operations::prepare_datagram(descriptor_.get(), endpoint,
                                                reuse_port);
}

udp_socket::~udp_socket()
{
    // Removing a socket with an active awaiter would leave a coroutine with a
    // dangling socket reference. Cancel its task before removing the handler.
    if (receive_ != nullptr || send_ != nullptr || pending_operations_ != 0)
        std::terminate();
}

auto udp_socket::descriptor() const noexcept -> native_socket
{
    return descriptor_.get();
}

auto udp_socket::local_endpoint() const -> ip_endpoint
{
    return detail::socket_operations::local_endpoint(descriptor_.get());
}

auto udp_socket::close() -> void
{
    event_loop::handler_call_scope scope(loop_);
    if (closing_) return;
    closing_ = true;
    const bool receive_kernel = receive_ != nullptr &&
                                receive_->operation_.pending_completion;
    const bool send_kernel = send_ != nullptr &&
                             send_->operation_.pending_completion;
    if (receive_kernel) {
        receive_->cancelled_ = true;
        detail::socket_operations::cancel(descriptor_.get(), receive_->operation_);
    }
    if (send_kernel) {
        send_->cancelled_ = true;
        detail::socket_operations::cancel(descriptor_.get(), send_->operation_);
    }
    if (!receive_kernel && !send_kernel) complete_pending(-ECANCELED);
    else {
        if (!receive_kernel) complete_receive(-ECANCELED);
        if (!send_kernel) complete_send(-ECANCELED);
    }
    if (pending_operations_ != 0) descriptor_.reset();
    else loop_.remove(registered_descriptor_);
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

udp_socket::receive_awaiter::receive_awaiter(
    udp_socket& socket, std::span<std::byte> buffer) noexcept
    : socket_(socket), buffer_(buffer)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
    operation_.context = this;
    operation_.complete = [](detail::socket_operation& operation,
                             std::size_t bytes, int error) noexcept {
        auto& self = *static_cast<receive_awaiter*>(operation.context);
        detail::socket_result result;
        result.transferred = bytes;
        if (self.cancelled_ || self.socket_.closing_)
            result.error = std::make_error_code(std::errc::operation_canceled);
        else if (error != 0) result.error = {error, std::system_category()};
        const int value = self.cancelled_ || self.socket_.closing_
                              ? -ECANCELED : numeric_result(result);
        self.socket_.complete_receive(
            value, detail::socket_operations::received_source(operation));
    };
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
    const auto result = detail::socket_operations::start_receive_from(
        socket_.descriptor_.get(), buffer_.data(), buffer_.size(), operation_);
    if (!result.pending) {
        socket_.receive_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(cancellation_);
        result_ = numeric_result(result);
        source_ = result.source;
        return false;
    }
    if (operation_.pending_completion) ++socket_.pending_operations_;
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
    if (self.operation_.pending_completion) self.socket_.close();
    else self.socket_.complete_receive(-ECANCELED);
}

udp_socket::send_awaiter::send_awaiter(
    udp_socket& socket, std::span<const std::byte> buffer,
    ip_endpoint destination) noexcept
    : socket_(socket), buffer_(buffer), destination_(destination)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
    operation_.context = this;
    operation_.complete = [](detail::socket_operation& operation,
                             std::size_t bytes, int error) noexcept {
        auto& self = *static_cast<send_awaiter*>(operation.context);
        detail::socket_result result;
        result.transferred = bytes;
        if (self.cancelled_ || self.socket_.closing_)
            result.error = std::make_error_code(std::errc::operation_canceled);
        else if (error != 0) result.error = {error, std::system_category()};
        self.socket_.complete_send(self.cancelled_ || self.socket_.closing_
                                       ? -ECANCELED : numeric_result(result));
    };
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
    const auto result = detail::socket_operations::start_send_to(
        socket_.descriptor_.get(), buffer_.data(), buffer_.size(),
        destination_, operation_);
    if (!result.pending) {
        socket_.send_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(cancellation_);
        result_ = numeric_result(result);
        return false;
    }
    if (operation_.pending_completion) ++socket_.pending_operations_;
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
    if (self.operation_.pending_completion) self.socket_.close();
    else self.socket_.complete_send(-ECANCELED);
}

auto udp_socket::update_interest() -> void
{
    loop_.set_io_interest(descriptor_.get(), receive_ != nullptr,
                          send_ != nullptr);
}

auto udp_socket::complete_receive(int result, ip_endpoint source) noexcept
    -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* operation = std::exchange(receive_, nullptr);
    if (operation == nullptr) return;
    if (operation->operation_.pending_completion) {
        operation->operation_.pending_completion = false;
        if (pending_operations_ == 0) std::terminate();
        --pending_operations_;
    }
    detail::coroutine_frame_access::detach_cancellation(
        operation->cancellation_);
    operation->result_ = result;
    operation->source_ = source;
    if (closing_ && pending_operations_ == 0)
        loop_.remove(registered_descriptor_);
    try {
        update_interest();
    } catch (...) {
        std::terminate();
    }
    const auto continuation = operation->continuation_;
    continuation.resume();
}

auto udp_socket::complete_send(int result) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* operation = std::exchange(send_, nullptr);
    if (operation == nullptr) return;
    if (operation->operation_.pending_completion) {
        operation->operation_.pending_completion = false;
        if (pending_operations_ == 0) std::terminate();
        --pending_operations_;
    }
    detail::coroutine_frame_access::detach_cancellation(
        operation->cancellation_);
    operation->result_ = result;
    if (closing_ && pending_operations_ == 0)
        loop_.remove(registered_descriptor_);
    try {
        update_interest();
    } catch (...) {
        std::terminate();
    }
    const auto continuation = operation->continuation_;
    continuation.resume();
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
    try {
        update_interest();
    } catch (...) {
        std::terminate();
    }
    if (receive_continuation) receive_continuation.resume();
    if (send_continuation) send_continuation.resume();
}

auto udp_socket::on_read() -> void
{
    if (receive_ == nullptr) return;
    const auto result = detail::socket_operations::start_receive_from(
        descriptor_.get(), receive_->buffer_.data(), receive_->buffer_.size(),
        receive_->operation_);
    if (!result.pending) complete_receive(numeric_result(result), result.source);
}

auto udp_socket::on_write() -> void
{
    if (send_ == nullptr) return;
    const auto result = detail::socket_operations::start_send_to(
        descriptor_.get(), send_->buffer_.data(), send_->buffer_.size(),
        send_->destination_, send_->operation_);
    if (!result.pending) complete_send(numeric_result(result));
}

auto udp_socket::on_error() -> void
{
    const auto error = detail::socket_operations::pending_error(
        descriptor_.get(), EIO);
    complete_pending(-error.value());
}

auto udp_socket::on_shutdown() -> void
{
    event_loop::handler_call_scope scope(loop_);
    close();
}

} // namespace eventloop
