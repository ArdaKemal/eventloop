#include "eventloop/udp_socket.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <exception>
#include <limits>
#include <stdexcept>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace {
[[nodiscard]] auto system_error(const char* operation) -> std::system_error
{
    return {errno, std::system_category(), operation};
}

[[nodiscard]] auto native_endpoint(udp_endpoint endpoint) noexcept -> sockaddr_in
{
    sockaddr_in native {};
    native.sin_family = AF_INET;
    native.sin_port = htons(endpoint.port);
    std::memcpy(&native.sin_addr, endpoint.address.data(),
                endpoint.address.size());
    return native;
}

[[nodiscard]] auto public_endpoint(const sockaddr_in& native) noexcept
    -> udp_endpoint
{
    udp_endpoint endpoint;
    std::memcpy(endpoint.address.data(), &native.sin_addr,
                endpoint.address.size());
    endpoint.port = ntohs(native.sin_port);
    return endpoint;
}

[[nodiscard]] auto retryable(int error) noexcept -> bool
{
    return error == EAGAIN || error == EWOULDBLOCK;
}

[[nodiscard]] auto try_receive(int descriptor, std::span<std::byte> buffer,
                               udp_endpoint& source) noexcept -> int
{
    if (buffer.size() > static_cast<std::size_t>(
                            std::numeric_limits<int>::max())) {
        return -EINVAL;
    }
    sockaddr_in native_source {};
    iovec iov {.iov_base = buffer.data(), .iov_len = buffer.size()};
    msghdr message {};
    message.msg_name = &native_source;
    message.msg_namelen = sizeof(native_source);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    for (;;) {
        const auto received = ::recvmsg(descriptor, &message, MSG_TRUNC);
        if (received >= 0) {
            if ((message.msg_flags & MSG_TRUNC) != 0 ||
                static_cast<std::size_t>(received) > buffer.size()) {
                return -EMSGSIZE;
            }
            source = public_endpoint(native_source);
            return static_cast<int>(received);
        }
        if (errno != EINTR) return -errno;
    }
}

[[nodiscard]] auto try_send(int descriptor, std::span<const std::byte> buffer,
                            udp_endpoint destination) noexcept -> int
{
    if (buffer.size() > 65507) return -EMSGSIZE;
    const auto native_destination = native_endpoint(destination);
    for (;;) {
        const auto sent = ::sendto(descriptor, buffer.data(), buffer.size(),
                                   MSG_NOSIGNAL,
                                   reinterpret_cast<const sockaddr*>(
                                       &native_destination),
                                   sizeof(native_destination));
        if (sent >= 0) return static_cast<int>(sent);
        if (errno != EINTR) return -errno;
    }
}

[[nodiscard]] auto error_code(int result) noexcept -> std::error_code
{
    return {-result, std::generic_category()};
}
} // namespace

udp_socket::udp_socket(event_loop& loop, std::uint16_t port,
                       std::string_view address, bool reuse_port)
    : loop_(loop)
{
    descriptor_.reset(::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                               0));
    if (!descriptor_) throw system_error("socket");

    const int enabled = 1;
    if (::setsockopt(descriptor_.get(), SOL_SOCKET, SO_REUSEADDR, &enabled,
                     sizeof(enabled)) == -1) {
        throw system_error("setsockopt(SO_REUSEADDR)");
    }
    if (reuse_port &&
        ::setsockopt(descriptor_.get(), SOL_SOCKET, SO_REUSEPORT, &enabled,
                     sizeof(enabled)) == -1) {
        throw system_error("setsockopt(SO_REUSEPORT)");
    }
    if (address.empty() || address.size() >= INET_ADDRSTRLEN ||
        address.find('\0') != std::string_view::npos) {
        throw std::invalid_argument("invalid IPv4 address");
    }
    std::array<char, INET_ADDRSTRLEN> address_text {};
    std::memcpy(address_text.data(), address.data(), address.size());
    sockaddr_in native {};
    native.sin_family = AF_INET;
    native.sin_port = htons(port);
    if (::inet_pton(AF_INET, address_text.data(), &native.sin_addr) != 1) {
        throw std::invalid_argument("invalid IPv4 address");
    }
    if (::bind(descriptor_.get(), reinterpret_cast<const sockaddr*>(&native),
               sizeof(native)) == -1) {
        throw system_error("bind");
    }
}

udp_socket::~udp_socket()
{
    // Removing a socket with an active awaiter would leave a coroutine with a
    // dangling socket reference. Cancel its task before removing the handler.
    if (receive_ != nullptr || send_ != nullptr) std::terminate();
}

auto udp_socket::descriptor() const noexcept -> int
{
    return descriptor_.get();
}

auto udp_socket::local_endpoint() const -> udp_endpoint
{
    sockaddr_in native {};
    socklen_t length = sizeof(native);
    if (::getsockname(descriptor_.get(), reinterpret_cast<sockaddr*>(&native),
                      &length) == -1) {
        throw system_error("getsockname");
    }
    return public_endpoint(native);
}

auto udp_socket::close() -> void
{
    event_loop::handler_call_scope scope(loop_);
    if (closing_) return;
    closing_ = true;
    complete_pending(-ECANCELED);
    loop_.remove(descriptor_.get());
}

auto udp_socket::async_receive_from(std::span<std::byte> buffer) noexcept
    -> receive_awaiter
{
    return {*this, buffer};
}

auto udp_socket::async_send_to(std::span<const std::byte> buffer,
                               udp_endpoint destination) noexcept -> send_awaiter
{
    return {*this, buffer, destination};
}

udp_socket::receive_awaiter::receive_awaiter(
    udp_socket& socket, std::span<std::byte> buffer) noexcept
    : socket_(socket), buffer_(buffer)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
}

auto udp_socket::receive_awaiter::start(
    std::coroutine_handle<> continuation,
    eventloop_detail::coroutine_cancellation_state& cancellation) noexcept -> bool
{
    if (cancellation.requested || socket_.closing_) {
        result_ = -ECANCELED;
        return false;
    }
    if (socket_.receive_ != nullptr) {
        result_ = -EBUSY;
        return false;
    }
    result_ = try_receive(socket_.descriptor_.get(), buffer_, source_);
    if (!retryable(-result_)) return false;

    continuation_ = continuation;
    if (!eventloop_detail::coroutine_frame_access::attach_cancellation(
            cancellation, cancellation_)) {
        result_ = -ECANCELED;
        return false;
    }
    socket_.receive_ = this;
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
    eventloop_detail::coroutine_frame_access::detach_cancellation(cancellation_);
    return false;
}

auto udp_socket::receive_awaiter::await_resume() const noexcept
    -> std::expected<udp_datagram, std::error_code>
{
    if (result_ < 0) return std::unexpected(error_code(result_));
    return udp_datagram {static_cast<std::size_t>(result_), source_};
}

auto udp_socket::receive_awaiter::cancel(
    eventloop_detail::coroutine_cancellation_node& node) noexcept -> void
{
    auto& self = *static_cast<receive_awaiter*>(node.operation);
    self.socket_.complete_receive(-ECANCELED);
}

udp_socket::send_awaiter::send_awaiter(
    udp_socket& socket, std::span<const std::byte> buffer,
    udp_endpoint destination) noexcept
    : socket_(socket), buffer_(buffer), destination_(destination)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
}

auto udp_socket::send_awaiter::start(
    std::coroutine_handle<> continuation,
    eventloop_detail::coroutine_cancellation_state& cancellation) noexcept -> bool
{
    if (cancellation.requested || socket_.closing_) {
        result_ = -ECANCELED;
        return false;
    }
    if (socket_.send_ != nullptr) {
        result_ = -EBUSY;
        return false;
    }
    result_ = try_send(socket_.descriptor_.get(), buffer_, destination_);
    if (!retryable(-result_)) return false;

    continuation_ = continuation;
    if (!eventloop_detail::coroutine_frame_access::attach_cancellation(
            cancellation, cancellation_)) {
        result_ = -ECANCELED;
        return false;
    }
    socket_.send_ = this;
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
    eventloop_detail::coroutine_frame_access::detach_cancellation(cancellation_);
    return false;
}

auto udp_socket::send_awaiter::await_resume() const noexcept
    -> std::expected<std::size_t, std::error_code>
{
    if (result_ < 0) return std::unexpected(error_code(result_));
    return static_cast<std::size_t>(result_);
}

auto udp_socket::send_awaiter::cancel(
    eventloop_detail::coroutine_cancellation_node& node) noexcept -> void
{
    auto& self = *static_cast<send_awaiter*>(node.operation);
    self.socket_.complete_send(-ECANCELED);
}

auto udp_socket::update_interest() -> void
{
    loop_.set_io_interest(descriptor_.get(), receive_ != nullptr,
                          send_ != nullptr);
}

auto udp_socket::complete_receive(int result, udp_endpoint source) noexcept
    -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* operation = std::exchange(receive_, nullptr);
    if (operation == nullptr) return;
    eventloop_detail::coroutine_frame_access::detach_cancellation(
        operation->cancellation_);
    operation->result_ = result;
    operation->source_ = source;
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
    eventloop_detail::coroutine_frame_access::detach_cancellation(
        operation->cancellation_);
    operation->result_ = result;
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
        eventloop_detail::coroutine_frame_access::detach_cancellation(
            receiving->cancellation_);
        receiving->result_ = result;
        receive_continuation = receiving->continuation_;
    }
    if (sending != nullptr) {
        eventloop_detail::coroutine_frame_access::detach_cancellation(
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
    udp_endpoint source;
    const int result = try_receive(descriptor_.get(), receive_->buffer_, source);
    if (!retryable(-result)) complete_receive(result, source);
}

auto udp_socket::on_write() -> void
{
    if (send_ == nullptr) return;
    const int result = try_send(descriptor_.get(), send_->buffer_,
                                send_->destination_);
    if (!retryable(-result)) complete_send(result);
}

auto udp_socket::on_error() -> void
{
    int error = 0;
    socklen_t length = sizeof(error);
    if (::getsockopt(descriptor_.get(), SOL_SOCKET, SO_ERROR, &error,
                     &length) == -1) {
        error = errno;
    }
    if (error == 0) error = EIO;
    complete_pending(-error);
}

auto udp_socket::on_shutdown() -> void
{
    event_loop::handler_call_scope scope(loop_);
    close();
}
