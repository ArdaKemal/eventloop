#include "eventloop/tcp_stream.h"
#include "eventloop/task.h"
#include "ip_endpoint_native.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

#include <sys/sendfile.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace eventloop {

namespace {
[[nodiscard]] auto code(int error) noexcept -> std::error_code
{
    return {error, std::generic_category()};
}

[[nodiscard]] auto transfer(int descriptor, void* buffer, std::size_t size,
                            bool read) noexcept
    -> std::expected<std::size_t, std::error_code>
{
    if (size == 0) return 0;
    if (buffer == nullptr ||
        size > static_cast<std::size_t>(std::numeric_limits<ssize_t>::max())) {
        return std::unexpected(code(EINVAL));
    }
    for (;;) {
        const auto result = read
            ? ::recv(descriptor, buffer, size, 0)
            : ::send(descriptor, buffer, size, MSG_NOSIGNAL);
        if (result >= 0) return static_cast<std::size_t>(result);
        if (errno == EINTR) continue;
        return std::unexpected(code(errno));
    }
}

} // namespace

tcp_stream::tcp_stream(event_loop& loop, unique_fd descriptor)
    : loop_(loop), descriptor_(std::move(descriptor))
{
    if (!descriptor_) {
        throw std::invalid_argument("TCP stream descriptor is invalid");
    }
}

tcp_stream::tcp_stream(event_loop& loop, ip_endpoint remote)
    : loop_(loop), remote_(remote), connected_(false),
      transport_activated_(true)
{
    descriptor_.reset(::socket(detail::socket_family(remote),
                               SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (!descriptor_) {
        throw std::system_error(errno, std::system_category(), "socket");
    }
    if (detail::set_ipv6_only(descriptor_.get(), remote) == -1) {
        throw std::system_error(errno, std::system_category(),
                                "setsockopt(IPV6_V6ONLY)");
    }
}

tcp_stream::~tcp_stream()
{
    if (connector_ != nullptr || reader_ != nullptr || writer_ != nullptr ||
        file_writer_ != nullptr) {
        std::terminate();
    }
}

auto tcp_stream::descriptor() const noexcept -> int
{
    return descriptor_.get();
}

auto tcp_stream::activate_async_transport() noexcept
    -> std::expected<void, std::error_code>
{
    if (transport_activated_) return {};
    if (closed_) return std::unexpected(code(EBADF));
    if (!connected_) return std::unexpected(code(ENOTCONN));
    const int flags = ::fcntl(descriptor_.get(), F_GETFL);
    if (flags == -1 || ::fcntl(descriptor_.get(), F_SETFL,
                               flags | O_NONBLOCK) == -1) {
        return std::unexpected(code(errno));
    }
    try {
        set_async_interest(false, false);
    } catch (const std::system_error& error) {
        return std::unexpected(error.code());
    }
    transport_activated_ = true;
    return {};
}

auto tcp_stream::close() -> void
{
    fail_and_close(code(ECANCELED));
}

auto tcp_stream::on_read() -> void
{
    if (reader_ == nullptr || closed_) return;
    auto result = transfer(descriptor_.get(), reader_->data_, reader_->size_, true);
    if (!result && result.error().value() == EAGAIN) return;
    if (result) complete_read(*result, {});
    else complete_read(0, result.error());
}

auto tcp_stream::on_write() -> void
{
    if (connector_ != nullptr && !closed_) {
        int error = 0;
        socklen_t length = sizeof(error);
        if (::getsockopt(descriptor_.get(), SOL_SOCKET, SO_ERROR, &error,
                         &length) == -1) error = errno;
        if (error != 0) fail_and_close(code(error));
        else {
            connected_ = true;
            complete_connect({});
        }
        return;
    }
    if (file_writer_ != nullptr && !closed_) {
        const auto error = file_writer_->advance();
        if (error.value() == EAGAIN) return;
        complete_file(error);
        return;
    }
    if (writer_ == nullptr || closed_) return;
    auto result = transfer(descriptor_.get(), writer_->data_, writer_->size_, false);
    if (!result && result.error().value() == EAGAIN) return;
    if (result) complete_write(*result, {});
    else complete_write(0, result.error());
}

auto tcp_stream::on_error() -> void
{
    int error = 0;
    socklen_t size = sizeof(error);
    if (getsockopt(descriptor_.get(), SOL_SOCKET, SO_ERROR, &error, &size) == -1) {
        error = errno;
    } else if (error == 0) {
        error = ECONNRESET;
    }
    fail_and_close(code(error));
}

auto tcp_stream::on_shutdown() -> void
{
    close();
}

auto tcp_stream::fail_and_close(std::error_code error) -> void
{
    event_loop::handler_call_scope scope(loop_);
    if (closed_) return;
    closed_ = true;
    complete_connect(error);
    complete_read(0, error);
    complete_write(0, error);
    complete_file(error);
    loop_.remove(descriptor_.get());
}

auto tcp_stream::set_async_interest(bool read_enabled,
                                    bool write_enabled) -> void
{
    if (read_interest_enabled_ == read_enabled &&
        write_interest_enabled_ == write_enabled) return;
    loop_.set_io_interest(descriptor_.get(), read_enabled, write_enabled);
    read_interest_enabled_ = read_enabled;
    write_interest_enabled_ = write_enabled;
}

auto tcp_stream::update_async_interest() noexcept -> void
{
    if (!closed_) {
        try {
            set_async_interest(reader_ != nullptr,
                connector_ != nullptr || writer_ != nullptr ||
                    file_writer_ != nullptr);
        } catch (...) {
            std::terminate();
        }
    }
}

auto tcp_stream::complete_connect(std::error_code error) noexcept
    -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* waiter = std::exchange(connector_, nullptr);
    if (waiter == nullptr) return;
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
    update_async_interest();
    waiter->finish(error);
}

auto tcp_stream::complete_read(std::size_t size,
                                          std::error_code error) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* waiter = std::exchange(reader_, nullptr);
    if (waiter == nullptr) return;
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
    waiter->finish(size, error);
    // The continuation often starts another read before returning. Keep the
    // existing read interest if it did, avoiding a disable/re-enable pair.
    update_async_interest();
}

auto tcp_stream::complete_write(std::size_t size,
                                           std::error_code error) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* waiter = std::exchange(writer_, nullptr);
    if (waiter == nullptr) return;
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
    update_async_interest();
    waiter->finish(size, error);
}

auto tcp_stream::complete_file(std::error_code error) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* waiter = std::exchange(file_writer_, nullptr);
    if (waiter == nullptr) return;
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
    update_async_interest();
    waiter->finish(error);
}

tcp_stream::connect_awaiter::connect_awaiter(
    tcp_stream& owner) noexcept : owner_(owner)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
}

tcp_stream::connect_awaiter::~connect_awaiter()
{
    if (owner_.connector_ == this) std::terminate();
}

auto tcp_stream::connect_awaiter::suspend(
    std::coroutine_handle<> handle,
    detail::coroutine_cancellation_state& state) -> bool
{
    if (owner_.closed_) {
        error_ = code(EBADF);
        return false;
    }
    if (owner_.connected_) {
        error_ = code(EISCONN);
        return false;
    }
    if (owner_.connect_started_) {
        error_ = code(EALREADY);
        return false;
    }
    if (state.requested) {
        error_ = code(ECANCELED);
        return false;
    }
    owner_.connect_started_ = true;
    const auto endpoint = detail::native_endpoint(owner_.remote_);
    const int result = ::connect(owner_.descriptor_.get(),
                                 endpoint.address(), endpoint.length);
    if (result == 0 || (result == -1 && errno == EISCONN)) {
        owner_.connected_ = true;
        return false;
    }
    if (errno != EINPROGRESS && errno != EINTR) {
        error_ = code(errno);
        return false;
    }

    continuation_ = handle;
    if (!detail::coroutine_frame_access::attach_cancellation(
            state, cancellation_)) {
        error_ = code(ECANCELED);
        return false;
    }
    owner_.connector_ = this;
    try {
        owner_.set_async_interest(false, true);
    } catch (const std::system_error& error) {
        owner_.connector_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(
            cancellation_);
        error_ = error.code();
        return false;
    }
    return true;
}

auto tcp_stream::connect_awaiter::cancel(
    detail::coroutine_cancellation_node& node) noexcept -> void
{
    auto& self = *static_cast<connect_awaiter*>(node.operation);
    self.owner_.fail_and_close(code(ECANCELED));
}

auto tcp_stream::connect_awaiter::finish(
    std::error_code error) noexcept -> void
{
    error_ = error;
    continuation_.resume();
}

auto tcp_stream::connect_awaiter::await_resume() const noexcept
    -> std::expected<void, std::error_code>
{
    if (error_) return std::unexpected(error_);
    return {};
}

template<bool Read>
tcp_stream::io_awaiter<Read>::io_awaiter(
    tcp_stream& owner, void* data, std::size_t size) noexcept
    : owner_(owner), data_(data), size_(size)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
}

template<bool Read>
tcp_stream::io_awaiter<Read>::~io_awaiter()
{
    if constexpr (Read) {
        if (owner_.reader_ == this) std::terminate();
    } else {
        if (owner_.writer_ == this) std::terminate();
    }
}

template<bool Read>
auto tcp_stream::io_awaiter<Read>::suspend(
    std::coroutine_handle<> handle,
    detail::coroutine_cancellation_state& state) -> bool
{
    if (auto activated = owner_.activate_async_transport(); !activated) {
        error_ = activated.error();
        return false;
    }
    if (owner_.closed_) {
        error_ = code(EBADF);
        return false;
    }
    if (!owner_.connected_) {
        error_ = code(ENOTCONN);
        return false;
    }
    if constexpr (Read) {
        if (owner_.reader_ != nullptr) {
            error_ = code(EBUSY);
            return false;
        }
    } else {
        if (owner_.writer_ != nullptr || owner_.file_writer_ != nullptr) {
            error_ = code(EBUSY);
            return false;
        }
    }
    if (state.requested) {
        error_ = code(ECANCELED);
        return false;
    }
    auto result = transfer(owner_.descriptor_.get(), data_, size_, Read);
    if (result) {
        transferred_ = *result;
        return false;
    }
    if (result.error().value() != EAGAIN) {
        error_ = result.error();
        return false;
    }
    continuation_ = handle;
    if (!detail::coroutine_frame_access::attach_cancellation(
            state, cancellation_)) {
        error_ = code(ECANCELED);
        return false;
    }
    if constexpr (Read) owner_.reader_ = this;
    else owner_.writer_ = this;
    try {
        owner_.set_async_interest(owner_.reader_ != nullptr,
                                  owner_.writer_ != nullptr);
    } catch (const std::system_error& error) {
        if constexpr (Read) owner_.reader_ = nullptr;
        else owner_.writer_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(
            cancellation_);
        error_ = error.code();
        return false;
    }
    return true;
}

template<bool Read>
auto tcp_stream::io_awaiter<Read>::cancel(
    detail::coroutine_cancellation_node& node) noexcept -> void
{
    auto& self = *static_cast<io_awaiter*>(node.operation);
    if constexpr (Read) self.owner_.complete_read(0, code(ECANCELED));
    else self.owner_.complete_write(0, code(ECANCELED));
}

template<bool Read>
auto tcp_stream::io_awaiter<Read>::finish(
    std::size_t size, std::error_code error) noexcept -> void
{
    transferred_ = size;
    error_ = error;
    continuation_.resume();
}

template<bool Read>
auto tcp_stream::io_awaiter<Read>::await_resume() const noexcept
    -> std::expected<std::size_t, std::error_code>
{
    if (error_) return std::unexpected(error_);
    return transferred_;
}

template class tcp_stream::io_awaiter<true>;
template class tcp_stream::io_awaiter<false>;

tcp_stream::file_awaiter::file_awaiter(tcp_stream& owner, unique_fd file,
                                       std::size_t size) noexcept
    : owner_(owner), file_(std::move(file)), remaining_(size)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
}

tcp_stream::file_awaiter::~file_awaiter()
{
    if (owner_.file_writer_ == this) std::terminate();
}

auto tcp_stream::file_awaiter::advance() noexcept -> std::error_code
{
    while (remaining_ != 0) {
        const auto requested = std::min(remaining_, std::size_t {0x7ffff000});
        const auto result = ::sendfile(owner_.descriptor_.get(), file_.get(),
                                       nullptr, requested);
        if (result > 0) {
            remaining_ -= static_cast<std::size_t>(result);
            continue;
        }
        if (result == 0) return code(EIO);
        if (errno == EINTR) continue;
        return code(errno);
    }
    return {};
}

auto tcp_stream::file_awaiter::suspend(
    std::coroutine_handle<> handle,
    detail::coroutine_cancellation_state& state) -> bool
{
    if (auto activated = owner_.activate_async_transport(); !activated) {
        error_ = activated.error();
        return false;
    }
    if (owner_.closed_ || !file_) {
        error_ = code(EBADF);
        return false;
    }
    if (owner_.writer_ != nullptr || owner_.file_writer_ != nullptr) {
        error_ = code(EBUSY);
        return false;
    }
    if (state.requested) {
        error_ = code(ECANCELED);
        return false;
    }
    error_ = advance();
    if (error_.value() != EAGAIN) return false;
    continuation_ = handle;
    if (!detail::coroutine_frame_access::attach_cancellation(
            state, cancellation_)) {
        error_ = code(ECANCELED);
        return false;
    }
    owner_.file_writer_ = this;
    try {
        owner_.set_async_interest(owner_.reader_ != nullptr, true);
    } catch (const std::system_error& error) {
        owner_.file_writer_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(
            cancellation_);
        error_ = error.code();
        return false;
    }
    return true;
}

auto tcp_stream::file_awaiter::cancel(
    detail::coroutine_cancellation_node& node) noexcept -> void
{
    auto& self = *static_cast<file_awaiter*>(node.operation);
    self.owner_.complete_file(code(ECANCELED));
}

auto tcp_stream::file_awaiter::finish(std::error_code error) noexcept -> void
{
    error_ = error;
    continuation_.resume();
}

auto tcp_stream::file_awaiter::await_resume() const noexcept
    -> std::expected<void, std::error_code>
{
    if (error_) return std::unexpected(error_);
    return {};
}

auto tcp_stream::send_file_task(event_loop& loop, tcp_stream& socket,
                                std::span<const std::byte> header,
                                unique_fd file, std::size_t size)
    -> task<std::expected<void, std::error_code>>
{
    (void)loop;
    while (!header.empty()) {
        auto sent = co_await socket.async_write_some(header);
        if (!sent) co_return std::unexpected(sent.error());
        if (*sent == 0) co_return std::unexpected(code(EIO));
        header = header.subspan(*sent);
    }
    co_return co_await tcp_stream::file_awaiter(socket, std::move(file), size);
}
auto tcp_stream::async_send_file(std::span<const std::byte> header,
                                  unique_fd file, std::size_t size)
    -> task<std::expected<void, std::error_code>>
{
    return send_file_task(loop_, *this, header, std::move(file), size);
}

} // namespace eventloop
