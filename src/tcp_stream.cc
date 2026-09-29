#include "eventloop/tcp_stream.h"
#include "eventloop/task.h"
#include "ip_endpoint_native.h"
#include "socket_operations.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace eventloop {

namespace {
[[nodiscard]] auto code(int error) noexcept -> std::error_code
{
    return {error, std::generic_category()};
}

} // namespace

tcp_stream::tcp_stream(event_loop& loop, unique_fd descriptor)
#ifdef _WIN32
    : loop_(loop), descriptor_(std::move(descriptor)),
      registered_descriptor_(descriptor_.get())
#else
    : loop_(loop), descriptor_(std::move(descriptor))
#endif
{
    if (!descriptor_) {
        throw std::invalid_argument("TCP stream descriptor is invalid");
    }
}

tcp_stream::tcp_stream(event_loop& loop, ip_endpoint remote)
    : loop_(loop), remote_(remote), connected_(false),
      transport_activated_(true)
{
    descriptor_.reset(detail::socket_operations::create(
        detail::socket_family(remote), SOCK_STREAM, 0));
#ifdef _WIN32
    registered_descriptor_ = descriptor_.get();
#endif
    if (auto error = detail::socket_operations::configure_client(
            descriptor_.get(), remote); error)
        throw std::system_error(error, "IPV6_V6ONLY");
}

tcp_stream::~tcp_stream()
{
    if (connector_ != nullptr || reader_ != nullptr || writer_ != nullptr ||
        file_writer_ != nullptr
#ifdef _WIN32
        || pending_operations_ != 0
#endif
    ) {
        std::terminate();
    }
}

auto tcp_stream::descriptor() const noexcept -> native_socket
{
    return descriptor_.get();
}

auto tcp_stream::activate_async_transport() noexcept
    -> std::expected<void, std::error_code>
{
    if (transport_activated_) return {};
    if (closed_) return std::unexpected(code(EBADF));
    if (!connected_) return std::unexpected(code(ENOTCONN));
    if (auto error = detail::socket_operations::activate(descriptor_.get()); error)
        return std::unexpected(error);
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
#ifdef _WIN32
    auto result = detail::socket_operations::start_read(
        descriptor_.get(), reader_->data_, reader_->size_, reader_->operation_);
#else
    detail::socket_operation operation;
    auto result = detail::socket_operations::start_read(
        descriptor_.get(), reader_->data_, reader_->size_, operation);
#endif
    if (result.pending) return;
    complete_read(result.transferred, result.error);
}

auto tcp_stream::on_write() -> void
{
    if (connector_ != nullptr && !closed_) {
        const auto error = detail::socket_operations::finish_connect(
            descriptor_.get());
        if (error) fail_and_close(error);
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
#ifdef _WIN32
    auto result = detail::socket_operations::start_write(
        descriptor_.get(), writer_->data_, writer_->size_, writer_->operation_);
#else
    detail::socket_operation operation;
    auto result = detail::socket_operations::start_write(
        descriptor_.get(), writer_->data_, writer_->size_, operation);
#endif
    if (result.pending) return;
    complete_write(result.transferred, result.error);
}

auto tcp_stream::on_error() -> void
{
    fail_and_close(detail::socket_operations::pending_error(
        descriptor_.get(), ECONNRESET));
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
#ifdef _WIN32
    if (connector_ != nullptr && connector_->operation_.pending_completion) {
        connector_->cancelled_ = true;
        detail::socket_operations::cancel(descriptor_.get(), connector_->operation_);
    } else complete_connect(error);
    if (reader_ != nullptr && reader_->operation_.pending_completion) {
        reader_->cancelled_ = true;
        detail::socket_operations::cancel(descriptor_.get(), reader_->operation_);
    } else complete_read(0, error);
    if (writer_ != nullptr && writer_->operation_.pending_completion) {
        writer_->cancelled_ = true;
        detail::socket_operations::cancel(descriptor_.get(), writer_->operation_);
    } else complete_write(0, error);
    if (file_writer_ != nullptr && file_writer_->operation_.pending_completion) {
        file_writer_->cancelled_ = true;
        detail::socket_operations::cancel(descriptor_.get(),
                                          file_writer_->operation_);
    } else complete_file(error);
    if (pending_operations_ != 0) descriptor_.reset();
    else loop_.remove(registered_descriptor_);
#else
    complete_connect(error);
    complete_read(0, error);
    complete_write(0, error);
    complete_file(error);
    loop_.remove(descriptor_.get());
#endif
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
#ifdef _WIN32
    if (waiter->operation_.pending_completion) {
        waiter->operation_.pending_completion = false;
        if (pending_operations_ == 0) std::terminate();
        --pending_operations_;
    }
#endif
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
#ifdef _WIN32
    if (closed_ && pending_operations_ == 0) loop_.remove(registered_descriptor_);
#endif
    update_async_interest();
    waiter->finish(error);
}

auto tcp_stream::complete_read(std::size_t size,
                                          std::error_code error) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* waiter = std::exchange(reader_, nullptr);
    if (waiter == nullptr) return;
#ifdef _WIN32
    if (waiter->operation_.pending_completion) {
        waiter->operation_.pending_completion = false;
        if (pending_operations_ == 0) std::terminate();
        --pending_operations_;
    }
#endif
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
#ifdef _WIN32
    if (closed_ && pending_operations_ == 0) loop_.remove(registered_descriptor_);
#endif
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
#ifdef _WIN32
    if (waiter->operation_.pending_completion) {
        waiter->operation_.pending_completion = false;
        if (pending_operations_ == 0) std::terminate();
        --pending_operations_;
    }
#endif
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
#ifdef _WIN32
    if (closed_ && pending_operations_ == 0) loop_.remove(registered_descriptor_);
#endif
    update_async_interest();
    waiter->finish(size, error);
}

auto tcp_stream::complete_file(std::error_code error) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* waiter = std::exchange(file_writer_, nullptr);
    if (waiter == nullptr) return;
#ifdef _WIN32
    if (waiter->operation_.pending_completion) std::terminate();
#endif
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
#ifdef _WIN32
    if (closed_ && pending_operations_ == 0 && !descriptor_)
        loop_.remove(registered_descriptor_);
#endif
    update_async_interest();
    waiter->finish(error);
}

tcp_stream::connect_awaiter::connect_awaiter(
    tcp_stream& owner) noexcept : owner_(owner)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
#ifdef _WIN32
    operation_.context = this;
    operation_.complete = [](detail::socket_operation& operation,
                             std::size_t, int error) noexcept {
        auto& self = *static_cast<connect_awaiter*>(operation.context);
        std::error_code result;
        if (self.cancelled_ || self.owner_.closed_) result = code(ECANCELED);
        else if (error == ERROR_CONNECTION_REFUSED)
            result = {WSAECONNREFUSED, std::system_category()};
        else if (error != 0) result = {error, std::system_category()};
        else result = detail::socket_operations::finish_connect(
            self.owner_.descriptor_.get());
        if (result && !self.owner_.closed_) {
            self.owner_.closed_ = true;
            self.owner_.descriptor_.reset();
        }
        if (!result) self.owner_.connected_ = true;
        self.owner_.complete_connect(result);
    };
#endif
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
    continuation_ = handle;
    if (!detail::coroutine_frame_access::attach_cancellation(
            state, cancellation_)) {
        error_ = code(ECANCELED);
        return false;
    }
    owner_.connector_ = this;
#ifdef _WIN32
    const auto result = detail::socket_operations::start_connect(
        owner_.descriptor_.get(), owner_.remote_, operation_);
#else
    detail::socket_operation operation;
    const auto result = detail::socket_operations::start_connect(
        owner_.descriptor_.get(), owner_.remote_, operation);
#endif
    if (!result.pending) {
        owner_.connector_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(cancellation_);
        error_ = result.error;
        if (!error_) owner_.connected_ = true;
        return false;
    }
#ifdef _WIN32
    if (operation_.pending_completion) ++owner_.pending_operations_;
#endif
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
    detail::coroutine_frame_access::detach_cancellation(self.cancellation_);
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
#ifdef _WIN32
    operation_.context = this;
    operation_.complete = [](detail::socket_operation& operation,
                             std::size_t bytes, int error) noexcept {
        auto& self = *static_cast<io_awaiter*>(operation.context);
        std::error_code result;
        if (self.cancelled_ || self.owner_.closed_) result = code(ECANCELED);
        else if (error != 0) result = {error, std::system_category()};
        if constexpr (Read) self.owner_.complete_read(bytes, result);
        else self.owner_.complete_write(bytes, result);
    };
#endif
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
    continuation_ = handle;
    if (!detail::coroutine_frame_access::attach_cancellation(
            state, cancellation_)) {
        error_ = code(ECANCELED);
        return false;
    }
    if constexpr (Read) owner_.reader_ = this;
    else owner_.writer_ = this;
#ifndef _WIN32
    detail::socket_operation operation;
#endif
    const auto result = [&] {
        if constexpr (Read)
            return detail::socket_operations::start_read(
                owner_.descriptor_.get(), data_, size_,
#ifdef _WIN32
                operation_);
#else
                operation);
#endif
        else
            return detail::socket_operations::start_write(
                owner_.descriptor_.get(), data_, size_,
#ifdef _WIN32
                operation_);
#else
                operation);
#endif
    }();
    if (!result.pending) {
        if constexpr (Read) owner_.reader_ = nullptr;
        else owner_.writer_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(cancellation_);
        transferred_ = result.transferred;
        error_ = result.error;
        return false;
    }
#ifdef _WIN32
    if (operation_.pending_completion) ++owner_.pending_operations_;
#endif
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
    detail::coroutine_frame_access::detach_cancellation(self.cancellation_);
#ifdef _WIN32
    if (self.operation_.pending_completion) self.owner_.close();
    else if constexpr (Read) self.owner_.complete_read(0, code(ECANCELED));
#else
    if constexpr (Read) self.owner_.complete_read(0, code(ECANCELED));
#endif
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
#ifdef _WIN32
    operation_.context = this;
    operation_.complete = [](detail::socket_operation& operation,
                             std::size_t bytes, int error) noexcept {
        auto& self = *static_cast<file_awaiter*>(operation.context);
        if (!operation.pending_completion || self.owner_.pending_operations_ == 0)
            std::terminate();
        operation.pending_completion = false;
        --self.owner_.pending_operations_;
        if (self.cancelled_ || self.owner_.closed_) {
            self.owner_.complete_file(code(ECANCELED));
            return;
        }
        if (error != 0) {
            self.owner_.complete_file({error, std::system_category()});
            return;
        }
        if (bytes == 0 || bytes > self.requested_ || bytes > self.remaining_) {
            self.owner_.complete_file(code(EIO));
            return;
        }
        self.remaining_ -= bytes;
        self.offset_ += bytes;
        const auto next = self.advance();
        if (next.value() != EAGAIN) self.owner_.complete_file(next);
    };
#endif
}

tcp_stream::file_awaiter::~file_awaiter()
{
    if (owner_.file_writer_ == this) std::terminate();
}

auto tcp_stream::file_awaiter::advance() noexcept -> std::error_code
{
    while (remaining_ != 0) {
#ifdef _WIN32
        requested_ = std::min(remaining_, std::size_t {0x7ffff000});
        const auto offset = static_cast<std::uint64_t>(offset_);
        operation_.overlapped = {};
        operation_.overlapped.Offset = static_cast<DWORD>(offset);
        operation_.overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32);
        const auto result = detail::socket_operations::start_send_file(
            owner_.descriptor_.get(), file_.get(), requested_, operation_);
#else
        detail::socket_operation operation;
        const auto requested = std::min(remaining_, std::size_t {0x7ffff000});
        const auto result = detail::socket_operations::start_send_file(
            owner_.descriptor_.get(), file_.get(), requested, operation);
#endif
        if (result.pending) {
#ifdef _WIN32
            if (operation_.pending_completion) ++owner_.pending_operations_;
#endif
            return code(EAGAIN);
        }
        if (result.error) return result.error;
        if (result.transferred > 0) {
            remaining_ -= result.transferred;
#ifdef _WIN32
            offset_ += result.transferred;
#endif
            continue;
        }
        return code(EIO);
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
    continuation_ = handle;
    if (!detail::coroutine_frame_access::attach_cancellation(
            state, cancellation_)) {
        error_ = code(ECANCELED);
        return false;
    }
    owner_.file_writer_ = this;
    error_ = advance();
    if (error_.value() != EAGAIN) {
        owner_.file_writer_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(cancellation_);
        return false;
    }
    try {
        owner_.set_async_interest(owner_.reader_ != nullptr, true);
    } catch (const std::system_error& error) {
#ifdef _WIN32
        if (operation_.pending_completion) {
            owner_.fail_and_close(error.code());
            return true;
        }
#endif
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
    detail::coroutine_frame_access::detach_cancellation(self.cancellation_);
#ifdef _WIN32
    if (self.operation_.pending_completion) {
        self.cancelled_ = true;
        detail::socket_operations::cancel(self.owner_.descriptor_.get(),
                                          self.operation_);
    } else self.owner_.complete_file(code(ECANCELED));
#else
    self.owner_.complete_file(code(ECANCELED));
#endif
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
