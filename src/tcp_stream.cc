#include "eventloop/tcp_stream.h"
#include "eventloop/task.h"
#include "socket_operations.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>
#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#endif

namespace eventloop {

namespace {
[[nodiscard]] auto code(int error) noexcept -> std::error_code
{
    return {error, std::generic_category()};
}

} // namespace

tcp_stream::tcp_stream(event_loop& loop, unique_fd descriptor)
    : loop_(loop), descriptor_(std::move(descriptor))
{
    if (!descriptor_) {
        throw std::invalid_argument("TCP stream descriptor is invalid");
    }
    detail::socket_operations::stream_register(*this);
}

tcp_stream::tcp_stream(event_loop& loop, ip_endpoint remote)
    : loop_(loop), remote_(remote), connected_(false),
      transport_activated_(true)
{
    descriptor_.reset(detail::socket_operations::create_stream(remote));
    detail::socket_operations::stream_register(*this);
    if (auto error = detail::socket_operations::configure_client(
            descriptor_.get(), remote); error)
        throw std::system_error(error, "configure TCP client socket");
}

#ifndef _WIN32
tcp_stream::tcp_stream(event_loop& loop, std::string_view unix_path)
    : loop_(loop), unix_path_(unix_path), unix_socket_(true),
      connected_(false), transport_activated_(true)
{
    if (unix_path.empty() || unix_path.size() >= sizeof(sockaddr_un::sun_path) ||
        unix_path.contains('\0'))
        throw std::invalid_argument("invalid Unix socket path");
    descriptor_.reset(detail::socket_operations::create(AF_UNIX, SOCK_STREAM, 0));
    detail::socket_operations::stream_register(*this);
}
#endif

tcp_stream::~tcp_stream()
{
    if (connector_ != nullptr || reader_ != nullptr || writer_ != nullptr ||
        file_writer_ != nullptr ||
#ifdef __linux__
        read_waiter_ != nullptr || second_read_waiter_ != nullptr ||
        write_waiter_ != nullptr || second_write_waiter_ != nullptr ||
#endif
        detail::socket_operations::stream_has_pending(*this)
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
#ifdef __linux__
    if (read_waiter_ != nullptr && !closed_) {
        complete_ready<true>({});
        return;
    }
#endif
    if (reader_ == nullptr || closed_) return;
    auto result = detail::socket_operations::start_read(
        descriptor_.get(), reader_->data_, reader_->size_, reader_->operation_);
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
#ifdef __linux__
    if (write_waiter_ != nullptr && !closed_) {
        complete_ready<false>({});
        return;
    }
#endif
    if (writer_ == nullptr || closed_) return;
    auto result = writer_->start();
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
    if (connector_ == nullptr || !detail::socket_operations::stream_cancel(
            *this, connector_->operation_)) complete_connect(error);
    if (reader_ == nullptr || !detail::socket_operations::stream_cancel(
            *this, reader_->operation_)) complete_read(0, error);
    if (writer_ == nullptr || !detail::socket_operations::stream_cancel(
            *this, writer_->operation_)) complete_write(0, error);
    if (file_writer_ == nullptr || !detail::socket_operations::stream_cancel(
            *this, file_writer_->operation_)) complete_file(error);
#ifdef __linux__
    complete_ready<true>(error);
    complete_ready<false>(error);
#endif
    detail::socket_operations::stream_close(*this);
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

// Completions call this after resuming their continuation, which often starts
// the next operation of the same kind. Updating afterward keeps that interest
// armed instead of issuing a disable/re-enable pair. The loop defers handler
// removal while a completion runs, so the stream outlives the continuation.
auto tcp_stream::update_async_interest() noexcept -> void
{
    if (!closed_) {
        try {
            set_async_interest(reader_ != nullptr
#ifdef __linux__
                || read_waiter_ != nullptr || second_read_waiter_ != nullptr
#endif
                ,
                connector_ != nullptr || writer_ != nullptr ||
                    file_writer_ != nullptr
#ifdef __linux__
                    || write_waiter_ != nullptr || second_write_waiter_ != nullptr
#endif
                );
        } catch (const std::system_error& error) {
            // Re-arming can fail at runtime (ENOMEM, or kqueue EPIPE for a
            // peer-closed socket). Fail the stream instead of the process.
            fail_and_close(error.code());
        }
    }
}

auto tcp_stream::complete_connect(std::error_code error) noexcept
    -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* waiter = std::exchange(connector_, nullptr);
    if (waiter == nullptr) return;
    detail::socket_operations::stream_retire(*this, waiter->operation_);
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
    waiter->finish(error);
    update_async_interest();
}

auto tcp_stream::complete_read(std::size_t size,
                                          std::error_code error) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* waiter = std::exchange(reader_, nullptr);
    if (waiter == nullptr) return;
    detail::socket_operations::stream_retire(*this, waiter->operation_);
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
    waiter->finish(size, error);
    update_async_interest();
}

auto tcp_stream::complete_write(std::size_t size,
                                           std::error_code error) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* waiter = std::exchange(writer_, nullptr);
    if (waiter == nullptr) return;
    detail::socket_operations::stream_retire(*this, waiter->operation_);
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
    waiter->finish(size, error);
    update_async_interest();
}

auto tcp_stream::complete_file(std::error_code error) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    auto* waiter = std::exchange(file_writer_, nullptr);
    if (waiter == nullptr) return;
    if (detail::socket_operations::stream_pending(waiter->operation_))
        std::terminate();
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
    waiter->finish(error);
    update_async_interest();
}

tcp_stream::connect_awaiter::connect_awaiter(
    tcp_stream& owner) noexcept : owner_(owner)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
    detail::socket_operations::stream_bind(
        owner_, operation_, this, detail::stream_operation_kind::connect);
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
#ifndef _WIN32
    const auto result = owner_.unix_socket_
        ? detail::socket_operations::start_unix_connect(
            owner_.descriptor_.get(), owner_.unix_path_, operation_)
        : detail::socket_operations::start_connect(
            owner_.descriptor_.get(), owner_.remote_, operation_);
#else
    const auto result = detail::socket_operations::start_connect(
        owner_.descriptor_.get(), owner_.remote_, operation_);
#endif
    if (!result.pending) {
        owner_.connector_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(cancellation_);
        error_ = result.error;
        if (!error_) owner_.connected_ = true;
        return false;
    }
    detail::socket_operations::stream_submitted(owner_, operation_);
    try {
        owner_.set_async_interest(false, true);
    } catch (const std::system_error& error) {
        if (detail::socket_operations::stream_pending(operation_)) {
            owner_.fail_and_close(error.code());
            return true;
        }
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
    tcp_stream& owner, void* data, std::size_t size, bool gather) noexcept
    : owner_(owner), data_(data), size_(size), gather_(gather)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
    detail::socket_operations::stream_bind(owner_, operation_, this,
        Read ? detail::stream_operation_kind::read
             : detail::stream_operation_kind::write);
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
        if (owner_.reader_ != nullptr
#ifdef __linux__
            || owner_.read_waiter_ != nullptr || owner_.second_read_waiter_ != nullptr
#endif
            ) {
            error_ = code(EBUSY);
            return false;
        }
    } else {
        if (owner_.writer_ != nullptr || owner_.file_writer_ != nullptr
#ifdef __linux__
            || owner_.write_waiter_ != nullptr || owner_.second_write_waiter_ != nullptr
#endif
            ) {
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
    const auto result = start();
    if (!result.pending) {
        if constexpr (Read) owner_.reader_ = nullptr;
        else owner_.writer_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(cancellation_);
        transferred_ = result.transferred;
        error_ = result.error;
        return false;
    }
    detail::socket_operations::stream_submitted(owner_, operation_);
    try {
        owner_.set_async_interest(owner_.reader_ != nullptr,
                                  owner_.writer_ != nullptr);
    } catch (const std::system_error& error) {
        if (detail::socket_operations::stream_pending(operation_)) {
            owner_.fail_and_close(error.code());
            return true;
        }
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
auto tcp_stream::io_awaiter<Read>::start() noexcept -> detail::socket_result
{
    const auto socket = owner_.descriptor_.get();
    if constexpr (Read) {
        return detail::socket_operations::start_read(socket, data_, size_, operation_);
    } else {
        if (!gather_)
            return detail::socket_operations::start_write(socket, data_, size_, operation_);
        return detail::socket_operations::start_write_gather(socket,
            {static_cast<const std::span<const std::byte>*>(data_),
             std::min(size_, max_write_buffers)}, operation_);
    }
}

template<bool Read>
auto tcp_stream::io_awaiter<Read>::cancel(
    detail::coroutine_cancellation_node& node) noexcept -> void
{
    auto& self = *static_cast<io_awaiter*>(node.operation);
    detail::coroutine_frame_access::detach_cancellation(self.cancellation_);
    if (detail::socket_operations::stream_pending(self.operation_))
        self.owner_.close();
    else if constexpr (Read)
        self.owner_.complete_read(0, code(ECANCELED));
    else
        self.owner_.complete_write(0, code(ECANCELED));
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
                                       std::uint64_t offset, std::size_t size) noexcept
    : owner_(owner), file_(std::move(file)), offset_(offset), remaining_(size)
{
    cancellation_.operation = this;
    cancellation_.cancel = &cancel;
    detail::socket_operations::stream_bind(
        owner_, operation_, this, detail::stream_operation_kind::file);
}

tcp_stream::file_awaiter::~file_awaiter()
{
    if (owner_.file_writer_ == this) std::terminate();
}

auto tcp_stream::file_awaiter::advance() noexcept -> std::error_code
{
    while (remaining_ != 0) {
        const auto requested = std::min(remaining_, std::size_t {0x7ffff000});
        const auto result = detail::socket_operations::stream_send_file(
            owner_, file_, offset_, requested, operation_);
        if (result.pending) {
            detail::socket_operations::stream_submitted(owner_, operation_);
            return code(EAGAIN);
        }
        if (result.error) return result.error;
        if (result.transferred > 0) {
            remaining_ -= result.transferred;
            offset_ += result.transferred;
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
    if (owner_.writer_ != nullptr || owner_.file_writer_ != nullptr
#ifdef __linux__
        || owner_.write_waiter_ != nullptr || owner_.second_write_waiter_ != nullptr
#endif
        ) {
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
        if (detail::socket_operations::stream_pending(operation_)) {
            owner_.fail_and_close(error.code());
            return true;
        }
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
    if (!detail::socket_operations::stream_cancel(
            self.owner_, self.operation_))
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
                                unique_fd file, std::uint64_t offset, std::size_t size)
    -> task<std::expected<void, std::error_code>>
{
    (void)loop;
    while (!header.empty()) {
        auto sent = co_await socket.async_write_some(header);
        if (!sent) co_return std::unexpected(sent.error());
        if (*sent == 0) co_return std::unexpected(code(EIO));
        header = header.subspan(*sent);
    }
    co_return co_await tcp_stream::file_awaiter(socket, std::move(file), offset, size);
}
auto tcp_stream::async_send_file(std::span<const std::byte> header,
                                  unique_fd file, std::uint64_t offset, std::size_t size)
    -> task<std::expected<void, std::error_code>>
{
    return send_file_task(loop_, *this, header, std::move(file), offset, size);
}

#ifdef __linux__
template<bool Read>
tcp_stream::readiness_awaiter<Read>::~readiness_awaiter()
{
    if constexpr (Read) {
        if (owner_.read_waiter_ == this || owner_.second_read_waiter_ == this)
            std::terminate();
    } else {
        if (owner_.write_waiter_ == this || owner_.second_write_waiter_ == this)
            std::terminate();
    }
}

template<bool Read>
auto tcp_stream::readiness_awaiter<Read>::suspend(
    std::coroutine_handle<> handle,
    detail::coroutine_cancellation_state& state) -> bool
{
    if (auto activated = owner_.activate_async_transport(); !activated) {
        error_ = activated.error();
        return false;
    }
    if (owner_.closed_) { error_ = code(ECANCELED); return false; }
    if constexpr (Read) {
        if (owner_.reader_ || (owner_.read_waiter_ && owner_.second_read_waiter_)) {
            error_ = code(EBUSY); return false;
        }
    } else {
        if (owner_.writer_ || owner_.file_writer_ ||
            (owner_.write_waiter_ && owner_.second_write_waiter_)) {
            error_ = code(EBUSY); return false;
        }
    }
    if (state.requested || !detail::coroutine_frame_access::attach_cancellation(
            state, cancellation_)) {
        error_ = code(ECANCELED);
        return false;
    }
    continuation_ = handle;
    if constexpr (Read) {
        if (owner_.read_waiter_) owner_.second_read_waiter_ = this;
        else owner_.read_waiter_ = this;
    } else {
        if (owner_.write_waiter_) owner_.second_write_waiter_ = this;
        else owner_.write_waiter_ = this;
    }
    try {
        owner_.set_async_interest(owner_.reader_ || owner_.read_waiter_ ||
            owner_.second_read_waiter_,
            owner_.connector_ || owner_.writer_ || owner_.file_writer_ ||
            owner_.write_waiter_ || owner_.second_write_waiter_);
    } catch (const std::system_error& error) {
        if constexpr (Read) {
            if (owner_.read_waiter_ == this) owner_.read_waiter_ = nullptr;
            else owner_.second_read_waiter_ = nullptr;
        } else {
            if (owner_.write_waiter_ == this) owner_.write_waiter_ = nullptr;
            else owner_.second_write_waiter_ = nullptr;
        }
        detail::coroutine_frame_access::detach_cancellation(cancellation_);
        error_ = error.code();
        return false;
    }
    return true;
}

template<bool Read>
auto tcp_stream::readiness_awaiter<Read>::cancel(
    detail::coroutine_cancellation_node& node) noexcept -> void
{
    auto& self = *static_cast<readiness_awaiter*>(node.operation);
    auto& owner = self.owner_;
    if constexpr (Read) {
        if (owner.read_waiter_ == &self) owner.read_waiter_ = nullptr;
        else owner.second_read_waiter_ = nullptr;
    } else {
        if (owner.write_waiter_ == &self) owner.write_waiter_ = nullptr;
        else owner.second_write_waiter_ = nullptr;
    }
    detail::coroutine_frame_access::detach_cancellation(self.cancellation_);
    owner.update_async_interest();
    self.finish(code(ECANCELED));
}

template<bool Read>
auto tcp_stream::complete_ready(std::error_code error) noexcept -> void
{
    event_loop::handler_call_scope scope(loop_);
    readiness_awaiter<Read>* first;
    readiness_awaiter<Read>* second;
    if constexpr (Read) {
        first = std::exchange(read_waiter_, nullptr);
        second = std::exchange(second_read_waiter_, nullptr);
    } else {
        first = std::exchange(write_waiter_, nullptr);
        second = std::exchange(second_write_waiter_, nullptr);
    }
    if (first) detail::coroutine_frame_access::detach_cancellation(first->cancellation_);
    if (second) detail::coroutine_frame_access::detach_cancellation(second->cancellation_);
    if (first) first->finish(error);
    if (second) second->finish(error);
    update_async_interest();
}

template class tcp_stream::readiness_awaiter<true>;
template class tcp_stream::readiness_awaiter<false>;
template auto tcp_stream::complete_ready<true>(std::error_code) noexcept -> void;
template auto tcp_stream::complete_ready<false>(std::error_code) noexcept -> void;
#endif

} // namespace eventloop
