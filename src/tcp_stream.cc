#include "eventloop/tcp_stream.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <stdexcept>

#include <sys/sendfile.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

[[nodiscard]] auto sigpipe_ignored() noexcept -> bool
{
    static const bool ignored = std::signal(SIGPIPE, SIG_IGN) != SIG_ERR;
    return ignored;
}

} // namespace

tcp_stream::tcp_stream(event_loop& loop, int descriptor)
    : loop_(loop), descriptor_(descriptor)
{
}

tcp_stream::~tcp_stream()
{
    close_file();
    ::close(descriptor_);
}

auto tcp_stream::descriptor() const noexcept -> int
{
    return descriptor_;
}

auto tcp_stream::write(std::span<const std::byte> data) -> void
{
    if (closing_ || closed_) {
        throw std::logic_error("cannot write to a closing TCP stream");
    }
    if (file_descriptor_ != -1) {
        throw std::logic_error("cannot write during a file transfer");
    }
    if (written_ != 0) {
        const auto remaining = output_size_ - written_;
        std::memmove(output_.data(), output_.data() + written_, remaining);
        output_size_ = remaining;
        written_ = 0;
    }
    if (data.size() > output_.size() - output_size_) {
        throw std::length_error("TCP write buffer capacity exceeded");
    }
    std::memcpy(output_.data() + output_size_, data.data(), data.size());
    output_size_ += data.size();
    flush();
}

auto tcp_stream::send_file(std::span<const std::byte> header, int descriptor,
                           std::size_t size) -> void
{
    if (!sigpipe_ignored()) {
        const int error = errno;
        ::close(descriptor);
        throw std::system_error(error, std::system_category(),
                                "ignore SIGPIPE");
    }
    if (closing_ || closed_) {
        ::close(descriptor);
        throw std::logic_error("cannot start a file transfer while closing");
    }
    if (written_ < output_size_) {
        ::close(descriptor);
        throw std::logic_error("cannot start a file transfer with pending bytes");
    }
    if (file_descriptor_ != -1) {
        ::close(descriptor);
        throw std::logic_error("cannot start a concurrent file transfer");
    }
    if (header.size() > output_.size()) {
        ::close(descriptor);
        throw std::length_error("TCP write buffer capacity exceeded");
    }

    std::memcpy(output_.data(), header.data(), header.size());
    output_size_ = header.size();
    written_ = 0;
    file_descriptor_ = descriptor;
    file_remaining_ = size;
    flush();
}

auto tcp_stream::close() -> void
{
    if (closing_ || closed_) {
        return;
    }
    closing_ = true;
    if (!write_pending()) {
        abort();
    } else {
        watch_writes(true);
    }
}

auto tcp_stream::ready() const noexcept -> bool
{
    return !closing_ && !closed_;
}

auto tcp_stream::write_pending() const noexcept -> bool
{
    return written_ < output_size_ || file_descriptor_ != -1;
}

auto tcp_stream::on_read() -> void
{
    std::array<std::byte, 4096> buffer {};
    for (;;) {
        const auto size = recv(descriptor_, buffer.data(), buffer.size(), 0);
        if (size > 0) {
            on_transport_data(std::span {buffer}.first(static_cast<std::size_t>(size)));
            if (closing_ || closed_) {
                return;
            }
            continue;
        }
        if (size == 0) {
            if (!peer_closed_) {
                peer_closed_ = true;
                on_transport_close();
            }
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        on_transport_error({errno, std::system_category()});
        return;
    }
}

auto tcp_stream::on_write() -> void
{
    flush();
}

auto tcp_stream::on_error() -> void
{
    int error = 0;
    socklen_t size = sizeof(error);
    if (getsockopt(descriptor_, SOL_SOCKET, SO_ERROR, &error, &size) == -1) {
        error = errno;
    } else if (error == 0) {
        error = ECONNRESET;
    }
    on_transport_error({error, std::system_category()});
}

auto tcp_stream::flush() -> void
{
    const bool had_output = write_pending();
    while (written_ < output_size_) {
        const int flags = MSG_NOSIGNAL |
            (file_descriptor_ != -1 && file_remaining_ != 0 ? MSG_MORE : 0);
        const auto size = send(descriptor_, output_.data() + written_,
                               output_size_ - written_, flags);
        if (size > 0) {
            written_ += static_cast<std::size_t>(size);
            continue;
        }
        if (size == -1 && errno == EINTR) {
            continue;
        }
        if (size == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            watch_writes(true);
            return;
        }
        on_transport_error({errno, std::system_category()});
        return;
    }

    output_size_ = 0;
    written_ = 0;

    while (file_descriptor_ != -1 && file_remaining_ != 0) {
        constexpr std::size_t maximum_send = 0x7ffff000;
        const auto requested = std::min(file_remaining_, maximum_send);
        const auto size = sendfile(descriptor_, file_descriptor_, nullptr, requested);
        if (size > 0) {
            file_remaining_ -= static_cast<std::size_t>(size);
            continue;
        }
        if (size == -1 && errno == EINTR) {
            continue;
        }
        if (size == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            watch_writes(true);
            return;
        }
        const int error = size == 0 ? EIO : errno;
        on_transport_error({error, std::system_category()});
        return;
    }
    close_file();

    watch_writes(false);
    if (peer_closed_ || closing_) {
        abort();
        return;
    }
    if (had_output && notifying_write_drained_) {
        write_drained_deferred_ = true;
        return;
    }
    if (had_output) {
        do {
            write_drained_deferred_ = false;
            notifying_write_drained_ = true;
            on_write_drained();
            notifying_write_drained_ = false;
        } while (write_drained_deferred_ && !write_pending() && !closing_ && !closed_);
    }
}

auto tcp_stream::on_transport_data(std::span<const std::byte> data) -> void
{
    emit_data(data);
}

auto tcp_stream::on_transport_close() -> void
{
    emit_close();
    close();
}

auto tcp_stream::on_transport_error(std::error_code error) -> void
{
    emit_error(error);
    abort();
}

auto tcp_stream::abort() -> void
{
    if (!closed_) {
        closed_ = true;
        closing_ = true;
        close_file();
        loop_.remove(descriptor_);
    }
}

auto tcp_stream::close_file() noexcept -> void
{
    if (file_descriptor_ != -1) {
        ::close(file_descriptor_);
        file_descriptor_ = -1;
        file_remaining_ = 0;
    }
}

auto tcp_stream::watch_writes(bool enabled) -> void
{
    if (watching_writes_ != enabled) {
        loop_.set_write_interest(descriptor_, enabled);
        watching_writes_ = enabled;
    }
}
