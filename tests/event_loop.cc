#include "eventloop/event_loop.h"
#include "eventloop/tcp_stream.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <stdexcept>
#include <system_error>

#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

[[nodiscard]] auto make_event() -> int
{
    const int descriptor = eventfd(1, EFD_CLOEXEC | EFD_NONBLOCK);
    if (descriptor == -1) {
        throw std::system_error(errno, std::system_category(), "eventfd");
    }
    return descriptor;
}

class throwing_handler final : public notifiable {
public:
    explicit throwing_handler(event_loop& loop)
        : loop_(loop), descriptor_(make_event())
    {
    }

    ~throwing_handler() override { ::close(descriptor_); }

    [[nodiscard]] auto descriptor() const noexcept -> int override
    {
        return descriptor_;
    }

private:
    auto on_read() -> void override
    {
        loop_.remove(descriptor_);
        throw std::runtime_error("expected handler failure");
    }

    auto on_write() -> void override {}
    auto on_error() -> void override {}

    event_loop& loop_;
    int descriptor_;
};

class stopping_handler final : public notifiable {
public:
    explicit stopping_handler(event_loop& loop)
        : loop_(loop), descriptor_(make_event())
    {
    }

    ~stopping_handler() override { ::close(descriptor_); }

    [[nodiscard]] auto descriptor() const noexcept -> int override
    {
        return descriptor_;
    }

private:
    auto on_read() -> void override { loop_.stop(); }
    auto on_write() -> void override {}
    auto on_error() -> void override {}

    event_loop& loop_;
    int descriptor_;
};

class sending_stream final : public tcp_stream {
public:
    sending_stream(event_loop& loop, int descriptor)
        : tcp_stream(loop, descriptor)
    {
    }

private:
    auto on_data(std::span<const std::byte>) -> void override {}
};

class receiving_handler final : public notifiable {
public:
    receiving_handler(event_loop& loop, int descriptor,
                      std::span<const std::byte> expected)
        : loop_(loop), descriptor_(descriptor), expected_(expected)
    {
    }

    ~receiving_handler() override { ::close(descriptor_); }

    [[nodiscard]] auto descriptor() const noexcept -> int override
    {
        return descriptor_;
    }

    [[nodiscard]] auto valid() const noexcept -> bool
    {
        return size_ == expected_.size() &&
               std::memcmp(received_.data(), expected_.data(), size_) == 0;
    }

private:
    auto on_read() -> void override
    {
        while (size_ < received_.size()) {
            const auto size = recv(descriptor_, received_.data() + size_,
                                   received_.size() - size_, 0);
            if (size > 0) {
                size_ += static_cast<std::size_t>(size);
                continue;
            }
            if (size == -1 && errno == EINTR) continue;
            if (size == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            throw std::system_error(
                size == 0 ? ECONNRESET : errno, std::system_category(), "recv");
        }
        loop_.stop();
    }

    auto on_write() -> void override {}
    auto on_error() -> void override
    {
        throw std::runtime_error("receiving socket failed");
    }

    event_loop& loop_;
    int descriptor_;
    std::span<const std::byte> expected_;
    std::array<std::byte, 64 * 1024> received_ {};
    std::size_t size_ {0};
};

auto backpressure_test() -> bool
{
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                   0, sockets) == -1) {
        return false;
    }

    const int send_buffer_size = 4096;
    if (setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &send_buffer_size,
                   sizeof(send_buffer_size)) == -1) {
        ::close(sockets[0]);
        ::close(sockets[1]);
        return false;
    }

    std::array<std::byte, 64 * 1024> message {};
    for (std::size_t index = 0; index < message.size(); ++index) {
        message[index] = static_cast<std::byte>(index);
    }

    event_loop loop;
    auto sender = std::make_unique<sending_stream>(loop, sockets[0]);
    auto* stream = sender.get();
    auto receiver = std::make_unique<receiving_handler>(loop, sockets[1], message);
    auto* result = receiver.get();
    loop.add(std::move(sender));
    loop.add(std::move(receiver));
    stream->write(message);
    loop.run();
    return result->valid();
}

} // namespace

auto main() -> int
{
    event_loop loop;
    auto throwing = std::make_unique<throwing_handler>(loop);
    const int released_descriptor = throwing->descriptor();
    loop.add(std::move(throwing));

    try {
        loop.run();
        return 1;
    } catch (const std::runtime_error&) {
    }

    auto stopping = std::make_unique<stopping_handler>(loop);
    if (stopping->descriptor() != released_descriptor) return 1;
    loop.add(std::move(stopping));
    loop.run();

    return backpressure_test() ? 0 : 1;
}
