#include "eventloop/event_loop.h"
#include "eventloop/tcp_stream.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <stdexcept>
#include <system_error>
#include <thread>

#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

[[nodiscard]] auto make_event(unsigned int initial_value = 1) -> int
{
    const int descriptor = eventfd(initial_value, EFD_CLOEXEC | EFD_NONBLOCK);
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

class fairness_handler final : public notifiable {
public:
    fairness_handler(event_loop& loop, int& post_count, int& observed_count)
        : loop_(loop), post_count_(post_count), observed_count_(observed_count),
          descriptor_(make_event(0))
    {
    }

    ~fairness_handler() override { ::close(descriptor_); }

    [[nodiscard]] auto descriptor() const noexcept -> int override
    {
        return descriptor_;
    }

private:
    auto on_read() -> void override
    {
        std::uint64_t value;
        (void)::read(descriptor_, &value, sizeof(value));
        observed_count_ = post_count_;
        loop_.stop();
    }

    auto on_write() -> void override {}
    auto on_error() -> void override { loop_.stop(); }

    event_loop& loop_;
    int& post_count_;
    int& observed_count_;
    int descriptor_;
};

struct reposting_task {
    static constexpr int limit = 512;

    auto run() noexcept -> void
    {
        ++count;
        if (count == 1) {
            const std::uint64_t value = 1;
            while (::write(descriptor, &value, sizeof(value)) == -1) {
                if (errno == EINTR) continue;
                loop.stop();
                return;
            }
        }
        if (count < limit &&
            !loop.post(execution_task([this]() noexcept { run(); }))) {
            loop.stop();
        }
    }

    event_loop& loop;
    int descriptor;
    int& count;
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

auto post_tests() -> bool
{
    {
        event_loop loop;
        bool ran = false;
        std::thread::id observed;
        const auto expected = std::this_thread::get_id();
        if (!loop.post(execution_task([&]() noexcept {
                ran = true;
                observed = std::this_thread::get_id();
                loop.stop();
            }))) {
            return false;
        }
        loop.run();
        if (!ran || observed != expected) return false;
    }

    {
        event_loop loop;
        std::atomic<bool> ran {false};
        std::atomic<bool> on_loop {false};
        const auto expected = std::this_thread::get_id();
        std::thread poster([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            if (!loop.post(execution_task([&]() noexcept {
                    ran.store(true);
                    on_loop.store(std::this_thread::get_id() == expected);
                    loop.stop();
                }))) {
                loop.stop();
            }
        });
        loop.run();
        poster.join();
        if (!ran.load() || !on_loop.load()) return false;
    }

    {
        event_loop loop(event_loop_options {.post_capacity = 2});
        int count = 0;
        const bool first = loop.post(execution_task([&]() noexcept { ++count; }));
        const bool second = loop.post(execution_task([&]() noexcept {
            ++count;
            loop.stop();
        }));
        execution_task third([&]() noexcept { ++count; });
        const bool third_accepted = loop.post(std::move(third));
        if (!first || !second || third_accepted || !third) return false;
        loop.run();
        if (count != 2) return false;
    }

    {
        event_loop loop;
        int post_count = 0;
        int observed_count = -1;
        auto handler = std::make_unique<fairness_handler>(
            loop, post_count, observed_count);
        const int descriptor = handler->descriptor();
        loop.add(std::move(handler));

        reposting_task task {loop, descriptor, post_count};
        if (!loop.post(execution_task([&task]() noexcept { task.run(); }))) {
            return false;
        }
        loop.run();
        if (observed_count <= 0 ||
            observed_count >= reposting_task::limit) {
            return false;
        }
    }

    return true;
}

auto executor_integration_test() -> bool
{
    event_loop loop(event_loop_options {.worker_count = 2});
    const auto loop_thread = std::this_thread::get_id();
    std::atomic<bool> offloaded {false};
    std::atomic<bool> on_worker {false};
    std::atomic<bool> returned {false};
    std::atomic<bool> on_loop {false};

    loop.task_executor().execute(execution_task([&]() noexcept {
        on_worker.store(std::this_thread::get_id() != loop_thread);
        offloaded.store(true);
        if (!loop.post(execution_task([&]() noexcept {
                returned.store(true);
                on_loop.store(std::this_thread::get_id() == loop_thread);
                loop.stop();
            }))) {
            loop.stop();
        }
    }));

    loop.run();
    return offloaded.load() && on_worker.load() && returned.load() &&
           on_loop.load();
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

    if (!backpressure_test()) return 1;
    if (!post_tests()) return 1;
    if (!executor_integration_test()) return 1;
    return 0;
}
