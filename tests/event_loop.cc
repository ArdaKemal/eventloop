#include "eventloop/event_loop.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <new>
#include <span>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>

#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(EVENTLOOP_TEST_WRAP_TIMERFD)
namespace {
int injected_timer_arm_errors = 0;
}

extern "C" auto __real_timerfd_settime(int descriptor, int flags,
                                         const itimerspec* value,
                                         itimerspec* old_value) -> int;

extern "C" auto __wrap_timerfd_settime(int descriptor, int flags,
                                         const itimerspec* value,
                                         itimerspec* old_value) -> int
{
    if (injected_timer_arm_errors != 0) {
        --injected_timer_arm_errors;
        errno = EIO;
        return -1;
    }
    return __real_timerfd_settime(descriptor, flags, value, old_value);
}
#endif

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

class shutdown_handler final : public notifiable {
public:
    shutdown_handler(event_loop& loop, int& shutdowns, bool& destroyed,
                     bool drain)
        : loop_(loop), shutdowns_(shutdowns), destroyed_(destroyed),
          drain_(drain), descriptor_(make_event(0))
    {
    }

    ~shutdown_handler() override
    {
        destroyed_ = true;
        ::close(descriptor_);
    }

    [[nodiscard]] auto descriptor() const noexcept -> int override
    {
        return descriptor_;
    }

private:
    auto on_read() -> void override {}
    auto on_write() -> void override {}
    auto on_error() -> void override {}
    auto on_shutdown() -> void override
    {
        ++shutdowns_;
        if (drain_) loop_.remove(descriptor_);
    }

    event_loop& loop_;
    int& shutdowns_;
    bool& destroyed_;
    bool drain_;
    int descriptor_;
};

class reentrant_shutdown_handler final : public notifiable {
public:
    reentrant_shutdown_handler(event_loop& loop, bool& alive_in_read,
                               bool& alive_in_shutdown, bool& destroyed)
        : loop_(loop), alive_in_read_(alive_in_read),
          alive_in_shutdown_(alive_in_shutdown), destroyed_(destroyed),
          descriptor_(make_event())
    {
    }

    ~reentrant_shutdown_handler() override
    {
        destroyed_ = true;
        ::close(descriptor_);
    }

    [[nodiscard]] auto descriptor() const noexcept -> int override
    {
        return descriptor_;
    }

private:
    auto on_read() -> void override
    {
        loop_.shutdown(event_loop::clock::duration::zero());
        alive_in_read_ = !destroyed_;
    }

    auto on_write() -> void override {}
    auto on_error() -> void override {}
    auto on_shutdown() -> void override
    {
        loop_.shutdown(event_loop::clock::duration::zero());
        alive_in_shutdown_ = !destroyed_;
    }

    event_loop& loop_;
    bool& alive_in_read_;
    bool& alive_in_shutdown_;
    bool& destroyed_;
    int descriptor_;
};

class throwing_shutdown_handler final : public notifiable {
public:
    explicit throwing_shutdown_handler(bool& destroyed)
        : destroyed_(destroyed), descriptor_(make_event(0)) {}

    ~throwing_shutdown_handler() override
    {
        destroyed_ = true;
        ::close(descriptor_);
    }

    [[nodiscard]] auto descriptor() const noexcept -> int override
    {
        return descriptor_;
    }

private:
    auto on_read() -> void override {}
    auto on_write() -> void override {}
    auto on_error() -> void override {}
    auto on_shutdown() -> void override
    {
        throw std::runtime_error("expected shutdown failure");
    }

    bool& destroyed_;
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

class throwing_callback_stream final : public tcp_stream {
public:
    throwing_callback_stream(event_loop& loop, int descriptor,
                             bool throw_on_close)
        : tcp_stream(loop, descriptor), throw_on_close_(throw_on_close) {}

private:
    auto on_data(std::span<const std::byte>) -> void override
    {
        if (!throw_on_close_) {
            throw std::runtime_error("expected data callback failure");
        }
    }

    auto on_close() -> void override
    {
        if (throw_on_close_) {
            throw std::runtime_error("expected close callback failure");
        }
    }

    bool throw_on_close_;
};

class throwing_write_drained_stream final : public tcp_stream {
public:
    using tcp_stream::tcp_stream;

private:
    auto on_data(std::span<const std::byte>) -> void override {}
    auto on_write_drained() -> void override
    {
        throw std::runtime_error("expected write callback failure");
    }
};

class self_closing_stream final : public tcp_stream {
public:
    using tcp_stream::tcp_stream;

private:
    auto on_data(std::span<const std::byte>) -> void override {}
    auto on_write_drained() -> void override { close(); }
};

auto callback_failure_test(bool throw_on_close) -> bool
{
    int sockets[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
        return false;
    }
    unique_fd peer(sockets[1]);
    event_loop loop;
    loop.add(std::make_unique<throwing_callback_stream>(
        loop, sockets[0], throw_on_close));
    if (throw_on_close) {
        if (::shutdown(peer.get(), SHUT_WR) != 0) return false;
    } else {
        const char byte = 'x';
        if (::send(peer.get(), &byte, 1, 0) != 1) return false;
    }
    try {
        (void)loop.run();
        return false;
    } catch (const std::runtime_error&) {
    }
    return ::fcntl(sockets[0], F_GETFD) == -1 && errno == EBADF;
}

auto write_callback_failure_test() -> bool
{
    int sockets[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
        return false;
    }
    unique_fd peer(sockets[1]);
    event_loop loop;
    auto sender = std::make_unique<throwing_write_drained_stream>(loop,
                                                                  sockets[0]);
    auto* stream = sender.get();
    loop.add(std::move(sender));
    constexpr std::array<std::byte, 1> byte {std::byte {'x'}};
    try {
        stream->write(byte);
        return false;
    } catch (const std::runtime_error&) {
    }
    return ::fcntl(sockets[0], F_GETFD) == -1 && errno == EBADF;
}

auto self_closing_write_test() -> bool
{
    int sockets[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
        return false;
    }
    unique_fd peer(sockets[1]);
    event_loop loop;
    auto sender = std::make_unique<self_closing_stream>(loop, sockets[0]);
    auto* stream = sender.get();
    loop.add(std::move(sender));
    constexpr std::array<std::byte, 1> byte {std::byte {'x'}};
    stream->write(byte);
    return ::fcntl(sockets[0], F_GETFD) == -1 && errno == EBADF;
}

class throwing_owned_stream final : public tcp_stream {
public:
    throwing_owned_stream(event_loop& loop, unique_fd descriptor)
        : tcp_stream(loop, std::move(descriptor))
    {
        throw std::runtime_error("expected stream construction failure");
    }

private:
    auto on_data(std::span<const std::byte>) -> void override {}
};

auto descriptor_ownership_test() -> bool
{
    event_loop loop;
    try {
        sending_stream invalid(loop, -1);
        return false;
    } catch (const std::invalid_argument&) {
    }
    const int descriptor = make_event(0);
    try {
        auto stream = std::make_unique<throwing_owned_stream>(
            loop, unique_fd(descriptor));
        return false;
    } catch (const std::runtime_error&) {
    }
    return ::fcntl(descriptor, F_GETFD) == -1 && errno == EBADF;
}

auto file_transfer_ownership_test() -> bool
{
    int sockets[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
        return false;
    }
    unique_fd peer(sockets[1]);
    event_loop loop;
    sending_stream stream(loop, sockets[0]);
    try {
        stream.send_file({}, unique_fd {}, 1);
        return false;
    } catch (const std::invalid_argument&) {
    }
    try {
        stream.send_file({}, stream.descriptor(), 1);
        return false;
    } catch (const std::invalid_argument&) {
    }
    if (::fcntl(stream.descriptor(), F_GETFD) == -1) return false;

    const int descriptor = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (descriptor == -1) return false;
    const std::array<std::byte, 64 * 1024 + 1> oversized {};
    try {
        stream.send_file(oversized, unique_fd(descriptor), 1);
        return false;
    } catch (const std::length_error&) {
    }
    return ::fcntl(descriptor, F_GETFD) == -1 && errno == EBADF;
}

class failing_acceptor final : public tcp_acceptor {
public:
    failing_acceptor(event_loop& loop, int& accepted_descriptor)
        : tcp_acceptor(loop, 0), accepted_descriptor_(accepted_descriptor) {}

private:
    auto on_accept(int descriptor) -> void override
    {
        on_accept_owned(unique_fd(descriptor));
    }

    auto on_accept_owned(unique_fd descriptor) -> void override
    {
        accepted_descriptor_ = descriptor.get();
        throw std::bad_alloc {};
    }

    int& accepted_descriptor_;
};

class legacy_acceptor final : public tcp_acceptor {
public:
    legacy_acceptor(event_loop& loop, bool& accepted)
        : tcp_acceptor(loop, 0), accepted_(accepted) {}

private:
    auto on_accept(int descriptor) -> void override
    {
        unique_fd client(descriptor);
        accepted_ = true;
        owner().stop();
    }

    bool& accepted_;
};

[[nodiscard]] auto connect_to(int listening_descriptor) -> unique_fd
{
    sockaddr_in address {};
    socklen_t address_size = sizeof(address);
    if (::getsockname(listening_descriptor,
                      reinterpret_cast<sockaddr*>(&address),
                      &address_size) != 0) return {};
    unique_fd client(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (!client || ::connect(client.get(),
                             reinterpret_cast<sockaddr*>(&address),
                             address_size) != 0) return {};
    return client;
}

auto accepted_descriptor_failure_test() -> bool
{
    event_loop loop;
    int accepted_descriptor = -1;
    auto acceptor = std::make_unique<failing_acceptor>(loop, accepted_descriptor);
    auto client = connect_to(acceptor->descriptor());
    if (!client) return false;
    loop.add(std::move(acceptor));
    try {
        (void)loop.run();
        return false;
    } catch (const std::bad_alloc&) {
    }
    return accepted_descriptor != -1 &&
           ::fcntl(accepted_descriptor, F_GETFD) == -1 && errno == EBADF;
}

auto legacy_acceptor_test() -> bool
{
    event_loop loop;
    bool accepted = false;
    auto acceptor = std::make_unique<legacy_acceptor>(loop, accepted);
    auto client = connect_to(acceptor->descriptor());
    if (!client) return false;
    loop.add(std::move(acceptor));
    return loop.run() == event_loop_result::stopped && accepted;
}

auto empty_handler_test() -> bool
{
    event_loop loop;
    try {
        loop.add({});
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}

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
        execution_task empty;
        if (loop.post(std::move(empty))) return false;
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

auto timer_tests() -> bool
{
    event_loop loop;
    bool cancelled_ran = false;
    bool first_ran = false;
    bool second_ran = false;

    const auto cancelled = loop.schedule_after(
        std::chrono::milliseconds {1},
        execution_task([&]() noexcept { cancelled_ran = true; }));
    if (!loop.cancel(cancelled) || loop.cancel(cancelled)) return false;
    const auto distant = loop.schedule_after(
        event_loop::clock::duration::max(),
        execution_task([&]() noexcept { cancelled_ran = true; }));
    if (!loop.cancel(distant)) return false;

    const auto deadline = event_loop::clock::now() +
                          std::chrono::milliseconds {5};
    (void)loop.schedule_at(
        deadline, execution_task([&]() noexcept { first_ran = true; }));
    (void)loop.schedule_at(deadline, execution_task([&]() noexcept {
        second_ran = true;
        loop.stop();
    }));

    if (loop.run() != event_loop_result::stopped) return false;
    return first_ran && second_ran && !cancelled_ran &&
           event_loop::clock::now() >= deadline;
}

auto timer_arm_failure_test() -> bool
{
#if defined(EVENTLOOP_TEST_WRAP_TIMERFD)
    event_loop loop;
    bool rejected_ran = false;
    bool accepted_ran = false;
    (void)loop.schedule_after(std::chrono::milliseconds {5},
                              execution_task([&]() noexcept {
                                  accepted_ran = true;
                                  loop.stop();
                              }));
    injected_timer_arm_errors = 1;
    try {
        (void)loop.schedule_after(std::chrono::milliseconds {1},
                                  execution_task([&]() noexcept {
                                      rejected_ran = true;
                                  }));
        return false;
    } catch (const std::system_error& error) {
        if (error.code().value() != EIO) return false;
    }
    if (injected_timer_arm_errors != 0 ||
        loop.run() != event_loop_result::stopped) return false;
    return accepted_ran && !rejected_ran;
#else
    return true;
#endif
}

auto shutdown_tests() -> bool
{
    {
        event_loop loop;
        bool destroyed = false;
        loop.add(std::make_unique<throwing_shutdown_handler>(destroyed));
        try {
            loop.shutdown(std::chrono::seconds {1});
            return false;
        } catch (const std::runtime_error&) {
        }
        if (!destroyed || loop.run() != event_loop_result::stopped) {
            return false;
        }
    }

    {
        event_loop loop;
        bool alive_in_read = false;
        bool alive_in_shutdown = false;
        bool destroyed = false;
        loop.add(std::make_unique<reentrant_shutdown_handler>(
            loop, alive_in_read, alive_in_shutdown, destroyed));
        if (loop.run() != event_loop_result::stopped || !alive_in_read ||
            !alive_in_shutdown || !destroyed) {
            return false;
        }
    }

    {
        event_loop loop;
        int shutdowns = 0;
        bool destroyed = false;
        loop.add(std::make_unique<shutdown_handler>(
            loop, shutdowns, destroyed, true));
        loop.shutdown(std::chrono::seconds {1});
        if (loop.run() != event_loop_result::stopped || shutdowns != 1 ||
            !destroyed) {
            return false;
        }
    }

    {
        event_loop loop;
        int shutdowns = 0;
        bool destroyed = false;
        loop.add(std::make_unique<shutdown_handler>(
            loop, shutdowns, destroyed, false));
        const auto started = event_loop::clock::now();
        loop.shutdown(std::chrono::milliseconds {5});
        if (loop.run() != event_loop_result::stopped || shutdowns != 1 ||
            !destroyed ||
            event_loop::clock::now() - started < std::chrono::milliseconds {5}) {
            return false;
        }
    }

    {
        event_loop loop;
        int shutdowns = 0;
        bool destroyed = false;
        bool drained = false;
        auto handler = std::make_unique<shutdown_handler>(
            loop, shutdowns, destroyed, false);
        const int descriptor = handler->descriptor();
        loop.add(std::move(handler));
        loop.shutdown(event_loop::clock::duration::max());
        (void)loop.schedule_after(std::chrono::milliseconds {5},
                                  execution_task([&]() noexcept {
                                      drained = true;
                                      loop.remove(descriptor);
                                  }));
        if (loop.run() != event_loop_result::stopped || !drained ||
            shutdowns != 1 || !destroyed) {
            return false;
        }
    }
    return true;
}

auto signal_test() -> bool
{
    event_loop loop;
    std::thread interrupter([] {
        std::this_thread::sleep_for(std::chrono::milliseconds {5});
        (void)::kill(::getpid(), SIGTERM);
    });
    const auto result = loop.run();
    interrupter.join();
    return result == event_loop_result::interrupted;
}

auto nested_signal_mask_test() -> bool
{
    sigset_t signals {};
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    sigset_t original {};
    if (sigprocmask(SIG_UNBLOCK, &signals, &original) == -1) return false;

    bool valid = false;
    try {
        auto first = std::make_unique<event_loop>();
        auto second = std::make_unique<event_loop>();
        first.reset();
        sigset_t current {};
        valid = sigprocmask(SIG_SETMASK, nullptr, &current) == 0 &&
                sigismember(&current, SIGINT) == 1 &&
                sigismember(&current, SIGTERM) == 1;
        second.reset();
        valid = valid && sigprocmask(SIG_SETMASK, nullptr, &current) == 0 &&
                sigismember(&current, SIGINT) == 0 &&
                sigismember(&current, SIGTERM) == 0;
    } catch (...) {
        sigprocmask(SIG_SETMASK, &original, nullptr);
        return false;
    }
    sigprocmask(SIG_SETMASK, &original, nullptr);
    return valid;
}

} // namespace

auto main() -> int
{
    if (!nested_signal_mask_test()) return 1;
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
    if (!callback_failure_test(false) || !callback_failure_test(true) ||
        !write_callback_failure_test() || !self_closing_write_test()) return 1;
    if (!descriptor_ownership_test()) return 1;
    if (!file_transfer_ownership_test()) return 1;
    if (!accepted_descriptor_failure_test()) return 1;
    if (!legacy_acceptor_test()) return 1;
    if (!empty_handler_test()) return 1;
    if (!post_tests()) return 1;
    if (!executor_integration_test()) return 1;
    if (!timer_tests()) return 1;
    if (!timer_arm_failure_test()) return 1;
    if (!shutdown_tests()) return 1;
    if (!signal_test()) return 1;
    return 0;
}
