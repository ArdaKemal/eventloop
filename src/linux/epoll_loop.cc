#include "epoll_loop.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <ctime>
#include <exception>
#include <limits>
#include <system_error>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <unistd.h>

namespace eventloop {

namespace {
[[nodiscard]] auto system_error(const char* operation) -> std::system_error
{
    return {errno, std::system_category(), operation};
}

struct signal_mask_state {
    std::size_t users {0};
    sigset_t original {};
};

thread_local signal_mask_state thread_signal_mask;
} // namespace

epoll_loop::signal_mask_guard::signal_mask_guard()
    : owner_thread_(std::this_thread::get_id())
{
    sigemptyset(&signals_);
    sigaddset(&signals_, SIGINT);
    sigaddset(&signals_, SIGTERM);
    if (thread_signal_mask.users == 0) {
        if (sigprocmask(SIG_BLOCK, &signals_,
                        &thread_signal_mask.original) == -1) {
            throw system_error("sigprocmask");
        }
    }
    ++thread_signal_mask.users;
}

epoll_loop::signal_mask_guard::~signal_mask_guard()
{
    if (owner_thread_ != std::this_thread::get_id() ||
        thread_signal_mask.users == 0) {
        std::terminate();
    }
    if (--thread_signal_mask.users == 0) {
        sigprocmask(SIG_SETMASK, &thread_signal_mask.original, nullptr);
    }
}

epoll_loop::epoll_loop()
{
    signal_descriptor_.reset(signalfd(
        -1, &signal_mask_.signals(), SFD_CLOEXEC | SFD_NONBLOCK));
    if (!signal_descriptor_) throw system_error("signalfd");

    epoll_descriptor_.reset(epoll_create1(EPOLL_CLOEXEC));
    if (!epoll_descriptor_) throw system_error("epoll_create1");

    stop_descriptor_.reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (!stop_descriptor_) throw system_error("eventfd");

    wake_descriptor_.reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (!wake_descriptor_) throw system_error("eventfd");

    update_descriptor(signal_descriptor_.get(), true, false, EPOLL_CTL_ADD);
    update_descriptor(stop_descriptor_.get(), true, false, EPOLL_CTL_ADD);
    update_descriptor(wake_descriptor_.get(), true, false, EPOLL_CTL_ADD);
}

epoll_loop::~epoll_loop() = default;

auto epoll_loop::add_descriptor(int descriptor, bool read_enabled) -> void
{
    update_descriptor(descriptor, read_enabled, false, EPOLL_CTL_ADD);
}

auto epoll_loop::remove_descriptor(int descriptor) -> void
{
    if (epoll_ctl(epoll_descriptor_.get(), EPOLL_CTL_DEL, descriptor, nullptr) == -1 &&
        errno != ENOENT && errno != EBADF) {
        throw system_error("epoll_ctl(DEL)");
    }
}

auto epoll_loop::set_io_interest(int descriptor, bool read_enabled,
                                bool write_enabled) -> void
{
    update_descriptor(descriptor, read_enabled, write_enabled, EPOLL_CTL_MOD);
}

auto epoll_loop::set_write_interest(int descriptor, bool enabled) -> void
{
    set_io_interest(descriptor, true, enabled);
}

auto epoll_loop::request_stop() -> void
{
    const std::uint64_t value = 1;
    for (;;) {
        if (write(stop_descriptor_.get(), &value, sizeof(value)) != -1) return;
        if (errno == EINTR) continue;
        if (errno == EAGAIN) return;
        throw system_error("eventfd write");
    }
}

auto epoll_loop::wake() noexcept -> void
{
    const std::uint64_t value = 1;
    for (;;) {
        if (write(wake_descriptor_.get(), &value, sizeof(value)) != -1) return;
        if (errno == EINTR) continue;
        if (errno == EAGAIN) return;
        std::terminate();
    }
}

auto epoll_loop::arm_timer(
    std::optional<std::chrono::steady_clock::duration> delay) noexcept -> void
{
    if (!delay) {
        deadline_.reset();
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    // Deadlines saturate, so a long delay must not overflow the time point.
    deadline_ = *delay <= std::chrono::steady_clock::duration::zero() ? now
        : *delay >= std::chrono::steady_clock::time_point::max() - now
            ? std::chrono::steady_clock::time_point::max() : now + *delay;
}

// The timeout is recomputed from the deadline on every call, so a retry
// after EINTR waits only for the remainder.
auto epoll_loop::wait(epoll_event* events, int capacity, bool nonblocking)
    -> int
{
    using namespace std::chrono;
    std::optional<steady_clock::duration> remaining;
    if (nonblocking) remaining = steady_clock::duration::zero();
    else if (deadline_)
        remaining = std::max(*deadline_ - steady_clock::now(),
                             steady_clock::duration::zero());
    if (nanosecond_timeouts_) {
        timespec timeout {};
        if (remaining) {
            const auto seconds = duration_cast<std::chrono::seconds>(*remaining);
            timeout.tv_sec = static_cast<time_t>(seconds.count());
            timeout.tv_nsec = static_cast<long>(
                duration_cast<nanoseconds>(*remaining - seconds).count());
        }
        const int count = epoll_pwait2(epoll_descriptor_.get(), events, capacity,
                                       remaining ? &timeout : nullptr, nullptr);
        // Seccomp filters that predate the syscall may report EPERM.
        if (count != -1 || (errno != ENOSYS && errno != EPERM)) return count;
        nanosecond_timeouts_ = false;
    }
    int milliseconds = -1;
    if (remaining) {
        milliseconds = static_cast<int>(std::min<steady_clock::rep>(
            ceil<std::chrono::milliseconds>(*remaining).count(),
            std::numeric_limits<int>::max()));
    }
    return epoll_wait(epoll_descriptor_.get(), events, capacity, milliseconds);
}

auto epoll_loop::poll(std::span<ready_event> events, bool nonblocking)
    -> poll_result
{
    std::array<epoll_event, 64> native_events {};
    const auto capacity = static_cast<int>(std::min(events.size(), native_events.size()));

    int count;
    do {
        count = wait(native_events.data(), capacity, nonblocking);
    } while (count == -1 && errno == EINTR);
    if (count == -1) {
        throw system_error("epoll_wait");
    }

    std::size_t output_count = 0;
    bool stop_requested = false;
    bool signal_requested = false;
    for (int index = 0; index < count; ++index) {
        const auto& native = native_events[static_cast<std::size_t>(index)];
        if (native.data.fd == signal_descriptor_.get()) {
            signalfd_siginfo info {};
            (void)read(signal_descriptor_.get(), &info, sizeof(info));
            signal_requested = true;
            continue;
        }
        if (native.data.fd == stop_descriptor_.get()) {
            std::uint64_t value;
            (void)read(stop_descriptor_.get(), &value, sizeof(value));
            stop_requested = true;
            continue;
        }
        if (native.data.fd == wake_descriptor_.get()) {
            std::uint64_t value;
            (void)read(wake_descriptor_.get(), &value, sizeof(value));
            continue;
        }

        events[output_count++] = {
            .descriptor = native.data.fd,
            .readable = (native.events & (EPOLLIN | EPOLLRDHUP)) != 0,
            .writable = (native.events & EPOLLOUT) != 0,
            // EPOLLHUP may accompany readable buffered data. Drain it before
            // reporting the hangup so a final reply is not lost.
            .error = (native.events & EPOLLERR) != 0 ||
                     ((native.events & EPOLLHUP) != 0 &&
                      (native.events & EPOLLIN) == 0),
        };
    }
    return {.event_count = output_count,
            .stop_requested = stop_requested,
            .signal_requested = signal_requested};
}

auto epoll_loop::update_descriptor(int descriptor, bool read_enabled,
                                   bool write_enabled, int operation) -> void
{
    epoll_event event {};
    event.events = 0;
    if (read_enabled) event.events |= EPOLLIN | EPOLLRDHUP;
    if (write_enabled) {
        event.events |= EPOLLOUT;
    }
    event.data.fd = descriptor;
    if (epoll_ctl(epoll_descriptor_.get(), operation, descriptor, &event) == -1) {
        throw system_error("epoll_ctl");
    }
}

} // namespace eventloop
