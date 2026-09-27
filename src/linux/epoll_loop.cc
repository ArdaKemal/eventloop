#include "epoll_loop.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <exception>
#include <system_error>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

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

    timer_descriptor_.reset(timerfd_create(
        CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK));
    if (!timer_descriptor_) throw system_error("timerfd_create");

    update_descriptor(signal_descriptor_.get(), true, false, EPOLL_CTL_ADD);
    update_descriptor(stop_descriptor_.get(), true, false, EPOLL_CTL_ADD);
    update_descriptor(wake_descriptor_.get(), true, false, EPOLL_CTL_ADD);
    update_descriptor(timer_descriptor_.get(), true, false, EPOLL_CTL_ADD);
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
    std::optional<std::chrono::steady_clock::duration> delay) -> void
{
    itimerspec value {};
    if (delay) {
        auto nanoseconds = std::chrono::ceil<std::chrono::nanoseconds>(*delay);
        if (nanoseconds <= std::chrono::nanoseconds::zero()) {
            nanoseconds = std::chrono::nanoseconds {1};
        }
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
            nanoseconds);
        const auto remainder = nanoseconds - seconds;
        value.it_value.tv_sec = static_cast<time_t>(seconds.count());
        value.it_value.tv_nsec = static_cast<long>(remainder.count());
    }
    if (timerfd_settime(timer_descriptor_.get(), 0, &value, nullptr) == -1) {
        throw system_error("timerfd_settime");
    }
}

auto epoll_loop::poll(std::span<ready_event> events, bool nonblocking)
    -> poll_result
{
    std::array<epoll_event, 64> native_events {};
    const auto capacity = static_cast<int>(std::min(events.size(), native_events.size()));

    int count;
    do {
        count = epoll_wait(epoll_descriptor_.get(), native_events.data(), capacity,
                           nonblocking ? 0 : -1);
    } while (count == -1 && errno == EINTR);
    if (count == -1) {
        throw system_error("epoll_wait");
    }

    std::size_t output_count = 0;
    bool stop_requested = false;
    bool signal_requested = false;
    bool wake_requested = false;
    bool timer_requested = false;
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
            wake_requested = true;
            continue;
        }
        if (native.data.fd == timer_descriptor_.get()) {
            std::uint64_t value;
            (void)read(timer_descriptor_.get(), &value, sizeof(value));
            timer_requested = true;
            continue;
        }

        events[output_count++] = {
            .descriptor = native.data.fd,
            .readable = (native.events & (EPOLLIN | EPOLLRDHUP)) != 0,
            .writable = (native.events & EPOLLOUT) != 0,
            .error = (native.events & (EPOLLERR | EPOLLHUP)) != 0,
        };
    }
    return {.event_count = output_count,
            .stop_requested = stop_requested,
            .signal_requested = signal_requested,
            .wake_requested = wake_requested,
            .timer_requested = timer_requested};
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
