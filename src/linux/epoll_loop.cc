#include "epoll_loop.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <exception>
#include <system_error>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <unistd.h>

namespace {
[[nodiscard]] auto system_error(const char* operation) -> std::system_error
{
    return {errno, std::system_category(), operation};
}
} // namespace

epoll_loop::epoll_loop()
{
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &signals, &original_signal_mask_) == -1) {
        throw system_error("sigprocmask");
    }

    signal_descriptor_ = signalfd(-1, &signals, SFD_CLOEXEC | SFD_NONBLOCK);
    if (signal_descriptor_ == -1) {
        const auto error = system_error("signalfd");
        sigprocmask(SIG_SETMASK, &original_signal_mask_, nullptr);
        throw error;
    }

    epoll_descriptor_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_descriptor_ == -1) {
        const auto error = system_error("epoll_create1");
        close(signal_descriptor_);
        sigprocmask(SIG_SETMASK, &original_signal_mask_, nullptr);
        throw error;
    }

    stop_descriptor_ = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (stop_descriptor_ == -1) {
        const auto error = system_error("eventfd");
        close(epoll_descriptor_);
        close(signal_descriptor_);
        sigprocmask(SIG_SETMASK, &original_signal_mask_, nullptr);
        throw error;
    }

    wake_descriptor_ = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wake_descriptor_ == -1) {
        const auto error = system_error("eventfd");
        close(stop_descriptor_);
        close(epoll_descriptor_);
        close(signal_descriptor_);
        sigprocmask(SIG_SETMASK, &original_signal_mask_, nullptr);
        throw error;
    }

    try {
        update_descriptor(signal_descriptor_, false, EPOLL_CTL_ADD);
        update_descriptor(stop_descriptor_, false, EPOLL_CTL_ADD);
        update_descriptor(wake_descriptor_, false, EPOLL_CTL_ADD);
    } catch (...) {
        close(wake_descriptor_);
        close(stop_descriptor_);
        close(epoll_descriptor_);
        close(signal_descriptor_);
        sigprocmask(SIG_SETMASK, &original_signal_mask_, nullptr);
        throw;
    }
}

epoll_loop::~epoll_loop()
{
    close(signal_descriptor_);
    close(stop_descriptor_);
    close(wake_descriptor_);
    close(epoll_descriptor_);
    sigprocmask(SIG_SETMASK, &original_signal_mask_, nullptr);
}

auto epoll_loop::add_descriptor(int descriptor) -> void
{
    update_descriptor(descriptor, false, EPOLL_CTL_ADD);
}

auto epoll_loop::remove_descriptor(int descriptor) -> void
{
    if (epoll_ctl(epoll_descriptor_, EPOLL_CTL_DEL, descriptor, nullptr) == -1 &&
        errno != ENOENT && errno != EBADF) {
        throw system_error("epoll_ctl(DEL)");
    }
}

auto epoll_loop::set_write_interest(int descriptor, bool enabled) -> void
{
    update_descriptor(descriptor, enabled, EPOLL_CTL_MOD);
}

auto epoll_loop::request_stop() -> void
{
    const std::uint64_t value = 1;
    if (write(stop_descriptor_, &value, sizeof(value)) == -1 && errno != EAGAIN) {
        throw system_error("eventfd write");
    }
}

auto epoll_loop::wake() noexcept -> void
{
    const std::uint64_t value = 1;
    for (;;) {
        if (write(wake_descriptor_, &value, sizeof(value)) != -1) return;
        if (errno == EINTR) continue;
        if (errno == EAGAIN) return;
        std::terminate();
    }
}

auto epoll_loop::poll(std::span<ready_event> events) -> poll_result
{
    std::array<epoll_event, 64> native_events {};
    const auto capacity = static_cast<int>(std::min(events.size(), native_events.size()));

    int count;
    do {
        count = epoll_wait(epoll_descriptor_, native_events.data(), capacity, -1);
    } while (count == -1 && errno == EINTR);
    if (count == -1) {
        throw system_error("epoll_wait");
    }

    std::size_t output_count = 0;
    bool stop_requested = false;
    bool wake_requested = false;
    for (int index = 0; index < count; ++index) {
        const auto& native = native_events[static_cast<std::size_t>(index)];
        if (native.data.fd == signal_descriptor_) {
            signalfd_siginfo info {};
            (void)read(signal_descriptor_, &info, sizeof(info));
            stop_requested = true;
            continue;
        }
        if (native.data.fd == stop_descriptor_) {
            std::uint64_t value;
            (void)read(stop_descriptor_, &value, sizeof(value));
            stop_requested = true;
            continue;
        }
        if (native.data.fd == wake_descriptor_) {
            std::uint64_t value;
            (void)read(wake_descriptor_, &value, sizeof(value));
            wake_requested = true;
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
            .wake_requested = wake_requested};
}

auto epoll_loop::update_descriptor(int descriptor, bool write_enabled, int operation) -> void
{
    epoll_event event {};
    event.events = EPOLLIN | EPOLLRDHUP;
    if (write_enabled) {
        event.events |= EPOLLOUT;
    }
    event.data.fd = descriptor;
    if (epoll_ctl(epoll_descriptor_, operation, descriptor, &event) == -1) {
        throw system_error("epoll_ctl");
    }
}
