#include "kqueue_loop.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <exception>
#include <stdexcept>
#include <system_error>

#include <fcntl.h>
#include <sys/event.h>
#include <sys/time.h>

namespace eventloop {
namespace {
constexpr unsigned int stop_identifier = 1;
constexpr unsigned int wake_identifier = 2;

struct signal_mask_state {
    std::size_t users {0};
    sigset_t original {};
};

thread_local signal_mask_state thread_signals;

[[nodiscard]] auto system_error(const char* operation) -> std::system_error
{
    return {errno, std::system_category(), operation};
}

auto change_filter(int queue, uintptr_t identifier, short filter,
                   unsigned short flags, unsigned int notes = 0) -> void
{
    struct kevent change {};
    EV_SET(&change, identifier, filter, flags, notes, 0, nullptr);
    // No eventlist: registration errors are reported by the syscall, and this
    // cannot consume an unrelated pending readiness or wake notification.
    while (::kevent(queue, &change, 1, nullptr, 0, nullptr) == -1) {
        if (errno == EINTR) continue;
        throw system_error("kevent change");
    }
}
} // namespace

kqueue_loop::signal_guard::signal_guard()
    : owner_thread_(std::this_thread::get_id())
{
    sigemptyset(&signals_);
    sigaddset(&signals_, SIGINT);
    sigaddset(&signals_, SIGTERM);
    if (thread_signals.users == 0 &&
        ::sigprocmask(SIG_BLOCK, &signals_, &thread_signals.original) == -1) {
        throw system_error("sigprocmask");
    }
    ++thread_signals.users;
}

kqueue_loop::signal_guard::~signal_guard()
{
    if (owner_thread_ != std::this_thread::get_id() || thread_signals.users == 0) {
        std::terminate();
    }
    if (--thread_signals.users == 0 &&
        ::sigprocmask(SIG_SETMASK, &thread_signals.original, nullptr) == -1)
        std::terminate();
}

kqueue_loop::kqueue_loop() : queue_(::kqueue())
{
    if (!queue_) throw system_error("kqueue");
    const int flags = ::fcntl(queue_.get(), F_GETFD);
    if (flags == -1 || ::fcntl(queue_.get(), F_SETFD, flags | FD_CLOEXEC) == -1)
        throw system_error("fcntl kqueue");
    change_filter(queue_.get(), stop_identifier, EVFILT_USER, EV_ADD | EV_CLEAR);
    change_filter(queue_.get(), wake_identifier, EVFILT_USER, EV_ADD | EV_CLEAR);
    // EVFILT_SIGNAL observes signal attempts while the owner thread has these
    // signals blocked, matching the epoll backend's signalfd behavior.
    change_filter(queue_.get(), SIGINT, EVFILT_SIGNAL, EV_ADD | EV_CLEAR);
    change_filter(queue_.get(), SIGTERM, EVFILT_SIGNAL, EV_ADD | EV_CLEAR);
}

auto kqueue_loop::add_descriptor(int descriptor, bool read_enabled) -> void
{
    change_filter(queue_.get(), static_cast<uintptr_t>(descriptor), EVFILT_READ,
                  EV_ADD | (read_enabled ? EV_ENABLE : EV_DISABLE));
    try {
        change_filter(queue_.get(), static_cast<uintptr_t>(descriptor),
                      EVFILT_WRITE, EV_ADD | EV_DISABLE);
    } catch (...) {
        const auto error = std::current_exception();
        try { remove_descriptor(descriptor); }
        catch (...) {} // Preserve the registration failure during cleanup.
        std::rethrow_exception(error);
    }
}

auto kqueue_loop::remove_descriptor(int descriptor) -> void
{
    constexpr std::array filters {
        static_cast<short>(EVFILT_READ), static_cast<short>(EVFILT_WRITE)};
    for (const short filter : filters) {
        try {
            change_filter(queue_.get(), static_cast<uintptr_t>(descriptor),
                          filter, EV_DELETE);
        } catch (const std::system_error& error) {
            if (error.code().value() != ENOENT && error.code().value() != EBADF)
                throw;
        }
    }
}

auto kqueue_loop::set_io_interest(int descriptor, bool read_enabled,
                                 bool write_enabled) -> void
{
    change_filter(queue_.get(), static_cast<uintptr_t>(descriptor), EVFILT_READ,
                  read_enabled ? EV_ENABLE : EV_DISABLE);
    change_filter(queue_.get(), static_cast<uintptr_t>(descriptor), EVFILT_WRITE,
                  write_enabled ? EV_ENABLE : EV_DISABLE);
}

auto kqueue_loop::set_write_interest(int descriptor, bool enabled) -> void
{
    set_io_interest(descriptor, true, enabled);
}

auto kqueue_loop::trigger(unsigned int identifier) -> void
{
    change_filter(queue_.get(), identifier, EVFILT_USER, 0, NOTE_TRIGGER);
}

auto kqueue_loop::request_stop() -> void { trigger(stop_identifier); }

auto kqueue_loop::wake() noexcept -> void
{
    try { trigger(wake_identifier); }
    catch (...) { std::terminate(); }
}

auto kqueue_loop::arm_timer(
    std::optional<std::chrono::steady_clock::duration> delay) noexcept -> void
{
    if (!delay) { deadline_.reset(); return; }
    const auto now = std::chrono::steady_clock::now();
    const auto remaining = std::chrono::steady_clock::time_point::max() - now;
    deadline_ = *delay <= std::chrono::steady_clock::duration::zero() ? now :
        *delay >= remaining ? std::chrono::steady_clock::time_point::max() :
        now + *delay;
}

auto kqueue_loop::poll(std::span<ready_event> events, bool nonblocking)
    -> poll_result
{
    if (events.empty()) throw std::invalid_argument("empty kqueue event buffer");
    std::array<struct kevent, 64> native_events {};
    const int capacity = static_cast<int>(std::min(events.size(), native_events.size()));
    int count;
    for (;;) {
        timespec timeout {};
        const timespec* timeout_pointer = nullptr;
        if (nonblocking) {
            timeout_pointer = &timeout;
        } else if (deadline_) {
            const auto now = std::chrono::steady_clock::now();
            if (*deadline_ > now) {
                const auto delay = *deadline_ - now;
                const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(delay);
                const auto remainder = std::chrono::ceil<std::chrono::nanoseconds>(delay - seconds);
                timeout.tv_sec = static_cast<time_t>(seconds.count());
                timeout.tv_nsec = static_cast<long>(remainder.count());
                if (timeout.tv_nsec == 1'000'000'000L) {
                    ++timeout.tv_sec;
                    timeout.tv_nsec = 0;
                }
            }
            timeout_pointer = &timeout;
        }
        count = ::kevent(queue_.get(), nullptr, 0, native_events.data(),
                         capacity, timeout_pointer);
        if (count >= 0) break;
        if (errno != EINTR) throw system_error("kevent wait");
        // A signal handler may interrupt the wait before its filter is read.
        // Retry with the remaining deadline, never the original timeout.
    }

    poll_result result {};
    if (deadline_ && std::chrono::steady_clock::now() >= *deadline_) {
        result.timer_requested = true;
        deadline_.reset();
    }
    for (int index = 0; index < count; ++index) {
        const auto& native = native_events[static_cast<std::size_t>(index)];
        if ((native.flags & EV_ERROR) != 0 && native.data != 0)
            throw std::system_error(static_cast<int>(native.data),
                                    std::system_category(), "kevent event");
        if (native.filter == EVFILT_USER) {
            if (native.ident == stop_identifier) result.stop_requested = true;
            if (native.ident == wake_identifier) result.wake_requested = true;
            continue;
        }
        if (native.filter == EVFILT_SIGNAL) {
            // EVFILT_SIGNAL observes a blocked signal without consuming it.
            // Retire the pending signal before restoring the owner's mask,
            // otherwise its default disposition would run on loop destruction.
            // Darwin has no sigtimedwait; only call sigwait after sigpending
            // confirms this blocked signal is already available.
            sigset_t pending {};
            const int signal = static_cast<int>(native.ident);
            if (::sigpending(&pending) == -1) throw system_error("sigpending");
            if (sigismember(&pending, signal) == 1) {
                sigset_t selected {};
                sigemptyset(&selected);
                sigaddset(&selected, signal);
                int received = 0;
                const int error = ::sigwait(&selected, &received);
                if (error != 0)
                    throw std::system_error(error, std::system_category(), "sigwait");
            }
            result.signal_requested = true;
            continue;
        }
        // Merge the two filters so a handler receives one combined notification.
        const int descriptor = static_cast<int>(native.ident);
        std::size_t output = 0;
        while (output < result.event_count && events[output].descriptor != descriptor)
            ++output;
        if (output == result.event_count)
            events[result.event_count++] = {descriptor, false, false, false};
        auto& event = events[output];
        event.readable |= native.filter == EVFILT_READ;
        event.writable |= native.filter == EVFILT_WRITE;
        // Read EOF remains readable so buffered bytes and a zero-length read
        // reach the coroutine. Only an actual socket error is fatal.
        event.error |= (native.flags & EV_EOF) != 0 && native.fflags != 0;
    }
    return result;
}

} // namespace eventloop
