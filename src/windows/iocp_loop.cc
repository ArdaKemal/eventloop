#include "windows/iocp_loop.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <system_error>

namespace eventloop {
namespace {
constexpr ULONG_PTR wake_key = 1;
constexpr ULONG_PTR stop_key = 2;

#ifndef EVENTLOOP_WINDOWS_SHARED
class winsock_runtime {
public:
    winsock_runtime()
    {
        WSADATA data {};
        const int startup = ::WSAStartup(MAKEWORD(2, 2), &data);
        if (startup != 0) {
            throw std::system_error(startup, std::system_category(), "WSAStartup");
        }
    }

    ~winsock_runtime() { ::WSACleanup(); }

    winsock_runtime(const winsock_runtime&) = delete;
    auto operator=(const winsock_runtime&) -> winsock_runtime& = delete;
};

auto ensure_winsock() -> void
{
    // In executable-linked builds, the process owns this Winsock reference.
    // Shared builds cannot clean up from a C++ DLL static destructor.
    static const winsock_runtime runtime;
    (void)runtime;
}
#endif

[[nodiscard]] auto timeout_for(
    std::optional<std::chrono::steady_clock::time_point> deadline,
    bool nonblocking) noexcept -> DWORD
{
    if (nonblocking) return 0;
    if (!deadline) return INFINITE;
    const auto remaining = *deadline - std::chrono::steady_clock::now();
    if (remaining <= std::chrono::steady_clock::duration::zero()) return 0;
    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
        remaining);
    if (milliseconds.count() >= static_cast<decltype(milliseconds.count())>(INFINITE - 1))
        return INFINITE - 1;
    return static_cast<DWORD>(milliseconds.count() +
                              (milliseconds < remaining ? 1 : 0));
}
} // namespace

iocp_loop::iocp_loop()
{
#ifdef EVENTLOOP_WINDOWS_SHARED
    WSADATA data {};
    const int startup = ::WSAStartup(MAKEWORD(2, 2), &data);
    if (startup != 0) {
        throw std::system_error(startup, std::system_category(), "WSAStartup");
    }
#else
    ensure_winsock();
#endif
    port_ = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (port_ == nullptr) {
        const auto error = ::GetLastError();
#ifdef EVENTLOOP_WINDOWS_SHARED
        ::WSACleanup();
#endif
        throw std::system_error(static_cast<int>(error),
                                std::system_category(), "CreateIoCompletionPort");
    }
}

iocp_loop::~iocp_loop()
{
    if (port_ != nullptr) ::CloseHandle(port_);
#ifdef EVENTLOOP_WINDOWS_SHARED
    ::WSACleanup();
#endif
}

auto iocp_loop::add_descriptor(native_socket descriptor, bool) -> void
{
    if (::CreateIoCompletionPort(reinterpret_cast<HANDLE>(descriptor), port_, 0,
                                 0) == nullptr) {
        throw std::system_error(static_cast<int>(::GetLastError()),
                                std::system_category(), "CreateIoCompletionPort(socket)");
    }
}

auto iocp_loop::remove_descriptor(native_socket) -> void
{
    // Association ends when the socket closes. Its queued packets still have
    // to be dequeued before the operation storage can be released.
}

auto iocp_loop::set_io_interest(native_socket, bool, bool) -> void {}
auto iocp_loop::set_write_interest(native_socket, bool) -> void {}

auto iocp_loop::request_stop() -> void
{
    if (!::PostQueuedCompletionStatus(port_, 0, stop_key, nullptr)) {
        throw std::system_error(static_cast<int>(::GetLastError()),
                                std::system_category(), "PostQueuedCompletionStatus(stop)");
    }
}

auto iocp_loop::wake() noexcept -> void
{
    if (!::PostQueuedCompletionStatus(port_, 0, wake_key, nullptr)) std::terminate();
}

auto iocp_loop::arm_timer(
    std::optional<std::chrono::steady_clock::duration> delay) noexcept -> void
{
    if (!delay) {
        deadline_.reset();
    } else {
        const auto now = std::chrono::steady_clock::now();
        const auto maximum = std::chrono::steady_clock::time_point::max();
        deadline_ = *delay > std::chrono::steady_clock::duration::zero() &&
                            now >= maximum - *delay
                        ? maximum
                        : now + *delay;
    }
}

auto iocp_loop::poll(std::span<ready_event> events, bool nonblocking)
    -> poll_result
{
    poll_result result;
    if (events.empty()) throw std::invalid_argument("IOCP poll needs event storage");
    for (;;) {
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        OVERLAPPED* overlapped = nullptr;
        const BOOL ok = ::GetQueuedCompletionStatus(
            port_, &bytes, &key, &overlapped,
            result.event_count == 0 ? timeout_for(deadline_, nonblocking) : 0);
        const DWORD error = ok ? 0 : ::GetLastError();
        if (!ok && overlapped == nullptr) {
            if (error != WAIT_TIMEOUT) {
                throw std::system_error(static_cast<int>(error),
                                        std::system_category(),
                                        "GetQueuedCompletionStatus");
            }
            if (result.event_count == 0 && !nonblocking && deadline_ &&
                std::chrono::steady_clock::now() < *deadline_) continue;
            break;
        }
        if (overlapped != nullptr) {
            static_assert(offsetof(detail::socket_operation, overlapped) == 0);
            events[result.event_count++] = {
                reinterpret_cast<detail::socket_operation*>(overlapped), bytes, error};
        } else if (key == wake_key) {
            result.wake_requested = true;
        } else if (key == stop_key) {
            result.stop_requested = true;
        }
        if (result.event_count == events.size() || result.stop_requested ||
            result.wake_requested) break;
    }
    if (deadline_ && std::chrono::steady_clock::now() >= *deadline_) {
        result.timer_requested = true;
    }
    return result;
}

} // namespace eventloop
