#pragma once

#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace test_socket {

#ifdef __APPLE__
inline constexpr int no_signal = 0;

// Darwin supplies these socket properties through fcntl/setsockopt rather
// than socket/accept flags. Close on any setup failure, preserving errno.
inline auto configure(int descriptor, bool nonblocking) -> int
{
    if (descriptor == -1) return -1;
    const int flags = ::fcntl(descriptor, F_GETFD);
    const int no_sigpipe = 1;
    bool failed = flags == -1 ||
        ::fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == -1 ||
        ::setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE,
                     &no_sigpipe, sizeof(no_sigpipe)) == -1;
    if (!failed && nonblocking) {
        const int status = ::fcntl(descriptor, F_GETFL);
        failed = status == -1 ||
            ::fcntl(descriptor, F_SETFL, status | O_NONBLOCK) == -1;
    }
    if (failed) {
        const int error = errno;
        (void)::close(descriptor);
        errno = error;
        return -1;
    }
    return descriptor;
}
#else
inline constexpr int no_signal = MSG_NOSIGNAL;
#endif

inline auto socket(int family, int type) -> int
{
#ifdef __APPLE__
    return configure(::socket(family, type, 0), false);
#else
    return ::socket(family, type | SOCK_CLOEXEC, 0);
#endif
}

inline auto accept(int listener, bool nonblocking = false) -> int
{
#ifdef __APPLE__
    return configure(::accept(listener, nullptr, nullptr), nonblocking);
#else
    return ::accept4(listener, nullptr, nullptr,
                     SOCK_CLOEXEC | (nonblocking ? SOCK_NONBLOCK : 0));
#endif
}

} // namespace test_socket
#endif
