#include "eventloop/unix_socket.h"
#include "socket_operations.h"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <system_error>
#include <unistd.h>

namespace eventloop {
namespace {

auto validate_path(std::string_view path) -> void
{
    if (path.empty() || path.size() >= sizeof(sockaddr_un::sun_path) ||
        path.find('\0') != std::string_view::npos)
        throw std::invalid_argument("invalid Unix socket path");
}

[[nodiscard]] auto create_listener(std::string_view path) -> unique_fd
{
    validate_path(path);
    unique_fd descriptor(detail::socket_operations::create(AF_UNIX, SOCK_STREAM, 0));
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.data(), path.size());
    const auto length = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + path.size() + 1);
    if (::bind(descriptor.get(), reinterpret_cast<const sockaddr*>(&address),
               length) == -1)
        throw std::system_error(errno, std::system_category(), "bind Unix socket");
    if (::listen(descriptor.get(), SOMAXCONN) == -1) {
        const int error = errno;
        // The path was created by the successful bind above.
        (void)::unlink(address.sun_path);
        throw std::system_error(error, std::system_category(), "listen Unix socket");
    }
    return descriptor;
}

} // namespace

unix_acceptor::unix_acceptor(event_loop& loop, std::string_view path)
    : tcp_acceptor(loop, create_listener(path), true)
{
    std::memcpy(path_.data(), path.data(), path.size());
    struct stat identity {};
    if (::lstat(path_.data(), &identity) == -1)
        throw std::system_error(errno, std::system_category(), "lstat Unix socket");
    device_ = static_cast<std::uint64_t>(identity.st_dev);
    inode_ = static_cast<std::uint64_t>(identity.st_ino);
}

unix_acceptor::~unix_acceptor()
{
    close();
}

auto unix_acceptor::close() -> void
{
    if (path_closed_) return;
    path_closed_ = true;
    tcp_acceptor::close();
    if (path_[0] == '\0') return;
    struct stat current {};
    if (::lstat(path_.data(), &current) == 0 && S_ISSOCK(current.st_mode) &&
        static_cast<std::uint64_t>(current.st_dev) == device_ &&
        static_cast<std::uint64_t>(current.st_ino) == inode_)
        (void)::unlink(path_.data());
    path_[0] = '\0';
}

} // namespace eventloop
