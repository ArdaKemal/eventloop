#include "../http/file_operations.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <ctime>
#include <memory>
#include <limits>
#include <stdexcept>
#include <system_error>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace eventloop::http::detail {

auto open_root(std::string_view root) -> unique_fd
{
    if (root.empty() || root.size() >= 4096 ||
        root.find('\0') != std::string_view::npos)
        throw std::invalid_argument("HTTP root path is invalid or too long");
    std::string path(root);
    unique_fd descriptor(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (!descriptor) throw std::system_error(errno, std::system_category(),
                                             "open HTTP root");
    return descriptor;
}

auto open_child(native_socket parent, std::string_view name,
                bool directory_required) noexcept -> unique_fd
{
    if (name.empty() || name.find('/') != std::string_view::npos ||
        name.find('\0') != std::string_view::npos || name.size() >= 4096)
        return {};
    char path[4096] {};
    std::memcpy(path, name.data(), name.size());
    return unique_fd(openat(parent, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
                           (directory_required ? O_DIRECTORY : 0)));
}

auto duplicate_file(native_socket file) noexcept -> unique_fd
{
    return unique_fd(fcntl(file, F_DUPFD_CLOEXEC, 0));
}

auto get_file_info(native_socket file) noexcept -> std::optional<file_info>
{
    struct stat info {};
    if (fstat(file, &info) != 0) return std::nullopt;
    return file_info {
        S_ISREG(info.st_mode) ? file_info::type::regular :
        S_ISDIR(info.st_mode) ? file_info::type::directory : file_info::type::other,
        info.st_size < 0 ? 0U : static_cast<std::uint64_t>(info.st_size),
        static_cast<std::int64_t>(info.st_mtime),
#if defined(__APPLE__)
        static_cast<std::uint32_t>(info.st_mtimespec.tv_nsec),
        static_cast<std::int64_t>(info.st_ctimespec.tv_sec),
        static_cast<std::uint32_t>(info.st_ctimespec.tv_nsec),
#else
        static_cast<std::uint32_t>(info.st_mtim.tv_nsec),
        static_cast<std::int64_t>(info.st_ctim.tv_sec),
        static_cast<std::uint32_t>(info.st_ctim.tv_nsec),
#endif
        static_cast<std::uint64_t>(info.st_dev),
        static_cast<std::uint64_t>(info.st_ino)};
}

auto read_file(native_socket file, std::span<std::byte> output) noexcept -> bool
{
    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto count = ::read(file, output.data() + offset,
                                  std::min(output.size() - offset,
                                           static_cast<std::size_t>(SSIZE_MAX)));
        if (count > 0) offset += static_cast<std::size_t>(count);
        else if (count == -1 && errno == EINTR) continue;
        else return false;
    }
    return true;
}

auto read_file_at(native_socket file, std::uint64_t position,
                  std::span<std::byte> output) noexcept -> bool
{
    constexpr auto max_offset = static_cast<std::uint64_t>(
        std::numeric_limits<off_t>::max());
    if (position > max_offset || output.size() > max_offset - position)
        return false;
    std::size_t read_size = 0;
    while (read_size < output.size()) {
        const auto count = ::pread(file, output.data() + read_size,
            std::min(output.size() - read_size,
                     static_cast<std::size_t>(SSIZE_MAX)),
            static_cast<off_t>(position + read_size));
        if (count > 0) read_size += static_cast<std::size_t>(count);
        else if (count == -1 && errno == EINTR) continue;
        else return false;
    }
    return true;
}

auto list_directory(native_socket descriptor, std::size_t limit)
    -> std::optional<std::vector<directory_entry>>
{
    const int duplicate = dup(descriptor);
    if (duplicate == -1) return std::nullopt;
    struct closer {
        auto operator()(DIR* value) const noexcept -> void { (void)closedir(value); }
    };
    std::unique_ptr<DIR, closer> directory(fdopendir(duplicate));
    if (!directory) { (void)close(duplicate); return std::nullopt; }
    std::vector<directory_entry> entries;
    for (;;) {
        errno = 0;
        dirent* entry = readdir(directory.get());
        if (!entry) return errno == 0 ? std::optional {std::move(entries)}
                                      : std::nullopt;
        if (std::strcmp(entry->d_name, ".") == 0 ||
            std::strcmp(entry->d_name, "..") == 0) continue;
        bool is_directory = entry->d_type == DT_DIR;
        if (entry->d_type == DT_UNKNOWN) {
            struct stat info {};
            is_directory = fstatat(descriptor, entry->d_name, &info,
                                   AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(info.st_mode);
        }
        entries.push_back({entry->d_name, is_directory});
        if (entries.size() > limit) return std::optional {std::move(entries)};
    }
}

auto format_http_time(std::int64_t value, std::span<char> output) noexcept
    -> std::size_t
{
    const auto seconds = static_cast<std::time_t>(value);
    std::tm time {};
    if (gmtime_r(&seconds, &time) == nullptr) return 0;
    return std::strftime(output.data(), output.size(),
                         "%a, %d %b %Y %H:%M:%S GMT", &time);
}

} // namespace eventloop::http::detail
