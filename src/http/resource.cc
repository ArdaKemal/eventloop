#include "resource.h"
#include "file_operations.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <span>
#include <utility>

#if defined(__linux__) && __has_include(<linux/openat2.h>)
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace eventloop::http::detail {
namespace {

[[nodiscard]] constexpr auto hex_value(char value) noexcept -> int
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

} // namespace

auto decode_target(std::string_view target, std::span<char> output) noexcept
    -> std::expected<std::size_t, resource_error>
{
    target = target.substr(0, target.find_first_of("?#"));
    if (target.empty() || target.front() != '/') {
        return std::unexpected(resource_error::invalid_target);
    }

    std::size_t size = 0;
    for (std::size_t input = 1; input < target.size(); ++input) {
        char value = target[input];
        if (value == '%') {
            if (input + 2 >= target.size()) {
                return std::unexpected(resource_error::invalid_target);
            }
            const int high = hex_value(target[input + 1]);
            const int low = hex_value(target[input + 2]);
            if (high < 0 || low < 0) {
                return std::unexpected(resource_error::invalid_target);
            }
            value = static_cast<char>((high << 4) | low);
            input += 2;
        }
        if (value == '\0' || value == '\\' ||
            static_cast<unsigned char>(value) < 0x20) {
            return std::unexpected(resource_error::invalid_target);
        }
        if (size == output.size()) {
            return std::unexpected(resource_error::target_too_long);
        }
        output[size++] = value;
    }

    const std::string_view decoded {output.data(), size};
    std::size_t segment_start = 0;
    while (segment_start <= decoded.size()) {
        const auto slash = decoded.find('/', segment_start);
        const auto segment = decoded.substr(
            segment_start, slash == std::string_view::npos
                ? decoded.size() - segment_start
                : slash - segment_start);
        if (segment == "..") {
            return std::unexpected(resource_error::invalid_target);
        }
        if (slash == std::string_view::npos) break;
        segment_start = slash + 1;
    }

    if (size == 0) output[size++] = '.';
    return size;
}

auto open_decoded(native_socket root, std::span<const char> path) noexcept
    -> unique_fd
{
#if defined(SYS_openat2) && defined(RESOLVE_NO_SYMLINKS)
    std::string_view relative(path.data(), path.size());
    if (relative.contains('\0')) return {};
    while (relative.starts_with('/')) relative.remove_prefix(1);
    if (relative.empty()) relative = ".";
    if (relative.size() < 4096) {
        std::array<char, 4096> name {};
        std::memcpy(name.data(), relative.data(), relative.size());
        const open_how how {
            .flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
            .mode = 0,
            .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
        };
        const auto descriptor = ::syscall(SYS_openat2, root, name.data(), &how, sizeof(how));
        if (descriptor >= 0) return unique_fd(static_cast<int>(descriptor));
        // Only unavailable or filtered syscalls use the component walk.
        if (errno != ENOSYS && errno != EPERM) return {};
    }
#endif
    std::size_t start = 0;
    native_socket parent = root;
    unique_fd owned_parent;

    while (start < path.size()) {
        while (start < path.size() && path[start] == '/') ++start;
        if (start == path.size()) break;

        auto end = start;
        while (end < path.size() && path[end] != '/') ++end;
        unique_fd next = open_child(parent,
            std::string_view {path.data() + start, end - start},
            end < path.size());
        if (!next) {
            return {};
        }
        owned_parent = std::move(next);
        parent = owned_parent.get();
        start = end + 1;
    }

    if (owned_parent) return owned_parent;
    return open_child(root, ".", false);
}

auto open_resource(native_socket root, std::string_view target) noexcept
    -> std::expected<unique_fd, resource_error>
{
    std::array<char, 4096> path {};
    const auto size = decode_target(target, path);
    if (!size) return std::unexpected(size.error());

    auto descriptor = open_decoded(root, std::span {path}.first(*size));
    if (!descriptor) return std::unexpected(resource_error::open_failed);
    return descriptor;
}

} // namespace eventloop::http::detail
