#pragma once

#include "eventloop/native_socket.h"
#include "eventloop/unique_fd.h"
#include "directory_listing.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace eventloop::http::detail {

struct file_info {
    enum class type { other, regular, directory } kind {type::other};
    std::uint64_t size {0};
    std::int64_t modified {0}; // Unix seconds.
    std::uint32_t modified_nanoseconds {0};
    std::int64_t changed {0}; // Last metadata change, Unix seconds.
    std::uint32_t changed_nanoseconds {0};
    std::uint64_t volume {0};
    std::uint64_t identity {0};
};

struct directory_entry {
    std::string name;
    bool is_directory {false};
};

[[nodiscard]] auto open_root(std::string_view path) -> unique_fd;
[[nodiscard]] auto open_child(native_socket parent, std::string_view name,
                              bool directory_required) noexcept -> unique_fd;
// A second owned descriptor for the same open file, or an empty one on
// failure. Reads through it at explicit offsets do not disturb the original.
[[nodiscard]] auto duplicate_file(native_socket file) noexcept -> unique_fd;
[[nodiscard]] auto get_file_info(native_socket file) noexcept
    -> std::optional<file_info>;
[[nodiscard]] auto read_file(native_socket file, std::span<std::byte> output) noexcept
    -> bool;
[[nodiscard]] auto read_file_at(native_socket file, std::uint64_t offset,
                                std::span<std::byte> output) noexcept -> bool;
[[nodiscard]] auto list_directory(native_socket directory, std::size_t limit)
    -> std::optional<std::vector<directory_entry>>;
[[nodiscard]] auto format_http_time(std::int64_t unix_seconds,
                                    std::span<char> output) noexcept -> std::size_t;
// The current time for a Date field, formatted at most once per second per
// thread (again after a clock change or a formatting failure). The view is
// valid on this thread until the next call; copy it before suspending.
[[nodiscard]] inline auto current_http_date() noexcept -> std::string_view
{
    static thread_local std::array<char, 64> text {};
    static thread_local std::time_t second {};
    static thread_local std::size_t size {0};
    const auto now = std::time(nullptr);
    if (now != second || size == 0) {
        size = format_http_time(now, text);
        second = now;
    }
    return {text.data(), size};
}

// Shared directory HTML renderer, with ownership of the directory handle.
// Applies the directory_listing_max_* bounds and stable byte-wise name order.
[[nodiscard]] auto render_directory_listing(unique_fd directory)
    -> std::expected<std::vector<char>, directory_listing_error>;

} // namespace eventloop::http::detail
