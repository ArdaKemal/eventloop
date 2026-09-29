#pragma once

#include "eventloop/unique_fd.h"

#include <cstddef>
#include <cstdint>
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
};

struct directory_entry {
    std::string name;
    bool is_directory {false};
};

[[nodiscard]] auto open_root(std::string_view path) -> unique_fd;
[[nodiscard]] auto open_child(native_socket parent, std::string_view name,
                              bool directory_required) noexcept -> unique_fd;
[[nodiscard]] auto get_file_info(native_socket file) noexcept
    -> std::optional<file_info>;
[[nodiscard]] auto read_file(native_socket file, std::span<std::byte> output) noexcept
    -> bool;
[[nodiscard]] auto read_file_at(native_socket file, std::uint64_t offset,
                                std::span<std::byte> output) noexcept -> bool;
[[nodiscard]] auto list_directory(native_socket directory)
    -> std::optional<std::vector<directory_entry>>;
[[nodiscard]] auto format_http_time(std::int64_t unix_seconds,
                                    std::span<char> output) noexcept -> std::size_t;

// Shared directory HTML renderer, with ownership of the directory handle.
[[nodiscard]] auto render_directory_listing(unique_fd directory)
    -> std::optional<std::vector<char>>;

} // namespace eventloop::http::detail
