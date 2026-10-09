#pragma once

#include "eventloop/native_socket.h"
#include "eventloop/unique_fd.h"

#include <cstddef>
#include <expected>
#include <span>
#include <string_view>

namespace eventloop::http::detail {

enum class resource_error {
    invalid_target,
    target_too_long,
    open_failed,
};

// Percent-decodes the path of target into output, rejecting ".." components,
// NUL, backslash, and control characters; an empty path becomes ".".
// Returns the decoded size.
[[nodiscard]] auto decode_target(std::string_view target, std::span<char> output) noexcept
    -> std::expected<std::size_t, resource_error>;

// Opens a decoded path below root, rejecting symlinks in every component.
// Linux uses openat2 when available, with the component walk as fallback.
[[nodiscard]] auto open_decoded(native_socket root, std::span<const char> path) noexcept
    -> unique_fd;

// Decode a request target and open it below root without following symlinks.
// Open failures are left to the caller to map to its protocol's response.
[[nodiscard]] auto open_resource(native_socket root, std::string_view target) noexcept
    -> std::expected<unique_fd, resource_error>;

} // namespace eventloop::http::detail
