#pragma once

#include "eventloop/unique_fd.h"

#include <expected>
#include <string_view>

namespace eventloop::http::detail {

enum class resource_error {
    invalid_target,
    target_too_long,
    open_failed,
};

// Decode a request target and walk below root one component at a time.
// Every opened component uses O_NOFOLLOW; open failures are left to the
// caller to map to its protocol's response.
[[nodiscard]] auto open_resource(native_socket root, std::string_view target) noexcept
    -> std::expected<unique_fd, resource_error>;

} // namespace eventloop::http::detail
