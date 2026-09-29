#pragma once

#include "eventloop/native_socket.h"

#include <optional>
#include <vector>

namespace eventloop::http {

[[nodiscard]] auto make_directory_listing(native_socket descriptor)
    -> std::optional<std::vector<char>>;

} // namespace eventloop::http
