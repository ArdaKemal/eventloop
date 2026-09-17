#pragma once

#include <cstddef>
#include <optional>
#include <vector>

namespace http {

[[nodiscard]] auto make_directory_listing(int descriptor)
    -> std::optional<std::vector<std::byte>>;

} // namespace http
