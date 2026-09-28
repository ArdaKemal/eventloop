#pragma once

#include <optional>
#include <vector>

namespace eventloop::http {

[[nodiscard]] auto make_directory_listing(int descriptor)
    -> std::optional<std::vector<char>>;

} // namespace eventloop::http
