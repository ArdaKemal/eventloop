#pragma once

#include <string_view>

namespace http {

[[nodiscard]] auto mime_type_from_path(std::string_view path) noexcept
    -> std::string_view;

} // namespace http
