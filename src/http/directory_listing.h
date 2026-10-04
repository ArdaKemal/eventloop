#pragma once

#include "eventloop/native_socket.h"

#include <cstddef>
#include <expected>
#include <string_view>
#include <vector>

namespace eventloop::http {

enum class directory_listing_error {
    list_failed,
    too_many_entries,
    too_large,
};

// Bounded directory listings. Entries are the directory's own children except
// "." and ".."; hidden (dot) names are listed. Rendering stops once the entry
// count or generated HTML size would exceed these limits and reports the
// matching error instead.
inline constexpr std::size_t directory_listing_max_entries = 4096;
inline constexpr std::size_t directory_listing_max_bytes = 1u << 20;
inline constexpr std::string_view directory_listing_error_body =
    "directory listing too large\n";

[[nodiscard]] auto make_directory_listing(native_socket descriptor)
    -> std::expected<std::vector<char>, directory_listing_error>;

} // namespace eventloop::http
