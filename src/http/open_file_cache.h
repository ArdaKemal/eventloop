#pragma once

#include "file_operations.h"
#include "resource.h"
#include "eventloop/native_socket.h"
#include "eventloop/unique_fd.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string_view>
#include <vector>

namespace eventloop::http::detail {

class open_file_cache;

// A file below the document root, either owned or pinned in an
// open_file_cache. A pinned descriptor stays open until the handle is
// released, even when its cache entry is replaced; responses sharing it read
// at explicit offsets.
class static_file {
public:
    static_file() noexcept = default;
    static_file(unique_fd owned) noexcept : owned_(std::move(owned)) {}
    static_file(static_file&& other) noexcept;
    auto operator=(static_file&& other) noexcept -> static_file&;
    static_file(const static_file&) = delete;
    auto operator=(const static_file&) -> static_file& = delete;
    ~static_file();

    [[nodiscard]] auto get() const noexcept -> native_socket;
    [[nodiscard]] explicit operator bool() const noexcept;
    [[nodiscard]] auto cached() const noexcept -> bool { return cache_ != nullptr; }
    auto reset() noexcept -> void;
    // An owned descriptor, for an operation that needs its own file position.
    [[nodiscard]] auto take_owned() noexcept -> unique_fd { return std::move(owned_); }

private:
    friend class open_file_cache;
    unique_fd owned_;
    open_file_cache* cache_ {nullptr};
    std::uint32_t slot_ {0};
};

struct opened_resource {
    static_file file;
    file_info info;
};

// Keeps up to capacity regular files open below one document root, keyed by
// decoded path, for one event loop. Entries are opened and revalidated
// through open_decoded(): a hit at least revalidate_after after its last
// check walks the path again and replaces the entry if the file changed, so
// a changed, replaced, or removed file may be served as before for that
// long. Storage is allocated at construction; when every entry is pinned the
// request is served uncached.
class open_file_cache {
public:
    static constexpr std::size_t max_capacity = 65536;
    static constexpr std::size_t max_key_size = 255;
    static constexpr std::chrono::seconds revalidate_after {1};

    explicit open_file_cache(std::size_t capacity);
    ~open_file_cache();
    open_file_cache(const open_file_cache&) = delete;
    auto operator=(const open_file_cache&) -> open_file_cache& = delete;

    // Like open_resource() plus get_file_info(); a failed stat is open_failed.
    [[nodiscard]] auto open(native_socket root, std::string_view target,
                            std::chrono::steady_clock::time_point now) noexcept
        -> std::expected<opened_resource, resource_error>;

private:
    friend class static_file;
    struct entry;

    [[nodiscard]] auto pinned(std::uint32_t slot) noexcept -> opened_resource;
    [[nodiscard]] auto store(std::string_view key, std::uint64_t hash, unique_fd file,
                             const file_info& info,
                             std::chrono::steady_clock::time_point now) noexcept
        -> opened_resource;
    [[nodiscard]] auto acquire_slot() noexcept -> std::uint32_t;
    auto remove(std::uint32_t slot) noexcept -> void;
    auto unpin(std::uint32_t slot) noexcept -> void;
    [[nodiscard]] auto descriptor(std::uint32_t slot) const noexcept -> native_socket;
    [[nodiscard]] auto key(std::uint32_t slot) const noexcept -> std::string_view;

    std::vector<entry> entries_;
    std::unique_ptr<char[]> keys_;
    std::vector<std::uint32_t> buckets_;
    std::uint32_t free_;
    std::uint64_t tick_ {0};
};

// The document root a server shares with its connections, and its optional
// open-file cache.
struct document_root {
    unique_fd descriptor;
    std::unique_ptr<open_file_cache> cache;
};

// Opens target below root through cache when it is set, otherwise as
// open_resource() followed by get_file_info().
[[nodiscard]] auto open_static(native_socket root, open_file_cache* cache,
                               std::string_view target) noexcept
    -> std::expected<opened_resource, resource_error>;

} // namespace eventloop::http::detail
