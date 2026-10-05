#include "open_file_cache.h"

#include <array>
#include <bit>
#include <cstring>
#include <exception>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>

namespace eventloop::http::detail {
namespace {

constexpr std::uint32_t no_slot = std::numeric_limits<std::uint32_t>::max();

[[nodiscard]] auto hash_key(std::string_view key) noexcept -> std::uint64_t
{
    std::uint64_t hash = 14695981039346656037ull;
    for (const char value : key) {
        hash ^= static_cast<unsigned char>(value);
        hash *= 1099511628211ull;
    }
    return hash;
}

[[nodiscard]] auto same_file(const file_info& left, const file_info& right) noexcept -> bool
{
    return left.kind == right.kind && left.volume == right.volume &&
        left.identity == right.identity && left.size == right.size &&
        left.modified == right.modified &&
        left.modified_nanoseconds == right.modified_nanoseconds &&
        left.changed == right.changed && left.changed_nanoseconds == right.changed_nanoseconds;
}

} // namespace

struct open_file_cache::entry {
    enum class state : std::uint8_t { free, live, retired };
    unique_fd file;
    file_info info;
    std::chrono::steady_clock::time_point validated;
    std::uint64_t hash {0};
    std::uint64_t used {0};
    std::uint32_t pins {0};
    // Next entry in a bucket chain, or in the free list.
    std::uint32_t next {no_slot};
    std::uint16_t key_size {0};
    state status {state::free};
};

static_file::static_file(static_file&& other) noexcept
    : owned_(std::move(other.owned_)), cache_(std::exchange(other.cache_, nullptr)),
      slot_(other.slot_)
{
}

auto static_file::operator=(static_file&& other) noexcept -> static_file&
{
    if (this == &other) return *this;
    reset();
    owned_ = std::move(other.owned_);
    cache_ = std::exchange(other.cache_, nullptr);
    slot_ = other.slot_;
    return *this;
}

static_file::~static_file()
{
    reset();
}

auto static_file::get() const noexcept -> native_socket
{
    return cache_ != nullptr ? cache_->descriptor(slot_) : owned_.get();
}

static_file::operator bool() const noexcept
{
    return cache_ != nullptr || static_cast<bool>(owned_);
}

auto static_file::reset() noexcept -> void
{
    owned_.reset();
    if (auto* cache = std::exchange(cache_, nullptr)) cache->unpin(slot_);
}

open_file_cache::open_file_cache(std::size_t capacity)
{
    if (capacity == 0 || capacity > max_capacity)
        throw std::invalid_argument("open file cache capacity must be 1..65536");
    entries_.resize(capacity);
    keys_ = std::make_unique<char[]>(capacity * max_key_size);
    buckets_.assign(std::bit_ceil(capacity * 2), no_slot);
    for (std::size_t index = 0; index < capacity; ++index)
        entries_[index].next = index + 1 < capacity ? static_cast<std::uint32_t>(index + 1) : no_slot;
    free_ = 0;
}

open_file_cache::~open_file_cache()
{
    // Handles must not outlive the cache that pins their descriptors.
    for (const auto& value : entries_)
        if (value.pins != 0) std::terminate();
}

auto open_file_cache::descriptor(std::uint32_t slot) const noexcept -> native_socket
{
    return entries_[slot].file.get();
}

auto open_file_cache::key(std::uint32_t slot) const noexcept -> std::string_view
{
    return {keys_.get() + std::size_t {slot} * max_key_size, entries_[slot].key_size};
}

auto open_file_cache::pinned(std::uint32_t slot) noexcept -> opened_resource
{
    auto& value = entries_[slot];
    ++value.pins;
    value.used = ++tick_;
    opened_resource result {{}, value.info};
    result.file.cache_ = this;
    result.file.slot_ = slot;
    return result;
}

auto open_file_cache::acquire_slot() noexcept -> std::uint32_t
{
    if (free_ == no_slot) {
        // Evict the least recently used entry that no response holds.
        std::uint32_t victim = no_slot;
        for (std::uint32_t index = 0; index < entries_.size(); ++index) {
            const auto& value = entries_[index];
            if (value.status == entry::state::live && value.pins == 0 &&
                (victim == no_slot || value.used < entries_[victim].used))
                victim = index;
        }
        if (victim == no_slot) return no_slot;
        remove(victim);
    }
    const auto slot = free_;
    free_ = entries_[slot].next;
    entries_[slot].next = no_slot;
    return slot;
}

auto open_file_cache::store(std::string_view key_text, std::uint64_t hash, unique_fd file,
                            const file_info& info,
                            std::chrono::steady_clock::time_point now) noexcept
    -> opened_resource
{
    const auto slot = acquire_slot();
    if (slot == no_slot) return {std::move(file), info};
    auto& value = entries_[slot];
    value.file = std::move(file);
    value.info = info;
    value.validated = now;
    value.hash = hash;
    value.key_size = static_cast<std::uint16_t>(key_text.size());
    std::memcpy(keys_.get() + std::size_t {slot} * max_key_size, key_text.data(), key_text.size());
    value.status = entry::state::live;
    auto& bucket = buckets_[hash & (buckets_.size() - 1)];
    value.next = bucket;
    bucket = slot;
    return pinned(slot);
}

auto open_file_cache::remove(std::uint32_t slot) noexcept -> void
{
    auto& value = entries_[slot];
    auto* link = &buckets_[value.hash & (buckets_.size() - 1)];
    while (*link != slot) link = &entries_[*link].next;
    *link = value.next;
    value.next = no_slot;
    if (value.pins != 0) {
        // Responses still read it; unpin() closes and frees the entry.
        value.status = entry::state::retired;
        return;
    }
    value.file.reset();
    value.status = entry::state::free;
    value.next = free_;
    free_ = slot;
}

auto open_file_cache::unpin(std::uint32_t slot) noexcept -> void
{
    auto& value = entries_[slot];
    if (--value.pins != 0 || value.status != entry::state::retired) return;
    value.file.reset();
    value.status = entry::state::free;
    value.next = free_;
    free_ = slot;
}

auto open_file_cache::open(native_socket root, std::string_view target,
                           std::chrono::steady_clock::time_point now) noexcept
    -> std::expected<opened_resource, resource_error>
{
    std::array<char, 4096> path {};
    const auto size = decode_target(target, path);
    if (!size) return std::unexpected(size.error());
    const std::span<const char> decoded = std::span {path}.first(*size);
    const std::string_view key_text {path.data(), *size};
    auto open_file = [&]() -> std::expected<opened_resource, resource_error> {
        auto file = open_decoded(root, decoded);
        if (!file) return std::unexpected(resource_error::open_failed);
        const auto info = get_file_info(file.get());
        if (!info) return std::unexpected(resource_error::open_failed);
        return opened_resource {std::move(file), *info};
    };
    if (key_text.size() > max_key_size) return open_file();

    const auto hash = hash_key(key_text);
    auto slot = buckets_[hash & (buckets_.size() - 1)];
    while (slot != no_slot && (entries_[slot].hash != hash || key(slot) != key_text))
        slot = entries_[slot].next;

    if (slot != no_slot && now - entries_[slot].validated < revalidate_after)
        return pinned(slot);

    auto opened = open_file();
    if (slot != no_slot) {
        if (opened && same_file(opened->info, entries_[slot].info)) {
            entries_[slot].validated = now;
            return pinned(slot);
        }
        remove(slot);
    }
    if (!opened || opened->info.kind != file_info::type::regular) return opened;
    auto& file = opened->file;
    return store(key_text, hash, std::move(file.owned_), opened->info, now);
}

auto open_static(native_socket root, open_file_cache* cache, std::string_view target) noexcept
    -> std::expected<opened_resource, resource_error>
{
    if (cache != nullptr) return cache->open(root, target, std::chrono::steady_clock::now());
    auto opened = open_resource(root, target);
    if (!opened) return std::unexpected(opened.error());
    const auto info = get_file_info(opened->get());
    if (!info) return std::unexpected(resource_error::open_failed);
    return opened_resource {std::move(*opened), *info};
}

} // namespace eventloop::http::detail
