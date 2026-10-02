#pragma once

#include "quic/varint.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>

namespace eventloop::quic::detail {

enum class stream_role { client, server };
enum class stream_direction { bidirectional, unidirectional };
enum class stream_registry_error {
    invalid_stream_id,
    wrong_initiator,
    stream_limit,
    capacity_exhausted,
    closed,
    unknown_stream,
    invalid_limit,
};

inline constexpr std::uint64_t max_stream_count = std::uint64_t {1} << 60;

[[nodiscard]] constexpr auto stream_initiator(std::uint64_t id) noexcept
    -> stream_role
{
    return (id & 1) == 0 ? stream_role::client : stream_role::server;
}

[[nodiscard]] constexpr auto stream_type(std::uint64_t id) noexcept
    -> stream_direction
{
    return (id & 2) == 0 ? stream_direction::bidirectional
                         : stream_direction::unidirectional;
}

[[nodiscard]] constexpr auto stream_ordinal(std::uint64_t id) noexcept
    -> std::uint64_t
{
    return (id >> 2) + 1;
}

struct registered_stream {
    std::uint64_t id {0};
    bool can_send {false};
    bool can_receive {false};
    bool closed {false};
};

// Limits are cumulative stream ordinals. Active records use bounded slots;
// compact retired ordinal ranges prevent a delayed packet from reopening an
// old peer stream. Implicitly opened IDs acquire a record on first access.
template<std::size_t Capacity>
class stream_registry {
public:
    explicit constexpr stream_registry(stream_role role) noexcept : role_(role) {}

    [[nodiscard]] constexpr auto set_local_limit(stream_direction direction,
                                                  std::uint64_t limit) noexcept
        -> std::expected<void, stream_registry_error>
    {
        return increase_limit(local_limit_[index(direction)], limit);
    }

    [[nodiscard]] constexpr auto set_peer_limit(stream_direction direction,
                                                 std::uint64_t limit) noexcept
        -> std::expected<void, stream_registry_error>
    {
        return increase_limit(peer_limit_[index(direction)], limit);
    }

    [[nodiscard]] constexpr auto open_local(stream_direction direction) noexcept
        -> std::expected<std::uint64_t, stream_registry_error>
    {
        const auto type = index(direction);
        if (local_opened_[type] == peer_limit_[type])
            return std::unexpected(stream_registry_error::stream_limit);
        if (size_ == Capacity)
            return std::unexpected(stream_registry_error::capacity_exhausted);
        const auto ordinal = local_opened_[type] + 1;
        const auto id = ((ordinal - 1) << 2) |
                        (direction == stream_direction::unidirectional ? 2u : 0u) |
                        (role_ == stream_role::server ? 1u : 0u);
        streams_[size_++] = make_stream(id);
        local_opened_[type] = ordinal;
        return id;
    }

    // Receiving a higher ID implicitly opens all lower IDs of that type.
    // Repeated access returns the existing record; a closed record stays closed.
    [[nodiscard]] constexpr auto observe_peer(std::uint64_t id) noexcept
        -> std::expected<const registered_stream*, stream_registry_error>
    {
        if (id > max_varint_value)
            return std::unexpected(stream_registry_error::invalid_stream_id);
        if (stream_initiator(id) == role_)
            return std::unexpected(stream_registry_error::wrong_initiator);
        const auto type = index(stream_type(id));
        const auto ordinal = stream_ordinal(id);
        if (ordinal > local_limit_[type])
            return std::unexpected(stream_registry_error::stream_limit);
        if (auto* existing = find_mutable(id)) return existing;
        if (is_retired(id)) return std::unexpected(stream_registry_error::closed);
        if (size_ == Capacity)
            return std::unexpected(stream_registry_error::capacity_exhausted);
        streams_[size_] = make_stream(id);
        auto* created = &streams_[size_++];
        if (ordinal > peer_opened_[type]) peer_opened_[type] = ordinal;
        return created;
    }

    [[nodiscard]] constexpr auto close(std::uint64_t id) noexcept
        -> std::expected<void, stream_registry_error>
    {
        std::size_t position = 0;
        while (position < size_ && streams_[position].id != id) ++position;
        if (position == size_) return std::unexpected(is_retired(id)
            ? stream_registry_error::closed : stream_registry_error::unknown_stream);
        if (stream_initiator(id) != role_ && !remember_retired(id))
            return std::unexpected(stream_registry_error::capacity_exhausted);
        streams_[position] = streams_[--size_];
        streams_[size_] = {};
        return {};
    }

    [[nodiscard]] constexpr auto find(std::uint64_t id) const noexcept
        -> const registered_stream*
    {
        for (std::size_t i = 0; i < size_; ++i)
            if (streams_[i].id == id) return &streams_[i];
        return nullptr;
    }

    [[nodiscard]] constexpr auto was_opened(std::uint64_t id) const noexcept
        -> bool
    {
        if (id > max_varint_value) return false;
        const auto type = index(stream_type(id));
        return stream_ordinal(id) <=
            (stream_initiator(id) == role_ ? local_opened_[type]
                                           : peer_opened_[type]);
    }

    [[nodiscard]] constexpr auto local_opened(stream_direction direction) const
        noexcept -> std::uint64_t
    { return local_opened_[index(direction)]; }

    [[nodiscard]] constexpr auto peer_opened(stream_direction direction) const
        noexcept -> std::uint64_t
    { return peer_opened_[index(direction)]; }

    [[nodiscard]] constexpr auto size() const noexcept -> std::size_t
    { return size_; }

    [[nodiscard]] constexpr auto local_limit(stream_direction direction) const
        noexcept -> std::uint64_t
    { return local_limit_[index(direction)]; }

    [[nodiscard]] constexpr auto is_retired(std::uint64_t id) const noexcept -> bool
    {
        if (id > max_varint_value || find(id)) return false;
        const auto ordinal = stream_ordinal(id);
        if (stream_initiator(id) == role_)
            return ordinal <= local_opened_[index(stream_type(id))];
        const auto type = index(stream_type(id));
        for (std::size_t i = 0; i < retired_count_[type]; ++i)
            if (ordinal >= retired_[type][i].first &&
                ordinal <= retired_[type][i].last) return true;
        return false;
    }

private:
    struct ordinal_range { std::uint64_t first {}, last {}; };

    [[nodiscard]] constexpr auto remember_retired(std::uint64_t id) noexcept -> bool
    {
        const auto type = index(stream_type(id));
        const auto ordinal = stream_ordinal(id);
        auto& count = retired_count_[type];
        auto& ranges = retired_[type];
        ordinal_range merged {ordinal, ordinal};
        bool adjacent = false;
        for (std::size_t i = 0; i < count; ++i)
            adjacent |= ranges[i].first <= ordinal + 1 &&
                        ordinal <= ranges[i].last + 1;
        if (!adjacent && count == Capacity) return false;
        for (std::size_t i = 0; i < count;) {
            if (ranges[i].first > merged.last + 1 ||
                merged.first > ranges[i].last + 1) { ++i; continue; }
            merged.first = std::min(merged.first, ranges[i].first);
            merged.last = std::max(merged.last, ranges[i].last);
            ranges[i] = ranges[--count];
            i = 0;
        }
        ranges[count++] = merged;
        return true;
    }
    [[nodiscard]] constexpr auto find_mutable(std::uint64_t id) noexcept
        -> registered_stream*
    {
        for (std::size_t i = 0; i < size_; ++i)
            if (streams_[i].id == id) return &streams_[i];
        return nullptr;
    }

    [[nodiscard]] static constexpr auto index(stream_direction direction) noexcept
        -> std::size_t
    { return direction == stream_direction::bidirectional ? 0 : 1; }

    [[nodiscard]] constexpr auto make_stream(std::uint64_t id) const noexcept
        -> registered_stream
    {
        const bool local = stream_initiator(id) == role_;
        const bool bidi = stream_type(id) == stream_direction::bidirectional;
        return {id, local || bidi, !local || bidi, false};
    }

    [[nodiscard]] static constexpr auto increase_limit(std::uint64_t& current,
                                                        std::uint64_t limit)
        noexcept -> std::expected<void, stream_registry_error>
    {
        if (limit > max_stream_count)
            return std::unexpected(stream_registry_error::invalid_limit);
        if (limit > current) current = limit;
        return {};
    }

    stream_role role_;
    std::array<std::uint64_t, 2> local_limit_ {};
    std::array<std::uint64_t, 2> peer_limit_ {};
    std::array<std::uint64_t, 2> local_opened_ {};
    std::array<std::uint64_t, 2> peer_opened_ {};
    std::array<registered_stream, Capacity> streams_ {};
    std::size_t size_ {0};
    std::array<std::array<ordinal_range, Capacity>, 2> retired_ {};
    std::array<std::size_t, 2> retired_count_ {};
};

} // namespace eventloop::quic::detail
