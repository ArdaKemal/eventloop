#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>

namespace eventloop::quic::detail {

using path_handle = std::uint64_t;
using path_challenge = std::array<std::byte, 8>;

enum class path_validation_error {
    unknown_path,
    duplicate_path,
    full,
    counter_overflow,
    amplification_limited,
    challenge_pending,
    duplicate_challenge,
    unmatched_response,
};

enum class path_endpoint_role { client, server };

struct path_validation_slot {
    path_handle handle {0};
    std::uint64_t received_bytes {0};
    std::uint64_t sent_bytes {0};
    path_challenge challenge {};
    bool occupied {false};
    bool validated {false};
    bool challenge_pending {false};
};

// The caller owns the fixed slot storage and supplies fresh unpredictable data
// for every challenge. Counts are UDP payload bytes, including padding and
// discarded packets attributed to the connection. Call record_sent only after
// a send succeeds.
class path_validation {
public:
    constexpr path_validation(std::span<path_validation_slot> slots,
                              path_endpoint_role role) noexcept
        : slots_(slots), role_(role)
    {
        reset();
    }

    constexpr auto reset() noexcept -> void
    {
        for (auto& slot : slots_) slot = {};
    }

    [[nodiscard]] constexpr auto add(path_handle handle, bool validated = false)
        noexcept -> std::expected<void, path_validation_error>
    {
        if (find(handle) != nullptr)
            return std::unexpected(path_validation_error::duplicate_path);
        for (auto& slot : slots_) {
            if (slot.occupied) continue;
            slot = {};
            slot.handle = handle;
            slot.occupied = true;
            slot.validated = validated;
            return {};
        }
        return std::unexpected(path_validation_error::full);
    }

    [[nodiscard]] constexpr auto remove(path_handle handle) noexcept
        -> std::expected<void, path_validation_error>
    {
        auto* slot = find(handle);
        if (slot == nullptr)
            return std::unexpected(path_validation_error::unknown_path);
        *slot = {};
        return {};
    }

    [[nodiscard]] constexpr auto validate(path_handle handle) noexcept
        -> std::expected<void, path_validation_error>
    {
        auto* slot = find(handle);
        if (slot == nullptr)
            return std::unexpected(path_validation_error::unknown_path);
        slot->validated = true;
        slot->challenge_pending = false;
        return {};
    }

    [[nodiscard]] constexpr auto is_validated(path_handle handle) const noexcept
        -> std::expected<bool, path_validation_error>
    {
        const auto* slot = find(handle);
        if (slot == nullptr)
            return std::unexpected(path_validation_error::unknown_path);
        return slot->validated;
    }

    [[nodiscard]] constexpr auto record_received(path_handle handle,
                                                  std::uint64_t bytes) noexcept
        -> std::expected<void, path_validation_error>
    {
        auto* slot = find(handle);
        if (slot == nullptr)
            return std::unexpected(path_validation_error::unknown_path);
        if (bytes > max_bytes - slot->received_bytes)
            return std::unexpected(path_validation_error::counter_overflow);
        slot->received_bytes += bytes;
        return {};
    }

    [[nodiscard]] constexpr auto can_send(path_handle handle,
                                           std::uint64_t bytes) const noexcept
        -> std::expected<bool, path_validation_error>
    {
        const auto* slot = find(handle);
        if (slot == nullptr)
            return std::unexpected(path_validation_error::unknown_path);
        if (bytes > max_bytes - slot->sent_bytes)
            return std::unexpected(path_validation_error::counter_overflow);
        return bytes <= credit(*slot);
    }

    // Bytes this path may still send before anti-amplification blocks it.
    [[nodiscard]] constexpr auto send_credit(path_handle handle) const noexcept
        -> std::uint64_t
    {
        const auto* slot = find(handle);
        return slot == nullptr ? 0 : credit(*slot);
    }

    [[nodiscard]] constexpr auto record_sent(path_handle handle,
                                              std::uint64_t bytes) noexcept
        -> std::expected<void, path_validation_error>
    {
        const auto allowed = can_send(handle, bytes);
        if (!allowed) return std::unexpected(allowed.error());
        if (!*allowed)
            return std::unexpected(path_validation_error::amplification_limited);
        find(handle)->sent_bytes += bytes;
        return {};
    }

    [[nodiscard]] constexpr auto issue_challenge(path_handle handle,
                                                  path_challenge token) noexcept
        -> std::expected<void, path_validation_error>
    {
        auto* slot = find(handle);
        if (slot == nullptr)
            return std::unexpected(path_validation_error::unknown_path);
        if (slot->challenge_pending)
            return std::unexpected(path_validation_error::challenge_pending);
        for (const auto& other : slots_)
            if (other.occupied && other.challenge_pending &&
                other.challenge == token)
                return std::unexpected(path_validation_error::duplicate_challenge);
        slot->challenge = token;
        slot->challenge_pending = true;
        return {};
    }

    // A response may arrive on any path. The matched challenge's path is
    // validated and its token consumed, so duplicate responses do nothing.
    [[nodiscard]] constexpr auto response_matches(path_handle handle,
        path_challenge token) const noexcept -> std::expected<bool, path_validation_error>
    {
        const auto* slot = find(handle);
        if (!slot) return std::unexpected(path_validation_error::unknown_path);
        return slot->challenge_pending && slot->challenge == token;
    }

    [[nodiscard]] constexpr auto accept_response(path_challenge token) noexcept
        -> std::expected<path_handle, path_validation_error>
    {
        for (auto& slot : slots_) {
            if (!slot.occupied || !slot.challenge_pending ||
                slot.challenge != token)
                continue;
            slot.challenge_pending = false;
            slot.validated = true;
            return slot.handle;
        }
        return std::unexpected(path_validation_error::unmatched_response);
    }

    [[nodiscard]] constexpr auto bytes_received(path_handle handle) const noexcept
        -> std::expected<std::uint64_t, path_validation_error>
    {
        const auto* slot = find(handle);
        if (slot == nullptr)
            return std::unexpected(path_validation_error::unknown_path);
        return slot->received_bytes;
    }

    [[nodiscard]] constexpr auto bytes_sent(path_handle handle) const noexcept
        -> std::expected<std::uint64_t, path_validation_error>
    {
        const auto* slot = find(handle);
        if (slot == nullptr)
            return std::unexpected(path_validation_error::unknown_path);
        return slot->sent_bytes;
    }

private:
    static constexpr auto max_bytes = std::numeric_limits<std::uint64_t>::max();

    [[nodiscard]] constexpr auto find(path_handle handle) noexcept
        -> path_validation_slot*
    {
        for (auto& slot : slots_)
            if (slot.occupied && slot.handle == handle) return &slot;
        return nullptr;
    }

    [[nodiscard]] constexpr auto find(path_handle handle) const noexcept
        -> const path_validation_slot*
    {
        for (const auto& slot : slots_)
            if (slot.occupied && slot.handle == handle) return &slot;
        return nullptr;
    }

    [[nodiscard]] constexpr auto credit(const path_validation_slot& slot) const noexcept
        -> std::uint64_t
    {
        if (role_ == path_endpoint_role::client || slot.validated)
            return max_bytes - slot.sent_bytes;
        const auto limit = slot.received_bytes > max_bytes / 3
                               ? max_bytes : slot.received_bytes * 3;
        return limit > slot.sent_bytes ? limit - slot.sent_bytes : 0;
    }

    std::span<path_validation_slot> slots_ {};
    path_endpoint_role role_ {path_endpoint_role::server};
};

} // namespace eventloop::quic::detail
