#pragma once

#include "quic/congestion_control.h"
#include "quic/path_validation.h"
#include "quic/recovery_timer.h"

#include <array>
#include <cstddef>
#include <expected>
#include <optional>

namespace eventloop::quic::detail {

enum class path_recovery_error {
    invalid_datagram_size,
    active_path_exists,
    candidate_exists,
    no_candidate,
    duplicate_path,
    full,
    not_validated,
};

// One path's path-specific recovery state. Packet-number spaces, ACK ranges,
// sent-packet history, and loss detection stay connection-wide; only the RTT
// estimator and congestion controller are scoped to a path, because packets
// sent on one path must not contribute to another path's congestion control or
// RTT estimate (RFC 9000 Section 9.4).
struct path_recovery_slot {
    path_handle handle {0};
    rtt_estimator rtt {};
    newreno_congestion_controller congestion {};
    bool occupied {false};
    bool validated {false};
};

// Bounded owner of one active path and at most one candidate path. A candidate
// never replaces the active path implicitly: begin_candidate() registers it,
// mark_validated() records the caller's path-validation confirmation, and only
// promote_candidate() switches the active path. Promotion installs the
// candidate with fresh recovery state, resetting RTT and congestion control to
// initial values as required by RFC 9000 Section 9.4. cancel_candidate() and
// every rejected transition leave the active path and its state untouched.
//
// PATH_CHALLENGE/PATH_RESPONSE matching and anti-amplification accounting stay
// in path_validation.h; this class only mirrors the resulting validation flag.
template <std::size_t Capacity>
class path_recovery_state {
public:
    static_assert(Capacity >= 1, "at least one path slot is required");
    static constexpr std::size_t capacity = Capacity;

    constexpr path_recovery_state() noexcept = default;

    [[nodiscard]] constexpr auto reset(
        std::size_t max_datagram_size,
        recovery_duration starting_rtt = initial_rtt) noexcept
        -> std::expected<void, path_recovery_error>
    {
        newreno_congestion_controller probe;
        if (!probe.reset(max_datagram_size))
            return std::unexpected(path_recovery_error::invalid_datagram_size);
        for (auto& slot : slots_) slot = {};
        max_datagram_size_ = max_datagram_size;
        starting_rtt_ = starting_rtt;
        active_slot_.reset();
        candidate_slot_.reset();
        return {};
    }

    // Register the current path once, before any candidate is considered.
    [[nodiscard]] constexpr auto set_active(path_handle handle) noexcept
        -> std::expected<void, path_recovery_error>
    {
        if (active_slot_)
            return std::unexpected(path_recovery_error::active_path_exists);
        if (find(handle) != nullptr)
            return std::unexpected(path_recovery_error::duplicate_path);
        const auto index = free_slot();
        if (!index) return std::unexpected(path_recovery_error::full);
        initialize(slots_[*index], handle, true);
        active_slot_ = index;
        return {};
    }

    // Register a candidate path with fresh recovery state. The active path and
    // its state are unchanged until mark_validated() then promote_candidate().
    [[nodiscard]] constexpr auto begin_candidate(path_handle handle) noexcept
        -> std::expected<void, path_recovery_error>
    {
        if (candidate_slot_)
            return std::unexpected(path_recovery_error::candidate_exists);
        if (find(handle) != nullptr)
            return std::unexpected(path_recovery_error::duplicate_path);
        const auto index = free_slot();
        if (!index) return std::unexpected(path_recovery_error::full);
        initialize(slots_[*index], handle, false);
        candidate_slot_ = index;
        return {};
    }

    // Record the caller's path-validation confirmation for the candidate.
    [[nodiscard]] constexpr auto mark_validated() noexcept
        -> std::expected<void, path_recovery_error>
    {
        if (!candidate_slot_)
            return std::unexpected(path_recovery_error::no_candidate);
        slots_[*candidate_slot_].validated = true;
        return {};
    }

    // Promote the validated candidate to the active path. The new active path
    // starts from initial RTT and congestion state; the old active slot is
    // released. An unvalidated candidate is rejected without changing state.
    [[nodiscard]] constexpr auto promote_candidate() noexcept
        -> std::expected<void, path_recovery_error>
    {
        if (!candidate_slot_)
            return std::unexpected(path_recovery_error::no_candidate);
        auto& candidate = slots_[*candidate_slot_];
        if (!candidate.validated)
            return std::unexpected(path_recovery_error::not_validated);
        if (active_slot_) slots_[*active_slot_] = {};
        candidate.rtt.reset(starting_rtt_);
        (void)candidate.congestion.reset(max_datagram_size_);
        active_slot_ = candidate_slot_;
        candidate_slot_.reset();
        return {};
    }

    // Discard the candidate. The active path and its recovery state survive.
    [[nodiscard]] constexpr auto cancel_candidate() noexcept
        -> std::expected<void, path_recovery_error>
    {
        if (!candidate_slot_)
            return std::unexpected(path_recovery_error::no_candidate);
        slots_[*candidate_slot_] = {};
        candidate_slot_.reset();
        return {};
    }

    [[nodiscard]] constexpr auto active() noexcept -> path_recovery_slot*
    { return active_slot_ ? &slots_[*active_slot_] : nullptr; }
    [[nodiscard]] constexpr auto active() const noexcept
        -> const path_recovery_slot*
    { return active_slot_ ? &slots_[*active_slot_] : nullptr; }
    [[nodiscard]] constexpr auto candidate() noexcept -> path_recovery_slot*
    { return candidate_slot_ ? &slots_[*candidate_slot_] : nullptr; }
    [[nodiscard]] constexpr auto candidate() const noexcept
        -> const path_recovery_slot*
    { return candidate_slot_ ? &slots_[*candidate_slot_] : nullptr; }

    [[nodiscard]] constexpr auto active_handle() const noexcept
        -> std::optional<path_handle>
    {
        const auto* slot = active();
        return slot ? std::optional<path_handle> {slot->handle} : std::nullopt;
    }
    [[nodiscard]] constexpr auto candidate_handle() const noexcept
        -> std::optional<path_handle>
    {
        const auto* slot = candidate();
        return slot ? std::optional<path_handle> {slot->handle} : std::nullopt;
    }

    [[nodiscard]] constexpr auto find(path_handle handle) noexcept
        -> path_recovery_slot*
    {
        for (auto& slot : slots_)
            if (slot.occupied && slot.handle == handle) return &slot;
        return nullptr;
    }
    [[nodiscard]] constexpr auto find(path_handle handle) const noexcept
        -> const path_recovery_slot*
    {
        for (const auto& slot : slots_)
            if (slot.occupied && slot.handle == handle) return &slot;
        return nullptr;
    }

private:
    constexpr auto initialize(path_recovery_slot& slot, path_handle handle,
                              bool validated) noexcept -> void
    {
        slot = {};
        slot.handle = handle;
        slot.occupied = true;
        slot.validated = validated;
        slot.rtt.reset(starting_rtt_);
        if (!slot.congestion.reset(max_datagram_size_)) slot = {};
    }

    [[nodiscard]] constexpr auto free_slot() const noexcept
        -> std::optional<std::size_t>
    {
        for (std::size_t index = 0; index < slots_.size(); ++index)
            if (!slots_[index].occupied) return index;
        return std::nullopt;
    }

    std::array<path_recovery_slot, Capacity> slots_ {};
    std::optional<std::size_t> active_slot_ {};
    std::optional<std::size_t> candidate_slot_ {};
    std::size_t max_datagram_size_ {1200};
    recovery_duration starting_rtt_ {initial_rtt};
};

} // namespace eventloop::quic::detail
