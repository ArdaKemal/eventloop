#pragma once

#include "quic/varint.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace eventloop::quic::detail {

enum class connection_id_registry_error {
    invalid_limit,
    invalid_sequence,
    invalid_retire_prior_to,
    invalid_connection_id,
    invalid_reset_token,
    missing_initial,
    already_initialized,
    inconsistent_duplicate,
    connection_id_limit,
    capacity_exhausted,
    zero_length_connection_id,
    unknown_connection_id,
    retired_connection_id,
};

struct peer_connection_id {
    std::uint64_t sequence_number {0};
    std::array<std::byte, 20> bytes {};
    std::uint8_t length {0};
    std::array<std::byte, 16> reset_token {};
    bool has_reset_token {false};
    bool retired {false};
    bool retirement_pending {false};

    [[nodiscard]] constexpr auto id() const noexcept -> std::span<const std::byte>
    { return {bytes.data(), length}; }
};

// Capacity bounds all IDs observed over the connection lifetime, including
// retired IDs retained to validate reordered and duplicate frames. The caller
// queues RETIRE_CONNECTION_ID frames for pending retirements and owns their
// retransmission after mark_retirement_queued().
template<std::size_t Capacity>
class peer_connection_id_registry {
public:
    [[nodiscard]] constexpr auto set_active_limit(std::uint64_t limit) noexcept
        -> std::expected<void, connection_id_registry_error>
    {
        if (limit < 2 || limit > max_varint_value)
            return std::unexpected(connection_id_registry_error::invalid_limit);
        if (limit < active_count())
            return std::unexpected(connection_id_registry_error::connection_id_limit);
        active_limit_ = limit;
        return {};
    }

    // The peer's handshake Source Connection ID has sequence number zero.
    // A reset token, when provided by transport parameters, is optional here.
    [[nodiscard]] constexpr auto set_initial(std::span<const std::byte> id,
        std::span<const std::byte> reset_token = {}) noexcept
        -> std::expected<void, connection_id_registry_error>
    {
        if (initialized_)
            return std::unexpected(connection_id_registry_error::already_initialized);
        if (id.size() > 20)
            return std::unexpected(connection_id_registry_error::invalid_connection_id);
        if (!reset_token.empty() && reset_token.size() != 16)
            return std::unexpected(connection_id_registry_error::invalid_reset_token);
        if constexpr (Capacity == 0) {
            return std::unexpected(connection_id_registry_error::capacity_exhausted);
        } else {
            records_[0] = make_record(0, id, reset_token, false);
            size_ = 1;
            initialized_ = true;
            selected_ = 0;
            return {};
        }
    }

    // The server's stateless_reset_token transport parameter belongs to the
    // handshake connection ID, which is learned before the parameters.
    [[nodiscard]] constexpr auto set_initial_reset_token(
        std::span<const std::byte> reset_token) noexcept
        -> std::expected<void, connection_id_registry_error>
    {
        if (!initialized_)
            return std::unexpected(connection_id_registry_error::missing_initial);
        if (reset_token.size() != 16)
            return std::unexpected(connection_id_registry_error::invalid_reset_token);
        std::copy(reset_token.begin(), reset_token.end(), records_[0].reset_token.begin());
        records_[0].has_reset_token = true;
        return {};
    }

    // Also accepts preferred_address sequence number one. Older Retire Prior
    // To values are ignored, but still must not exceed this frame's sequence.
    [[nodiscard]] constexpr auto add(std::uint64_t sequence_number,
        std::uint64_t retire_prior_to, std::span<const std::byte> id,
        std::span<const std::byte> reset_token) noexcept
        -> std::expected<void, connection_id_registry_error>
    {
        if (!initialized_)
            return std::unexpected(connection_id_registry_error::missing_initial);
        if (sequence_number > max_varint_value)
            return std::unexpected(connection_id_registry_error::invalid_sequence);
        if (retire_prior_to > sequence_number)
            return std::unexpected(connection_id_registry_error::invalid_retire_prior_to);
        if (id.empty() || id.size() > 20)
            return std::unexpected(connection_id_registry_error::invalid_connection_id);
        if (reset_token.size() != 16)
            return std::unexpected(connection_id_registry_error::invalid_reset_token);
        if (records_[0].length == 0)
            return std::unexpected(connection_id_registry_error::zero_length_connection_id);

        const auto* existing = find(sequence_number);
        if (existing &&
            (existing->length != id.size() ||
             !std::equal(id.begin(), id.end(), existing->bytes.begin()) ||
             !existing->has_reset_token ||
             !std::equal(reset_token.begin(), reset_token.end(),
                         existing->reset_token.begin())))
            return std::unexpected(connection_id_registry_error::inconsistent_duplicate);
        for (std::size_t i = 0; i < size_; ++i)
            if (records_[i].sequence_number != sequence_number &&
                records_[i].length == id.size() &&
                std::equal(id.begin(), id.end(), records_[i].bytes.begin()))
                return std::unexpected(connection_id_registry_error::inconsistent_duplicate);

        const auto new_retire_prior_to = std::max(retire_prior_to_, retire_prior_to);
        std::size_t surviving = 0;
        for (std::size_t i = 0; i < size_; ++i)
            if (!records_[i].retired &&
                records_[i].sequence_number >= new_retire_prior_to)
                ++surviving;
        const bool new_active = !existing && sequence_number >= new_retire_prior_to;
        if (surviving + (new_active ? 1u : 0u) > active_limit_)
            return std::unexpected(connection_id_registry_error::connection_id_limit);
        if (!existing && size_ == Capacity)
            return std::unexpected(connection_id_registry_error::capacity_exhausted);

        // Commit only after all validation and capacity checks have succeeded.
        retire_prior_to_ = new_retire_prior_to;
        for (std::size_t i = 0; i < size_; ++i)
            if (!records_[i].retired &&
                records_[i].sequence_number < retire_prior_to_) {
                records_[i].retired = true;
                records_[i].retirement_pending = true;
            }
        if (!existing)
            records_[size_++] = make_record(sequence_number, id, reset_token,
                                            !new_active);
        if (selected_ && records_[*selected_].retired)
            selected_.reset();
        if (!selected_) select_first_active();
        return {};
    }

    [[nodiscard]] constexpr auto find(std::uint64_t sequence_number) const noexcept
        -> const peer_connection_id*
    {
        for (std::size_t i = 0; i < size_; ++i)
            if (records_[i].sequence_number == sequence_number) return &records_[i];
        return nullptr;
    }

    [[nodiscard]] constexpr auto select(std::uint64_t sequence_number) noexcept
        -> std::expected<void, connection_id_registry_error>
    {
        for (std::size_t i = 0; i < size_; ++i)
            if (records_[i].sequence_number == sequence_number) {
                if (records_[i].retired)
                    return std::unexpected(connection_id_registry_error::retired_connection_id);
                selected_ = i;
                return {};
            }
        return std::unexpected(connection_id_registry_error::unknown_connection_id);
    }

    [[nodiscard]] constexpr auto selected() const noexcept -> const peer_connection_id*
    { return selected_ ? &records_[*selected_] : nullptr; }

    [[nodiscard]] constexpr auto next_retirement() const noexcept
        -> std::optional<std::uint64_t>
    {
        std::optional<std::uint64_t> result;
        for (std::size_t i = 0; i < size_; ++i)
            if (records_[i].retirement_pending &&
                (!result || records_[i].sequence_number < *result))
                result = records_[i].sequence_number;
        return result;
    }

    [[nodiscard]] constexpr auto mark_retirement_queued(
        std::uint64_t sequence_number) noexcept
        -> std::expected<void, connection_id_registry_error>
    {
        for (std::size_t i = 0; i < size_; ++i)
            if (records_[i].sequence_number == sequence_number &&
                records_[i].retirement_pending) {
                records_[i].retirement_pending = false;
                return {};
            }
        return std::unexpected(connection_id_registry_error::unknown_connection_id);
    }

    [[nodiscard]] constexpr auto size() const noexcept -> std::size_t
    { return size_; }
    [[nodiscard]] constexpr auto active_count() const noexcept -> std::size_t
    {
        std::size_t count = 0;
        for (std::size_t i = 0; i < size_; ++i)
            if (!records_[i].retired) ++count;
        return count;
    }
    [[nodiscard]] constexpr auto retire_prior_to() const noexcept -> std::uint64_t
    { return retire_prior_to_; }
    [[nodiscard]] constexpr auto active_limit() const noexcept -> std::uint64_t
    { return active_limit_; }

private:
    [[nodiscard]] static constexpr auto make_record(std::uint64_t sequence_number,
        std::span<const std::byte> id, std::span<const std::byte> reset_token,
        bool retired) noexcept -> peer_connection_id
    {
        peer_connection_id record;
        record.sequence_number = sequence_number;
        record.length = static_cast<std::uint8_t>(id.size());
        std::copy(id.begin(), id.end(), record.bytes.begin());
        std::copy(reset_token.begin(), reset_token.end(), record.reset_token.begin());
        record.has_reset_token = !reset_token.empty();
        record.retired = retired;
        record.retirement_pending = retired;
        return record;
    }

    constexpr auto select_first_active() noexcept -> void
    {
        for (std::size_t i = 0; i < size_; ++i)
            if (!records_[i].retired &&
                (!selected_ || records_[i].sequence_number <
                    records_[*selected_].sequence_number))
                selected_ = i;
    }

    std::array<peer_connection_id, Capacity> records_ {};
    std::size_t size_ {0};
    std::uint64_t active_limit_ {2};
    std::uint64_t retire_prior_to_ {0};
    std::optional<std::size_t> selected_ {};
    bool initialized_ {false};
};

} // namespace eventloop::quic::detail
