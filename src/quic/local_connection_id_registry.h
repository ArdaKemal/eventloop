#pragma once

#include "quic/varint.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace eventloop::quic::detail {

enum class local_connection_id_error {
    invalid_limit,
    missing_initial,
    already_initialized,
    invalid_connection_id,
    invalid_reset_token,
    duplicate_connection_id,
    duplicate_reset_token,
    zero_length_connection_id,
    invalid_sequence,
    invalid_retire_prior_to,
    connection_id_limit,
    capacity_exhausted,
    invalid_preferred_address,
    retirement_pending,
    retiring_packet_destination,
};

struct local_connection_id {
    std::uint64_t sequence_number {0};
    std::uint64_t retire_prior_to {0};
    std::array<std::byte, 20> bytes {};
    std::uint8_t length {0};
    std::array<std::byte, 16> reset_token {};
    bool has_reset_token {false};
    bool preferred_address {false};
    bool retired {false};

    [[nodiscard]] constexpr auto id() const noexcept -> std::span<const std::byte>
    { return {bytes.data(), length}; }
};

// Capacity bounds lifetime issuance, including retired tombstones. The caller
// supplies unpredictable IDs/tokens, reserves output before issuance, and owns
// NEW_CONNECTION_ID serialization, ACK/loss tracking and retransmission. Records
// have stable addresses. Retire Prior To does not stop inbound CID routing until
// the peer sends RETIRE_CONNECTION_ID. Retry and original destination IDs are
// handshake routing aliases, not sequenced records in this registry.
template<std::size_t Capacity>
class local_connection_id_registry {
public:
    [[nodiscard]] constexpr auto set_active_limit(std::uint64_t limit) noexcept
        -> std::expected<void, local_connection_id_error>
    {
        if (limit < 2 || limit > max_varint_value)
            return std::unexpected(local_connection_id_error::invalid_limit);
        if (peer_active_count() > limit)
            return std::unexpected(local_connection_id_error::connection_id_limit);
        active_limit_ = limit;
        return {};
    }

    [[nodiscard]] constexpr auto set_initial(std::span<const std::byte> id,
        std::span<const std::byte> reset_token = {}) noexcept
        -> std::expected<void, local_connection_id_error>
    {
        if (size_ != 0)
            return std::unexpected(local_connection_id_error::already_initialized);
        if (id.size() > 20)
            return std::unexpected(local_connection_id_error::invalid_connection_id);
        if ((!reset_token.empty() && reset_token.size() != 16) ||
            (id.empty() && !reset_token.empty()))
            return std::unexpected(local_connection_id_error::invalid_reset_token);
        if constexpr (Capacity == 0) {
            return std::unexpected(local_connection_id_error::capacity_exhausted);
        } else {
            records_[size_++] = make_record(0, 0, id, reset_token, false);
            return {};
        }
    }

    // Must be called before issuing any NEW_CONNECTION_ID. The caller restricts
    // preferred_address to the server's handshake transport parameters.
    [[nodiscard]] constexpr auto set_preferred_address(std::span<const std::byte> id,
        std::span<const std::byte> reset_token) noexcept
        -> std::expected<const local_connection_id*, local_connection_id_error>
    {
        if (size_ == 0)
            return std::unexpected(local_connection_id_error::missing_initial);
        if (size_ != 1)
            return std::unexpected(local_connection_id_error::invalid_preferred_address);
        return append(id, reset_token, 0, true);
    }

    [[nodiscard]] constexpr auto issue(std::span<const std::byte> id,
        std::span<const std::byte> reset_token, std::uint64_t retire_prior_to = 0) noexcept
        -> std::expected<const local_connection_id*, local_connection_id_error>
    { return append(id, reset_token, retire_prior_to, false); }

    // Call only for an authenticated frame in an allowed packet number space.
    // true means a newly retired ID; false means an idempotent duplicate.
    [[nodiscard]] constexpr auto retire(std::uint64_t sequence_number,
        std::span<const std::byte> packet_destination_cid) noexcept
        -> std::expected<bool, local_connection_id_error>
    {
        if (size_ == 0)
            return std::unexpected(local_connection_id_error::missing_initial);
        if (records_[0].length == 0)
            return std::unexpected(local_connection_id_error::zero_length_connection_id);
        if (sequence_number >= size_)
            return std::unexpected(local_connection_id_error::invalid_sequence);
        auto& record = records_[static_cast<std::size_t>(sequence_number)];
        if (std::ranges::equal(record.id(), packet_destination_cid))
            return std::unexpected(local_connection_id_error::retiring_packet_destination);
        const bool changed = !record.retired;
        record.retired = true;
        return changed;
    }

    [[nodiscard]] constexpr auto find(std::uint64_t sequence_number) const noexcept
        -> const local_connection_id*
    { return sequence_number < size_ ? &records_[static_cast<std::size_t>(sequence_number)] : nullptr; }

    [[nodiscard]] constexpr auto match(std::span<const std::byte> id) const noexcept
        -> const local_connection_id*
    {
        for (std::size_t i = 0; i < size_; ++i)
            if (!records_[i].retired && std::ranges::equal(records_[i].id(), id))
                return &records_[i];
        return nullptr;
    }

    [[nodiscard]] constexpr auto size() const noexcept -> std::size_t { return size_; }
    [[nodiscard]] constexpr auto active_limit() const noexcept -> std::uint64_t { return active_limit_; }
    [[nodiscard]] constexpr auto retire_prior_to() const noexcept -> std::uint64_t { return retire_prior_to_; }
    [[nodiscard]] constexpr auto active_count() const noexcept -> std::size_t
    { return count_from(0); }
    // IDs the peer may keep after processing the latest retirement request.
    [[nodiscard]] constexpr auto peer_active_count() const noexcept -> std::size_t
    { return count_from(retire_prior_to_); }

private:
    [[nodiscard]] constexpr auto count_from(std::uint64_t first) const noexcept -> std::size_t
    {
        std::size_t count = 0;
        for (std::size_t i = 0; i < size_; ++i)
            if (!records_[i].retired && records_[i].sequence_number >= first) ++count;
        return count;
    }

    [[nodiscard]] constexpr auto append(std::span<const std::byte> id,
        std::span<const std::byte> reset_token, std::uint64_t retire_prior_to,
        bool preferred_address) noexcept
        -> std::expected<const local_connection_id*, local_connection_id_error>
    {
        if (size_ == 0)
            return std::unexpected(local_connection_id_error::missing_initial);
        if (records_[0].length == 0)
            return std::unexpected(local_connection_id_error::zero_length_connection_id);
        if (id.empty() || id.size() > 20)
            return std::unexpected(local_connection_id_error::invalid_connection_id);
        if (reset_token.size() != 16)
            return std::unexpected(local_connection_id_error::invalid_reset_token);
        if (size_ > max_varint_value)
            return std::unexpected(local_connection_id_error::invalid_sequence);
        if (retire_prior_to > size_ || retire_prior_to < retire_prior_to_)
            return std::unexpected(local_connection_id_error::invalid_retire_prior_to);
        if (retire_prior_to > retire_prior_to_ && active_count() != peer_active_count())
            return std::unexpected(local_connection_id_error::retirement_pending);
        for (std::size_t i = 0; i < size_; ++i) {
            if (std::ranges::equal(records_[i].id(), id))
                return std::unexpected(local_connection_id_error::duplicate_connection_id);
            if (records_[i].has_reset_token &&
                std::ranges::equal(records_[i].reset_token, reset_token))
                return std::unexpected(local_connection_id_error::duplicate_reset_token);
        }
        if (count_from(retire_prior_to) >= active_limit_)
            return std::unexpected(local_connection_id_error::connection_id_limit);
        if (size_ == Capacity)
            return std::unexpected(local_connection_id_error::capacity_exhausted);

        records_[size_] = make_record(size_, retire_prior_to, id, reset_token, preferred_address);
        retire_prior_to_ = retire_prior_to;
        return &records_[size_++];
    }

    [[nodiscard]] static constexpr auto make_record(std::uint64_t sequence_number,
        std::uint64_t retire_prior_to, std::span<const std::byte> id,
        std::span<const std::byte> reset_token, bool preferred_address) noexcept
        -> local_connection_id
    {
        local_connection_id record;
        record.sequence_number = sequence_number;
        record.retire_prior_to = retire_prior_to;
        record.length = static_cast<std::uint8_t>(id.size());
        std::copy(id.begin(), id.end(), record.bytes.begin());
        std::copy(reset_token.begin(), reset_token.end(), record.reset_token.begin());
        record.has_reset_token = !reset_token.empty();
        record.preferred_address = preferred_address;
        return record;
    }

    std::array<local_connection_id, Capacity> records_ {};
    std::size_t size_ {0};
    std::uint64_t active_limit_ {2};
    std::uint64_t retire_prior_to_ {0};
};

} // namespace eventloop::quic::detail
