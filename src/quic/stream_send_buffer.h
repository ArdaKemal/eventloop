#pragma once

#include "quic/crypto_send_buffer.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace eventloop::quic::detail {

enum class stream_send_error {
    invalid_flow_limit,
    invalid_offset,
    invalid_range,
    capacity_exceeded,
    flow_blocked,
    unsent_data,
    invalid_fin,
    closed,
};

struct stream_send_chunk {
    std::uint64_t offset {0};
    std::span<const std::byte> data {};
    bool fin {false};
};

// One stream's send queue. Bytes and per-byte state live in fixed internal
// storage. Packet identity and connection-level flow control stay with the
// caller. Returned data spans remain valid until append or acknowledge.
template<std::size_t Capacity>
class stream_send_buffer {
public:
    constexpr explicit stream_send_buffer(std::uint64_t flow_limit = 0) noexcept
        : flow_limit_(flow_limit)
    {
    }

    // Empties the buffer for a new stream without rewriting the byte storage.
    constexpr auto reset() noexcept -> void
    {
        bytes_.reset();
        flow_limit_ = 0;
        final_size_.reset();
        fin_pending_ = fin_sent_ = fin_acked_ = false;
    }

    [[nodiscard]] constexpr auto valid() const noexcept -> bool
    {
        return flow_limit_ <= max_varint_value;
    }

    [[nodiscard]] constexpr auto flow_limit() const noexcept -> std::uint64_t
    {
        return flow_limit_;
    }

    [[nodiscard]] constexpr auto extend_flow_limit(std::uint64_t limit) noexcept
        -> std::expected<void, stream_send_error>
    {
        if (limit > max_varint_value || limit < flow_limit_) {
            return std::unexpected(stream_send_error::invalid_flow_limit);
        }
        flow_limit_ = limit;
        return {};
    }

    [[nodiscard]] constexpr auto base_offset() const noexcept -> std::uint64_t
    {
        return bytes_.base_offset();
    }

    [[nodiscard]] constexpr auto next_offset() const noexcept -> std::uint64_t
    {
        return bytes_.next_offset();
    }

    [[nodiscard]] constexpr auto buffered_size() const noexcept -> std::size_t
    {
        return bytes_.buffered_size();
    }

    [[nodiscard]] constexpr auto writable_bytes() const noexcept -> std::size_t
    {
        return final_size_ ? 0 : Capacity - bytes_.buffered_size();
    }

    [[nodiscard]] constexpr auto final_size() const noexcept
        -> std::optional<std::uint64_t>
    {
        return final_size_;
    }

    [[nodiscard]] constexpr auto fin_acked() const noexcept -> bool
    {
        return fin_acked_;
    }

    [[nodiscard]] constexpr auto complete() const noexcept -> bool
    {
        return fin_acked_ && bytes_.base_offset() == bytes_.next_offset();
    }

    // Copies application bytes and assigns a monotonically increasing offset.
    // Flow credit gates transmission rather than application buffering.
    [[nodiscard]] constexpr auto append(std::span<const std::byte> data) noexcept
        -> std::expected<std::uint64_t, stream_send_error>
    {
        if (!valid())
            return std::unexpected(stream_send_error::invalid_flow_limit);
        if (final_size_) return std::unexpected(stream_send_error::closed);
        const auto result = bytes_.append(data);
        if (result) return *result;
        return std::unexpected(result.error() == crypto_send_error::invalid_offset
                                   ? stream_send_error::invalid_offset
                                   : stream_send_error::capacity_exceeded);
    }

    // Closing commits the final size. FIN can be sent with the last data chunk
    // or as an empty STREAM frame after the data was already sent.
    [[nodiscard]] constexpr auto close() noexcept
        -> std::expected<std::uint64_t, stream_send_error>
    {
        if (!valid())
            return std::unexpected(stream_send_error::invalid_flow_limit);
        if (final_size_) return std::unexpected(stream_send_error::closed);
        final_size_ = bytes_.next_offset();
        fin_pending_ = true;
        return *final_size_;
    }

    // Select the lowest pending byte range, clipped at peer flow credit and
    // the physical ring boundary. A pending FIN is attached at the final byte
    // or returned as an empty chunk when all data is already transmitted.
    [[nodiscard]] constexpr auto next_pending(std::size_t max_size) const noexcept
        -> stream_send_chunk
    {
        const auto chunk = bytes_.next_pending(max_size);
        if (!chunk.data.empty() && chunk.offset < flow_limit_) {
            const auto allowed = static_cast<std::size_t>(
                std::min<std::uint64_t>(chunk.data.size(),
                                        flow_limit_ - chunk.offset));
            const auto fin = fin_pending_ && final_size_ &&
                             chunk.offset + allowed == *final_size_;
            return {chunk.offset, chunk.data.first(allowed), fin};
        }
        if (fin_pending_ && final_size_ && *final_size_ <= flow_limit_) {
            return {*final_size_, {}, true};
        }
        return {};
    }

    [[nodiscard]] constexpr auto next_unacknowledged(std::size_t max_size) const noexcept
        -> stream_send_chunk
    {
        const auto chunk = bytes_.next_unacknowledged(max_size);
        if (!chunk.data.empty())
            return {chunk.offset, chunk.data, fin_sent_ && !fin_acked_ && final_size_ &&
                chunk.offset + chunk.data.size() == *final_size_};
        if (fin_sent_ && !fin_acked_ && final_size_) return {*final_size_, {}, true};
        return {};
    }

    // Read-only validation for owner-thread packet submission preflight.
    [[nodiscard]] constexpr auto preflight_mark_sent(std::uint64_t offset,
                                           std::size_t length,
                                           bool fin = false) const noexcept
        -> std::expected<void, stream_send_error>
    {
        if (const auto result = validate_sent_range(offset, length, fin); !result) return result;
        if (!bytes_.preflight_mark_sent(offset, length))
            return std::unexpected(stream_send_error::invalid_range);
        return {};
    }

    // Called after packet construction succeeds. Repeated transmissions are
    // valid for probes; ACKed bytes and ACKed FIN cannot be sent again.
    [[nodiscard]] constexpr auto mark_sent(std::uint64_t offset,
                                           std::size_t length,
                                           bool fin = false) noexcept
        -> std::expected<void, stream_send_error>
    {
        if (const auto result = validate_sent_range(offset, length, fin); !result) return result;
        if (!bytes_.mark_sent(offset, length))
            return std::unexpected(stream_send_error::invalid_range);
        if (fin) {
            fin_sent_ = true;
            fin_pending_ = false;
        }
        return {};
    }

    // Commit a range already validated by preflight_mark_sent within the same
    // serialized packet operation; skips the redundant validation rescan.
    constexpr auto mark_sent_trusted(std::uint64_t offset, std::size_t length,
                                     bool fin = false) noexcept -> void
    {
        bytes_.mark_sent_trusted(offset, length);
        if (fin) {
            fin_sent_ = true;
            fin_pending_ = false;
        }
    }

    // Reports may cover part of a transmitted STREAM frame. Retired prefixes
    // and duplicate reports are harmless. Both byte and FIN updates are atomic.
    [[nodiscard]] constexpr auto acknowledge(std::uint64_t offset,
                                              std::size_t length,
                                              bool fin = false) noexcept
        -> std::expected<void, stream_send_error>
    {
        if (!valid_range(offset, length))
            return std::unexpected(stream_send_error::invalid_range);
        if (fin && (!final_size_ || offset + length != *final_size_ ||
                    !fin_sent_))
            return std::unexpected(stream_send_error::invalid_fin);
        const auto result = bytes_.acknowledge(offset, length);
        if (!result) return std::unexpected(map_range_error(result.error()));
        if (fin) {
            fin_acked_ = true;
            fin_pending_ = false;
        }
        return {};
    }

    [[nodiscard]] constexpr auto mark_lost(std::uint64_t offset,
                                           std::size_t length,
                                           bool fin = false) noexcept
        -> std::expected<void, stream_send_error>
    {
        if (!valid_range(offset, length))
            return std::unexpected(stream_send_error::invalid_range);
        if (fin && (!final_size_ || offset + length != *final_size_ ||
                    !fin_sent_))
            return std::unexpected(stream_send_error::invalid_fin);
        const auto result = bytes_.mark_lost(offset, length);
        if (!result) return std::unexpected(map_range_error(result.error()));
        if (fin && !fin_acked_) fin_pending_ = true;
        return {};
    }

private:
    [[nodiscard]] constexpr auto validate_sent_range(std::uint64_t offset,
        std::size_t length, bool fin) const noexcept
        -> std::expected<void, stream_send_error>
    {
        if (!valid())
            return std::unexpected(stream_send_error::invalid_flow_limit);
        if (!valid_range(offset, length))
            return std::unexpected(stream_send_error::invalid_range);
        if (offset + length > flow_limit_)
            return std::unexpected(stream_send_error::flow_blocked);
        if (fin && (!final_size_ || offset + length != *final_size_ ||
                    fin_acked_))
            return std::unexpected(stream_send_error::invalid_fin);
        return {};
    }

    [[nodiscard]] constexpr auto valid_range(std::uint64_t offset,
                                             std::size_t length) const noexcept
        -> bool
    {
        return offset <= bytes_.next_offset() &&
               length <= bytes_.next_offset() - offset;
    }

    [[nodiscard]] static constexpr auto map_range_error(
        crypto_send_error error) noexcept -> stream_send_error
    {
        return error == crypto_send_error::unsent_data
                   ? stream_send_error::unsent_data
                   : stream_send_error::invalid_range;
    }

    std::uint64_t flow_limit_ {0};
    std::optional<std::uint64_t> final_size_ {};
    bool fin_pending_ {false};
    bool fin_sent_ {false};
    bool fin_acked_ {false};
    crypto_send_buffer<Capacity> bytes_;
};

} // namespace eventloop::quic::detail
