#pragma once

#include "quic/varint.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>

namespace eventloop::quic::detail {

enum class flow_control_error {
    invalid_value,
    unknown_stream,
    duplicate_stream,
    capacity_exhausted,
    stream_limit,
    connection_limit,
    over_consumed,
    final_size,
};

// Active streams use bounded slots. Aggregate byte counters survive removal;
// the caller validates stream IDs and stream state, and supplies
// the correct initial per-stream transport-parameter limit. Range calls may be
// repeated for retransmissions; consume() requires newly delivered contiguous
// bytes and must be called exactly once for each byte delivered to the app.
template<std::size_t Capacity>
class flow_control {
public:
    [[nodiscard]] static constexpr auto create(std::uint64_t send_max_data,
                                                std::uint64_t receive_max_data)
        noexcept -> std::expected<flow_control, flow_control_error>
    {
        if (send_max_data > max_varint_value ||
            receive_max_data > max_varint_value)
            return std::unexpected(flow_control_error::invalid_value);
        flow_control result;
        result.send_limit_ = send_max_data;
        result.receive_limit_ = receive_max_data;
        return result;
    }

    // Register both directions independently; use a zero limit for a direction
    // that the stream cannot carry. Neither registry nor ID validation lives
    // here. A duplicate active registration is an error.
    [[nodiscard]] constexpr auto add_stream(std::uint64_t id,
                                             std::uint64_t send_limit,
                                             std::uint64_t receive_limit) noexcept
        -> std::expected<void, flow_control_error>
    {
        if (id > max_varint_value || send_limit > max_varint_value ||
            receive_limit > max_varint_value)
            return std::unexpected(flow_control_error::invalid_value);
        if (find(id)) return std::unexpected(flow_control_error::duplicate_stream);
        if (size_ == Capacity)
            return std::unexpected(flow_control_error::capacity_exhausted);
        streams_[size_++] = {id, send_limit, receive_limit};
        return {};
    }

    [[nodiscard]] constexpr auto remove_stream(std::uint64_t id) noexcept
        -> std::expected<void, flow_control_error>
    {
        for (std::size_t i = 0; i < size_; ++i) {
            if (streams_[i].id != id) continue;
            streams_[i] = streams_[--size_];
            streams_[size_] = {};
            return {};
        }
        return std::unexpected(flow_control_error::unknown_stream);
    }

    // MAX_DATA and MAX_STREAM_DATA received from the peer. Stale or equal
    // values have no effect, as required by RFC 9000 section 4.2.
    [[nodiscard]] constexpr auto update_send_max_data(std::uint64_t limit)
        noexcept -> std::expected<void, flow_control_error>
    {
        if (limit > max_varint_value)
            return std::unexpected(flow_control_error::invalid_value);
        if (limit > send_limit_) send_limit_ = limit;
        return {};
    }

    [[nodiscard]] constexpr auto update_send_stream_limit(
        std::uint64_t id, std::uint64_t limit) noexcept
        -> std::expected<void, flow_control_error>
    {
        if (limit > max_varint_value)
            return std::unexpected(flow_control_error::invalid_value);
        auto* stream = find(id);
        if (!stream) return std::unexpected(flow_control_error::unknown_stream);
        if (limit > stream->send_limit) stream->send_limit = limit;
        return {};
    }

    // offset + length is the new potential highest offset. Failed calls leave
    // all state unchanged. Use send_stream_range(..., true) for STREAM+FIN.
    [[nodiscard]] constexpr auto send_range(std::uint64_t id,
                                             std::uint64_t offset,
                                             std::uint64_t length) noexcept
        -> std::expected<void, flow_control_error>
    {
        return send_stream_range(id, offset, length, false);
    }

    [[nodiscard]] constexpr auto send_stream_range(std::uint64_t id,
                                                    std::uint64_t offset,
                                                    std::uint64_t length,
                                                    bool fin) noexcept
        -> std::expected<void, flow_control_error>
    {
        return advance(id, offset, length, fin, true);
    }

    // Use receive_stream_range(..., true) for STREAM+FIN. The caller closes
    // the connection on stream_limit/connection_limit/final_size violations.
    [[nodiscard]] constexpr auto receive_range(std::uint64_t id,
                                                std::uint64_t offset,
                                                std::uint64_t length) noexcept
        -> std::expected<void, flow_control_error>
    {
        return receive_stream_range(id, offset, length, false);
    }

    [[nodiscard]] constexpr auto receive_stream_range(std::uint64_t id,
                                                       std::uint64_t offset,
                                                       std::uint64_t length,
                                                       bool fin) noexcept
        -> std::expected<void, flow_control_error>
    {
        return advance(id, offset, length, fin, false);
    }

    // RESET_STREAM final sizes are absolute offsets and consume credit even if
    // no corresponding STREAM data was observed. Repeated identical final
    // sizes are accepted; conflicting values are rejected.
    [[nodiscard]] constexpr auto set_send_final_size(
        std::uint64_t id, std::uint64_t final_size) noexcept
        -> std::expected<void, flow_control_error>
    {
        return advance(id, final_size, 0, true, true);
    }

    [[nodiscard]] constexpr auto set_receive_final_size(
        std::uint64_t id, std::uint64_t final_size) noexcept
        -> std::expected<void, flow_control_error>
    {
        return advance(id, final_size, 0, true, false);
    }

    // The application has consumed newly delivered contiguous bytes. Gaps and
    // duplicate delivery are the caller's responsibility. Consumption does not
    // itself advertise credit; replenish_* returns the current advertised
    // absolute limit after adding the requested window to consumed bytes.
    [[nodiscard]] constexpr auto consume(std::uint64_t id,
                                          std::uint64_t bytes) noexcept
        -> std::expected<void, flow_control_error>
    {
        auto* stream = find(id);
        if (!stream) return std::unexpected(flow_control_error::unknown_stream);
        if (bytes > stream->received - stream->consumed)
            return std::unexpected(flow_control_error::over_consumed);
        stream->consumed += bytes;
        consumed_ += bytes; // consumed_ <= received_total_ <= max_varint_value
        return {};
    }

    [[nodiscard]] constexpr auto replenish_receive_max_data(
        std::uint64_t window) noexcept
        -> std::expected<std::uint64_t, flow_control_error>
    {
        if (window > max_varint_value - consumed_)
            return std::unexpected(flow_control_error::invalid_value);
        const auto proposed = consumed_ + window;
        if (proposed > receive_limit_) receive_limit_ = proposed;
        return receive_limit_;
    }

    [[nodiscard]] constexpr auto replenish_receive_stream_limit(
        std::uint64_t id, std::uint64_t window) noexcept
        -> std::expected<std::uint64_t, flow_control_error>
    {
        auto* stream = find(id);
        if (!stream) return std::unexpected(flow_control_error::unknown_stream);
        if (window > max_varint_value - stream->consumed)
            return std::unexpected(flow_control_error::invalid_value);
        const auto proposed = stream->consumed + window;
        if (proposed > stream->receive_limit)
            stream->receive_limit = proposed;
        return stream->receive_limit;
    }

    [[nodiscard]] constexpr auto send_max_data() const noexcept -> std::uint64_t
    { return send_limit_; }
    [[nodiscard]] constexpr auto receive_max_data() const noexcept -> std::uint64_t
    { return receive_limit_; }
    [[nodiscard]] constexpr auto sent_total() const noexcept -> std::uint64_t
    { return sent_total_; }
    [[nodiscard]] constexpr auto received_total() const noexcept -> std::uint64_t
    { return received_total_; }
    [[nodiscard]] constexpr auto consumed_total() const noexcept -> std::uint64_t
    { return consumed_; }
    [[nodiscard]] constexpr auto size() const noexcept -> std::size_t
    { return size_; }

private:
    struct stream_state {
        std::uint64_t id {0};
        std::uint64_t send_limit {0};
        std::uint64_t receive_limit {0};
        std::uint64_t sent {0};
        std::uint64_t received {0};
        std::uint64_t consumed {0};
        std::optional<std::uint64_t> send_final_size {};
        std::optional<std::uint64_t> receive_final_size {};
    };

    [[nodiscard]] constexpr auto find(std::uint64_t id) noexcept -> stream_state*
    {
        for (std::size_t i = 0; i < size_; ++i)
            if (streams_[i].id == id) return &streams_[i];
        return nullptr;
    }

    [[nodiscard]] constexpr auto advance(std::uint64_t id,
                                          std::uint64_t offset,
                                          std::uint64_t length,
                                          bool fin,
                                          bool sending) noexcept
        -> std::expected<void, flow_control_error>
    {
        if (offset > max_varint_value || length > max_varint_value - offset)
            return std::unexpected(flow_control_error::invalid_value);
        auto* stream = find(id);
        if (!stream) return std::unexpected(flow_control_error::unknown_stream);
        const auto end = offset + length;
        const auto highest = sending ? stream->sent : stream->received;
        const auto& final_size = sending ? stream->send_final_size
                                         : stream->receive_final_size;
        if ((final_size && (end > *final_size || (fin && end != *final_size))) ||
            (fin && end < highest))
            return std::unexpected(flow_control_error::final_size);
        const auto stream_limit = sending ? stream->send_limit
                                          : stream->receive_limit;
        if (end > stream_limit)
            return std::unexpected(flow_control_error::stream_limit);
        const auto increase = end > highest ? end - highest : 0;
        const auto total = sending ? sent_total_ : received_total_;
        const auto connection_limit = sending ? send_limit_ : receive_limit_;
        if (increase > connection_limit - total)
            return std::unexpected(flow_control_error::connection_limit);
        if (sending) {
            if (increase != 0) stream->sent = end;
            sent_total_ += increase;
            if (fin) stream->send_final_size = end;
        } else {
            if (increase != 0) stream->received = end;
            received_total_ += increase;
            if (fin) stream->receive_final_size = end;
        }
        return {};
    }

    std::array<stream_state, Capacity> streams_ {};
    std::size_t size_ {0};
    std::uint64_t send_limit_ {0};
    std::uint64_t receive_limit_ {0};
    std::uint64_t sent_total_ {0};
    std::uint64_t received_total_ {0};
    std::uint64_t consumed_ {0};
};

} // namespace eventloop::quic::detail
