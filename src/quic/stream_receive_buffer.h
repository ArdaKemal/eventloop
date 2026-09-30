#pragma once

#include "quic/crypto_buffer.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

namespace eventloop::quic::detail {

enum class stream_receive_error {
    invalid_storage,
    invalid_flow_limit,
    invalid_offset,
    flow_limit_exceeded,
    capacity_exceeded,
    conflicting_data,
    final_size_error,
    invalid_consume,
};

// Reassembles one stream's STREAM data in caller-owned ring and bitmap storage.
// The spans must outlive this object. Calls are serialized by the owner.
class stream_receive_buffer {
public:
    constexpr stream_receive_buffer(std::span<std::byte> storage,
                                    std::span<std::byte> coverage,
                                    std::uint64_t flow_limit) noexcept
        : bytes_(storage, coverage), storage_capacity_(storage.size()),
          flow_limit_(flow_limit)
    {
    }

    stream_receive_buffer(const stream_receive_buffer&) = delete;
    auto operator=(const stream_receive_buffer&) -> stream_receive_buffer& = delete;

    [[nodiscard]] constexpr auto valid() const noexcept -> bool
    {
        return bytes_.valid() && flow_limit_ <= max_varint_value;
    }

    [[nodiscard]] constexpr auto flow_limit() const noexcept -> std::uint64_t
    {
        return flow_limit_;
    }

    // Flow credit can only increase. Existing buffered data is unaffected.
    [[nodiscard]] constexpr auto extend_flow_limit(std::uint64_t limit) noexcept
        -> std::expected<void, stream_receive_error>
    {
        if (limit > max_varint_value || limit < flow_limit_) {
            return std::unexpected(stream_receive_error::invalid_flow_limit);
        }
        flow_limit_ = limit;
        return {};
    }

    [[nodiscard]] constexpr auto next_offset() const noexcept -> std::uint64_t
    {
        return bytes_.next_offset();
    }

    [[nodiscard]] constexpr auto highest_received_offset() const noexcept
        -> std::uint64_t
    {
        return highest_received_offset_;
    }

    [[nodiscard]] constexpr auto final_size() const noexcept
        -> std::optional<std::uint64_t>
    {
        return final_size_;
    }

    [[nodiscard]] constexpr auto complete() const noexcept -> bool
    {
        return final_size_ && bytes_.next_offset() == *final_size_;
    }

    // Returns newly stored bytes. A FIN establishes the final size at the
    // frame end, including for a zero-length frame. Rejected input changes no
    // state. Overlaps already consumed cannot be checked again.
    [[nodiscard]] constexpr auto insert(std::uint64_t offset,
                                        std::span<const std::byte> data,
                                        bool fin = false) noexcept
        -> std::expected<std::size_t, stream_receive_error>
    {
        if (!bytes_.valid()) {
            return std::unexpected(stream_receive_error::invalid_storage);
        }
        if (flow_limit_ > max_varint_value) {
            return std::unexpected(stream_receive_error::invalid_flow_limit);
        }
        if (offset > max_varint_value ||
            data.size() > max_varint_value - offset) {
            return std::unexpected(stream_receive_error::invalid_offset);
        }

        const auto end = offset + data.size();
        if (end > flow_limit_) {
            return std::unexpected(stream_receive_error::flow_limit_exceeded);
        }
        if (final_size_ && (end > *final_size_ || (fin && end != *final_size_))) {
            return std::unexpected(stream_receive_error::final_size_error);
        }
        if (fin && end < highest_received_offset_) {
            return std::unexpected(stream_receive_error::final_size_error);
        }
        if (end > bytes_.next_offset() &&
            end - bytes_.next_offset() > storage_capacity_) {
            return std::unexpected(stream_receive_error::capacity_exceeded);
        }

        const auto added = bytes_.insert(offset, data);
        if (!added) {
            switch (added.error()) {
            case crypto_buffer_error::invalid_storage:
                return std::unexpected(stream_receive_error::invalid_storage);
            case crypto_buffer_error::invalid_offset:
                return std::unexpected(stream_receive_error::invalid_offset);
            case crypto_buffer_error::capacity_exceeded:
                return std::unexpected(stream_receive_error::capacity_exceeded);
            case crypto_buffer_error::conflicting_data:
                return std::unexpected(stream_receive_error::conflicting_data);
            case crypto_buffer_error::invalid_consume:
                return std::unexpected(stream_receive_error::invalid_consume);
            }
        }

        if (end > highest_received_offset_) highest_received_offset_ = end;
        if (fin) final_size_ = end;
        return *added;
    }

    // The returned span ends at the physical ring boundary. Consume and call
    // readable() again to access bytes after a wrap.
    [[nodiscard]] constexpr auto readable() const noexcept
        -> std::span<const std::byte>
    {
        return bytes_.readable();
    }

    [[nodiscard]] constexpr auto consume(std::size_t size) noexcept
        -> std::expected<void, stream_receive_error>
    {
        const auto result = bytes_.consume(size);
        if (!result) {
            return std::unexpected(result.error() ==
                                           crypto_buffer_error::invalid_storage
                                       ? stream_receive_error::invalid_storage
                                       : stream_receive_error::invalid_consume);
        }
        return {};
    }

private:
    crypto_receive_buffer bytes_;
    std::size_t storage_capacity_ {0};
    std::uint64_t flow_limit_ {0};
    std::uint64_t highest_received_offset_ {0};
    std::optional<std::uint64_t> final_size_ {};
};

} // namespace eventloop::quic::detail
