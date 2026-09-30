#pragma once

#include "quic/varint.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace eventloop::quic::detail {

enum class crypto_buffer_error {
    invalid_storage,
    invalid_offset,
    capacity_exceeded,
    conflicting_data,
    invalid_consume,
};

// Reassembles one encryption level's CRYPTO byte stream. Both spans must
// outlive this object. One bitmap bit tracks each byte in the ring storage.
class crypto_receive_buffer {
public:
    constexpr crypto_receive_buffer(std::span<std::byte> storage,
                                    std::span<std::byte> coverage) noexcept
        : storage_(storage), coverage_(coverage)
    {
        reset();
    }

    crypto_receive_buffer(const crypto_receive_buffer&) = delete;
    auto operator=(const crypto_receive_buffer&) -> crypto_receive_buffer& = delete;

    [[nodiscard]] constexpr auto valid() const noexcept -> bool
    {
        return !storage_.empty() &&
               coverage_.size() >= storage_.size() / 8 +
                                       (storage_.size() % 8 != 0);
    }

    [[nodiscard]] constexpr auto next_offset() const noexcept -> std::uint64_t
    {
        return next_offset_;
    }

    constexpr auto reset() noexcept -> void
    {
        next_offset_ = 0;
        for (auto& byte : coverage_) byte = std::byte {0};
    }

    // Returns the number of newly stored bytes. Previously consumed bytes are
    // ignored; conflicts are checked for all still-buffered overlap before
    // any new byte is written.
    [[nodiscard]] constexpr auto insert(std::uint64_t offset,
                                        std::span<const std::byte> data) noexcept
        -> std::expected<std::size_t, crypto_buffer_error>
    {
        if (!valid()) {
            return std::unexpected(crypto_buffer_error::invalid_storage);
        }
        if (offset > max_varint_value ||
            data.size() > max_varint_value - offset) {
            return std::unexpected(crypto_buffer_error::invalid_offset);
        }
        if (data.empty()) return 0;

        const auto end = offset + data.size();
        if (end <= next_offset_) return 0;
        if (end - next_offset_ > storage_.size()) {
            return std::unexpected(crypto_buffer_error::capacity_exceeded);
        }
        const auto start = offset < next_offset_ ? next_offset_ : offset;
        for (auto position = start; position < end; ++position) {
            const auto slot = static_cast<std::size_t>(position % storage_.size());
            if (covered(slot) && storage_[slot] != data[position - offset]) {
                return std::unexpected(crypto_buffer_error::conflicting_data);
            }
        }

        std::size_t added = 0;
        for (auto position = start; position < end; ++position) {
            const auto slot = static_cast<std::size_t>(position % storage_.size());
            if (!covered(slot)) {
                storage_[slot] = data[position - offset];
                set_covered(slot, true);
                ++added;
            }
        }
        return added;
    }

    // A span never crosses the physical end of the ring. Call consume() and
    // readable() again to obtain data after a wrap.
    [[nodiscard]] constexpr auto readable() const noexcept
        -> std::span<const std::byte>
    {
        if (!valid() || next_offset_ == max_varint_value) return {};
        const auto start = static_cast<std::size_t>(next_offset_ % storage_.size());
        std::size_t length = 0;
        while (length < storage_.size() - start && covered(start + length)) {
            ++length;
        }
        return storage_.subspan(start, length);
    }

    [[nodiscard]] constexpr auto consume(std::size_t size) noexcept
        -> std::expected<void, crypto_buffer_error>
    {
        if (!valid()) {
            return std::unexpected(crypto_buffer_error::invalid_storage);
        }
        if (size > readable().size()) {
            return std::unexpected(crypto_buffer_error::invalid_consume);
        }
        const auto start = static_cast<std::size_t>(next_offset_ % storage_.size());
        for (std::size_t i = 0; i < size; ++i) {
            set_covered(start + i, false);
        }
        next_offset_ += size;
        return {};
    }

private:
    [[nodiscard]] constexpr auto covered(std::size_t slot) const noexcept
        -> bool
    {
        const auto mask = static_cast<std::uint8_t>(1U << (slot % 8));
        return (std::to_integer<std::uint8_t>(coverage_[slot / 8]) & mask) != 0;
    }

    constexpr auto set_covered(std::size_t slot, bool value) noexcept -> void
    {
        const auto mask = static_cast<std::uint8_t>(1U << (slot % 8));
        const auto current = std::to_integer<std::uint8_t>(coverage_[slot / 8]);
        coverage_[slot / 8] = static_cast<std::byte>(
            value ? (current | mask) : (current & static_cast<std::uint8_t>(~mask)));
    }

    std::span<std::byte> storage_;
    std::span<std::byte> coverage_;
    std::uint64_t next_offset_ {0};
};

} // namespace eventloop::quic::detail
