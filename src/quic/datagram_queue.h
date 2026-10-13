#pragma once

#include "quic/varint.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace eventloop::quic::detail {

enum class datagram_queue_error {
    not_negotiated,
    frame_too_large,
    full,
    output_too_small,
    empty,
};

// The caller owns each slot's byte storage and the slot array. Storage must
// remain alive while the queue is in use. A slot holds exactly one datagram.
struct datagram_slot {
    std::span<std::byte> storage {};
    std::size_t size {0};
    bool length_present {true};
};

struct queued_datagram {
    std::span<const std::byte> data {};
    bool length_present {true};
};

class datagram_queue {
public:
    constexpr datagram_queue(std::span<datagram_slot> slots,
                             std::uint64_t max_frame_size = 0) noexcept
        : slots_(slots), max_frame_size_(max_frame_size)
    {
        reset(max_frame_size);
    }

    // A zero limit disables this direction. Reset also discards queued data.
    constexpr auto reset(std::uint64_t max_frame_size = 0) noexcept -> void
    {
        max_frame_size_ = max_frame_size;
        head_ = 0;
        count_ = 0;
        for (auto& slot : slots_) slot.size = 0;
    }

    [[nodiscard]] constexpr auto size() const noexcept -> std::size_t
    { return count_; }
    [[nodiscard]] constexpr auto capacity() const noexcept -> std::size_t
    { return slots_.size(); }
    [[nodiscard]] constexpr auto max_frame_size() const noexcept -> std::uint64_t
    { return max_frame_size_; }
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    { return count_ == 0; }

    // length_present selects RFC 9221 DATAGRAM type 0x31 or 0x30. The latter
    // extends to the end of its packet and must be placed last by the caller.
    [[nodiscard]] constexpr auto push(std::span<const std::byte> data,
                                      bool length_present = true) noexcept
        -> std::expected<void, datagram_queue_error>
    {
        if (max_frame_size_ == 0)
            return std::unexpected(datagram_queue_error::not_negotiated);

        const auto length_size = length_present ? varint_size(data.size()) : 0;
        const auto overhead = 1 + length_size;
        if ((length_present && length_size == 0) ||
            max_frame_size_ < overhead ||
            data.size() > max_frame_size_ - overhead)
            return std::unexpected(datagram_queue_error::frame_too_large);

        if (count_ == slots_.size())
            return std::unexpected(datagram_queue_error::full);
        auto& slot = slots_[(head_ + count_) % slots_.size()];
        if (data.size() > slot.storage.size())
            return std::unexpected(datagram_queue_error::frame_too_large);
        std::copy(data.begin(), data.end(), slot.storage.begin());
        slot.size = data.size();
        slot.length_present = length_present;
        ++count_;
        return {};
    }

    [[nodiscard]] constexpr auto front() const noexcept
        -> std::expected<queued_datagram, datagram_queue_error>
    {
        if (empty()) return std::unexpected(datagram_queue_error::empty);
        const auto& slot = slots_[head_];
        return queued_datagram {slot.storage.first(slot.size),
                                slot.length_present};
    }

    [[nodiscard]] constexpr auto pop() noexcept
        -> std::expected<void, datagram_queue_error>
    {
        if (empty()) return std::unexpected(datagram_queue_error::empty);
        slots_[head_].size = 0;
        head_ = (head_ + 1) % slots_.size();
        --count_;
        return {};
    }

    // Copies and removes one whole datagram. A short output leaves it queued.
    [[nodiscard]] constexpr auto consume(std::span<std::byte> output) noexcept
        -> std::expected<std::size_t, datagram_queue_error>
    {
        if (empty())
            return std::unexpected(max_frame_size_ == 0 ? datagram_queue_error::not_negotiated
                                                        : datagram_queue_error::empty);
        const auto& slot = slots_[head_];
        if (output.size() < slot.size)
            return std::unexpected(datagram_queue_error::output_too_small);
        std::copy_n(slot.storage.begin(), slot.size, output.begin());
        const auto size = slot.size;
        (void)pop();
        return size;
    }

private:
    std::span<datagram_slot> slots_ {};
    std::uint64_t max_frame_size_ {0};
    std::size_t head_ {0};
    std::size_t count_ {0};
};

} // namespace eventloop::quic::detail
