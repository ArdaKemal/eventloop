#pragma once

#include "eventloop/event_loop.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/quic.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

namespace eventloop::quic::detail {

class udp_endpoint;

// One endpoint's bounded inbox of datagrams forwarded by other endpoints in its
// worker group. Any thread may push; the owner loop drains through a posted
// task, with at most one pending at a time. Storage is reserved up front.
class worker_inbox : public std::enable_shared_from_this<worker_inbox> {
public:
    static constexpr std::size_t capacity = 64;

    worker_inbox(event_loop& loop, udp_endpoint& owner, std::size_t slot_size);
    worker_inbox(const worker_inbox&) = delete;
    auto operator=(const worker_inbox&) -> worker_inbox& = delete;

    // Any thread. Drops the datagram when the inbox is closed or full, or the
    // datagram exceeds the slot size.
    auto push(std::span<const std::byte> datagram, ip_endpoint source) noexcept -> void;
    // Owner loop. Stops accepting and forgets the endpoint; queued datagrams
    // are dropped. No post() targets the loop after this returns.
    auto close() noexcept -> void;

private:
    auto schedule() noexcept -> void;  // caller holds mutex_
    auto drain() noexcept -> void;     // owner loop

    event_loop& loop_;
    udp_endpoint* owner_;              // guarded by mutex_; null once closed
    std::size_t slot_size_;
    std::mutex mutex_;
    std::vector<std::byte> slots_;     // capacity * slot_size_
    std::array<std::size_t, capacity> sizes_ {};
    std::array<ip_endpoint, capacity> sources_ {};
    std::size_t head_ {0};
    std::size_t count_ {0};
    bool closed_ {false};
    bool scheduled_ {false};
    std::vector<std::byte> scratch_;   // owner loop: datagram being delivered
};

struct worker_group_access {
    // Throws std::invalid_argument for an index out of range or already held.
    static auto join(quic_worker_group&, std::uint8_t index,
                     std::shared_ptr<worker_inbox> inbox) -> void;
    static auto leave(quic_worker_group&, std::uint8_t index,
                      const worker_inbox& inbox) noexcept -> void;
    [[nodiscard]] static auto find(quic_worker_group&, std::uint8_t index) noexcept
        -> std::shared_ptr<worker_inbox>;
};

} // namespace eventloop::quic::detail
