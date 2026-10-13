#include "quic/worker_group.h"

#include "quic/udp_endpoint.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace eventloop {

class quic_worker_group::implementation {
public:
    explicit implementation(std::size_t workers) : inboxes(workers) {}
    std::mutex mutex;
    std::vector<std::shared_ptr<quic::detail::worker_inbox>> inboxes;
};

quic_worker_group::quic_worker_group(std::size_t workers)
{
    if (workers == 0 || workers > 256)
        throw std::invalid_argument("QUIC worker group size must be 1..256");
    implementation_ = std::make_unique<implementation>(workers);
}

quic_worker_group::~quic_worker_group() = default;

auto quic_worker_group::workers() const noexcept -> std::size_t
{ return implementation_->inboxes.size(); }

} // namespace eventloop

namespace eventloop::quic::detail {

worker_inbox::worker_inbox(event_loop& loop, udp_endpoint& owner, std::size_t slot_size)
    : loop_(loop), owner_(&owner), slot_size_(slot_size),
      slots_(capacity * slot_size), scratch_(slot_size)
{
}

auto worker_inbox::push(std::span<const std::byte> datagram, ip_endpoint source) noexcept
    -> void
{
    const std::lock_guard lock {mutex_};
    if (closed_) return;
    if (count_ < capacity && datagram.size() <= slot_size_) {
        const auto slot = (head_ + count_) % capacity;
        std::ranges::copy(datagram, slots_.begin() + static_cast<std::ptrdiff_t>(slot * slot_size_));
        sizes_[slot] = datagram.size();
        sources_[slot] = source;
        ++count_;
    }
    // Even a dropped datagram retries a failed post, or a full inbox would
    // never drain.
    if (count_ != 0 && !scheduled_) schedule();
}

auto worker_inbox::schedule() noexcept -> void
{
    // A failed post leaves the datagrams for the next push to schedule.
    scheduled_ = loop_.post([inbox = shared_from_this()]() noexcept { inbox->drain(); });
}

auto worker_inbox::close() noexcept -> void
{
    const std::lock_guard lock {mutex_};
    closed_ = true;
    count_ = 0;
    owner_ = nullptr;
}

auto worker_inbox::drain() noexcept -> void
{
    // Deliver at most one inbox's worth per task so other loop work runs.
    for (std::size_t delivered = 0;; ++delivered) {
        ip_endpoint source {};
        std::size_t size = 0;
        udp_endpoint* owner = nullptr;
        {
            const std::lock_guard lock {mutex_};
            if (count_ == 0) {
                scheduled_ = false;
                return;
            }
            if (delivered == capacity) {
                schedule();
                return;
            }
            size = sizes_[head_];
            source = sources_[head_];
            const auto first = slots_.begin() + static_cast<std::ptrdiff_t>(head_ * slot_size_);
            std::copy(first, first + static_cast<std::ptrdiff_t>(size), scratch_.begin());
            head_ = (head_ + 1) % capacity;
            --count_;
            owner = owner_;
        }
        if (owner) owner->deliver_forwarded(std::span(scratch_).first(size), source);
    }
}

auto worker_group_access::join(quic_worker_group& group, std::uint8_t index,
                               std::shared_ptr<worker_inbox> inbox) -> void
{
    auto& state = *group.implementation_;
    const std::lock_guard lock {state.mutex};
    if (index >= state.inboxes.size())
        throw std::invalid_argument("QUIC worker index is outside its group");
    if (state.inboxes[index])
        throw std::invalid_argument("QUIC worker index is already in use");
    state.inboxes[index] = std::move(inbox);
}

auto worker_group_access::leave(quic_worker_group& group, std::uint8_t index,
                                const worker_inbox& inbox) noexcept -> void
{
    auto& state = *group.implementation_;
    const std::lock_guard lock {state.mutex};
    if (index < state.inboxes.size() && state.inboxes[index].get() == &inbox)
        state.inboxes[index].reset();
}

auto worker_group_access::find(quic_worker_group& group, std::uint8_t index) noexcept
    -> std::shared_ptr<worker_inbox>
{
    auto& state = *group.implementation_;
    const std::lock_guard lock {state.mutex};
    return index < state.inboxes.size() ? state.inboxes[index] : nullptr;
}

} // namespace eventloop::quic::detail
