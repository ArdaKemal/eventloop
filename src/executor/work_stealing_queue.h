#pragma once

#include "eventloop/executor.h"

#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>

namespace eventloop {

// Unordered worker queues over one fixed payload pool. Clearing a ready bit
// claims the payload before touching it. Moving a callable never holds a FIFO
// position needed by another producer or consumer. See executor-scheduling.md.
class work_stealing_queue {
public:
    static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
    static_assert(std::atomic<std::size_t>::is_always_lock_free);
    static_assert(std::atomic<std::uintptr_t>::is_always_lock_free);

    work_stealing_queue(std::size_t capacity, std::size_t workers)
        : capacity_(checked_capacity(capacity)),
          workers_(checked_workers(workers)),
          stealing_(workers > 1),
          words_((capacity_ + 63) / 64),
          stride_((words_ + 7) & ~std::size_t {7}),
          slots_(std::make_unique<slot[]>(capacity_)),
          free_(std::make_unique<std::atomic<std::uint64_t>[]>(words_)),
          ready_(std::make_unique<bitmap_block[]>(
              checked_bitmap_size(workers_ * 2, stride_ / 8))),
          queues_(std::make_unique<worker_queue[]>(workers_ * 2))
    {
        for (std::size_t word = 0; word < words_; ++word) {
            const auto bits = word * 64 + 64 <= capacity_
                                  ? ~std::uint64_t {0}
                                  : (std::uint64_t {1} << (capacity_ % 64)) - 1;
            free_[word].store(bits, std::memory_order_relaxed);
        }
    }

    work_stealing_queue(const work_stealing_queue&) = delete;
    auto operator=(const work_stealing_queue&) -> work_stealing_queue& = delete;

    // cursor belongs to the submitting thread, not the queue. No task move
    // occurs until storage is reserved; a failed submission keeps its input.
    auto try_push(std::size_t worker, execution_task&& task,
                  std::size_t& cursor) noexcept -> bool
    {
        return push(worker, std::move(task), cursor);
    }

    auto try_push_external(std::size_t worker, execution_task&& task,
                           std::size_t& cursor) noexcept -> bool
    {
        return push(workers_ + worker, std::move(task), cursor);
    }

    auto try_pop_external(std::size_t worker, execution_task& output,
                          std::size_t& cursor) noexcept -> bool
    {
        return try_pop(workers_ + worker, output, cursor);
    }

private:
    auto push(std::size_t worker, execution_task&& task,
              std::size_t& cursor) noexcept -> bool
    {
        if (!task) return false;
        if (known_full(cursor)) return false;
        const bool previously_failed = (cursor & failed_scan_) != 0;
        // A power-of-two capacity also makes the bitmap word count a power
        // of two (one word for capacities below 64).
        const auto start = (cursor / 64) & (words_ - 1);
        for (std::size_t scanned = 0; scanned < words_; ++scanned) {
            const auto word = (start + scanned) & (words_ - 1);
            auto bits = free_[word].load(std::memory_order_relaxed);
            while (bits != 0) {
                const auto offset = static_cast<int>(cursor % 64);
                const auto bit = static_cast<unsigned>(
                    (std::countr_zero(std::rotr(bits, offset)) + offset) % 64);
                const auto mask = std::uint64_t {1} << bit;
                if (free_[word].compare_exchange_weak(
                        bits, bits & ~mask, std::memory_order_seq_cst,
                        std::memory_order_relaxed)) {
                    const auto index = word * 64 + bit;
                    cursor = (index + 1) & (capacity_ - 1);
                    slots_[index].task = std::move(task);
                    // Count precedes publication so a consumer can never
                    // underflow it. It is only a victim-selection hint: a
                    // publisher or dequeuer may pause between these steps.
                    if (stealing_) {
                        queues_[worker].queued.fetch_add(1, std::memory_order_seq_cst);
                    }
                    ready_word(worker, word).fetch_or(
                        mask, std::memory_order_seq_cst);
                    return true;
                }
            }
        }
        cursor |= failed_scan_;
        // A single failed attempt during a drain needs no cache registration.
        // Warm it only when this submitter encounters persistent exhaustion.
        if (previously_failed) remember_full();
        return false;
    }

public:
    auto try_pop(std::size_t worker, execution_task& output,
                 std::size_t& cursor) noexcept -> bool
    {
        if (stealing_ && queues_[worker].queued.load(std::memory_order_seq_cst) == 0) {
            return false;
        }
        const auto start = (cursor / 64) & (words_ - 1);
        for (std::size_t scanned = 0; scanned < words_; ++scanned) {
            const auto word = (start + scanned) & (words_ - 1);
            auto& published = ready_word(worker, word);
            auto bits = published.load(std::memory_order_seq_cst);
            while (bits != 0) {
                const auto offset = static_cast<int>(cursor % 64);
                const auto bit = static_cast<unsigned>(
                    (std::countr_zero(std::rotr(bits, offset)) + offset) % 64);
                const auto mask = std::uint64_t {1} << bit;
                if (published.compare_exchange_weak(
                        bits, bits & ~mask, std::memory_order_seq_cst,
                        std::memory_order_seq_cst)) {
                    if (stealing_) {
                        queues_[worker].queued.fetch_sub(1, std::memory_order_seq_cst);
                    }
                    const auto index = word * 64 + bit;
                    output = std::move(slots_[index].task);
                    free_[word].fetch_or(mask, std::memory_order_seq_cst);
                    // The release either invalidates a registered full check
                    // or precedes that check's SC bitmap verification. No RMW
                    // is needed while the cache is inactive.
                    if (full_.load(std::memory_order_seq_cst) != 0) {
                        full_.exchange(0, std::memory_order_seq_cst);
                    }
                    cursor = (index + 1) & (capacity_ - 1);
                    return true;
                }
            }
        }
        return false;
    }

    auto try_steal(std::size_t victim, execution_task& output,
                   std::size_t& cursor) noexcept -> bool
    {
        return has_backlog(victim) && try_pop(victim, output, cursor);
    }

    [[nodiscard]] auto has_backlog(std::size_t worker) const noexcept -> bool
    {
        return stealing_ && queues_[worker].queued.load(std::memory_order_seq_cst) > 1;
    }

    // Any task in a worker's local queue, including a lone one that
    // try_steal() leaves for its owner. A concurrent hint like has_backlog().
    [[nodiscard]] auto has_local_work(std::size_t worker) const noexcept -> bool
    {
        return stealing_ && queues_[worker].queued.load(std::memory_order_seq_cst) != 0;
    }

    // Only a cursor that previously failed consults the full cache. A
    // successful claim clears this bit along with advancing the cursor.
    [[nodiscard]] auto known_full(std::size_t cursor) const noexcept -> bool
    {
        return (cursor & failed_scan_) != 0 &&
               full_.load(std::memory_order_seq_cst) == full_pool_;
    }

    // True when an idle peer could take a task: any external task, or a local
    // queue above the stealing threshold. Counts are concurrent hints.
    [[nodiscard]] auto has_shareable_work() const noexcept -> bool
    {
        if (!stealing_) return false;
        for (std::size_t worker = 0; worker < workers_; ++worker) {
            if (queues_[workers_ + worker].queued.load(std::memory_order_seq_cst) != 0 ||
                queues_[worker].queued.load(std::memory_order_seq_cst) > 1) {
                return true;
            }
        }
        return false;
    }

private:
    auto remember_full() noexcept -> void
    {
        // An opaque stack identity stays unique while this checker can still
        // publish its result. A suspended checker never acts as a full result.
        // Consumers only clear identities; nobody dereferences them.
        alignas(2) std::byte probe;
        const auto identity = reinterpret_cast<std::uintptr_t>(&probe);
        std::uintptr_t expected = 0;
        if (!full_.compare_exchange_strong(expected, identity,
                                           std::memory_order_seq_cst,
                                           std::memory_order_seq_cst)) return;
        bool full = true;
        for (std::size_t word = 0; word < words_; ++word) {
            if (free_[word].load(std::memory_order_seq_cst) != 0) {
                full = false;
                break;
            }
        }
        expected = identity;
        full_.compare_exchange_strong(expected, full ? full_pool_ : 0,
                                     std::memory_order_seq_cst,
                                     std::memory_order_seq_cst);
    }

    friend struct work_stealing_queue_test_access;

    static constexpr std::uintptr_t full_pool_ {1};
    static constexpr std::size_t failed_scan_ {
        std::size_t {1} << (std::numeric_limits<std::size_t>::digits - 1)};

    static auto checked_capacity(std::size_t capacity) -> std::size_t
    {
        if (capacity < 2 || (capacity & (capacity - 1)) != 0) {
            throw std::invalid_argument(
                "executor queue capacity must be a power of two and at least two");
        }
        return capacity;
    }

    static auto checked_bitmap_size(std::size_t workers, std::size_t stride)
        -> std::size_t
    {
        if (workers == 0 || workers > std::numeric_limits<std::size_t>::max() / stride) {
            throw std::invalid_argument("invalid executor worker count");
        }
        return workers * stride;
    }

    static auto checked_workers(std::size_t workers) -> std::size_t
    {
        if (workers == 0 || workers > std::numeric_limits<std::size_t>::max() / 2) {
            throw std::invalid_argument("invalid executor worker count");
        }
        return workers;
    }

    struct alignas(32) slot { execution_task task; };
    struct alignas(64) worker_queue { std::atomic<std::size_t> queued {0}; };
    struct alignas(64) bitmap_block { std::atomic<std::uint64_t> words[8] {}; };

    auto ready_word(std::size_t worker, std::size_t word) noexcept
        -> std::atomic<std::uint64_t>&
    {
        return ready_[worker * (stride_ / 8) + word / 8].words[word % 8];
    }

    const std::size_t capacity_;
    const std::size_t workers_;
    const bool stealing_;
    const std::size_t words_;
    const std::size_t stride_;
    std::unique_ptr<slot[]> slots_;
    std::unique_ptr<std::atomic<std::uint64_t>[]> free_;
    std::unique_ptr<bitmap_block[]> ready_;
    std::unique_ptr<worker_queue[]> queues_;
    alignas(64) std::atomic<std::uintptr_t> full_ {0};
};

} // namespace eventloop
