#pragma once

#include "eventloop/executor.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>

// Bounded, fully preallocated MPMC ring buffer. Positions grow monotonically;
// `mask_` only maps a position onto a slot. Each slot's sequence number states
// whether the slot belongs to the next producer or the next consumer cycle.
class bounded_task_queue {
public:
    explicit bounded_task_queue(std::size_t capacity)
        : capacity_(checked_capacity(capacity)),
          mask_(capacity_ - 1),
          slots_(std::make_unique<slot[]>(capacity_))
    {
        for (std::size_t index = 0; index < capacity_; ++index) {
            slots_[index].sequence.store(index, std::memory_order_relaxed);
        }
    }

    bounded_task_queue(const bounded_task_queue&) = delete;
    auto operator=(const bounded_task_queue&) -> bounded_task_queue& = delete;

    // Claims a slot before touching `task`, so a full queue leaves the input
    // intact. Never blocks and never allocates. May retry on a lost race.
    auto try_push(execution_task&& task) noexcept -> bool
    {
        if (!task) return false;
        std::size_t position = enqueue_position_.load(std::memory_order_relaxed);
        for (;;) {
            slot& current = slots_[position & mask_];
            const std::size_t sequence =
                current.sequence.load(std::memory_order_acquire);
            const auto difference = static_cast<std::intptr_t>(sequence) -
                                    static_cast<std::intptr_t>(position);
            if (difference == 0) {
                if (enqueue_position_.compare_exchange_weak(
                        position, position + 1, std::memory_order_relaxed,
                        std::memory_order_relaxed)) {
                    current.task = std::move(task);
                    current.sequence.store(position + 1, std::memory_order_release);
                    return true;
                }
            } else if (difference < 0) {
                return false;
            } else {
                position = enqueue_position_.load(std::memory_order_relaxed);
            }
        }
    }

    // Moves a published task into `output`. Never blocks and never allocates.
    auto try_pop(execution_task& output) noexcept -> bool
    {
        std::size_t position = dequeue_position_.load(std::memory_order_relaxed);
        for (;;) {
            slot& current = slots_[position & mask_];
            const std::size_t sequence =
                current.sequence.load(std::memory_order_acquire);
            const auto difference = static_cast<std::intptr_t>(sequence) -
                                    static_cast<std::intptr_t>(position + 1);
            if (difference == 0) {
                if (dequeue_position_.compare_exchange_weak(
                        position, position + 1, std::memory_order_relaxed,
                        std::memory_order_relaxed)) {
                    output = std::move(current.task);
                    current.sequence.store(position + capacity_,
                                           std::memory_order_release);
                    return true;
                }
            } else if (difference < 0) {
                // A producer advances the enqueue position before publishing
                // the slot. When the head slot has been claimed, a task is on
                // its way and the consumer must not report an empty queue.
                if (difference == -1 &&
                    enqueue_position_.load(std::memory_order_acquire) > position) {
                    std::this_thread::yield();
                    continue;
                }
                return false;
            } else {
                position = dequeue_position_.load(std::memory_order_relaxed);
            }
        }
    }

private:
    [[nodiscard]] static auto checked_capacity(std::size_t capacity) -> std::size_t
    {
        if (capacity < 2 || (capacity & (capacity - 1)) != 0) {
            throw std::invalid_argument(
                "executor queue capacity must be a power of two and at least two");
        }
        return capacity;
    }

    struct slot {
        std::atomic<std::size_t> sequence;
        execution_task task;
    };

    const std::size_t capacity_;
    const std::size_t mask_;
    std::unique_ptr<slot[]> slots_;
    alignas(64) std::atomic<std::size_t> enqueue_position_ {0};
    alignas(64) std::atomic<std::size_t> dequeue_position_ {0};
};
