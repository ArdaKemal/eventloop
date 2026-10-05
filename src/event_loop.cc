#include "eventloop/event_loop.h"
#include "eventloop/detail/notifiable.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/udp_socket.h"
#include "eventloop/file_io.h"
#include "file_operation.h"
#include "eventloop/task.h"

#include "executor/bounded_task_queue.h"
#ifndef _WIN32
#include <pthread.h>
#include <signal.h>
#endif
#ifdef _WIN32
#include "windows/iocp_loop.h"
#elif defined(__APPLE__)
#include "macos/kqueue_loop.h"
#else
#include "linux/epoll_loop.h"
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <map>
#include <new>
#include <optional>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>


#if defined(__SANITIZE_ADDRESS__)
#define EVENTLOOP_ADDRESS_SANITIZER 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define EVENTLOOP_ADDRESS_SANITIZER 1
#endif
#endif

#if defined(EVENTLOOP_ADDRESS_SANITIZER)
#include <sanitizer/asan_interface.h>
#endif

namespace eventloop {

namespace {

#ifndef _WIN32
// Blocks SIGPIPE in the owning thread while any event loop lives there.
// Socket writes that cannot pass MSG_NOSIGNAL (OpenSSL kTLS write() and
// sendfile()) then fail with EPIPE instead of killing the process. The last
// loop on the thread discards a pending SIGPIPE and restores the mask.
class sigpipe_block {
public:
    sigpipe_block() noexcept
    {
        if (depth++ != 0) return;
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGPIPE);
        sigset_t previous;
        blocked = pthread_sigmask(SIG_BLOCK, &set, &previous) == 0 &&
                  sigismember(&previous, SIGPIPE) == 0;
    }
    ~sigpipe_block()
    {
        if (--depth != 0 || !blocked) return;
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGPIPE);
        sigset_t pending;
        int signal = 0;
        while (sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1 &&
               sigwait(&set, &signal) == 0) {}
        (void)pthread_sigmask(SIG_UNBLOCK, &set, nullptr);
        blocked = false;
    }
    sigpipe_block(const sigpipe_block&) = delete;
    auto operator=(const sigpipe_block&) -> sigpipe_block& = delete;

private:
    // Per thread: the number of live loops and whether the first one blocked.
    static thread_local std::size_t depth;
    static thread_local bool blocked;
};
thread_local std::size_t sigpipe_block::depth = 0;
thread_local bool sigpipe_block::blocked = false;
#else
struct sigpipe_block {};
#endif

constexpr std::size_t max_posted_tasks_per_iteration = 64;
constexpr std::size_t max_timers_per_iteration = 64;
#if defined(_WIN32) || defined(__APPLE__)
constexpr std::size_t coroutine_frame_alignment =
    std::max<std::size_t>(alignof(std::max_align_t), 16);
#else
constexpr std::size_t coroutine_frame_alignment = alignof(std::max_align_t);
#endif
static_assert(coroutine_frame_alignment >= alignof(std::max_align_t));

auto poison_memory(void* pointer, std::size_t size) noexcept -> void
{
#if defined(EVENTLOOP_ADDRESS_SANITIZER)
    ASAN_POISON_MEMORY_REGION(pointer, size);
#else
    (void)pointer;
    (void)size;
#endif
}

auto unpoison_memory(void* pointer, std::size_t size) noexcept -> void
{
#if defined(EVENTLOOP_ADDRESS_SANITIZER)
    ASAN_UNPOISON_MEMORY_REGION(pointer, size);
#else
    (void)pointer;
    (void)size;
#endif
}

class coroutine_frame_pool {
public:
    explicit coroutine_frame_pool(
        const std::array<std::size_t, coroutine_frame_sizes.size()>& capacities,
        const std::array<std::size_t, coroutine_frame_sizes.size()>&
            initial_capacities)
    {
        for (std::size_t index = 0; index < classes_.size(); ++index) {
            auto& current = classes_[index];
            current.payload_size = coroutine_frame_sizes[index];
            current.stride = sizeof(block_header) + current.payload_size;
            current.maximum_capacity = capacities[index];
            if (capacities[index] >
                (std::numeric_limits<std::size_t>::max() - sizeof(slab_header)) /
                    current.stride ||
                capacity_ >
                    std::numeric_limits<std::size_t>::max() - capacities[index]) {
                throw std::length_error("coroutine frame pool capacity is too large");
            }
            capacity_ += capacities[index];
            const auto initial = std::min(initial_capacities[index], capacities[index]);
            if (initial != 0) create_slab(current, index, initial, true);
        }
    }

    ~coroutine_frame_pool()
    {
        if (live_ != 0) std::terminate();
    }

    coroutine_frame_pool(const coroutine_frame_pool&) = delete;
    auto operator=(const coroutine_frame_pool&) -> coroutine_frame_pool& = delete;

    [[nodiscard]] auto try_allocate(std::size_t size) noexcept -> void*
    {
        for (std::size_t index = 0; index < classes_.size(); ++index) {
            auto& current = classes_[index];
            if (size > current.payload_size) continue;
            if (current.available == nullptr && !grow(current, index)) continue;

            auto* slab = current.available;
            if (slab == nullptr || slab->free == nullptr || slab->free_count == 0) {
                std::terminate();
            }
            auto* block = slab->free;
            slab->free = block->next;
            --slab->free_count;
            if (slab->free_count == 0) remove_available(current, *slab);
            block->magic = block_magic;
            block->allocated = true;
            block->requested_size = size;
            ++slab->live;
            unpoison_memory(reinterpret_cast<std::byte*>(block) +
                                sizeof(block_header),
                            size);
            ++live_;
            high_watermark_ = std::max(high_watermark_, live_);
            return reinterpret_cast<std::byte*>(block) + sizeof(block_header);
        }
        ++allocation_failures_;
        return nullptr;
    }

    static auto deallocate(void* pointer, std::size_t size) noexcept -> void
    {
        if (pointer == nullptr) return;
        auto* block = reinterpret_cast<block_header*>(
            static_cast<std::byte*>(pointer) - sizeof(block_header));
        if (!block->allocated || block->magic != block_magic ||
            block->slab == nullptr || block->slab->owner == nullptr) {
            std::terminate();
        }
        block->slab->owner->release(*block, size);
    }

    [[nodiscard]] auto statistics() const noexcept
        -> coroutine_pool_statistics
    {
        return {
            .capacity = capacity_,
            .live = live_,
            .high_watermark = high_watermark_,
            .allocation_failures = allocation_failures_,
            .active_roots = 0,
            .backed_capacity = backed_capacity_,
        };
    }

private:
    struct slab_header;

    struct alignas(coroutine_frame_alignment) block_header {
        slab_header* slab;
        union {
            block_header* next; // Active while the block is free.
            std::uint64_t magic; // Active while the block is allocated.
        };
        std::size_t requested_size;
        bool allocated;
    };

#ifndef _WIN32
    static_assert(sizeof(block_header) == 2 * coroutine_frame_alignment);
#endif

    struct alignas(coroutine_frame_alignment) slab_header {
        slab_header* all_next;
        slab_header* available_previous;
        slab_header* available_next;
        block_header* free;
        std::size_t capacity;
        std::size_t live;
        std::size_t free_count;
        coroutine_frame_pool* owner;
        std::size_t class_index;
        bool retained;
    };

#ifndef _WIN32
    static_assert(sizeof(slab_header) == 5 * coroutine_frame_alignment);
#endif

    struct size_class {
        ~size_class()
        {
            auto* slab = slabs;
            while (slab != nullptr) {
                auto* next = slab->all_next;
                ::operator delete(slab,
                                  std::align_val_t {coroutine_frame_alignment});
                slab = next;
            }
        }

        size_class() = default;
        size_class(const size_class&) = delete;
        auto operator=(const size_class&) -> size_class& = delete;

        slab_header* slabs {nullptr};
        slab_header* available {nullptr};
        std::size_t payload_size {0};
        std::size_t stride {0};
        std::size_t maximum_capacity {0};
        std::size_t backed_capacity {0};
    };

    static constexpr std::uint64_t block_magic = 0xc07a4e5f4a4d4501ULL;

    static auto remove_available(size_class& current, slab_header& slab) noexcept
        -> void
    {
        if (slab.available_previous != nullptr) {
            slab.available_previous->available_next = slab.available_next;
        } else {
            current.available = slab.available_next;
        }
        if (slab.available_next != nullptr) {
            slab.available_next->available_previous = slab.available_previous;
        }
        slab.available_previous = nullptr;
        slab.available_next = nullptr;
    }

    static auto add_available(size_class& current, slab_header& slab) noexcept
        -> void
    {
        slab.available_previous = nullptr;
        slab.available_next = current.available;
        if (current.available != nullptr) {
            current.available->available_previous = &slab;
        }
        current.available = &slab;
    }

    auto create_slab(size_class& current, std::size_t class_index,
                     std::size_t capacity, bool retained) -> void
    {
        const auto bytes = sizeof(slab_header) + current.stride * capacity;
        auto* slab = std::construct_at(static_cast<slab_header*>(::operator new(
            bytes, std::align_val_t {coroutine_frame_alignment})),
            slab_header {
                .all_next = current.slabs,
                .available_previous = nullptr,
                .available_next = nullptr,
                .free = nullptr,
                .capacity = capacity,
                .live = 0,
                .free_count = capacity,
                .owner = this,
                .class_index = class_index,
                .retained = retained,
            });
        current.slabs = slab;
        auto* storage = reinterpret_cast<std::byte*>(slab) + sizeof(slab_header);
        for (std::size_t index = 0; index < capacity; ++index) {
            auto* block = std::construct_at(
                reinterpret_cast<block_header*>(storage + index * current.stride),
                block_header {
                    .slab = slab,
                    .next = slab->free,
                    .requested_size = 0,
                    .allocated = false,
                });
            poison_memory(storage + index * current.stride +
                              sizeof(block_header),
                          current.payload_size);
            slab->free = block;
        }
        current.backed_capacity += capacity;
        backed_capacity_ += capacity;
        add_available(current, *slab);
    }

    auto grow(size_class& current, std::size_t class_index) noexcept -> bool
    {
        if (current.backed_capacity >= current.maximum_capacity) return false;
        const auto remaining = current.maximum_capacity - current.backed_capacity;
        const auto growth = current.backed_capacity == 0
            ? std::min<std::size_t>(64, remaining)
            : std::min(current.backed_capacity, remaining);
        try {
            create_slab(current, class_index, growth, false);
        } catch (const std::bad_alloc&) {
            return false;
        }
        return true;
    }

    auto release(block_header& block, std::size_t size) noexcept -> void
    {
        if (block.slab == nullptr || block.slab->owner != this ||
            block.slab->class_index >= classes_.size()) std::terminate();
        auto& current = classes_[block.slab->class_index];
        if ((size != 0 && size > current.payload_size) || live_ == 0 ||
            block.slab->live == 0 ||
            block.slab->free_count >= block.slab->capacity) {
            std::terminate();
        }
        auto& slab = *block.slab;
        poison_memory(reinterpret_cast<std::byte*>(&block) +
                          sizeof(block_header),
                      block.requested_size);
        block.requested_size = 0;
        block.allocated = false;
        const bool was_full = slab.free_count == 0;
        block.next = slab.free;
        slab.free = &block;
        ++slab.free_count;
        --slab.live;
        --live_;
        if (was_full) add_available(current, slab);

        if (slab.live == 0 && !slab.retained) {
            remove_available(current, slab);
            auto** link = &current.slabs;
            while (*link != &slab) {
                if (*link == nullptr) std::terminate();
                link = &(*link)->all_next;
            }
            *link = slab.all_next;
            current.backed_capacity -= slab.capacity;
            backed_capacity_ -= slab.capacity;
            ::operator delete(&slab,
                              std::align_val_t {coroutine_frame_alignment});
        }
    }

    std::array<size_class, coroutine_frame_sizes.size()> classes_;
    std::size_t capacity_ {0};
    std::size_t backed_capacity_ {0};
    std::size_t live_ {0};
    std::size_t high_watermark_ {0};
    std::size_t allocation_failures_ {0};
};

[[nodiscard]] auto is_power_of_two(std::size_t value) noexcept -> bool
{
    return value != 0 && (value & (value - 1)) == 0;
}

[[nodiscard]] auto checked_options(event_loop_options options) -> event_loop_options
{
    if (options.post_capacity < 2 || !is_power_of_two(options.post_capacity)) {
        throw std::invalid_argument(
            "event loop post capacity must be a power of two and at least two");
    }
    if (options.coroutine_completion_capacity < 2 ||
        !is_power_of_two(options.coroutine_completion_capacity)) {
        throw std::invalid_argument(
            "coroutine completion capacity must be a power of two and at least two");
    }
    if (options.file_io_depth < 2 || !is_power_of_two(options.file_io_depth)) {
        throw std::invalid_argument(
            "file I/O depth must be a power of two and at least two");
    }
    return options;
}


} // namespace

class event_loop::implementation {
public:
    explicit implementation(event_loop_options options)
        : coroutine_frames(options.coroutine_frame_capacities,
                           options.coroutine_frame_initial_capacities),
          posted_tasks(options.post_capacity),
          coroutine_completions(options.coroutine_completion_capacity),
          coroutine_completion_capacity(options.coroutine_completion_capacity),
          blocking_executor_available(options.worker_count != 0),
          task_executor(options.worker_count == 0
                            ? make_single_thread_executor()
                            : make_multi_thread_executor(
                                  {.worker_count = options.worker_count})),
          file_io_depth(options.file_io_depth)
    {
    }

    ~implementation()
    {
        // A worker or the kernel may still hold a pointer into a live frame.
        // Reject invalid lifetime use before joining workers or freeing the
        // ring, rather than detecting it only when the frame pool is destroyed.
        if (coroutine_frames.statistics().live != 0) std::terminate();
    }

    auto initialize_file_executor() -> void
    {
        if (file_executor) return;
        file_executor = make_multi_thread_executor(
            {.worker_count = 1, .queue_capacity = file_io_depth});
    }

    [[nodiscard]] auto submit_file(detail::file_io_operation& operation)
        noexcept -> int
    {
        if (shutting_down) return -ECANCELED;
        if (!file_executor) {
            try {
                initialize_file_executor();
            } catch (const std::system_error& error) {
                return -error.code().value();
            } catch (const std::bad_alloc&) {
                return -ENOMEM;
            } catch (...) {
                return -EIO;
            }
        }
        if (file_io_inflight == file_io_depth) {
            return -EAGAIN;
        }
        if (reserve_coroutine_completion() !=
            detail::completion_reservation_result::accepted) {
            return -EAGAIN;
        }
        execution_task work([this, &operation]() noexcept {
            const int result = detail::perform_file_operation(operation);
            execution_task completion([this, &operation, result]() noexcept {
                complete_file(operation, result);
            });
            post_coroutine_completion(std::move(completion));
        });
        if (!file_executor->execute(std::move(work))) {
            release_coroutine_completion();
            return -EAGAIN;
        }
        ++file_io_inflight;
        return 0;
    }

    auto complete_file(detail::file_io_operation& operation,
                       int result) noexcept -> void
    {
        if (file_io_inflight == 0) std::terminate();
        --file_io_inflight;
        operation.finish(operation, result);
    }

    [[nodiscard]] auto drain_posted() -> bool
    {
        execution_task task;
        std::size_t count = 0;
        while (count < max_posted_tasks_per_iteration &&
               posted_tasks.try_pop(task)) {
            task();
            ++count;
        }
        return count == max_posted_tasks_per_iteration;
    }

    [[nodiscard]] auto drain_coroutine_completions() -> bool
    {
        execution_task task;
        std::size_t count = 0;
        while (count < max_posted_tasks_per_iteration &&
               coroutine_completions.try_pop(task)) {
            const auto previous = reserved_coroutine_completions.fetch_sub(
                1, std::memory_order_acq_rel);
            if (previous == 0) std::terminate();
            task();
            ++count;
        }
        return count == max_posted_tasks_per_iteration;
    }

    [[nodiscard]] auto reserve_coroutine_completion() noexcept
        -> detail::completion_reservation_result
    {
        if (shutting_down) {
            return detail::completion_reservation_result::shutting_down;
        }
        auto reserved = reserved_coroutine_completions.load(
            std::memory_order_relaxed);
        while (reserved < coroutine_completion_capacity) {
            if (reserved_coroutine_completions.compare_exchange_weak(
                    reserved, reserved + 1, std::memory_order_acq_rel,
                    std::memory_order_relaxed)) {
                return detail::completion_reservation_result::accepted;
            }
        }
        return detail::completion_reservation_result::capacity_exhausted;
    }

    auto release_coroutine_completion() noexcept -> void
    {
        const auto previous = reserved_coroutine_completions.fetch_sub(
            1, std::memory_order_acq_rel);
        if (previous == 0) std::terminate();
    }

    auto post_coroutine_completion(execution_task&& completion) noexcept -> void
    {
        if (!coroutine_completions.try_push(std::move(completion))) {
            std::terminate();
        }
        poller.wake();
    }

    [[nodiscard]] auto submit_blocking(execution_task&& work) noexcept
        -> detail::blocking_submission_result
    {
        if (!blocking_executor_available) {
            return detail::blocking_submission_result::no_worker_threads;
        }
        return task_executor->execute(std::move(work))
                   ? detail::blocking_submission_result::accepted
                   : detail::blocking_submission_result::queue_full;
    }

    auto erase_pending() -> void
    {
        for (const native_socket descriptor : pending_removals) {
            handlers.erase(descriptor);
        }
        pending_removals.clear();
    }

    auto finish_dispatch() -> void
    {
        if (--dispatch_depth != 0) return;
        if (force_shutdown_pending) {
            force_shutdown_pending = false;
#ifdef _WIN32
            // Closing an IOCP socket requests cancellation. Keep each handler
            // until its outstanding completions have been dequeued.
            ++dispatch_depth;
            for (auto& [descriptor, handler] : handlers) {
                if (!pending_removals.contains(descriptor)) handler->on_shutdown();
            }
            --dispatch_depth;
            erase_pending();
#else
            pending_removals.clear();
            handlers.clear();
#endif
        } else {
            erase_pending();
        }
    }

    auto arm_next_timer() -> void
    {
        std::optional<event_loop::clock::time_point> deadline;
        if (!timers.empty()) deadline = timers.begin()->first.first;
        if (coroutine_timers != nullptr &&
            (!deadline || coroutine_timers->deadline < *deadline)) {
            deadline = coroutine_timers->deadline;
        }
        // Registering or cancelling a later timer leaves the earliest
        // deadline unchanged; skip the poller syscall unless that deadline
        // is due, since an expired poller timer must be armed again.
        const auto now = event_loop::clock::now();
        if (deadline == armed_deadline && (!deadline || *deadline > now)) return;
        if (!deadline) poller.arm_timer(std::nullopt);
        else poller.arm_timer(*deadline - now);
        armed_deadline = deadline;
    }

    auto add_timer(event_loop::clock::time_point deadline,
                   execution_task&& task) -> void
    {
        if (!task) {
            throw std::invalid_argument("timer task cannot be empty");
        }

        const auto id = next_timer++;
        auto timer = timers.emplace(timer_key {deadline, id},
                                    std::move(task)).first;
        try {
            arm_next_timer();
        } catch (...) {
            timers.erase(timer);
            throw;
        }
    }

    auto run_due_timers() -> void
    {
        std::size_t count = 0;
        while (!timers.empty() && count < max_timers_per_iteration &&
               timers.begin()->first.first <= event_loop::clock::now()) {
            auto task = std::move(timers.begin()->second);
            timers.erase(timers.begin());
            task();
            ++count;
        }
        while (coroutine_timers != nullptr &&
               count < max_timers_per_iteration &&
               coroutine_timers->deadline <= event_loop::clock::now()) {
            auto* timer = coroutine_timers;
            unlink_coroutine_timer(*timer);
            detail::coroutine_frame_access::detach_cancellation(
                timer->cancellation);
            const auto handle = timer->handle;
            handle.resume();
            ++count;
        }
        arm_next_timer();
    }

    auto register_coroutine_timer(
        detail::coroutine_timer_node& timer) -> void
    {
        if (timer.owner != owner || timer.previous != nullptr ||
            timer.next != nullptr || timer.child != nullptr ||
            coroutine_timers == &timer) {
            std::terminate();
        }
        // Insertion is O(1) and removal O(log n) amortized, whatever the mix
        // of timeout lengths.
        timer.sequence = next_timer_sequence++;
        coroutine_timers = meld_timers(coroutine_timers, &timer);
        try {
            arm_next_timer();
        } catch (...) {
            unlink_coroutine_timer(timer);
            throw;
        }
    }

    auto cancel_coroutine_timer(
        detail::coroutine_timer_node& timer) noexcept -> void
    {
        if (timer.owner != owner) std::terminate();
        unlink_coroutine_timer(timer);
        detail::coroutine_frame_access::detach_cancellation(
            timer.cancellation);
        try {
            arm_next_timer();
        } catch (...) {
            std::terminate();
        }
    }

    auto force_shutdown() noexcept -> void
    {
#ifdef _WIN32
        if (dispatch_depth != 0) {
            force_shutdown_pending = true;
            return;
        }
        ++dispatch_depth;
        for (auto& [descriptor, handler] : handlers) {
            if (!pending_removals.contains(descriptor)) handler->on_shutdown();
        }
        finish_dispatch();
#else
        if (dispatch_depth != 0) {
            force_shutdown_pending = true;
            return;
        }
        pending_removals.clear();
        handlers.clear();
#endif
    }

    [[nodiscard]] auto shutdown_complete() const noexcept -> bool
    {
        return shutting_down && handlers.empty() && active_roots == nullptr;
    }

    auto attach_root(detail::coroutine_root_node& root) noexcept -> void
    {
        if (root.owner != nullptr) std::terminate();
        root.owner = owner;
        root.previous = nullptr;
        root.next = active_roots;
        if (active_roots != nullptr) active_roots->previous = &root;
        active_roots = &root;
        ++active_root_count;
    }

    auto complete_root(detail::coroutine_root_node& root) noexcept -> void
    {
        if (root.owner != owner || active_root_count == 0) std::terminate();
        if (root.cancellation.head != nullptr) std::terminate();
        if (root.previous != nullptr) root.previous->next = root.next;
        else active_roots = root.next;
        if (root.next != nullptr) root.next->previous = root.previous;
        --active_root_count;

        root.previous = nullptr;
        root.next = completed_roots;
        completed_roots = &root;
    }

    auto drain_completed_roots() noexcept -> void
    {
        while (completed_roots != nullptr) {
            auto* root = completed_roots;
            completed_roots = root->next;
            const auto handle = root->handle;
            root->owner = nullptr;
            root->next = nullptr;
            handle.destroy();
        }
    }

    auto request_root_cancellation() noexcept -> void
    {
        for (auto* root = active_roots; root != nullptr; root = root->next) {
            root->cancellation.requested = true;
        }
        for (;;) {
            detail::coroutine_cancellation_node* cancellation = nullptr;
            for (auto* root = active_roots; root != nullptr; root = root->next) {
                if (root->cancellation.head != nullptr) {
                    cancellation = root->cancellation.head;
                    break;
                }
            }
            if (cancellation == nullptr) break;
            const auto cancel = cancellation->cancel;
            if (cancel == nullptr) std::terminate();
            cancel(*cancellation);
        }
    }

private:
    auto unlink_coroutine_timer(
        detail::coroutine_timer_node& timer) noexcept -> void
    {
        if (&timer == coroutine_timers) {
            coroutine_timers = merge_timer_pairs(timer.child);
        } else {
            if (timer.previous->child == &timer) timer.previous->child = timer.next;
            else timer.previous->next = timer.next;
            if (timer.next != nullptr) timer.next->previous = timer.previous;
            coroutine_timers = meld_timers(coroutine_timers, merge_timer_pairs(timer.child));
        }
        timer.previous = nullptr;
        timer.next = nullptr;
        timer.child = nullptr;
        timer.owner = nullptr;
    }

    [[nodiscard]] static auto fires_before(const detail::coroutine_timer_node& left,
                                           const detail::coroutine_timer_node& right) noexcept
        -> bool
    {
        return left.deadline < right.deadline ||
            (left.deadline == right.deadline && left.sequence < right.sequence);
    }

    // Joins two heap roots; the later one becomes the earlier one's first child.
    [[nodiscard]] static auto meld_timers(detail::coroutine_timer_node* left,
                                          detail::coroutine_timer_node* right) noexcept
        -> detail::coroutine_timer_node*
    {
        if (left == nullptr) return right;
        if (right == nullptr) return left;
        if (fires_before(*right, *left)) std::swap(left, right);
        right->previous = left;
        right->next = left->child;
        if (left->child != nullptr) left->child->previous = right;
        left->child = right;
        return left;
    }

    // Two-pass pairing of a sibling list into one root, without recursion.
    [[nodiscard]] static auto merge_timer_pairs(detail::coroutine_timer_node* first) noexcept
        -> detail::coroutine_timer_node*
    {
        detail::coroutine_timer_node* pairs = nullptr;
        while (first != nullptr) {
            auto* left = first;
            auto* right = left->next;
            first = right != nullptr ? right->next : nullptr;
            left->previous = left->next = nullptr;
            if (right != nullptr) right->previous = right->next = nullptr;
            auto* melded = meld_timers(left, right);
            melded->next = pairs;
            pairs = melded;
        }
        detail::coroutine_timer_node* result = nullptr;
        while (pairs != nullptr) {
            auto* next = pairs->next;
            pairs->next = nullptr;
            result = meld_timers(result, pairs);
            pairs = next;
        }
        return result;
    }

public:

    using timer_key = std::pair<event_loop::clock::time_point,
                                std::uint64_t>;
    // First member: blocks SIGPIPE before any socket exists and restores the
    // mask after every socket and worker is gone.
    [[no_unique_address]] sigpipe_block sigpipe;
    coroutine_frame_pool coroutine_frames;
#ifdef _WIN32
    iocp_loop poller;
#elif defined(__APPLE__)
    kqueue_loop poller;
#else
    epoll_loop poller;
#endif
    const std::thread::id owner_thread {std::this_thread::get_id()};
    bounded_task_queue posted_tasks;
    // Only the owning loop thread reads or writes this hint. Local yield
    // continuations and same-thread posts use posted_tasks without writing
    // to the backend wake notifier.
    bool local_post_pending {false};
    bounded_task_queue coroutine_completions;
    const std::size_t coroutine_completion_capacity;
    std::atomic<std::size_t> reserved_coroutine_completions {0};
    const bool blocking_executor_available;
    std::unique_ptr<executor> task_executor;
    const std::size_t file_io_depth;
    std::unique_ptr<executor> file_executor;
    std::size_t file_io_inflight {0};
    std::unordered_map<native_socket, std::unique_ptr<detail::notifiable>> handlers;
    std::unordered_set<native_socket> pending_removals;
    std::map<timer_key, execution_task> timers;
    std::uint64_t next_timer {1};
    std::size_t dispatch_depth {0};
    bool force_shutdown_pending {false};
    bool shutting_down {false};
    event_loop* owner {nullptr};
    detail::coroutine_root_node* active_roots {nullptr};
    detail::coroutine_root_node* completed_roots {nullptr};
    // Root of the pairing heap of coroutine timers: the earliest deadline.
    detail::coroutine_timer_node* coroutine_timers {nullptr};
    std::uint64_t next_timer_sequence {0};
    // The deadline the poller timer is armed for, if any.
    std::optional<event_loop::clock::time_point> armed_deadline;
    std::size_t active_root_count {0};
};

event_loop::event_loop() : event_loop(event_loop_options {}) {}

event_loop::event_loop(event_loop_options options)
    : implementation_(std::make_unique<implementation>(checked_options(options)))
{
    implementation_->owner = this;
}

event_loop::~event_loop() = default;

event_loop::handler_call_scope::handler_call_scope(event_loop& loop) noexcept
{
    if (loop.implementation_->dispatch_depth == 0) {
        loop_ = &loop;
        ++loop.implementation_->dispatch_depth;
    }
}

event_loop::handler_call_scope::~handler_call_scope() noexcept
{
    if (loop_ != nullptr) loop_->implementation_->finish_dispatch();
}

auto event_loop::run() -> event_loop_result
{
    std::array<ready_event, 64> events {};
    for (;;) {
        implementation_->drain_completed_roots();
        if (implementation_->shutdown_complete()) {
            return event_loop_result::stopped;
        }
        const auto result = implementation_->poller.poll(
            events, implementation_->local_post_pending);
        if (result.event_count != 0) ++implementation_->dispatch_depth;

        try {
            for (std::size_t index = 0; index < result.event_count; ++index) {
#ifndef _WIN32
                if (implementation_->force_shutdown_pending) break;
#endif
                const auto event = events[index];
#ifdef _WIN32
                event.operation->complete(*event.operation, event.bytes,
                                          event.error);
#else
                const auto found = implementation_->handlers.find(event.descriptor);
                if (found == implementation_->handlers.end()) {
                    continue;
                }
                auto* const handler = found->second.get();

                if (event.error) {
                    handler->on_error();
                    continue;
                }
                if (event.readable) {
                    handler->on_read();
                }
                if (event.writable &&
                    !implementation_->force_shutdown_pending &&
                    !implementation_->pending_removals.contains(
                        event.descriptor)) {
                    handler->on_write();
                }
#endif
            }
        } catch (...) {
            if (result.event_count != 0) implementation_->finish_dispatch();
            throw;
        }

        if (result.event_count != 0) implementation_->finish_dispatch();
        implementation_->drain_completed_roots();

        if (result.wake_requested || implementation_->local_post_pending) {
            implementation_->local_post_pending = false;
            const bool more_posted = implementation_->drain_posted();
            const bool more_completions =
                implementation_->drain_coroutine_completions();
            if (more_posted || more_completions) {
                implementation_->local_post_pending = true;
            }
            implementation_->drain_completed_roots();
        }
        if (result.timer_requested) {
            implementation_->run_due_timers();
            implementation_->drain_completed_roots();
        }
        if (implementation_->shutdown_complete()) {
            return event_loop_result::stopped;
        }
        if (result.stop_requested) {
            return event_loop_result::stopped;
        }
        if (result.signal_requested) {
            return event_loop_result::interrupted;
        }
    }
}

auto event_loop::stop() -> void
{
    implementation_->poller.request_stop();
}

auto event_loop::shutdown(clock::duration timeout) -> void
{
    if (implementation_->shutting_down) {
        implementation_->request_root_cancellation();
        implementation_->force_shutdown();
        implementation_->poller.wake();
        return;
    }

    implementation_->shutting_down = true;
    ++implementation_->dispatch_depth;
    try {
        implementation_->request_root_cancellation();
        for (auto& [descriptor, handler] : implementation_->handlers) {
            if (!implementation_->pending_removals.contains(descriptor)) {
                handler->on_shutdown();
            }
        }
    } catch (...) {
        implementation_->force_shutdown();
        implementation_->finish_dispatch();
        implementation_->poller.wake();
        throw;
    }
    implementation_->finish_dispatch();

    if (implementation_->handlers.empty()) {
        implementation_->poller.wake();
        return;
    }
    if (timeout <= clock::duration::zero()) {
        implementation_->force_shutdown();
        implementation_->poller.wake();
        return;
    }

    auto* const state = implementation_.get();
    try {
        implementation_->add_timer(
            detail::deadline_after(timeout),
            execution_task([state]() noexcept { state->force_shutdown(); }));
    } catch (...) {
        implementation_->force_shutdown();
        implementation_->poller.wake();
        throw;
    }
    implementation_->poller.wake();
}

auto event_loop::add(std::unique_ptr<tcp_acceptor> handler) -> void
{
    auto base = std::unique_ptr<detail::notifiable>(
        static_cast<detail::notifiable*>(handler.release()));
    add_handler(std::move(base));
}

auto event_loop::add(std::unique_ptr<tcp_stream> handler) -> void
{
    auto base = std::unique_ptr<detail::notifiable>(
        static_cast<detail::notifiable*>(handler.release()));
    add_handler(std::move(base));
}

auto event_loop::add(std::unique_ptr<udp_socket> handler) -> void
{
    auto base = std::unique_ptr<detail::notifiable>(
        static_cast<detail::notifiable*>(handler.release()));
    add_handler(std::move(base));
}

auto event_loop::add_handler(
    std::unique_ptr<detail::notifiable> handler) -> void
{
    if (!handler) {
        throw std::invalid_argument("cannot add an empty handler");
    }
    if (implementation_->shutting_down) {
        throw std::logic_error("cannot add a handler during shutdown");
    }
    const native_socket descriptor = handler->descriptor();
    if (implementation_->handlers.contains(descriptor)) {
        throw std::logic_error("descriptor is already registered");
    }

    implementation_->poller.add_descriptor(
        descriptor, handler->initial_read_interest());
    try {
        implementation_->handlers.emplace(descriptor, std::move(handler));
    } catch (...) {
        implementation_->poller.remove_descriptor(descriptor);
        throw;
    }
}

auto event_loop::remove(native_socket descriptor) -> void
{
    if (!implementation_->handlers.contains(descriptor) ||
        implementation_->pending_removals.contains(descriptor)) {
        return;
    }
    if (implementation_->dispatch_depth != 0) {
        implementation_->pending_removals.insert(descriptor);
        try {
            implementation_->poller.remove_descriptor(descriptor);
        } catch (...) {
            implementation_->pending_removals.erase(descriptor);
            throw;
        }
    } else {
        implementation_->poller.remove_descriptor(descriptor);
        implementation_->handlers.erase(descriptor);
    }
}

auto event_loop::set_io_interest(native_socket descriptor, bool read_enabled,
                                 bool write_enabled) -> void
{
#ifdef _WIN32
    // IOCP operations are submitted directly; readiness interest is unused.
    (void)descriptor;
    (void)read_enabled;
    (void)write_enabled;
#else
    if (!implementation_->pending_removals.contains(descriptor)) {
        implementation_->poller.set_io_interest(descriptor, read_enabled,
                                                write_enabled);
    }
#endif
}

auto event_loop::set_write_interest(native_socket descriptor, bool enabled) -> void
{
    set_io_interest(descriptor, true, enabled);
}

auto event_loop::post(execution_task&& task) noexcept -> bool
{
    if (std::this_thread::get_id() == implementation_->owner_thread) {
        return post_local(std::move(task));
    }
    if (!implementation_->posted_tasks.try_push(std::move(task))) {
        return false;
    }
    implementation_->poller.wake();
    return true;
}

auto event_loop::post_local(execution_task&& task) noexcept -> bool
{
    if (!implementation_->posted_tasks.try_push(std::move(task))) return false;
    implementation_->local_post_pending = true;
    return true;
}

auto event_loop::task_executor() noexcept -> executor&
{
    return *implementation_->task_executor;
}

auto event_loop::spawn(task<void>&& operation) -> task_spawn_result
{
    if (operation.allocation_failed_) {
        return task_spawn_result::frame_allocation_failure;
    }
    if (operation.handle_ == nullptr) return task_spawn_result::invalid_task;
    if (operation.handle_.promise().loop_ != this) {
        return task_spawn_result::invalid_task;
    }
    if (!can_spawn()) {
        return task_spawn_result::shutting_down;
    }

    auto handle = operation.release_for_spawn();
    auto& promise = handle.promise();
    const bool started = promise.started_;
    promise.started_ = true;
    return spawn_root(promise.root_, handle, started);
}

auto event_loop::can_spawn() const noexcept -> bool
{
    return !implementation_->shutting_down;
}

auto event_loop::spawn_root(detail::coroutine_root_node& root,
                            std::coroutine_handle<> handle,
                            bool started) -> task_spawn_result
{
    if (handle.done()) {
        handle.destroy();
        return task_spawn_result::accepted;
    }

    implementation_->attach_root(root);
    if (!started) {
        handle.resume();
    }
    implementation_->drain_completed_roots();
    return task_spawn_result::accepted;
}

auto event_loop::coroutine_statistics() const noexcept
    -> coroutine_pool_statistics
{
    auto statistics = implementation_->coroutine_frames.statistics();
    statistics.active_roots = implementation_->active_root_count;
    return statistics;
}

auto detail::coroutine_frame_access::allocate(
    event_loop& loop, std::size_t size) noexcept -> void*
{
    return loop.implementation_->coroutine_frames.try_allocate(size);
}

auto detail::coroutine_frame_access::deallocate(
    void* pointer, std::size_t size) noexcept -> void
{
    coroutine_frame_pool::deallocate(pointer, size);
}

auto detail::coroutine_frame_access::complete_root(
    coroutine_root_node& root) noexcept -> void
{
    if (root.owner == nullptr) std::terminate();
    root.owner->implementation_->complete_root(root);
}

auto detail::coroutine_frame_access::register_timer(
    event_loop& loop, coroutine_timer_node& timer) -> void
{
    loop.implementation_->register_coroutine_timer(timer);
}

auto detail::coroutine_frame_access::cancel_timer(
    coroutine_timer_node& timer) noexcept -> void
{
    if (timer.owner == nullptr) std::terminate();
    timer.owner->implementation_->cancel_coroutine_timer(timer);
}

auto detail::coroutine_frame_access::attach_cancellation(
    coroutine_cancellation_state& state,
    coroutine_cancellation_node& node) noexcept -> bool
{
    if (node.state != nullptr || node.previous != nullptr || node.next != nullptr) {
        std::terminate();
    }
    if (state.requested) return false;
    node.state = &state;
    node.next = state.head;
    if (state.head != nullptr) state.head->previous = &node;
    state.head = &node;
    return true;
}

auto detail::coroutine_frame_access::detach_cancellation(
    coroutine_cancellation_node& node) noexcept -> void
{
    if (node.state == nullptr) return;
    auto& state = *node.state;
    if (node.previous != nullptr) node.previous->next = node.next;
    else state.head = node.next;
    if (node.next != nullptr) node.next->previous = node.previous;
    node.previous = nullptr;
    node.next = nullptr;
    node.state = nullptr;
}

auto detail::coroutine_frame_access::request_cancellation(
    coroutine_cancellation_state& state) noexcept -> void
{
    state.requested = true;
    while (state.head != nullptr) {
        auto* node = state.head;
        if (node->cancel == nullptr) std::terminate();
        node->cancel(*node);
    }
}

auto detail::coroutine_frame_access::reserve_completion(
    event_loop& loop) noexcept -> completion_reservation_result
{
    return loop.implementation_->reserve_coroutine_completion();
}

auto detail::coroutine_frame_access::release_completion(
    event_loop& loop) noexcept -> void
{
    loop.implementation_->release_coroutine_completion();
}

auto detail::coroutine_frame_access::post_completion(
    event_loop& loop, execution_task&& completion) noexcept -> void
{
    loop.implementation_->post_coroutine_completion(std::move(completion));
}

auto detail::coroutine_frame_access::submit_blocking(
    event_loop& loop, execution_task&& work) noexcept
    -> blocking_submission_result
{
    return loop.implementation_->submit_blocking(std::move(work));
}

auto detail::coroutine_frame_access::submit_file(
    event_loop& loop, file_io_operation& operation) noexcept
    -> int
{
    return loop.implementation_->submit_file(operation);
}

} // namespace eventloop
