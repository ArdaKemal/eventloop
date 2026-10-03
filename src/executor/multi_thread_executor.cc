#include "eventloop/executor.h"

#include "work_stealing_queue.h"

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

#if defined(_MSC_VER)
#define EVENTLOOP_EXECUTOR_NOINLINE __declspec(noinline)
#else
#define EVENTLOOP_EXECUTOR_NOINLINE __attribute__((noinline))
#endif

namespace eventloop {

namespace {

[[nodiscard]] auto is_power_of_two(std::size_t value) noexcept -> bool
{
    return value != 0 && (value & (value - 1)) == 0;
}

// One consumer per signal. Notifications coalesce and are independent of task
// ownership: a thief cannot consume the victim's wakeup. Register the waiter
// before checking the signal, using the publication/registration SC handshake.
class alignas(64) wake_signal {
public:
    wake_signal() = default;

    wake_signal(const wake_signal&) = delete;
    auto operator=(const wake_signal&) -> wake_signal& = delete;

    auto release() noexcept -> void
    {
        // Every publication and every signal observation/consumption is SC.
        // If an existing signal covers this publication, its consumer's next
        // queue check observes it; avoid another RMW while the owner is busy.
        if (pending_.load(std::memory_order_seq_cst) != 0) return;
        if (pending_.exchange(1, std::memory_order_seq_cst) == 0 &&
            waiting_.load(std::memory_order_seq_cst)) {
            pending_.notify_one();
        }
    }

    auto acquire() noexcept -> void
    {
        if (pending_.exchange(0, std::memory_order_seq_cst) != 0) return;
        waiting_.store(true, std::memory_order_seq_cst);
        while (pending_.exchange(0, std::memory_order_seq_cst) == 0) {
            pending_.wait(0, std::memory_order_relaxed);
        }
        waiting_.store(false, std::memory_order_relaxed);
    }

    // Registered after the sleeper count and before the second queue check.
    auto set_idle(bool idle) noexcept -> void
    {
        idle_.store(idle, std::memory_order_seq_cst);
    }

    [[nodiscard]] auto idle() const noexcept -> bool
    {
        return idle_.load(std::memory_order_seq_cst);
    }

private:
    // int is libstdc++'s Linux futex wait type.
    std::atomic<int> pending_ {0};
    std::atomic<bool> waiting_ {false};
    std::atomic<bool> idle_ {false};
};

struct worker_context {
    const executor* owner {nullptr};
    std::size_t index {0};
    std::size_t cursor {0};
};

thread_local worker_context current_worker;
thread_local std::size_t external_worker {0};
thread_local std::size_t external_cursor {
    std::hash<std::thread::id> {}(std::this_thread::get_id())};

class multi_thread_executor final : public executor {
public:
    explicit multi_thread_executor(const multi_thread_executor_options& options)
        : worker_count_(options.worker_count),
          queue_(options.queue_capacity, options.worker_count),
          wake_(std::make_unique<wake_signal[]>(options.worker_count))
    {
        workers_.reserve(options.worker_count);
        try {
            for (std::size_t index = 0; index < options.worker_count; ++index) {
                workers_.emplace_back([this, index, capacity = options.queue_capacity] {
                    worker_loop(index, index * (capacity / worker_count_));
                });
            }
        } catch (...) {
            shutdown();
            throw;
        }
    }

    ~multi_thread_executor() override { shutdown(); }

    auto execute(execution_task&& task) noexcept -> bool override
    {
        if (!task || !accepting_.load(std::memory_order_acquire)) {
            return false;
        }
        const bool local = worker_count_ != 1 && current_worker.owner == this;
        auto& cursor = local ? current_worker.cursor : external_cursor;
        // Repeated rejection returns before dispatch saves its working state.
        if (queue_.known_full(cursor)) return false;
        return dispatch(std::move(task), local, cursor);
    }

private:
    EVENTLOOP_EXECUTOR_NOINLINE auto dispatch(execution_task&& task, bool local,
                                              std::size_t& cursor) noexcept -> bool
    {
        // A background executor with one worker needs neither dispatch nor
        // victim selection. Keep the same publication and ownership rules.
        if (worker_count_ == 1) {
            if (!queue_.try_push(0, std::move(task), cursor)) return false;
            wake_[0].release();
            return true;
        }
        if (!local && external_worker >= worker_count_) external_worker = 0;
        const auto worker = local ? current_worker.index : external_worker++;
        const bool queued = local ? queue_.try_push(worker, std::move(task), cursor)
                                  : queue_.try_push_external(worker, std::move(task), cursor);
        if (!queued) {
            return false;
        }
        wake_[worker].release();
        // An idle target observes its own signal. Otherwise one idle peer is
        // enough: a woken worker that leaves shareable work wakes the next.
        if ((!local || queue_.has_backlog(worker)) &&
            sleepers_.load(std::memory_order_seq_cst) != 0 &&
            !wake_[worker].idle()) {
            wake_idle_peer(worker);
        }
        return true;
    }

    // Publication precedes these SC idle loads. A worker that registers later
    // repeats its queue check after registration and observes the work.
    auto wake_idle_peer(std::size_t busy) noexcept -> void
    {
        for (std::size_t offset = 1; offset < worker_count_; ++offset) {
            auto peer = busy + offset;
            if (peer >= worker_count_) peer -= worker_count_;
            if (wake_[peer].idle()) {
                wake_[peer].release();
                return;
            }
        }
    }

    auto shutdown() noexcept -> void
    {
        // Shutdown also participates in the SC signal handshake: a coalesced
        // existing signal must cover the worker's next shutdown observation.
        accepting_.store(false, std::memory_order_seq_cst);
        for (std::size_t index = 0; index < workers_.size(); ++index) {
            wake_[index].release();
        }
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

    auto take_work(std::size_t index, std::size_t& victim, std::size_t& cursor,
                   execution_task& task) noexcept -> bool
    {
        if (queue_.try_pop(index, task, cursor)) return true;
        if (worker_count_ == 1) return false;
        if (queue_.try_pop_external(index, task, cursor)) return true;
        for (std::size_t scanned = 0; scanned < worker_count_; ++scanned) {
            const auto candidate = victim;
            if (++victim == worker_count_) victim = 0;
            if (candidate != index) {
                // External submissions have no worker affinity. Even a lone
                // job behind a blocked owner must be available to idle peers.
                if (queue_.try_pop_external(candidate, task, cursor) ||
                    queue_.try_steal(candidate, task, cursor)) return true;
            }
        }
        return false;
    }

    auto worker_loop(std::size_t index, std::size_t cursor) noexcept -> void
    {
        current_worker = {this, index, cursor};
        std::size_t victim = index + 1 == worker_count_ ? 0 : index + 1;
        std::size_t dequeue_cursor = cursor;
        for (;;) {
            execution_task task;
            if (take_work(index, victim, dequeue_cursor, task)) {
                task();
                continue;
            }
            if (!accepting_.load(std::memory_order_seq_cst)) {
                return;
            }
            // A sole worker is always its own target, so only peers track idleness.
            const bool shared = worker_count_ > 1;
            sleepers_.fetch_add(1, std::memory_order_seq_cst);
            if (shared) wake_[index].set_idle(true);
            // Either publication observes this registration and signals us,
            // or this second SC queue check observes the published work.
            bool found = take_work(index, victim, dequeue_cursor, task);
            if (!found && accepting_.load(std::memory_order_seq_cst)) {
                wake_[index].acquire();
                found = take_work(index, victim, dequeue_cursor, task);
            }
            if (shared) wake_[index].set_idle(false);
            sleepers_.fetch_sub(1, std::memory_order_seq_cst);
            if (!found) continue;
            // Producers that observed this worker idle signalled only this
            // worker. Their publications precede the idle clear above, so
            // this check sees any of their work this worker leaves behind.
            if (shared && sleepers_.load(std::memory_order_seq_cst) != 0 &&
                queue_.has_shareable_work()) {
                wake_idle_peer(index);
            }
            task();
        }
    }

    const std::size_t worker_count_;
    work_stealing_queue queue_;
    std::unique_ptr<wake_signal[]> wake_;
    std::vector<std::jthread> workers_;
    std::atomic<std::size_t> sleepers_ {0};
    std::atomic<bool> accepting_ {true};
};

} // namespace

auto make_multi_thread_executor(multi_thread_executor_options options)
    -> std::unique_ptr<executor>
{
    if (options.worker_count == 0) {
        throw std::invalid_argument("executor worker count must be greater than zero");
    }
    if (options.queue_capacity < 2 || !is_power_of_two(options.queue_capacity)) {
        throw std::invalid_argument(
            "executor queue capacity must be a power of two and at least two");
    }
    return std::make_unique<multi_thread_executor>(options);
}

} // namespace eventloop
