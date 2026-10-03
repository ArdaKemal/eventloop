#include "eventloop/executor.h"

#include "work_stealing_queue.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>
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

// An idle peer takes a lone local task only after its owner has started no
// task for this long. Shorter delays move work away from owners that are
// about to reach it; longer ones extend the wait behind a blocked owner.
// Sleep granularity can lengthen it (Windows sleeps are millisecond-based).
constexpr auto stall_detection_delay = std::chrono::microseconds {100};

// Per-owner stall detection state, on its own line: the owner writes started
// for every task, and only lone pushes and watchers read this line. Neither
// the wake signal (read by external producers) nor the queue counts (read by
// every scanning thief) would keep that write private.
struct alignas(64) owner_progress {
    // Tasks started by this worker; written only by it. A relaxed hint: a
    // stale read can only move a task to another worker, which is allowed.
    std::atomic<std::uint64_t> started {0};
    // At most one peer watches an owner's lone local task. Whoever clears
    // this repeats its SC queue check; a lone pusher publishes before its SC
    // load of this flag, so one of them observes the task.
    std::atomic<bool> watched {false};
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
          wake_(std::make_unique<wake_signal[]>(options.worker_count)),
          progress_(std::make_unique<owner_progress[]>(options.worker_count))
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
        // A lone local task is not shareable yet, but a busy owner may never
        // return to it. Wake one peer to watch it unless one already does.
        // The watch lasts at least stall_detection_delay, so an owner's lone
        // pushes cause at most one such wake per delay, not one per task.
        if (local && !queue_.has_backlog(worker)) {
            if (!progress_[worker].watched.load(std::memory_order_seq_cst) &&
                sleepers_.load(std::memory_order_seq_cst) != 0) {
                wake_idle_peer(worker);
            }
        } else if (sleepers_.load(std::memory_order_seq_cst) != 0 &&
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

    // Claims the watch of a peer whose local queue holds work the stealing
    // threshold leaves to its owner. Returns worker_count_ when none.
    auto claim_watch(std::size_t index, std::uint64_t& started) noexcept
        -> std::size_t
    {
        for (std::size_t offset = 1; offset < worker_count_; ++offset) {
            auto peer = index + offset;
            if (peer >= worker_count_) peer -= worker_count_;
            auto& owner = progress_[peer];
            if (queue_.has_local_work(peer) &&
                !owner.watched.load(std::memory_order_seq_cst) &&
                !owner.watched.exchange(true, std::memory_order_seq_cst)) {
                started = owner.started.load(std::memory_order_relaxed);
                return peer;
            }
        }
        return worker_count_;
    }

    // Local work that no idle peer would otherwise be told about.
    [[nodiscard]] auto has_unwatched_local_work(std::size_t index) const noexcept
        -> bool
    {
        for (std::size_t peer = 0; peer < worker_count_; ++peer) {
            if (peer != index && queue_.has_local_work(peer) &&
                !progress_[peer].watched.load(std::memory_order_seq_cst)) {
                return true;
            }
        }
        return false;
    }

    // Runs outside the idle state, like a task: producers wake other idle
    // peers meanwhile, and this worker checks every queue when it ends.
    auto watch(std::size_t index, std::size_t owner, std::uint64_t started,
               std::size_t& victim, std::size_t& cursor,
               execution_task& task) noexcept -> bool
    {
        // A producer that signalled this worker while it was registered idle
        // published before the idle clear; take that work instead of waiting.
        bool found = take_work(index, victim, cursor, task);
        if (!found) {
            std::this_thread::sleep_for(stall_detection_delay);
            // An owner that started no task in the delay is stalled in one.
            found = progress_[owner].started.load(std::memory_order_relaxed) == started &&
                    queue_.try_pop(owner, task, cursor);
        }
        progress_[owner].watched.store(false, std::memory_order_seq_cst);
        // Repeat the queue check after clearing the watch (see owner_progress).
        return found || take_work(index, victim, cursor, task);
    }

    auto start(std::size_t index, execution_task& task) noexcept -> void
    {
        // A sole worker has no peer to watch it.
        if (worker_count_ != 1) {
            auto& started = progress_[index].started;
            started.store(started.load(std::memory_order_relaxed) + 1,
                          std::memory_order_relaxed);
        }
        task();
    }

    auto worker_loop(std::size_t index, std::size_t cursor) noexcept -> void
    {
        current_worker = {this, index, cursor};
        std::size_t victim = index + 1 == worker_count_ ? 0 : index + 1;
        std::size_t dequeue_cursor = cursor;
        // A sole worker is always its own target, so only peers track idleness.
        const bool shared = worker_count_ > 1;
        bool watched = false;
        for (;;) {
            execution_task task;
            // After a watch, take_work() has just failed: register idle.
            if (!std::exchange(watched, false) &&
                take_work(index, victim, dequeue_cursor, task)) {
                start(index, task);
                continue;
            }
            if (!accepting_.load(std::memory_order_seq_cst)) {
                return;
            }
            sleepers_.fetch_add(1, std::memory_order_seq_cst);
            if (shared) wake_[index].set_idle(true);
            // Either publication observes this registration and signals us,
            // or this second SC queue check observes the published work.
            bool found = take_work(index, victim, dequeue_cursor, task);
            std::size_t owner = worker_count_;
            std::uint64_t started = 0;
            while (!found && accepting_.load(std::memory_order_seq_cst)) {
                // Checked after registration, like the queues above: a lone
                // pusher either observes this worker idle or its task here.
                if (shared && (owner = claim_watch(index, started)) != worker_count_) break;
                wake_[index].acquire();
                found = take_work(index, victim, dequeue_cursor, task);
            }
            if (shared) wake_[index].set_idle(false);
            sleepers_.fetch_sub(1, std::memory_order_seq_cst);
            if (owner != worker_count_) {
                found = watch(index, owner, started, victim, dequeue_cursor, task);
                watched = !found;
            }
            if (!found) continue;
            // Producers that observed this worker idle signalled only this
            // worker. Their publications precede the idle clear above, so
            // this check sees any of their work this worker leaves behind.
            // That includes a lone local task whose wake this worker took.
            if (shared && sleepers_.load(std::memory_order_seq_cst) != 0 &&
                (queue_.has_shareable_work() || has_unwatched_local_work(index))) {
                wake_idle_peer(index);
            }
            start(index, task);
        }
    }

    const std::size_t worker_count_;
    work_stealing_queue queue_;
    std::unique_ptr<wake_signal[]> wake_;
    std::unique_ptr<owner_progress[]> progress_;
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
