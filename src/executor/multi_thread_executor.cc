#include "eventloop/executor.h"

#include "bounded_task_queue.h"

#include <atomic>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {

[[nodiscard]] auto is_power_of_two(std::size_t value) noexcept -> bool
{
    return value != 0 && (value & (value - 1)) == 0;
}

// libstdc++'s futex-backed counting_semaphore can miss a wake after the
// counter changes away from and back to the value observed by a waiter. Keep
// waiter registration separate and only wait while the permit count is zero.
class wake_semaphore {
public:
    wake_semaphore() = default;

    wake_semaphore(const wake_semaphore&) = delete;
    auto operator=(const wake_semaphore&) -> wake_semaphore& = delete;

    auto release() noexcept -> void
    {
        permits_.fetch_add(1, std::memory_order_seq_cst);
        if (waiters_.load(std::memory_order_seq_cst) != 0) {
            permits_.notify_one();
        }
    }

    auto acquire() noexcept -> void
    {
        for (;;) {
            int permits = permits_.load(std::memory_order_relaxed);
            while (permits == 0) {
                // The producer cannot miss this waiter while this worker
                // also misses the producer's new permit.
                waiters_.fetch_add(1, std::memory_order_seq_cst);
                for (;;) {
                    permits = permits_.load(std::memory_order_seq_cst);
                    if (permits != 0) break;
                    permits_.wait(0, std::memory_order_relaxed);
                }
                waiters_.fetch_sub(1, std::memory_order_relaxed);
            }
            if (permits_.compare_exchange_weak(
                    permits, permits - 1, std::memory_order_acquire,
                    std::memory_order_relaxed)) {
                return;
            }
        }
    }

private:
    // int is libstdc++'s Linux futex wait type, avoiding its waiter-pool path.
    std::atomic<int> permits_ {0};
    std::atomic<int> waiters_ {0};
};

class multi_thread_executor final : public executor {
public:
    explicit multi_thread_executor(const multi_thread_executor_options& options)
        : queue_(options.queue_capacity)
    {
        workers_.reserve(options.worker_count);
        try {
            for (std::size_t index = 0; index < options.worker_count; ++index) {
                workers_.emplace_back([this] { worker_loop(); });
            }
        } catch (...) {
            shutdown();
            throw;
        }
    }

    ~multi_thread_executor() override { shutdown(); }

    auto execute(execution_task&& task) noexcept -> bool override
    {
        if (!accepting_.load(std::memory_order_acquire)) {
            return false;
        }
        if (!queue_.try_push(std::move(task))) {
            return false;
        }
        ready_.release();
        return true;
    }

private:
    auto shutdown() noexcept -> void
    {
        accepting_.store(false, std::memory_order_release);
        for (std::size_t index = 0; index < workers_.size(); ++index) {
            ready_.release();
        }
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

    auto worker_loop() noexcept -> void
    {
        for (;;) {
            ready_.acquire();
            execution_task task;
            if (queue_.try_pop(task)) {
                task();
                continue;
            }
            if (!accepting_.load(std::memory_order_acquire)) {
                return;
            }
        }
    }

    bounded_task_queue queue_;
    wake_semaphore ready_;
    std::vector<std::jthread> workers_;
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
