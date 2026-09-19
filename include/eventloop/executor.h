#pragma once

#include <concepts>
#include <cstddef>
#include <exception>
#include <memory>
#include <type_traits>
#include <utility>

// Work submitted to an executor is a fixed-capacity, move-only, type-erased
// callable. A callable must be invocable with no arguments, return void, and
// be noexcept to invoke and to move construct. Callables that do not fit the
// inline storage or exceed its alignment are rejected at compile time. The
// wrapper itself never allocates.
namespace executor_detail {

inline constexpr std::size_t task_storage_size = 64;
inline constexpr std::size_t task_storage_alignment = alignof(std::max_align_t);

template<typename Callable>
concept inline_callable =
    requires(Callable& callable) {
        { callable() } noexcept -> std::same_as<void>;
    } &&
    std::is_nothrow_move_constructible_v<Callable> &&
    std::is_nothrow_destructible_v<Callable> &&
    (sizeof(Callable) <= task_storage_size) &&
    (alignof(Callable) <= task_storage_alignment);

} // namespace executor_detail

class execution_task {
public:
    execution_task() noexcept = default;

    template<typename Function>
    execution_task(Function&& function)
        requires executor_detail::inline_callable<std::decay_t<Function>>
    {
        using callable = std::decay_t<Function>;

        static constexpr operations table {
            .invoke = [](void* storage) noexcept {
                (*static_cast<callable*>(storage))();
            },
            .move = [](void* destination, void* source) noexcept {
                std::construct_at(static_cast<callable*>(destination),
                                  std::move(*static_cast<callable*>(source)));
                std::destroy_at(static_cast<callable*>(source));
            },
            .destroy = [](void* storage) noexcept {
                std::destroy_at(static_cast<callable*>(storage));
            },
        };

        std::construct_at(reinterpret_cast<callable*>(storage_),
                          std::forward<Function>(function));
        operations_ = &table;
    }

    ~execution_task() { reset(); }

    execution_task(execution_task&& other) noexcept { move_from(other); }

    auto operator=(execution_task&& other) noexcept -> execution_task&
    {
        if (this != &other) {
            reset();
            move_from(other);
        }
        return *this;
    }

    execution_task(const execution_task&) = delete;
    auto operator=(const execution_task&) -> execution_task& = delete;

    explicit operator bool() const noexcept { return operations_ != nullptr; }

    auto operator()() noexcept -> void
    {
        if (operations_ == nullptr) {
            std::terminate();
        }
        operations_->invoke(storage_);
    }

private:
    struct operations {
        auto (*invoke)(void* storage) noexcept -> void;
        auto (*move)(void* destination, void* source) noexcept -> void;
        auto (*destroy)(void* storage) noexcept -> void;
    };

    auto reset() noexcept -> void
    {
        if (operations_ != nullptr) {
            operations_->destroy(storage_);
            operations_ = nullptr;
        }
    }

    auto move_from(execution_task& other) noexcept -> void
    {
        if (other.operations_ != nullptr) {
            other.operations_->move(storage_, other.storage_);
            operations_ = other.operations_;
            other.operations_ = nullptr;
        }
    }

    alignas(executor_detail::task_storage_alignment)
        std::byte storage_[executor_detail::task_storage_size] {};
    const operations* operations_ {nullptr};
};

// Executors own a fixed execution strategy. Submitting work never allocates.
// execute() returns true once ownership of the task has been accepted:
// the single-thread executor has already run it; the multi-thread executor
// has queued it for a worker. A false result means the multi-thread queue is
// full or the executor is shutting down, and a named task remains valid for a
// fallback path. Calling execute() concurrently is supported; destroying an
// executor while execute() is running is not.
class executor {
public:
    virtual ~executor() = default;

    executor(const executor&) = delete;
    auto operator=(const executor&) -> executor& = delete;

    virtual auto execute(execution_task&& task) noexcept -> bool = 0;

protected:
    executor() = default;
};

struct multi_thread_executor_options {
    std::size_t worker_count;
    std::size_t queue_capacity {1024};
};

// Work runs on the calling thread before execute() returns.
auto make_single_thread_executor() -> std::unique_ptr<executor>;

// worker_count must be greater than zero. queue_capacity must be a power of
// two and at least two, otherwise std::invalid_argument is thrown. Destruction
// drains accepted work and waits for it to finish.
auto make_multi_thread_executor(multi_thread_executor_options options)
    -> std::unique_ptr<executor>;
