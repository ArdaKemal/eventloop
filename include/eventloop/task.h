#pragma once

#include "eventloop/event_loop.h"

#include <coroutine>
#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <functional>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>

enum class task_result {
    success,
    frame_allocation_failure,
};

enum class task_state {
    not_started,
    suspended,
    completed,
    frame_allocation_failure,
};

enum class timer_wait_result {
    expired,
    cancelled,
};

enum class blocking_error {
    no_worker_threads,
    executor_queue_full,
    completion_capacity_exhausted,
    cancelled,
    shutting_down,
};

template<typename T>
class task;

// Coroutine functions returning task must take their owning event_loop as the
// first argument. Started tasks and their frames remain loop-affine. Root
// tasks should normally be transferred to event_loop::spawn().
template<>
class [[nodiscard]] task<void> {
public:
    struct promise_type;
    using handle_type = std::coroutine_handle<promise_type>;

    task() noexcept = default;
    ~task() { reset(); }

    task(task&& other) noexcept
        : handle_(std::exchange(other.handle_, {})),
          allocation_failed_(std::exchange(other.allocation_failed_, false))
    {
    }

    auto operator=(task&& other) noexcept -> task&
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, {});
            allocation_failed_ =
                std::exchange(other.allocation_failed_, false);
        }
        return *this;
    }

    task(const task&) = delete;
    auto operator=(const task&) -> task& = delete;

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return handle_ != nullptr;
    }

    [[nodiscard]] auto state() const noexcept -> task_state
    {
        if (allocation_failed_) return task_state::frame_allocation_failure;
        if (handle_ == nullptr) return task_state::completed;
        if (handle_.done()) return task_state::completed;
        return handle_.promise().started_ ? task_state::suspended
                                          : task_state::not_started;
    }

    auto start() -> task_state
    {
        if (allocation_failed_) return task_state::frame_allocation_failure;
        if (handle_ == nullptr || handle_.done()) return task_state::completed;
        if (handle_.promise().started_) {
            throw std::logic_error("coroutine task has already been started");
        }
        handle_.promise().started_ = true;
        handle_.resume();
        return handle_.done() ? task_state::completed : task_state::suspended;
    }

    [[nodiscard]] auto result() const -> task_result
    {
        if (allocation_failed_) return task_result::frame_allocation_failure;
        if (handle_ != nullptr && !handle_.done()) {
            throw std::logic_error("coroutine task has not completed");
        }
        return task_result::success;
    }

    class awaiter {
    public:
        explicit awaiter(task&& source) noexcept
            : handle_(std::exchange(source.handle_, {})),
              allocation_failed_(
                  std::exchange(source.allocation_failed_, false))
        {
        }

        ~awaiter() { reset(); }

        awaiter(awaiter&& other) noexcept
            : handle_(std::exchange(other.handle_, {})),
              allocation_failed_(
                  std::exchange(other.allocation_failed_, false))
        {
        }

        awaiter(const awaiter&) = delete;
        auto operator=(const awaiter&) -> awaiter& = delete;
        auto operator=(awaiter&&) -> awaiter& = delete;

        [[nodiscard]] auto await_ready() const noexcept -> bool
        {
            return allocation_failed_ || handle_ == nullptr || handle_.done();
        }

        auto await_suspend(handle_type continuation) noexcept
            -> std::coroutine_handle<>
        {
            if (handle_.promise().started_) std::terminate();
            handle_.promise().started_ = true;
            handle_.promise().continuation_ = continuation;
            handle_.promise().cancellation_ =
                continuation.promise().cancellation_;
            return handle_;
        }

        auto await_resume() noexcept -> task_result
        {
            if (allocation_failed_) return task_result::frame_allocation_failure;
            if (handle_ != nullptr) {
                handle_.destroy();
                handle_ = {};
            }
            return task_result::success;
        }

    private:
        auto reset() noexcept -> void
        {
            if (handle_ == nullptr) return;
            if (handle_.promise().started_ && !handle_.done()) std::terminate();
            handle_.destroy();
        }

        handle_type handle_ {};
        bool allocation_failed_ {false};
    };

    auto operator co_await() && noexcept -> awaiter
    {
        return awaiter(std::move(*this));
    }

    struct promise_type {
        template<typename... Arguments>
        explicit promise_type(event_loop& loop, Arguments&&...) noexcept
            : loop_(&loop), cancellation_(&root_.cancellation)
        {
        }

        static auto operator delete(void* pointer) noexcept -> void
        {
            eventloop_detail::coroutine_frame_access::deallocate(pointer, 0);
        }

        template<typename... Arguments>
        static auto operator new(std::size_t size, event_loop& loop,
                                 Arguments&&...) noexcept -> void*
        {
            return eventloop_detail::coroutine_frame_access::allocate(loop, size);
        }

        template<typename... Arguments>
        static auto operator delete(void* pointer, std::size_t size,
                                    event_loop&, Arguments&&...) noexcept -> void
        {
            eventloop_detail::coroutine_frame_access::deallocate(pointer, size);
        }

        [[nodiscard]] static auto get_return_object_on_allocation_failure() noexcept
            -> task
        {
            return task({}, true);
        }

        [[nodiscard]] auto get_return_object() noexcept -> task
        {
            const auto handle = handle_type::from_promise(*this);
            root_.handle = handle;
            return task(handle, false);
        }

        [[nodiscard]] static auto initial_suspend() noexcept
            -> std::suspend_always
        {
            return {};
        }

        struct final_awaiter {
            [[nodiscard]] static auto await_ready() noexcept -> bool
            {
                return false;
            }

            static auto await_suspend(handle_type handle) noexcept
                -> std::coroutine_handle<>
            {
                auto& promise = handle.promise();
                if (promise.root_.owner != nullptr) {
                    eventloop_detail::coroutine_frame_access::complete_root(
                        promise.root_);
                    return std::noop_coroutine();
                }
                const auto continuation = promise.continuation_;
                return continuation != nullptr ? continuation
                                               : std::noop_coroutine();
            }

            static auto await_resume() noexcept -> void {}
        };

        [[nodiscard]] static auto final_suspend() noexcept -> final_awaiter
        {
            return {};
        }

        static auto return_void() noexcept -> void {}
        [[noreturn]] static auto unhandled_exception() noexcept -> void
        {
            std::terminate();
        }

    private:
        friend class task;
        friend class task::awaiter;
        friend class event_loop;
        friend class task_cancellation_awaiter;
        friend class event_loop_timer_awaiter;
        template<typename Function>
        friend class event_loop_blocking_awaiter;

        event_loop* loop_;
        eventloop_detail::coroutine_root_node root_;
        eventloop_detail::coroutine_cancellation_state* cancellation_;
        std::coroutine_handle<> continuation_ {};
        bool started_ {false};
    };

private:
    friend class event_loop;

    explicit task(handle_type handle, bool allocation_failed) noexcept
        : handle_(handle), allocation_failed_(allocation_failed)
    {
    }

    auto reset() noexcept -> void
    {
        if (handle_ == nullptr) return;
        if (handle_.promise().started_ && !handle_.done()) std::terminate();
        handle_.destroy();
    }

    [[nodiscard]] auto release_for_spawn() noexcept -> handle_type
    {
        allocation_failed_ = false;
        return std::exchange(handle_, {});
    }

    handle_type handle_ {};
    bool allocation_failed_ {false};
};

class task_cancellation_awaiter {
public:
    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }

    auto await_suspend(task<void>::handle_type handle) noexcept -> bool
    {
        requested_ = handle.promise().cancellation_->requested;
        return false;
    }

    [[nodiscard]] auto await_resume() const noexcept -> bool
    {
        return requested_;
    }

private:
    bool requested_ {false};
};

[[nodiscard]] inline auto cancellation_requested() noexcept
    -> task_cancellation_awaiter
{
    return {};
}

namespace eventloop_detail {

template<typename Result>
class blocking_result_storage {
public:
    template<typename Function>
    auto invoke(Function& function) noexcept -> void
    {
        value_.emplace(std::invoke(function));
    }

    auto take() noexcept -> std::expected<Result, blocking_error>
    {
        return std::expected<Result, blocking_error>(std::move(*value_));
    }

private:
    std::optional<Result> value_;
};

template<>
class blocking_result_storage<void> {
public:
    template<typename Function>
    static auto invoke(Function& function) noexcept -> void
    {
        std::invoke(function);
    }

    static auto take() noexcept -> std::expected<void, blocking_error>
    {
        return {};
    }
};

} // namespace eventloop_detail

template<typename Function>
class event_loop_blocking_awaiter {
public:
    using function_type = Function;
    using value_type = std::invoke_result_t<function_type&>;
    using result_type = std::expected<value_type, blocking_error>;

    explicit event_loop_blocking_awaiter(event_loop& loop,
                                         function_type&& function) noexcept
        : loop_(loop), function_(std::move(function))
    {
        cancellation_.operation = this;
        cancellation_.cancel = &cancel;
    }

    event_loop_blocking_awaiter(const event_loop_blocking_awaiter&) = delete;
    auto operator=(const event_loop_blocking_awaiter&)
        -> event_loop_blocking_awaiter& = delete;

    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }

    auto await_suspend(task<void>::handle_type handle) noexcept -> bool
    {
        auto& cancellation = *handle.promise().cancellation_;
        if (cancellation.requested) {
            error_ = blocking_error::cancelled;
            return false;
        }

        const auto reservation =
            eventloop_detail::coroutine_frame_access::reserve_completion(loop_);
        if (reservation !=
            eventloop_detail::completion_reservation_result::accepted) {
            error_ = reservation ==
                             eventloop_detail::completion_reservation_result::shutting_down
                         ? blocking_error::shutting_down
                         : blocking_error::completion_capacity_exhausted;
            return false;
        }

        if (!eventloop_detail::coroutine_frame_access::attach_cancellation(
                cancellation, cancellation_)) {
            eventloop_detail::coroutine_frame_access::release_completion(loop_);
            error_ = blocking_error::cancelled;
            return false;
        }

        handle_ = handle;
        execution_task work([this]() noexcept { execute(); });
        const auto submission =
            eventloop_detail::coroutine_frame_access::submit_blocking(
                loop_, std::move(work));
        if (submission !=
            eventloop_detail::blocking_submission_result::accepted) {
            eventloop_detail::coroutine_frame_access::detach_cancellation(
                cancellation_);
            eventloop_detail::coroutine_frame_access::release_completion(loop_);
            error_ = submission ==
                             eventloop_detail::blocking_submission_result::no_worker_threads
                         ? blocking_error::no_worker_threads
                         : blocking_error::executor_queue_full;
            return false;
        }
        return true;
    }

    [[nodiscard]] auto await_resume() noexcept -> result_type
    {
        if (error_) return std::unexpected(*error_);
        return storage_.take();
    }

private:
    static auto cancel(
        eventloop_detail::coroutine_cancellation_node& cancellation) noexcept
        -> void
    {
        auto* operation = static_cast<event_loop_blocking_awaiter*>(
            cancellation.operation);
        operation->cancelled_.store(true, std::memory_order_release);
        eventloop_detail::coroutine_frame_access::detach_cancellation(
            cancellation);
    }

    auto execute() noexcept -> void
    {
        if (!cancelled_.load(std::memory_order_acquire)) {
            storage_.invoke(function_);
        }
        execution_task completion([this]() noexcept { complete(); });
        eventloop_detail::coroutine_frame_access::post_completion(
            loop_, std::move(completion));
    }

    auto complete() noexcept -> void
    {
        eventloop_detail::coroutine_frame_access::detach_cancellation(
            cancellation_);
        if (cancelled_.load(std::memory_order_acquire)) {
            error_ = blocking_error::cancelled;
        }
        const auto handle = handle_;
        handle.resume();
    }

    event_loop& loop_;
    function_type function_;
    eventloop_detail::blocking_result_storage<value_type> storage_;
    eventloop_detail::coroutine_cancellation_node cancellation_;
    task<void>::handle_type handle_ {};
    std::atomic<bool> cancelled_ {false};
    std::optional<blocking_error> error_;
};

template<typename Function>
    requires std::is_nothrow_invocable_v<std::decay_t<Function>&> &&
             std::is_nothrow_move_constructible_v<std::decay_t<Function>> &&
             std::is_nothrow_destructible_v<std::decay_t<Function>> &&
             (!std::is_reference_v<
                 std::invoke_result_t<std::decay_t<Function>&>>) &&
             (std::is_void_v<
                  std::invoke_result_t<std::decay_t<Function>&>> ||
              (std::is_nothrow_move_constructible_v<
                   std::invoke_result_t<std::decay_t<Function>&>> &&
               std::is_nothrow_destructible_v<
                   std::invoke_result_t<std::decay_t<Function>&>>))
[[nodiscard]] auto run_blocking(event_loop& loop, Function&& function) noexcept
    -> event_loop_blocking_awaiter<std::decay_t<Function>>
{
    return event_loop_blocking_awaiter<std::decay_t<Function>>(
        loop, std::forward<Function>(function));
}

class event_loop_timer_awaiter {
public:
    event_loop_timer_awaiter(event_loop& loop,
                             event_loop::clock::time_point deadline) noexcept
        : loop_(loop)
    {
        timer_.deadline = deadline;
        timer_.cancellation.operation = this;
        timer_.cancellation.cancel = &cancel;
    }

    event_loop_timer_awaiter(const event_loop_timer_awaiter&) = delete;
    auto operator=(const event_loop_timer_awaiter&)
        -> event_loop_timer_awaiter& = delete;

    [[nodiscard]] auto await_ready() const noexcept -> bool
    {
        return timer_.deadline <= event_loop::clock::now();
    }

    auto await_suspend(task<void>::handle_type handle) -> bool
    {
        auto& cancellation = *handle.promise().cancellation_;
        if (cancellation.requested) {
            result_ = timer_wait_result::cancelled;
            return false;
        }

        timer_.handle = handle;
        timer_.owner = &loop_;
        timer_.cancellation.operation = this;
        timer_.cancellation.cancel = &cancel;
        if (!eventloop_detail::coroutine_frame_access::attach_cancellation(
                cancellation, timer_.cancellation)) {
            timer_.owner = nullptr;
            result_ = timer_wait_result::cancelled;
            return false;
        }
        try {
            eventloop_detail::coroutine_frame_access::register_timer(loop_, timer_);
        } catch (...) {
            eventloop_detail::coroutine_frame_access::detach_cancellation(
                timer_.cancellation);
            timer_.owner = nullptr;
            throw;
        }
        return true;
    }

    [[nodiscard]] auto await_resume() const noexcept -> timer_wait_result
    {
        return result_;
    }

private:
    friend struct eventloop_detail::coroutine_frame_access;

    static auto cancel(
        eventloop_detail::coroutine_cancellation_node& cancellation) noexcept
        -> void
    {
        auto* awaiter = static_cast<event_loop_timer_awaiter*>(
            cancellation.operation);
        auto& timer = awaiter->timer_;
        eventloop_detail::coroutine_frame_access::cancel_timer(timer);
        awaiter->result_ = timer_wait_result::cancelled;
        const auto handle = timer.handle;
        handle.resume();
    }

    event_loop& loop_;
    eventloop_detail::coroutine_timer_node timer_;
    timer_wait_result result_ {timer_wait_result::expired};
};

[[nodiscard]] inline auto sleep_until(
    event_loop& loop, event_loop::clock::time_point deadline) noexcept
    -> event_loop_timer_awaiter
{
    return {loop, deadline};
}

[[nodiscard]] inline auto sleep_for(
    event_loop& loop, event_loop::clock::duration delay) noexcept
    -> event_loop_timer_awaiter
{
    return sleep_until(loop, event_loop::clock::now() + delay);
}

class event_loop_yield_awaiter {
public:
    explicit event_loop_yield_awaiter(event_loop& loop) noexcept : loop_(loop) {}

    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }

    auto await_suspend(std::coroutine_handle<> handle) noexcept -> bool
    {
        execution_task continuation(
            [handle]() noexcept { handle.resume(); });
        queued_ = true;
        if (loop_.post(std::move(continuation))) return true;
        queued_ = false;
        return false;
    }

    // False means the bounded post queue was full and suspension was skipped.
    [[nodiscard]] auto await_resume() const noexcept -> bool { return queued_; }

private:
    event_loop& loop_;
    bool queued_ {false};
};

[[nodiscard]] inline auto yield(event_loop& loop) noexcept
    -> event_loop_yield_awaiter
{
    return event_loop_yield_awaiter(loop);
}
