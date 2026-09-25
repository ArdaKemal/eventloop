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
    cancelled,
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
namespace eventloop_detail { struct composition_task_access; }

// Coroutine functions returning task must take their owning event_loop as the
// first argument. Started tasks and their frames remain loop-affine. Root
// tasks should normally be transferred to event_loop::spawn().
template<>
class [[nodiscard]] task<void> {
public:
    struct promise_type;
    using handle_type = std::coroutine_handle<promise_type>;
    using result_type = task_result;

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

        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> continuation) noexcept
            -> std::coroutine_handle<>
        {
            if (handle_.promise().started_ ||
                handle_.promise().loop_ != continuation.promise().owner_loop()) {
                std::terminate();
            }
            handle_.promise().started_ = true;
            handle_.promise().continuation_ = continuation;
            handle_.promise().cancellation_ =
                continuation.promise().cancellation_state();
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
                    std::coroutine_handle<> continuation =
                        promise.completion_ != nullptr
                            ? promise.completion_(promise.completion_context_)
                            : std::noop_coroutine();
                    eventloop_detail::coroutine_frame_access::complete_root(
                        promise.root_);
                    return continuation;
                }
                if (promise.completion_ != nullptr) {
                    return promise.completion_(promise.completion_context_);
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

        [[nodiscard]] auto owner_loop() const noexcept -> event_loop* { return loop_; }
        [[nodiscard]] auto cancellation_state() const noexcept
            -> eventloop_detail::coroutine_cancellation_state*
        {
            return cancellation_;
        }

    private:
        friend class task;
        friend class task::awaiter;
        friend class event_loop;
        template<typename> friend class task_handle;
        friend struct eventloop_detail::composition_task_access;
        friend class task_cancellation_awaiter;
        friend class event_loop_timer_awaiter;
        template<typename Function>
        friend class event_loop_blocking_awaiter;
        template<eventloop_detail::file_opcode Kind>
        friend class file_io_awaiter;

        event_loop* loop_;
        eventloop_detail::coroutine_root_node root_;
        eventloop_detail::coroutine_cancellation_state* cancellation_;
        std::coroutine_handle<> continuation_ {};
        void* completion_context_ {nullptr};
        std::coroutine_handle<> (*completion_)(void*) noexcept {nullptr};
        bool started_ {false};
    };

private:
    friend class event_loop;
    template<typename> friend class task_handle;
    friend struct eventloop_detail::composition_task_access;

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

// Value tasks use the same bounded frame pool and loop-affine continuation
// rules as task<void>. The expected wrapper distinguishes a missing frame from
// a value whose own type is std::expected.
template<typename T>
class [[nodiscard]] task {
public:
    static_assert(!std::is_void_v<T> && !std::is_reference_v<T>);
    struct promise_type;
    using handle_type = std::coroutine_handle<promise_type>;
    using result_type = std::expected<T, task_result>;

    task() noexcept = default;
    ~task() { reset(); }
    task(task&& other) noexcept
        : handle_(std::exchange(other.handle_, {})),
          allocation_failed_(std::exchange(other.allocation_failed_, false)) {}
    auto operator=(task&& other) noexcept -> task&
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, {});
            allocation_failed_ = std::exchange(other.allocation_failed_, false);
        }
        return *this;
    }
    task(const task&) = delete;
    auto operator=(const task&) -> task& = delete;
    [[nodiscard]] explicit operator bool() const noexcept { return handle_ != nullptr; }
    [[nodiscard]] auto state() const noexcept -> task_state
    {
        if (allocation_failed_) return task_state::frame_allocation_failure;
        if (handle_ == nullptr || handle_.done()) return task_state::completed;
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
    [[nodiscard]] auto result() -> result_type
    {
        if (allocation_failed_ || handle_ == nullptr) {
            return std::unexpected(task_result::frame_allocation_failure);
        }
        if (!handle_.done()) throw std::logic_error("coroutine task has not completed");
        auto& value = handle_.promise().value_;
        if (!value) throw std::logic_error("coroutine task result was already taken");
        result_type result(std::move(*value));
        value.reset();
        return result;
    }

    class awaiter {
    public:
        explicit awaiter(task&& source) noexcept
            : handle_(std::exchange(source.handle_, {})),
              allocation_failed_(std::exchange(source.allocation_failed_, false)) {}
        ~awaiter() { reset(); }
        awaiter(awaiter&& other) noexcept
            : handle_(std::exchange(other.handle_, {})),
              allocation_failed_(std::exchange(other.allocation_failed_, false)) {}
        awaiter(const awaiter&) = delete;
        auto operator=(const awaiter&) -> awaiter& = delete;
        [[nodiscard]] auto await_ready() const noexcept -> bool
        {
            return allocation_failed_ || handle_ == nullptr || handle_.done();
        }
        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> continuation) noexcept
            -> std::coroutine_handle<>
        {
            auto& promise = handle_.promise();
            if (promise.started_ ||
                promise.loop_ != continuation.promise().owner_loop()) {
                std::terminate();
            }
            promise.started_ = true;
            promise.continuation_ = continuation;
            promise.cancellation_ = continuation.promise().cancellation_state();
            return handle_;
        }
        auto await_resume() -> result_type
        {
            if (allocation_failed_ || handle_ == nullptr) {
                return std::unexpected(task_result::frame_allocation_failure);
            }
            auto value = std::move(*handle_.promise().value_);
            handle_.destroy();
            handle_ = {};
            return value;
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
    auto operator co_await() && noexcept -> awaiter { return awaiter(std::move(*this)); }

    struct promise_type {
        template<typename... Arguments>
        explicit promise_type(event_loop& loop, Arguments&&...) noexcept
            : loop_(&loop), cancellation_(&root_.cancellation) {}
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
        [[nodiscard]] static auto get_return_object_on_allocation_failure() noexcept -> task
        {
            return task({}, true);
        }
        [[nodiscard]] auto get_return_object() noexcept -> task
        {
            auto handle = handle_type::from_promise(*this);
            root_.handle = handle;
            return task(handle, false);
        }
        [[nodiscard]] static auto initial_suspend() noexcept -> std::suspend_always { return {}; }
        struct final_awaiter {
            [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }
            static auto await_suspend(handle_type handle) noexcept -> std::coroutine_handle<>
            {
                auto& promise = handle.promise();
                if (promise.root_.owner != nullptr) {
                    std::coroutine_handle<> continuation =
                        promise.completion_ != nullptr
                            ? promise.completion_(promise.completion_context_)
                            : std::noop_coroutine();
                    eventloop_detail::coroutine_frame_access::complete_root(
                        promise.root_);
                    return continuation;
                }
                if (promise.completion_ != nullptr) {
                    return promise.completion_(promise.completion_context_);
                }
                return promise.continuation_ != nullptr ? promise.continuation_
                                                        : std::noop_coroutine();
            }
            static auto await_resume() noexcept -> void {}
        };
        [[nodiscard]] static auto final_suspend() noexcept -> final_awaiter { return {}; }
        template<typename Value>
        auto return_value(Value&& value) -> void
        {
            value_.emplace(std::forward<Value>(value));
        }
        [[noreturn]] static auto unhandled_exception() noexcept -> void { std::terminate(); }
        [[nodiscard]] auto owner_loop() const noexcept -> event_loop* { return loop_; }
        [[nodiscard]] auto cancellation_state() const noexcept
            -> eventloop_detail::coroutine_cancellation_state*
        {
            return cancellation_;
        }
    private:
        friend class task;
        friend class task::awaiter;
        friend class event_loop;
        template<typename> friend class task_handle;
        friend struct eventloop_detail::composition_task_access;
        friend class task_cancellation_awaiter;
        friend class event_loop_timer_awaiter;
        template<typename Function> friend class event_loop_blocking_awaiter;
        template<eventloop_detail::file_opcode Kind> friend class file_io_awaiter;
        event_loop* loop_;
        eventloop_detail::coroutine_root_node root_;
        eventloop_detail::coroutine_cancellation_state* cancellation_;
        std::coroutine_handle<> continuation_ {};
        void* completion_context_ {nullptr};
        std::coroutine_handle<> (*completion_)(void*) noexcept {nullptr};
        std::optional<T> value_;
        bool started_ {false};
    };
private:
    friend class event_loop;
    template<typename> friend class task_handle;
    friend struct eventloop_detail::composition_task_access;
    explicit task(handle_type handle, bool allocation_failed) noexcept
        : handle_(handle), allocation_failed_(allocation_failed) {}
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

// A stable, single-use owner for an observed root task. The object must stay
// alive until completion; requesting cancellation does not release that duty.
// All methods run on the owning loop thread.
template<typename T>
class task_handle {
public:
    static_assert(std::is_void_v<T> || std::is_nothrow_move_constructible_v<T>,
                  "observed task values must be nothrow movable");
    using result_type = typename task<T>::result_type;

    task_handle() noexcept = default;
    ~task_handle()
    {
        if (root_ != nullptr || waiter_ != nullptr) std::terminate();
    }
    task_handle(const task_handle&) = delete;
    auto operator=(const task_handle&) -> task_handle& = delete;
    task_handle(task_handle&&) = delete;
    auto operator=(task_handle&&) -> task_handle& = delete;

    [[nodiscard]] auto done() const noexcept -> bool { return completed_; }

    // Cooperative cancellation. Completion may be delayed by worker or
    // kernel references to the task frame.
    [[nodiscard]] auto cancel() noexcept -> bool
    {
        if (root_ == nullptr) return false;
        eventloop_detail::coroutine_frame_access::request_cancellation(
            root_->cancellation);
        return true;
    }

    [[nodiscard]] auto take_result() -> result_type
    {
        if (!completed_ || !result_) {
            throw std::logic_error("observed task result is unavailable");
        }
        auto value = std::move(*result_);
        result_.reset();
        return value;
    }

    class awaiter {
    public:
        explicit awaiter(task_handle& owner) noexcept : owner_(owner)
        {
            cancellation_.operation = this;
            cancellation_.cancel = &cancel_wait;
        }
        ~awaiter()
        {
            if (owner_.waiter_ == this) std::terminate();
        }
        awaiter(const awaiter&) = delete;
        auto operator=(const awaiter&) -> awaiter& = delete;
        awaiter(awaiter&&) = delete;
        [[nodiscard]] auto await_ready() const noexcept -> bool
        {
            return owner_.completed_;
        }
        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> continuation) noexcept
            -> bool
        {
            if (!owner_.bound_ || owner_.waiter_ != nullptr ||
                owner_.loop_ != continuation.promise().owner_loop()) {
                std::terminate();
            }
            continuation_ = continuation;
            arming_ = true;
            owner_.waiter_ = this;
            if (!eventloop_detail::coroutine_frame_access::attach_cancellation(
                    *continuation.promise().cancellation_state(), cancellation_)) {
                (void)owner_.cancel();
            }
            arming_ = false;
            return !owner_.completed_;
        }
        auto await_resume() -> result_type { return owner_.take_result(); }

    private:
        friend class task_handle;
        static auto cancel_wait(
            eventloop_detail::coroutine_cancellation_node& node) noexcept -> void
        {
            auto& self = *static_cast<awaiter*>(node.operation);
            eventloop_detail::coroutine_frame_access::detach_cancellation(node);
            (void)self.owner_.cancel();
        }
        auto complete() noexcept -> std::coroutine_handle<>
        {
            eventloop_detail::coroutine_frame_access::detach_cancellation(
                cancellation_);
            return arming_ ? std::noop_coroutine() : continuation_;
        }
        task_handle& owner_;
        eventloop_detail::coroutine_cancellation_node cancellation_ {};
        std::coroutine_handle<> continuation_ {};
        bool arming_ {false};
    };

    auto operator co_await() & noexcept -> awaiter { return awaiter(*this); }

private:
    friend class event_loop;
    static auto complete_root(void* context) noexcept
        -> std::coroutine_handle<>
    {
        auto& self = *static_cast<task_handle*>(context);
        if constexpr (std::is_void_v<T>) {
            self.result_.emplace(task_result::success);
        } else {
            auto handle = task<T>::handle_type::from_address(
                self.root_->handle.address());
            self.result_.emplace(std::move(*handle.promise().value_));
        }
        self.root_ = nullptr;
        self.completed_ = true;
        if (self.waiter_ == nullptr) return std::noop_coroutine();
        auto* waiter = std::exchange(self.waiter_, nullptr);
        return waiter->complete();
    }

    event_loop* loop_ {nullptr};
    eventloop_detail::coroutine_root_node* root_ {nullptr};
    std::optional<result_type> result_;
    awaiter* waiter_ {nullptr};
    bool bound_ {false};
    bool completed_ {false};
};

template<typename T>
auto event_loop::spawn(task<T>&& operation, task_handle<T>& observer)
    -> task_spawn_result
{
    if (operation.allocation_failed_) {
        return task_spawn_result::frame_allocation_failure;
    }
    if (operation.handle_ == nullptr || observer.bound_) {
        return task_spawn_result::invalid_task;
    }
    auto& promise = operation.handle_.promise();
    if (promise.loop_ != this || promise.started_) {
        return task_spawn_result::invalid_task;
    }
    if (!can_spawn()) return task_spawn_result::shutting_down;

    observer.loop_ = this;
    observer.root_ = &promise.root_;
    observer.bound_ = true;
    promise.completion_context_ = &observer;
    promise.completion_ = &task_handle<T>::complete_root;
    promise.started_ = true;
    auto handle = operation.release_for_spawn();
    return spawn_root(promise.root_, handle, false);
}

class task_cancellation_awaiter {
public:
    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }

    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
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

    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
    {
        if (handle.promise().owner_loop() != &loop_) std::terminate();
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
    std::coroutine_handle<> handle_ {};
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

    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }

    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) -> bool
    {
        if (handle.promise().owner_loop() != &loop_) std::terminate();
        if (timer_.deadline <= event_loop::clock::now()) return false;
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
    return sleep_until(loop, eventloop_detail::deadline_after(delay));
}

class event_loop_yield_awaiter {
public:
    explicit event_loop_yield_awaiter(event_loop& loop) noexcept : loop_(loop) {}

    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }

    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
    {
        if (handle.promise().owner_loop() != &loop_) std::terminate();
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
