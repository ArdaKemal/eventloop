#pragma once

#include "eventloop/task.h"

#include <array>
#include <chrono>
#include <coroutine>
#include <cstddef>
#include <expected>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>

namespace eventloop {

namespace detail {

struct composition_task_access {
    template<typename T>
    static auto loop(const task<T>& operation) noexcept -> event_loop*
    {
        return operation.handle_ ? operation.handle_.promise().loop_ : nullptr;
    }

    template<typename T>
    static auto started(const task<T>& operation) noexcept -> bool
    {
        return operation.handle_ && operation.handle_.promise().started_;
    }

    template<typename T>
    static auto done(const task<T>& operation) noexcept -> bool
    {
        return !operation.handle_ || operation.handle_.done();
    }

    template<typename T>
    static auto start(task<T>& operation,
                      coroutine_cancellation_state& cancellation,
                      void* context,
                      std::coroutine_handle<> (*complete)(void*) noexcept) -> void
    {
        if (!operation.handle_) return;
        auto& promise = operation.handle_.promise();
        promise.cancellation_ = &cancellation;
        promise.completion_context_ = context;
        promise.completion_ = complete;
        promise.started_ = true;
        operation.handle_.resume();
    }

    template<typename T>
    static auto result(task<T>& operation) -> typename task<T>::result_type
    {
        return operation.result();
    }

    static auto request_cancel(coroutine_cancellation_state& state) noexcept -> void
    {
        state.requested = true;
        while (state.head != nullptr) {
            auto* node = state.head;
            node->cancel(*node);
        }
    }
};

template<typename T> using composition_result_t = typename task<T>::result_type;

template<typename T>
[[nodiscard]] auto cancelled_result() -> composition_result_t<T>
{
    if constexpr (std::is_void_v<T>) return task_result::cancelled;
    else return std::unexpected(task_result::cancelled);
}

} // namespace detail

template<typename... T>
struct race_winner {
    std::size_t index;
    std::variant<detail::composition_result_t<T>...> result;
};

namespace detail {

// Fixed-arity composition. Every branch owns one task and an independent
// cancellation state. The parent's cancellation node fans out to all branches.
// A completed branch transfers to the parent only after every branch has
// retired, so await_resume may safely destroy all child frames.
template<bool FirstWins, typename... T>
class task_composition_awaiter {
    static_assert(sizeof...(T) != 0);
    static constexpr std::size_t count = sizeof...(T);

public:
    explicit task_composition_awaiter(task<T>&&... operations)
        : operations_(std::move(operations)...)
    {
        parent_node_.operation = this;
        parent_node_.cancel = &cancel_parent;
    }
    task_composition_awaiter(const task_composition_awaiter&) = delete;
    auto operator=(const task_composition_awaiter&) -> task_composition_awaiter& = delete;
    task_composition_awaiter(task_composition_awaiter&&) = delete;
    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }

    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> parent) -> bool
    {
        parent_ = parent;
        auto& promise = parent.promise();
        validate(promise.owner_loop(), std::index_sequence_for<T...> {});
        if (!detail::coroutine_frame_access::attach_cancellation(
                *promise.cancellation_state(), parent_node_)) {
            parent_cancelled_ = true;
            return false;
        }
        driving_ = true;
        start_all(std::index_sequence_for<T...> {});
        driving_ = false;
        if (completed_ == count) {
            detach_parent();
            return false;
        }
        return true;
    }

    auto await_resume()
    {
        if constexpr (FirstWins) {
            using winner_type = race_winner<T...>;
            if (parent_cancelled_ && winner_ == count) {
                return std::expected<winner_type, task_result>(
                    std::unexpected(task_result::cancelled));
            }
            return std::expected<winner_type, task_result>(
                make_winner());
        } else {
            return take_all(std::index_sequence_for<T...> {});
        }
    }

private:
    template<std::size_t... I>
    auto validate(event_loop* loop, std::index_sequence<I...>) -> void
    {
        auto check = [loop](auto& operation) {
            if (detail::composition_task_access::started(operation)) {
                throw std::logic_error("composition operand already started");
            }
            auto* child_loop = detail::composition_task_access::loop(operation);
            if (child_loop != nullptr && child_loop != loop) {
                throw std::logic_error("composition operand belongs to another event loop");
            }
        };
        (check(std::get<I>(operations_)), ...);
    }

    template<std::size_t... I>
    auto start_all(std::index_sequence<I...>) -> void
    {
        (start_one<I>(), ...);
    }

    template<std::size_t I>
    auto start_one() -> void
    {
        auto& operation = std::get<I>(operations_);
        if (detail::composition_task_access::done(operation)) {
            finish(I);
            return;
        }
        detail::composition_task_access::start(
            operation, branches_[I], this, &complete_branch<I>);
    }

    template<std::size_t I>
    static auto complete_branch(void* context) noexcept -> std::coroutine_handle<>
    {
        return static_cast<task_composition_awaiter*>(context)->finish(I);
    }

    auto finish(std::size_t index) noexcept -> std::coroutine_handle<>
    {
        if (finished_[index]) std::terminate();
        finished_[index] = true;
        ++completed_;
        if constexpr (FirstWins) {
            if (winner_ == count && !parent_cancelled_) {
                winner_ = index;
                const bool was_driving = driving_;
                driving_ = true;
                for (std::size_t i = 0; i < count; ++i) {
                    if (i != index && !finished_[i]) {
                        detail::composition_task_access::request_cancel(branches_[i]);
                    }
                }
                driving_ = was_driving;
            }
        }
        if (completed_ == count && !driving_) {
            detach_parent();
            return parent_;
        }
        return std::noop_coroutine();
    }

    static auto cancel_parent(detail::coroutine_cancellation_node& node)
        noexcept -> void
    {
        auto& self = *static_cast<task_composition_awaiter*>(node.operation);
        self.detach_parent();
        self.parent_cancelled_ = true;
        self.driving_ = true;
        for (std::size_t i = 0; i < count; ++i) {
            if (!self.finished_[i]) {
                detail::composition_task_access::request_cancel(
                    self.branches_[i]);
            }
        }
        self.driving_ = false;
        if (self.completed_ == count) {
            self.detach_parent();
            const auto parent = self.parent_;
            parent.resume();
        }
    }

    auto detach_parent() noexcept -> void
    {
        detail::coroutine_frame_access::detach_cancellation(parent_node_);
    }

    template<std::size_t... I>
    auto take_all(std::index_sequence<I...>)
    {
        return std::tuple<detail::composition_result_t<T>...> {
            take_one<I>()...
        };
    }

    template<std::size_t I>
    auto take_one() -> detail::composition_result_t<std::tuple_element_t<I, std::tuple<T...>>>
    {
        using value_type = std::tuple_element_t<I, std::tuple<T...>>;
        if (!finished_[I]) return detail::cancelled_result<value_type>();
        return detail::composition_task_access::result(
            std::get<I>(operations_));
    }

    template<std::size_t I = 0>
    auto make_winner() -> race_winner<T...>
    {
        if constexpr (I == count) {
            std::terminate();
        } else {
            if (winner_ == I) {
                return {I, std::variant<detail::composition_result_t<T>...>(
                    std::in_place_index<I>, take_one<I>())};
            }
            return make_winner<I + 1>();
        }
    }

    std::tuple<task<T>...> operations_;
    std::array<detail::coroutine_cancellation_state, count> branches_ {};
    std::array<bool, count> finished_ {};
    detail::coroutine_cancellation_node parent_node_ {};
    std::coroutine_handle<> parent_ {};
    std::size_t completed_ {0};
    std::size_t winner_ {count};
    bool driving_ {false};
    bool parent_cancelled_ {false};
};

} // namespace detail

template<typename... T>
[[nodiscard]] auto when_all(task<T>&&... operations)
{
    return detail::task_composition_awaiter<false, T...>(
        std::move(operations)...);
}

template<typename... T>
[[nodiscard]] auto race(task<T>&&... operations)
{
    return detail::task_composition_awaiter<true, T...>(
        std::move(operations)...);
}

template<typename T>
struct timeout_result {
    enum class outcome { completed, timed_out, cancelled } state;
    std::optional<detail::composition_result_t<T>> result;
};

namespace detail {
// Reports whether the awaiting task's cancellation was already requested.
struct cancellation_requested_awaiter {
    bool requested {false};
    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }
    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
    {
        requested = handle.promise().cancellation_state()->requested;
        return false;
    }
    [[nodiscard]] auto await_resume() const noexcept -> bool { return requested; }
};

inline auto timeout_timer(event_loop& loop, event_loop::clock::duration duration)
    -> task<void>
{
    // An operation that completed synchronously has already cancelled this
    // branch; skip reading the clock for a deadline nobody waits on.
    if (co_await cancellation_requested_awaiter {}) co_return;
    (void)co_await sleep_for(loop, duration);
}
} // namespace detail

template<typename T>
[[nodiscard]] auto with_timeout(event_loop& loop, task<T> operation,
                                event_loop::clock::duration duration)
    -> task<timeout_result<T>>
{
    if (duration <= event_loop::clock::duration::zero()) {
        const auto* child_loop = detail::composition_task_access::loop(operation);
        if (detail::composition_task_access::started(operation) ||
            (child_loop != nullptr && child_loop != &loop)) {
            throw std::logic_error("timeout operand is not an unstarted task on this loop");
        }
        co_return timeout_result<T> {timeout_result<T>::outcome::timed_out, {}};
    }
    auto winner = co_await race(std::move(operation),
                                detail::timeout_timer(loop, duration));
    if (!winner) co_return timeout_result<T> {timeout_result<T>::outcome::cancelled, {}};
    if (winner->index == 1) {
        co_return timeout_result<T> {timeout_result<T>::outcome::timed_out, {}};
    }
    co_return timeout_result<T> {
        timeout_result<T>::outcome::completed,
        std::get<0>(std::move(winner->result))
    };
}

} // namespace eventloop
