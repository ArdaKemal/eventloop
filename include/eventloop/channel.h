#pragma once

#include "eventloop/event_loop.h"

#include <cerrno>
#include <coroutine>
#include <cstddef>
#include <exception>
#include <expected>
#include <optional>
#include <span>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <type_traits>
#include <utility>

namespace eventloop {

namespace detail {
template<typename T, bool Sending> class channel_awaiter;
}

// Loop-local FIFO with caller-owned, initially disengaged slots. The storage
// is exclusively borrowed until destruction. T need not be default constructible
// or assignable. Channel and storage must outlive pending operations, including
// queued resumptions. See docs/channel.md for transfer, close, and lifetime rules.
template<typename T>
class channel {
    static_assert(std::is_nothrow_move_constructible_v<T> &&
                  std::is_nothrow_destructible_v<T>,
                  "channel values must be nothrow movable and destructible");
    static_assert(alignof(T) <= alignof(std::max_align_t),
                  "channel values must fit coroutine-frame alignment");

    struct wait_queue;

    struct waiter {
        explicit waiter(channel& owner) noexcept : owner_(owner)
        {
            cancellation_.operation = this;
            cancellation_.cancel = &cancel;
        }
        ~waiter()
        {
            if (active_) std::terminate();
        }
        waiter(const waiter&) = delete;
        auto operator=(const waiter&) -> waiter& = delete;

        static auto cancel(detail::coroutine_cancellation_node& node) noexcept -> void
        {
            auto& self = *static_cast<waiter*>(node.operation);
            self.owner_.complete(self, ECANCELED);
        }

        channel& owner_;
        std::optional<T> value_;
        detail::wakeup_node ready_;
        detail::coroutine_cancellation_node cancellation_;
        wait_queue* queue_ {nullptr};
        waiter* previous_ {nullptr};
        waiter* next_ {nullptr};
        int error_ {0};
        bool active_ {false};
    };

    struct wait_queue {
        auto push(waiter& item) noexcept -> void
        {
            item.queue_ = this;
            item.previous_ = tail;
            if (tail != nullptr) tail->next_ = &item;
            else head = &item;
            tail = &item;
        }

        auto remove(waiter& item) noexcept -> void
        {
            if (item.previous_ != nullptr) item.previous_->next_ = item.next_;
            else head = item.next_;
            if (item.next_ != nullptr) item.next_->previous_ = item.previous_;
            else tail = item.previous_;
            item.queue_ = nullptr;
            item.previous_ = nullptr;
            item.next_ = nullptr;
        }

        waiter* head {nullptr};
        waiter* tail {nullptr};
    };

public:
    explicit channel(event_loop& loop, std::span<std::optional<T>> storage)
        : loop_(loop), storage_(storage)
    {
        if (storage.empty()) throw std::invalid_argument("channel storage is empty");
        for (const auto& slot : storage) {
            if (slot) throw std::invalid_argument("channel storage is occupied");
        }
    }
    ~channel()
    {
        check_thread();
        if (active_waiters_ != 0) std::terminate();
        for (auto& slot : storage_) slot.reset();
    }
    channel(const channel&) = delete;
    auto operator=(const channel&) -> channel& = delete;

    [[nodiscard]] auto capacity() const noexcept -> std::size_t
    {
        check_thread();
        return storage_.size();
    }
    [[nodiscard]] auto size() const noexcept -> std::size_t
    {
        check_thread();
        return size_;
    }

    // On EAGAIN (full) or EPIPE (closed), value is not moved from.
    [[nodiscard]] auto try_send(T&& value) noexcept -> std::expected<void, std::error_code>
    {
        check_thread();
        if (closed_) return std::unexpected(error(EPIPE));
        if (receivers_.head != nullptr) {
            auto& receiver = *receivers_.head;
            receiver.value_.emplace(std::move(value));
            complete(receiver, 0);
        } else {
            if (size_ == storage_.size()) return std::unexpected(error(EAGAIN));
            push(std::move(value));
        }
        return {};
    }

    [[nodiscard]] auto try_receive() noexcept -> std::expected<T, std::error_code>
    {
        check_thread();
        if (size_ == 0) return std::unexpected(error(closed_ ? EPIPE : EAGAIN));
        std::expected<T, std::error_code> result(std::in_place, std::move(*storage_[head_]));
        storage_[head_].reset();
        head_ = next(head_);
        --size_;
        // Reserve the freed slot for the oldest sender before returning.
        if (senders_.head != nullptr) {
            auto& sender = *senders_.head;
            push(std::move(*sender.value_));
            complete(sender, 0);
        }
        return result;
    }

    // Owns value immediately, including on failure or cancellation. Waits for
    // capacity; EPIPE after close, ECANCELED if cancelled before transfer.
    [[nodiscard]] auto async_send(T value) noexcept -> detail::channel_awaiter<T, true>;
    // Waits for a value; EPIPE when closed and drained, ECANCELED before transfer.
    [[nodiscard]] auto async_receive() noexcept -> detail::channel_awaiter<T, false>;

    // Rejects uncommitted sends; buffered values remain available to receivers.
    auto close() noexcept -> void
    {
        check_thread();
        closed_ = true;
        while (senders_.head != nullptr) complete(*senders_.head, EPIPE);
        while (receivers_.head != nullptr) complete(*receivers_.head, EPIPE);
    }

private:
    template<typename, bool> friend class detail::channel_awaiter;

    [[nodiscard]] static auto error(int value) noexcept -> std::error_code
    {
        return {value, std::generic_category()};
    }
    auto check_thread() const noexcept -> void
    {
        if (std::this_thread::get_id() != thread_) std::terminate();
    }
    [[nodiscard]] auto next(std::size_t index) const noexcept -> std::size_t
    {
        return index + 1 == storage_.size() ? 0 : index + 1;
    }
    auto push(T&& value) noexcept -> void
    {
        storage_[tail_].emplace(std::move(value));
        tail_ = next(tail_);
        ++size_;
    }
    auto complete(waiter& item, int result) noexcept -> void
    {
        item.queue_->remove(item);
        detail::coroutine_frame_access::detach_cancellation(item.cancellation_);
        item.error_ = result;
        detail::coroutine_frame_access::schedule_wakeup(loop_, item.ready_);
    }

    event_loop& loop_;
    std::span<std::optional<T>> storage_;
    const std::thread::id thread_ {std::this_thread::get_id()};
    wait_queue senders_, receivers_;
    std::size_t head_ {0}, tail_ {0}, size_ {0};
    std::size_t active_waiters_ {0};
    bool closed_ {false};
};

namespace detail {

template<typename T, bool Sending>
class channel_awaiter : private channel<T>::waiter {
    using base = typename channel<T>::waiter;

public:
    explicit channel_awaiter(channel<T>& owner) noexcept requires (!Sending)
        : base(owner) {}
    channel_awaiter(channel<T>& owner, T&& value) noexcept requires Sending
        : base(owner)
    {
        this->value_.emplace(std::move(value));
    }

    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }

    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
    {
        auto& owner = this->owner_;
        owner.check_thread();
        if (handle.promise().owner_loop() != &owner.loop_) std::terminate();
        auto& cancellation = *handle.promise().cancellation_state();
        if (cancellation.requested) {
            this->error_ = ECANCELED;
            return false;
        }
        if constexpr (Sending) {
            auto result = owner.try_send(std::move(*this->value_));
            if (result) return false;
            this->error_ = result.error().value();
        } else {
            auto result = owner.try_receive();
            if (result) {
                this->value_.emplace(std::move(*result));
                return false;
            }
            this->error_ = result.error().value();
        }
        if (this->error_ != EAGAIN) return false;
        if (!coroutine_frame_access::attach_cancellation(cancellation, this->cancellation_)) {
            this->error_ = ECANCELED;
            return false;
        }
        this->error_ = 0;
        this->ready_.handle = handle;
        this->active_ = true;
        ++owner.active_waiters_;
        if constexpr (Sending) owner.senders_.push(*this);
        else owner.receivers_.push(*this);
        return true;
    }

    [[nodiscard]] auto await_resume() noexcept
        -> std::expected<std::conditional_t<Sending, void, T>, std::error_code>
    {
        if (std::exchange(this->active_, false)) --this->owner_.active_waiters_;
        if (this->error_ != 0) return std::unexpected(channel<T>::error(this->error_));
        if constexpr (Sending) return {};
        else return std::expected<T, std::error_code>(std::in_place, std::move(*this->value_));
    }
};

} // namespace detail

template<typename T>
auto channel<T>::async_send(T value) noexcept -> detail::channel_awaiter<T, true>
{
    check_thread();
    return {*this, std::move(value)};
}

template<typename T>
auto channel<T>::async_receive() noexcept -> detail::channel_awaiter<T, false>
{
    check_thread();
    return detail::channel_awaiter<T, false>(*this);
}

} // namespace eventloop
