#pragma once

#include "eventloop/event_loop.h"

#include <cerrno>
#include <coroutine>
#include <cstddef>
#include <exception>
#include <expected>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>

namespace eventloop {

namespace detail { class semaphore_awaiter; }

// A fixed number of loop-local acquisitions, returned by owning permits.
// The semaphore must outlive permits and pending acquisitions, including
// queued resumptions. See docs/semaphore.md for bounds and lifetime rules.
class semaphore {
public:
    class permit;

    explicit semaphore(event_loop& loop, std::size_t capacity)
        : loop_(loop), capacity_(capacity), available_(capacity)
    {
        if (capacity == 0) throw std::invalid_argument("semaphore capacity is zero");
    }
    ~semaphore()
    {
        check_thread();
        if (available_ != capacity_ || active_waiters_ != 0) std::terminate();
    }
    semaphore(const semaphore&) = delete;
    auto operator=(const semaphore&) -> semaphore& = delete;

    [[nodiscard]] auto capacity() const noexcept -> std::size_t
    {
        check_thread();
        return capacity_;
    }
    [[nodiscard]] auto available() const noexcept -> std::size_t
    {
        check_thread();
        return available_;
    }
    // EAGAIN when every permit is held or reserved for a queued waiter.
    [[nodiscard]] auto try_acquire() noexcept -> std::expected<permit, std::error_code>;
    // ECANCELED before reservation; a queued reservation wins cancellation.
    [[nodiscard]] auto async_acquire() noexcept -> detail::semaphore_awaiter;

private:
    friend class detail::semaphore_awaiter;

    auto check_thread() const noexcept -> void
    {
        if (std::this_thread::get_id() != thread_) std::terminate();
    }
    auto release_permit() noexcept -> void;
    auto complete(detail::semaphore_awaiter& waiter, int error) noexcept -> void;

    event_loop& loop_;
    const std::thread::id thread_ {std::this_thread::get_id()};
    const std::size_t capacity_;
    std::size_t available_;
    detail::semaphore_awaiter* head_ {nullptr};
    detail::semaphore_awaiter* tail_ {nullptr};
    std::size_t active_waiters_ {0};
};

// Owns one acquisition. Move/release/destruction stay on the owning loop
// thread. Empty and moved-from permits return nothing.
class semaphore::permit {
public:
    permit() noexcept = default;
    ~permit() { release(); }
    permit(const permit&) = delete;
    auto operator=(const permit&) -> permit& = delete;
    permit(permit&& other) noexcept : owner_(std::exchange(other.owner_, nullptr))
    {
        if (owner_ != nullptr) owner_->check_thread();
    }
    auto operator=(permit&& other) noexcept -> permit&
    {
        if (other.owner_ != nullptr) other.owner_->check_thread();
        if (this != &other) {
            release();
            owner_ = std::exchange(other.owner_, nullptr);
        }
        return *this;
    }
    [[nodiscard]] explicit operator bool() const noexcept
    {
        if (owner_ != nullptr) owner_->check_thread();
        return owner_ != nullptr;
    }
    auto release() noexcept -> void
    {
        if (auto* owner = std::exchange(owner_, nullptr)) owner->release_permit();
    }

private:
    friend class semaphore;
    friend class detail::semaphore_awaiter;
    explicit permit(semaphore& owner) noexcept : owner_(&owner) {}
    semaphore* owner_ {nullptr};
};

namespace detail {

class semaphore_awaiter {
public:
    explicit semaphore_awaiter(semaphore& owner) noexcept : owner_(owner)
    {
        cancellation_.operation = this;
        cancellation_.cancel = &cancel;
    }
    ~semaphore_awaiter()
    {
        if (active_) std::terminate();
    }
    semaphore_awaiter(const semaphore_awaiter&) = delete;
    auto operator=(const semaphore_awaiter&) -> semaphore_awaiter& = delete;

    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }

    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
    {
        owner_.check_thread();
        if (handle.promise().owner_loop() != &owner_.loop_) std::terminate();
        if (ready_.handle) std::terminate();
        ready_.handle = handle;
        auto& cancellation = *handle.promise().cancellation_state();
        if (cancellation.requested) {
            error_ = ECANCELED;
            return false;
        }
        if (owner_.available_ != 0) {
            --owner_.available_;
            return false;
        }
        if (!coroutine_frame_access::attach_cancellation(cancellation, cancellation_)) {
            error_ = ECANCELED;
            return false;
        }
        active_ = true;
        ++owner_.active_waiters_;
        previous_ = owner_.tail_;
        if (previous_ != nullptr) previous_->next_ = this;
        else owner_.head_ = this;
        owner_.tail_ = this;
        return true;
    }

    [[nodiscard]] auto await_resume() noexcept -> std::expected<semaphore::permit, std::error_code>
    {
        if (std::exchange(active_, false)) --owner_.active_waiters_;
        if (error_ != 0) return std::unexpected(std::error_code(error_, std::generic_category()));
        return semaphore::permit(owner_);
    }

private:
    friend class eventloop::semaphore;

    static auto cancel(coroutine_cancellation_node& node) noexcept -> void
    {
        auto& self = *static_cast<semaphore_awaiter*>(node.operation);
        self.owner_.complete(self, ECANCELED);
    }

    semaphore& owner_;
    wakeup_node ready_;
    coroutine_cancellation_node cancellation_;
    semaphore_awaiter* previous_ {nullptr};
    semaphore_awaiter* next_ {nullptr};
    int error_ {0};
    bool active_ {false};
};

} // namespace detail

inline auto semaphore::try_acquire() noexcept -> std::expected<permit, std::error_code>
{
    check_thread();
    if (available_ == 0)
        return std::unexpected(std::error_code(EAGAIN, std::generic_category()));
    --available_;
    return permit(*this);
}

inline auto semaphore::async_acquire() noexcept -> detail::semaphore_awaiter
{
    check_thread();
    return detail::semaphore_awaiter(*this);
}

inline auto semaphore::release_permit() noexcept -> void
{
    check_thread();
    // A handed-off acquisition stays unavailable until its new owner releases
    // it. Reserving before queuing prevents newer callers from taking it.
    if (head_ != nullptr) complete(*head_, 0);
    else ++available_;
}

inline auto semaphore::complete(detail::semaphore_awaiter& waiter, int error) noexcept -> void
{
    if (waiter.previous_ != nullptr) waiter.previous_->next_ = waiter.next_;
    else head_ = waiter.next_;
    if (waiter.next_ != nullptr) waiter.next_->previous_ = waiter.previous_;
    else tail_ = waiter.previous_;
    waiter.previous_ = nullptr;
    waiter.next_ = nullptr;
    detail::coroutine_frame_access::detach_cancellation(waiter.cancellation_);
    waiter.error_ = error;
    detail::coroutine_frame_access::schedule_wakeup(loop_, waiter.ready_);
}

} // namespace eventloop
