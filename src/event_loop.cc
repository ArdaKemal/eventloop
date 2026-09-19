#include "eventloop/event_loop.h"

#include "executor/bounded_task_queue.h"
#include "linux/epoll_loop.h"

#include <array>
#include <map>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace {
constexpr std::size_t max_posted_tasks_per_iteration = 64;
constexpr std::size_t max_timers_per_iteration = 64;

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
    return options;
}
} // namespace

class event_loop::implementation {
public:
    explicit implementation(event_loop_options options)
        : posted_tasks(options.post_capacity),
          task_executor(options.worker_count == 0
                            ? make_single_thread_executor()
                            : make_multi_thread_executor(
                                  {.worker_count = options.worker_count}))
    {}

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

    auto erase_pending() -> void
    {
        for (const int descriptor : pending_removals) {
            handlers.erase(descriptor);
        }
        pending_removals.clear();
    }

    auto arm_next_timer() -> void
    {
        if (timers.empty()) {
            poller.arm_timer(std::nullopt);
            return;
        }
        poller.arm_timer(timers.begin()->first.first - event_loop::clock::now());
    }

    [[nodiscard]] auto add_timer(event_loop::clock::time_point deadline,
                                 execution_task&& task) -> event_loop::timer_id
    {
        if (!task) {
            throw std::invalid_argument("timer task cannot be empty");
        }

        const auto id = next_timer++;
        timers.emplace(timer_key {deadline, id}, std::move(task));
        arm_next_timer();
        return id;
    }

    auto cancel_timer(event_loop::timer_id id) noexcept -> bool
    {
        for (auto timer = timers.begin(); timer != timers.end(); ++timer) {
            if (timer->first.second != id) continue;
            timers.erase(timer);
            try {
                arm_next_timer();
            } catch (...) {
                std::terminate();
            }
            return true;
        }
        return false;
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
        arm_next_timer();
    }

    auto force_shutdown() noexcept -> void
    {
        pending_removals.clear();
        handlers.clear();
    }

    [[nodiscard]] auto shutdown_complete() const noexcept -> bool
    {
        return shutting_down && handlers.empty();
    }

    using timer_key = std::pair<event_loop::clock::time_point,
                                event_loop::timer_id>;
    epoll_loop poller;
    bounded_task_queue posted_tasks;
    std::unique_ptr<executor> task_executor;
    std::unordered_map<int, std::unique_ptr<notifiable>> handlers;
    std::unordered_set<int> pending_removals;
    std::map<timer_key, execution_task> timers;
    event_loop::timer_id next_timer {1};
    bool dispatching {false};
    bool shutting_down {false};
};

event_loop::event_loop() : event_loop(event_loop_options {}) {}

event_loop::event_loop(event_loop_options options)
    : implementation_(std::make_unique<implementation>(checked_options(options)))
{
}

event_loop::~event_loop() = default;

auto event_loop::run() -> event_loop_result
{
    std::array<ready_event, 64> events {};
    for (;;) {
        if (implementation_->shutdown_complete()) {
            return event_loop_result::stopped;
        }
        const auto result = implementation_->poller.poll(events);
        implementation_->dispatching = true;

        try {
            for (std::size_t index = 0; index < result.event_count; ++index) {
                const auto event = events[index];
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
                    !implementation_->pending_removals.contains(event.descriptor)) {
                    handler->on_write();
                }
            }
        } catch (...) {
            implementation_->dispatching = false;
            implementation_->erase_pending();
            throw;
        }

        implementation_->dispatching = false;
        implementation_->erase_pending();

        if (result.wake_requested) {
            if (implementation_->drain_posted()) {
                implementation_->poller.wake();
            }
        }
        if (result.timer_requested) {
            implementation_->run_due_timers();
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
        implementation_->force_shutdown();
        implementation_->poller.wake();
        return;
    }

    implementation_->shutting_down = true;
    implementation_->dispatching = true;
    try {
        for (auto& [descriptor, handler] : implementation_->handlers) {
            if (!implementation_->pending_removals.contains(descriptor)) {
                handler->on_shutdown();
            }
        }
    } catch (...) {
        implementation_->dispatching = false;
        implementation_->erase_pending();
        throw;
    }
    implementation_->dispatching = false;
    implementation_->erase_pending();

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
    (void)implementation_->add_timer(
        clock::now() + timeout,
        execution_task([state]() noexcept { state->force_shutdown(); }));
    implementation_->poller.wake();
}

auto event_loop::add(std::unique_ptr<notifiable> handler) -> void
{
    if (implementation_->shutting_down) {
        throw std::logic_error("cannot add a handler during shutdown");
    }
    const int descriptor = handler->descriptor();
    if (implementation_->handlers.contains(descriptor)) {
        throw std::logic_error("descriptor is already registered");
    }

    implementation_->poller.add_descriptor(descriptor);
    try {
        implementation_->handlers.emplace(descriptor, std::move(handler));
    } catch (...) {
        implementation_->poller.remove_descriptor(descriptor);
        throw;
    }
}

auto event_loop::remove(int descriptor) -> void
{
    if (!implementation_->handlers.contains(descriptor) ||
        implementation_->pending_removals.contains(descriptor)) {
        return;
    }
    implementation_->poller.remove_descriptor(descriptor);
    if (implementation_->dispatching) {
        implementation_->pending_removals.insert(descriptor);
    } else {
        implementation_->handlers.erase(descriptor);
    }
}

auto event_loop::set_write_interest(int descriptor, bool enabled) -> void
{
    if (!implementation_->pending_removals.contains(descriptor)) {
        implementation_->poller.set_write_interest(descriptor, enabled);
    }
}

auto event_loop::post(execution_task&& task) noexcept -> bool
{
    if (!implementation_->posted_tasks.try_push(std::move(task))) {
        return false;
    }
    implementation_->poller.wake();
    return true;
}

auto event_loop::schedule_at(clock::time_point deadline, execution_task&& task)
    -> timer_id
{
    return implementation_->add_timer(deadline, std::move(task));
}

auto event_loop::schedule_after(clock::duration delay, execution_task&& task)
    -> timer_id
{
    return schedule_at(clock::now() + delay, std::move(task));
}

auto event_loop::cancel(timer_id timer) noexcept -> bool
{
    return implementation_->cancel_timer(timer);
}

auto event_loop::task_executor() noexcept -> executor&
{
    return *implementation_->task_executor;
}
