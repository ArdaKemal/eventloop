#include "eventloop/event_loop.h"

#include "executor/bounded_task_queue.h"
#include "linux/epoll_loop.h"

#include <array>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace {
constexpr std::size_t max_posted_tasks_per_iteration = 64;

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

    epoll_loop poller;
    bounded_task_queue posted_tasks;
    std::unique_ptr<executor> task_executor;
    std::unordered_map<int, std::unique_ptr<notifiable>> handlers;
    std::unordered_set<int> pending_removals;
    bool dispatching {false};
};

event_loop::event_loop() : event_loop(event_loop_options {}) {}

event_loop::event_loop(event_loop_options options)
    : implementation_(std::make_unique<implementation>(checked_options(options)))
{
}

event_loop::~event_loop() = default;

auto event_loop::run() -> void
{
    std::array<ready_event, 64> events {};
    for (;;) {
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
        if (result.stop_requested) {
            return;
        }
    }
}

auto event_loop::stop() -> void
{
    implementation_->poller.request_stop();
}

auto event_loop::add(std::unique_ptr<notifiable> handler) -> void
{
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

auto event_loop::task_executor() noexcept -> executor&
{
    return *implementation_->task_executor;
}
