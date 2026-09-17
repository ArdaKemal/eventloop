#include "eventloop/event_loop.h"

#include "linux/epoll_loop.h"

#include <array>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

class event_loop::implementation {
public:
    epoll_loop poller;
    std::unordered_map<int, std::unique_ptr<notifiable>> handlers;
    std::unordered_set<int> pending_removals;
    bool dispatching {false};

    auto erase_pending() -> void
    {
        for (const int descriptor : pending_removals) {
            handlers.erase(descriptor);
        }
        pending_removals.clear();
    }
};

event_loop::event_loop() : implementation_(std::make_unique<implementation>()) {}
event_loop::~event_loop() = default;

auto event_loop::run() -> void
{
    std::array<ready_event, 64> events {};
    for (;;) {
        const auto result = implementation_->poller.poll(events);
        implementation_->dispatching = true;

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

        implementation_->dispatching = false;
        implementation_->erase_pending();
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
