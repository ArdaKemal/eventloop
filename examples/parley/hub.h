#pragma once

// Online realtime connections (WebSocket or server-sent events) and fan-out.
// Each connection has a bounded queue of shared, already encoded JSON events
// and a writer coroutine that drains it. A connection whose queue is full is
// closed rather than blocking the sender; its client reconnects and reloads.

#include "store.h"

#include "eventloop/event_loop.h"
#include "eventloop/wakeup.h"

#include <cstddef>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace parley {

inline constexpr std::size_t max_clients = 4096;
inline constexpr std::size_t max_clients_per_user = 16;
inline constexpr std::size_t max_client_queue = 512;

using payload = std::shared_ptr<const std::string>;

struct client {
    client(eventloop::event_loop& loop, user_id who) : user(who), wake(loop) {}

    user_id user;
    std::deque<payload> queue;
    eventloop::wakeup wake;
    bool closing {false};
};

class hub {
public:
    explicit hub(store& data) : data_(data) {}

    // False when the server or this user is at its connection limit.
    [[nodiscard]] auto attach(client& connection) -> bool;
    auto detach(client& connection) -> void;
    [[nodiscard]] auto online(user_id who) const -> bool { return clients_.contains(who); }

    auto send(client& connection, payload event) -> void;
    auto send_user(user_id who, const payload& event) -> void;
    auto send_members(const conversation& where, const payload& event, user_id except = 0) -> void;
    auto send_everyone(const payload& event) -> void;
    // Keeps idle streams alive through proxies and detects dead SSE peers.
    auto heartbeat() -> void;

private:
    auto close(client& connection) -> void;

    store& data_;
    std::unordered_map<user_id, std::vector<client*>> clients_;
    std::size_t count_ {0};
};

[[nodiscard]] auto make_payload(std::string text) -> payload;

} // namespace parley
