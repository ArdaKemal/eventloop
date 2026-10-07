#include "hub.h"

#include <algorithm>

namespace parley {

auto make_payload(std::string text) -> payload
{
    return std::make_shared<const std::string>(std::move(text));
}

namespace {

auto presence(const store& data, const user& who, bool online) -> payload
{
    std::string text;
    json_writer out(text);
    out.begin_object().field("t", "presence").key("user");
    data.write_user(out, who, online);
    out.end_object();
    return make_payload(std::move(text));
}

} // namespace

auto hub::attach(client& connection) -> bool
{
    if (count_ >= max_clients) return false;
    auto& list = clients_[connection.user];
    if (list.size() >= max_clients_per_user) return false;
    list.push_back(&connection);
    ++count_;
    if (list.size() == 1)
        if (auto* who = data_.find_user(connection.user)) send_everyone(presence(data_, *who, true));
    return true;
}

auto hub::detach(client& connection) -> void
{
    const auto found = clients_.find(connection.user);
    if (found == clients_.end()) return;
    auto& list = found->second;
    const auto position = std::ranges::find(list, &connection);
    if (position == list.end()) return;
    list.erase(position);
    --count_;
    if (!list.empty()) return;
    clients_.erase(found);
    if (auto* who = data_.find_user(connection.user)) {
        data_.record_last_seen(*who, now_ms());
        send_everyone(presence(data_, *who, false));
    }
}

auto hub::close(client& connection) -> void
{
    connection.closing = true;
    connection.queue.clear();
    connection.wake.notify();
}

auto hub::send(client& connection, payload event) -> void
{
    if (connection.closing) return;
    if (connection.queue.size() >= max_client_queue) {
        close(connection);
        return;
    }
    connection.queue.push_back(std::move(event));
    connection.wake.notify();
}

auto hub::send_user(user_id who, const payload& event) -> void
{
    const auto found = clients_.find(who);
    if (found == clients_.end()) return;
    for (auto* connection : found->second) send(*connection, event);
}

auto hub::send_members(const conversation& where, const payload& event, user_id except) -> void
{
    for (const auto& entry : where.members)
        if (entry.user != except) send_user(entry.user, event);
}

auto hub::send_everyone(const payload& event) -> void
{
    for (auto& [who, list] : clients_)
        for (auto* connection : list) send(*connection, event);
}

auto hub::heartbeat() -> void
{
    static const auto ping = make_payload(R"({"t":"ping"})");
    send_everyone(ping);
}

} // namespace parley
