#include "server.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <system_error>

namespace skirmish {
namespace {

using eventloop::event_loop;
using eventloop::flatten_result;
using eventloop::sleep_for;
using eventloop::sleep_until;
using eventloop::task;
using eventloop::task_handle;
using eventloop::task_spawn_result;
using eventloop::timer_wait_result;
using eventloop::http::make_error_code;
using eventloop::http::webtransport_errc;
using eventloop::http::webtransport_session;
using eventloop::http::webtransport_stream;
using eventloop::quic_stream_direction;

// Coroutines take the event loop first: the frame pool is selected by it.
using clock_type = event_loop::clock;
using namespace std::chrono_literals;

constexpr std::array<std::string_view, 1> kProtocols {"skirmish/1"};
constexpr std::size_t kDatagramBuffer = 1500;
constexpr std::size_t kEventQueueLimit = 256;
constexpr std::size_t kPongQueueLimit = 8;
constexpr auto kHelloTimeout = 5s;
constexpr auto kChatInterval = 500ms;
constexpr auto kStatsPeriod = 5s;
constexpr auto kTickPeriod = std::chrono::microseconds(16667);  // 60 Hz
// Replaced by a newer death before its killcam finished (respawn uses proto::kResetKillcamRespawn).
constexpr std::uint32_t kResetKillcamReplaced = 0x13;
// Killcam frames play at 60 Hz. Paced sends carry 6 frames (100 ms of playback) per batch.
constexpr std::size_t kKillcamHeaderSize = 5;
constexpr std::size_t kKillcamBatchFrames = 6;
constexpr auto kKillcamBatchPeriod = std::chrono::duration<double, std::milli>(100.0);

// Writes every byte, retrying partial writes; fin ends the stream after them.
auto write_all([[maybe_unused]] event_loop& loop, webtransport_stream& stream,
               std::span<const std::byte> bytes, bool fin) -> task<std::expected<void, std::error_code>>
{
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        auto sent = flatten_result(co_await stream.async_write(bytes.subspan(offset), false));
        if (!sent) co_return std::unexpected(sent.error());
        offset += *sent;
    }
    if (fin) {
        auto closed = flatten_result(co_await stream.async_write({}, true));
        if (!closed) co_return std::unexpected(closed.error());
    }
    co_return std::expected<void, std::error_code> {};
}

// Fills buffer exactly; a FIN before that is an error.
auto read_exact(event_loop& loop, webtransport_stream& stream, std::span<std::byte> buffer)
    -> task<std::expected<void, std::error_code>>
{
    (void)loop;
    std::size_t got = 0;
    while (got < buffer.size()) {
        auto count = flatten_result(co_await stream.async_read(buffer.subspan(got)));
        if (!count) co_return std::unexpected(count.error());
        if (*count == 0) co_return std::unexpected(std::make_error_code(std::errc::connection_reset));
        got += *count;
    }
    co_return std::expected<void, std::error_code> {};
}

// Reads until FIN. A stream longer than buffer fails with capacity_exceeded.
auto read_until_fin(event_loop& loop, webtransport_stream& stream, std::span<std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
    (void)loop;
    std::size_t size = 0;
    for (;;) {
        if (size == buffer.size()) {
            co_return std::unexpected(make_error_code(webtransport_errc::capacity_exceeded));
        }
        auto count = flatten_result(co_await stream.async_read(buffer.subspan(size)));
        if (!count) co_return std::unexpected(count.error());
        if (*count == 0) co_return size;
        size += *count;
    }
}

auto to_text(std::span<const std::byte> bytes) -> std::string_view
{
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

auto hello_watchdog(event_loop& loop, game_server& game, client& c) -> task<void>
{
    if (co_await sleep_for(loop, kHelloTimeout) == timer_wait_result::cancelled) co_return;
    if (!c.joined) game.request_close(c, proto::kCloseProtocol, "no HELLO");
}

auto monitor_session(event_loop& loop, game_server& game, client& c, webtransport_session& session)
    -> task<void>
{
    (void)loop;
    // The only task that closes the session, so the close code is set in one place.
    for (;;) {
        if (!(co_await c.monitor_wake.async_wait())) co_return;
        if (c.closing) co_return;
        if (c.close_requested) break;
    }
    game.note_close(c.close_code);
    (void)co_await session.async_close(c.close_code, c.close_reason);
}

auto control_reader(event_loop& loop, game_server& game, client& c, webtransport_stream& control)
    -> task<void>
{
    std::array<std::byte, 2> header {};
    std::vector<std::byte> body;
    for (;;) {
        if (!flatten_result(co_await read_exact(loop, control, header))) break;
        const auto length = std::to_integer<std::size_t>(header[0]) |
                            (std::to_integer<std::size_t>(header[1]) << 8);
        if (length == 0 || length > proto::kMaxControlPayload) {
            game.request_close(c, proto::kCloseProtocol, "protocol error");
            break;
        }
        body.resize(length);
        if (!flatten_result(co_await read_exact(loop, control, body))) break;
        proto::byte_reader r(body);
        const auto type = r.u8();
        if (c.joined || type != proto::kHello) {
            game.request_close(c, proto::kCloseProtocol, "protocol error");
            break;
        }
        const auto name_length = r.u8();
        const auto name = r.bytes(name_length);
        if (!r.done()) {
            game.request_close(c, proto::kCloseProtocol, "protocol error");
            break;
        }
        if (name_length == 0 || name_length > proto::kMaxName || !proto::valid_utf8(name)) {
            game.request_close(c, proto::kCloseBadName, "invalid name");
            break;
        }
        game.join_player(c, to_text(name));
    }
    // FIN or a failed read: the client is leaving.
    game.request_close(c, 0, "");
}

auto event_writer(event_loop& loop, game_server& game, client& c, webtransport_stream& control)
    -> task<void>
{
    for (;;) {
        if (c.closing) co_return;
        if (c.events.empty()) {
            if (!(co_await c.event_wake.async_wait())) co_return;
            continue;
        }
        auto message = std::move(c.events.front());
        c.events.pop_front();
        if (!flatten_result(co_await write_all(loop, control, message, false))) {
            game.request_close(c, 0, "");
            co_return;
        }
    }
}

auto datagram_reader(event_loop&, game_server& game, client& c, webtransport_session& session)
    -> task<void>
{
    std::vector<std::byte> buffer(kDatagramBuffer);
    for (;;) {
        auto size = flatten_result(co_await session.async_receive_datagram(buffer));
        if (!size) break;
        game.on_datagram(c, std::span<const std::byte>(buffer).first(*size));
    }
    game.request_close(c, 0, "");
}

auto datagram_writer(event_loop&, game_server& game, client& c, webtransport_session& session)
    -> task<void>
{
    for (;;) {
        if (c.closing) co_return;
        if (c.pongs.empty() && !c.snapshot_due) {
            if (!(co_await c.datagram_wake.async_wait())) co_return;
            continue;
        }
        while (!c.pongs.empty()) {
            const auto pong = c.pongs.front();
            c.pongs.pop_front();
            if (flatten_result(co_await session.async_send_datagram(pong))) ++game.stats().pongs;
        }
        if (!c.snapshot_due) continue;
        c.snapshot_due = false;
        if (!c.joined) continue;
        game.world().encode_snapshot(c.id, session.max_datagram_size(), c.snapshot);
        if (flatten_result(co_await session.async_send_datagram(c.snapshot))) {
            ++game.stats().snapshots;
        } else {
            ++game.stats().snapshot_failures;
        }
    }
}

// Size of the killcam frame at offset: a u16 length, then that many bytes.
// A truncated tail is returned whole rather than read past the payload.
auto killcam_frame_size(std::span<const std::byte> payload, std::size_t offset) -> std::size_t
{
    const auto remaining = payload.size() - offset;
    if (remaining < 2) return remaining;
    const auto length = std::to_integer<std::size_t>(payload[offset]) |
                        (std::to_integer<std::size_t>(payload[offset + 1]) << 8);
    return std::min(remaining, 2 + length);
}

// Writes a killcam paced at the server's killcam speed. The header goes first,
// then batches on a fixed schedule measured from the start, so pacing never
// drifts, then FIN. A superseded or closing session ends the write with
// operation_canceled, which the caller does not count.
auto send_killcam(event_loop& loop, game_server& game, client& c, webtransport_stream& stream,
                  std::span<const std::byte> payload) -> task<std::expected<void, std::error_code>>
{
    const double speed = game.killcam_speed();
    if (speed == 0) co_return flatten_result(co_await write_all(loop, stream, payload, true));

    auto written = flatten_result(co_await write_all(loop, stream, payload.first(kKillcamHeaderSize), false));
    if (!written) co_return written;
    const auto period = std::chrono::duration_cast<clock_type::duration>(kKillcamBatchPeriod / speed);
    auto deadline = clock_type::now();
    std::size_t offset = kKillcamHeaderSize;
    while (offset < payload.size()) {
        std::size_t end = offset;
        for (std::size_t n = 0; n < kKillcamBatchFrames && end < payload.size(); ++n) {
            end += killcam_frame_size(payload, end);
        }
        written = flatten_result(co_await write_all(loop, stream, payload.subspan(offset, end - offset), false));
        if (!written) co_return written;
        offset = end;
        // Every batch, including the last, is followed by its period, so the
        // stream lasts frames / 60 / speed before FIN.
        deadline += period;
        if (co_await sleep_until(loop, deadline) == timer_wait_result::cancelled) {
            co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        }
        if (c.closing || c.killcam_stream != &stream) {
            co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        }
    }
    co_return flatten_result(co_await write_all(loop, stream, {}, true));
}

// Clears the client's killcam_stream pointer when the writer leaves the
// stream, including when its coroutine is cancelled. The pointer refers to a
// coroutine local, so it must not outlive the stream.
struct killcam_stream_guard {
    client& c;
    webtransport_stream* stream;
    ~killcam_stream_guard()
    {
        if (c.killcam_stream == stream) c.killcam_stream = nullptr;
    }
};

auto killcam_writer(event_loop& loop, game_server& game, client& c, webtransport_session& session)
    -> task<void>
{
    for (;;) {
        if (c.closing) co_return;
        if (c.killcam_payload.empty()) {
            if (!(co_await c.killcam_wake.async_wait())) co_return;
            continue;
        }
        std::vector<std::byte> payload;
        payload.swap(c.killcam_payload);
        const auto epoch = c.respawn_epoch;
        auto opened = flatten_result(co_await session.async_open_stream(quic_stream_direction::unidirectional));
        if (!opened) continue;
        webtransport_stream stream = std::move(*opened);
        ++game.stats().killcams_started;
        if (epoch != c.respawn_epoch) {
            // Respawned while the stream was opening.
            (void)stream.reset(proto::kResetKillcamRespawn);
            ++game.stats().killcams_reset;
            continue;
        }
        c.killcam_stream = &stream;
        const killcam_stream_guard guard {c, &stream};
        // Only a stream the peer stopped counts as cancelled here. A reset by
        // respawn or replacement was counted where it happened.
        auto written = flatten_result(co_await send_killcam(loop, game, c, stream, payload));
        if (written) {
            ++game.stats().killcams_completed;
        } else if (written.error() == make_error_code(webtransport_errc::stream_reset)) {
            ++game.stats().killcams_cancelled;
        }
    }
}

auto chat_stream(event_loop& loop, game_server& game, client& c, webtransport_stream stream)
    -> task<void>
{
    std::array<std::byte, proto::kMaxChat + 1> buffer {};
    auto read = flatten_result(co_await read_until_fin(loop, stream, buffer));
    if (!read) {
        if (read.error() == make_error_code(webtransport_errc::capacity_exceeded)) {
            (void)stream.stop_sending(proto::kStopChatTooLong);
        }
        co_return;
    }
    const auto text = std::span<const std::byte>(buffer).first(*read);
    if (text.empty() || !proto::valid_utf8(text) || !c.joined || c.closing) co_return;
    const auto now = clock_type::now();
    if (c.chatted && now - c.last_chat < kChatInterval) {
        const std::string notice = "chat too fast";
        std::vector<std::byte> payload {std::byte {static_cast<std::uint8_t>(notice.size())}};
        for (const char ch : notice) payload.push_back(std::byte {static_cast<std::uint8_t>(ch)});
        game.push_event(c, proto::frame_message(proto::kNotice, payload));
        co_return;
    }
    c.chatted = true;
    c.last_chat = now;
    ++game.stats().chats;
    std::vector<std::byte> payload {std::byte {c.id}, std::byte {static_cast<std::uint8_t>(text.size())}};
    payload.insert(payload.end(), text.begin(), text.end());
    game.broadcast(proto::frame_message(proto::kChat, payload));
}

auto scoreboard_stream(event_loop& loop, game_server& game, webtransport_stream stream) -> task<void>
{
    std::array<std::byte, 8> request {};
    auto read = flatten_result(co_await read_until_fin(loop, stream, request));
    if (!read || *read != 1 || request[0] != std::byte {proto::kRpcScoreboard}) {
        (void)stream.reset(0);
        co_return;
    }
    ++game.stats().rpcs;
    const auto response = game.scoreboard_payload();
    (void)flatten_result(co_await write_all(loop, stream, response, true));
}

// Runs the session's children until it ends. Every child is awaited before
// the session handler returns, because the session is borrowed from it.
auto run_session(event_loop& loop, game_server& game, webtransport_session& session, client& c)
    -> task<void>
{
    const bool spawned = game.spawn_child(loop, c, kMonitorSlot, monitor_session(loop, game, c, session)) &&
        game.spawn_child(loop, c, kDatagramInSlot, datagram_reader(loop, game, c, session)) &&
        game.spawn_child(loop, c, kDatagramOutSlot, datagram_writer(loop, game, c, session)) &&
        game.spawn_child(loop, c, kKillcamSlot, killcam_writer(loop, game, c, session));
    if (!spawned) game.request_close(c, proto::kCloseServerFull, "server busy");
    (void)game.spawn_child(loop, c, kWatchdogSlot, hello_watchdog(loop, game, c));

    std::optional<webtransport_stream> control;
    for (;;) {
        auto accepted = flatten_result(co_await session.async_accept_stream());
        if (!accepted) break;
        if (!control) {
            // The first client bidirectional stream carries the control messages.
            if (accepted->direction() != quic_stream_direction::bidirectional) {
                game.request_close(c, proto::kCloseProtocol, "protocol error");
                continue;
            }
            control.emplace(std::move(*accepted));
            if (!game.spawn_child(loop, c, kControlSlot, control_reader(loop, game, c, *control)) ||
                !game.spawn_child(loop, c, kEventsSlot, event_writer(loop, game, c, *control))) {
                game.request_close(c, proto::kCloseServerFull, "server busy");
            }
            continue;
        }

        for (std::size_t slot = kFirstStreamSlot; slot < kChildSlotCount; ++slot) {
            auto& child = c.children[slot];
            if (child && child->done()) {
                (void)co_await *child;
                child.reset();
            }
        }
        std::size_t free_slot = kChildSlotCount;
        for (std::size_t slot = kFirstStreamSlot; slot < kChildSlotCount; ++slot) {
            if (!c.children[slot]) {
                free_slot = slot;
                break;
            }
        }
        if (free_slot == kChildSlotCount) {
            // Busy: four handlers already run for this player.
            if (accepted->direction() == quic_stream_direction::bidirectional) {
                (void)accepted->reset(proto::kBusy);
            } else {
                (void)accepted->stop_sending(proto::kBusy);
            }
            continue;
        }
        const bool spawned = accepted->direction() == quic_stream_direction::unidirectional
            ? game.spawn_child(loop, c, free_slot, chat_stream(loop, game, c, std::move(*accepted)))
            : game.spawn_child(loop, c, free_slot, scoreboard_stream(loop, game, std::move(*accepted)));
        if (!spawned) game.request_close(c, proto::kCloseServerFull, "server busy");
    }

    // The session has ended: wake every child, stop the watchdog, and wait for all of them.
    game.end_session(c);
    if (c.children[kWatchdogSlot]) (void)c.children[kWatchdogSlot]->cancel();
    for (auto& child : c.children) {
        if (child) (void)co_await *child;
    }
}

} // namespace

client::client(event_loop& loop, std::uint8_t slot_id)
    : id(slot_id), monitor_wake(loop), event_wake(loop), datagram_wake(loop), killcam_wake(loop)
{
}

game_server::game_server(std::size_t max_players, std::string cert_hash_json, double killcam_speed)
    : world_(make_arena()), clients_(max_players), cert_hash_json_(std::move(cert_hash_json)),
      killcam_speed_(killcam_speed)
{
}

auto game_server::begin_shutdown() -> void
{
    shutting_down_ = true;
    for (auto& c : clients_) {
        if (c) request_close(*c, proto::kCloseShutdown, "server shutting down");
    }
}

auto game_server::reserve(event_loop& loop) -> std::optional<std::uint8_t>
{
    for (std::size_t i = 0; i < clients_.size(); ++i) {
        if (clients_[i]) continue;
        clients_[i] = std::make_unique<client>(loop, static_cast<std::uint8_t>(i));
        return static_cast<std::uint8_t>(i);
    }
    return std::nullopt;
}

auto game_server::release(std::uint8_t id) -> void
{
    auto& slot = clients_[id];
    if (slot->joined) {
        slot->joined = false;
        world_.leave(id);
        std::vector<std::byte> payload {std::byte {id}};
        broadcast(proto::frame_message(proto::kLeave, payload));
    }
    slot.reset();
}

auto game_server::spawn_child(event_loop& loop, client& c, std::size_t slot, task<void>&& operation) -> bool
{
    auto handle = std::make_unique<task_handle<void>>();
    if (loop.spawn(std::move(operation), *handle) != task_spawn_result::accepted) return false;
    c.children[slot] = std::move(handle);
    return true;
}

auto game_server::request_close(client& c, std::uint32_t code, std::string_view reason) -> void
{
    if (c.close_requested || c.closing) return;
    c.close_requested = true;
    c.close_code = code;
    c.close_reason = std::string(reason);
    c.monitor_wake.notify();
}

auto game_server::end_session(client& c) -> void
{
    c.closing = true;
    c.monitor_wake.notify();
    c.event_wake.notify();
    c.datagram_wake.notify();
    c.killcam_wake.notify();
}

auto game_server::push_event(client& c, std::vector<std::byte>&& message) -> void
{
    if (c.closing || c.close_requested) return;
    if (c.events.size() >= kEventQueueLimit) {
        request_close(c, proto::kCloseTooSlow, "too slow");
        return;
    }
    c.events.push_back(std::move(message));
    c.event_wake.notify();
}

auto game_server::broadcast(const std::vector<std::byte>& message) -> void
{
    for (auto& other : clients_) {
        if (!other || !other->joined) continue;
        auto copy = message;
        push_event(*other, std::move(copy));
    }
}

auto game_server::welcome_message(std::uint8_t id) const -> std::vector<std::byte>
{
    std::vector<std::byte> payload;
    proto::byte_writer w(payload);
    const auto& arena = world_.arena();
    w.u8(id);
    w.u16(proto::kTickRate);
    w.u16(proto::kSnapshotRate);
    w.u8(static_cast<std::uint8_t>(arena.width));
    w.u8(static_cast<std::uint8_t>(arena.height));
    for (const auto cell : arena.cells) w.u8(cell);
    std::size_t others = 0;
    for (std::size_t i = 0; i < kMaxPlayers; ++i) {
        if (i != id && world_.player_at(static_cast<std::uint8_t>(i)).active) ++others;
    }
    w.u8(static_cast<std::uint8_t>(others));
    for (std::size_t i = 0; i < kMaxPlayers; ++i) {
        const auto& p = world_.player_at(static_cast<std::uint8_t>(i));
        if (i == id || !p.active) continue;
        w.u8(static_cast<std::uint8_t>(i));
        w.u8(static_cast<std::uint8_t>(p.name.size()));
        w.text(p.name);
        w.u16(p.kills);
        w.u16(p.deaths);
    }
    return proto::frame_message(proto::kWelcome, payload);
}

auto game_server::scoreboard_payload() const -> std::vector<std::byte>
{
    std::vector<std::byte> payload;
    proto::byte_writer w(payload);
    w.u8(static_cast<std::uint8_t>(world_.active_count()));
    for (std::size_t i = 0; i < kMaxPlayers; ++i) {
        const auto& p = world_.player_at(static_cast<std::uint8_t>(i));
        if (!p.active) continue;
        w.u8(static_cast<std::uint8_t>(i));
        w.u8(static_cast<std::uint8_t>(p.name.size()));
        w.text(p.name);
        w.u16(p.kills);
        w.u16(p.deaths);
    }
    return payload;
}

auto game_server::join_player(client& c, std::string_view name) -> void
{
    world_.join(c.id, name);
    c.joined = true;
    push_event(c, welcome_message(c.id));
    std::vector<std::byte> payload;
    proto::byte_writer w(payload);
    w.u8(c.id);
    w.u8(static_cast<std::uint8_t>(name.size()));
    w.text(name);
    broadcast(proto::frame_message(proto::kJoin, payload));
}

auto game_server::on_datagram(client& c, std::span<const std::byte> data) -> void
{
    proto::byte_reader r(data);
    const auto type = r.u8();
    if (type == proto::kClientPing) {
        if (data.size() != proto::kPingSize || c.pongs.size() >= kPongQueueLimit) return;
        std::array<std::byte, proto::kPingSize> pong {};
        std::copy(data.begin(), data.end(), pong.begin());
        c.pongs.push_back(pong);
        c.datagram_wake.notify();
        return;
    }
    if (type != proto::kClientInput) return;
    const auto newest = r.u32();
    const auto count = r.u8();
    if (count < 1 || count > proto::kMaxInputsPerPacket) return;
    std::array<input, proto::kMaxInputsPerPacket> inputs {};
    for (std::size_t i = 0; i < count; ++i) {
        inputs[i].buttons = r.u8();
        inputs[i].yaw = r.u16();
        inputs[i].view_tick = r.u32();
    }
    if (!r.done()) return;
    for (std::size_t i = 0; i < count; ++i) {
        if (newest < i + 1) continue;
        auto value = inputs[i];
        value.seq = newest - static_cast<std::uint32_t>(i);
        if (world_.queue_input(c.id, value)) ++stats_.inputs;
    }
}

auto game_server::tick_once() -> void
{
    world_.tick(events_);
    for (const auto& kill : events_.kills) {
        std::vector<std::byte> payload {std::byte {kill.killer}, std::byte {kill.victim},
                                        std::byte {static_cast<std::uint8_t>(kill.weapon_type)}};
        broadcast(proto::frame_message(proto::kKill, payload));
        auto& victim = clients_[kill.victim];
        if (!victim) continue;
        // A new death replaces a killcam still streaming. The writer sees its pointer cleared and moves on.
        if (victim->killcam_stream != nullptr) {
            (void)victim->killcam_stream->reset(kResetKillcamReplaced);
            ++stats_.killcams_reset;
            victim->killcam_stream = nullptr;
        }
        world_.encode_killcam(kill.killer, kill.victim, victim->killcam_payload);
        victim->killcam_wake.notify();
    }
    for (const auto id : events_.respawns) {
        auto& c = clients_[id];
        if (!c) continue;
        c->killcam_payload.clear();
        ++c->respawn_epoch;
        if (c->killcam_stream != nullptr) {
            (void)c->killcam_stream->reset(proto::kResetKillcamRespawn);
            ++stats_.killcams_reset;
            c->killcam_stream = nullptr;
        }
    }
    if (world_.current_tick() % kSnapshotEvery != 0) return;
    for (auto& c : clients_) {
        if (!c || !c->joined) continue;
        c->snapshot_due = true;
        c->datagram_wake.notify();
    }
}

auto game_server::print_stats(event_loop& loop) -> void
{
    const auto coroutines = loop.coroutine_statistics();
    const auto& s = stats_;
    std::printf("[5s] players=%zu inputs=%llu lost_total=%llu snapshots=%llu snapshot_failures=%llu "
                "pongs=%llu killcams sent=%llu done=%llu cancelled=%llu reset=%llu chats=%llu rpcs=%llu "
                "closed=[%llu %llu %llu %llu %llu %llu] coroutines live=%zu roots=%zu\n",
                world_.active_count(), static_cast<unsigned long long>(s.inputs),
                static_cast<unsigned long long>(world_.lost_inputs()),
                static_cast<unsigned long long>(s.snapshots),
                static_cast<unsigned long long>(s.snapshot_failures),
                static_cast<unsigned long long>(s.pongs),
                static_cast<unsigned long long>(s.killcams_started),
                static_cast<unsigned long long>(s.killcams_completed),
                static_cast<unsigned long long>(s.killcams_cancelled),
                static_cast<unsigned long long>(s.killcams_reset),
                static_cast<unsigned long long>(s.chats), static_cast<unsigned long long>(s.rpcs),
                static_cast<unsigned long long>(s.closed[0]), static_cast<unsigned long long>(s.closed[1]),
                static_cast<unsigned long long>(s.closed[2]), static_cast<unsigned long long>(s.closed[3]),
                static_cast<unsigned long long>(s.closed[4]), static_cast<unsigned long long>(s.closed[5]),
                coroutines.live, coroutines.active_roots);
    std::fflush(stdout);
    stats_ = counters {};
}

auto tick_loop(event_loop& loop, game_server& game) -> task<void>
{
    auto deadline = clock_type::now() + kTickPeriod;
    for (;;) {
        if (co_await sleep_until(loop, deadline) == timer_wait_result::cancelled) co_return;
        game.tick_once();
        deadline += kTickPeriod;
        // More than five ticks behind: resynchronize instead of catching up.
        const auto now = clock_type::now();
        if (now - deadline > 5 * kTickPeriod) deadline = now + kTickPeriod;
    }
}

auto stats_loop(event_loop& loop, game_server& game) -> task<void>
{
    auto deadline = clock_type::now() + kStatsPeriod;
    for (;;) {
        if (co_await sleep_until(loop, deadline) == timer_wait_result::cancelled) co_return;
        deadline += kStatsPeriod;
        game.print_stats(loop);
    }
}

auto arena_session(event_loop& loop, eventloop::http::request& request, eventloop::http::response& response)
    -> task<void>
{
    auto& game = *static_cast<game_server*>(request.route_context());
    const auto origin = request.header_value("origin");
    const std::string expected = "https://" + std::string(request.authority());
    if (!origin || *origin != expected) {
        (void)co_await response.async_send(403, {});
        co_return;
    }
    if (!game.accepting()) {
        (void)co_await response.async_send(503, {});
        co_return;
    }
    auto accepted = flatten_result(co_await request.async_accept_webtransport(kProtocols));
    if (!accepted) co_return;
    auto& session = *accepted;
    const auto id = game.reserve(loop);
    if (!id) {
        game.note_close(proto::kCloseServerFull);
        (void)co_await session.async_close(proto::kCloseServerFull, "server full");
        co_return;
    }
    co_await run_session(loop, game, session, game.client_at(*id));
    game.release(*id);
}

auto cert_hash(event_loop&, eventloop::http::request& request, eventloop::http::response& response)
    -> task<void>
{
    const auto& game = *static_cast<const game_server*>(request.route_context());
    const std::array<eventloop::http::header, 2> headers {{
        {"content-type", "application/json"},
        {"cache-control", "no-store"},
    }};
    (void)co_await response.async_send(200, headers, std::as_bytes(std::span(game.cert_hash_json())));
}

} // namespace skirmish
