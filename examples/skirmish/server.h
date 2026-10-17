// Network layer for Skirmish: WebTransport sessions, datagram snapshots, the
// control stream, scoreboard and chat streams, killcams, and the 60 Hz tick.
// Everything runs on the event loop's thread.
#pragma once

#include "protocol.h"
#include "world.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/request.h"
#include "eventloop/http/response.h"
#include "eventloop/http/webtransport.h"
#include "eventloop/task.h"
#include "eventloop/wakeup.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace skirmish {

// Counters for one stats window; reset after each print.
struct counters {
    std::uint64_t inputs {0};
    std::uint64_t pongs {0};
    std::uint64_t snapshots {0};
    std::uint64_t snapshot_failures {0};
    std::uint64_t killcams_started {0};
    std::uint64_t killcams_completed {0};
    std::uint64_t killcams_cancelled {0};
    std::uint64_t killcams_reset {0};
    std::uint64_t chats {0};
    std::uint64_t rpcs {0};
    std::array<std::uint64_t, proto::kCloseCodeCount> closed {};
};

// Child task slots per session. Stream handlers share the last four.
inline constexpr std::size_t kWatchdogSlot = 0;
inline constexpr std::size_t kMonitorSlot = 1;
inline constexpr std::size_t kControlSlot = 2;
inline constexpr std::size_t kEventsSlot = 3;
inline constexpr std::size_t kDatagramInSlot = 4;
inline constexpr std::size_t kDatagramOutSlot = 5;
inline constexpr std::size_t kKillcamSlot = 6;
inline constexpr std::size_t kStreamSlots = 4;
inline constexpr std::size_t kFirstStreamSlot = 7;
inline constexpr std::size_t kChildSlotCount = kFirstStreamSlot + kStreamSlots;

// State for one player slot. Its wakeups have one waiter each. Stored behind
// unique_ptr because wakeups cannot move.
struct client {
    client(eventloop::event_loop& loop, std::uint8_t slot_id);
    client(const client&) = delete;
    auto operator=(const client&) -> client& = delete;

    std::uint8_t id;
    bool joined {false};
    bool closing {false};
    bool close_requested {false};
    std::uint32_t close_code {0};
    std::string close_reason;

    eventloop::wakeup monitor_wake;
    eventloop::wakeup event_wake;
    eventloop::wakeup datagram_wake;
    eventloop::wakeup killcam_wake;

    std::deque<std::vector<std::byte>> events;
    std::deque<std::array<std::byte, proto::kPingSize>> pongs;
    bool snapshot_due {false};
    std::vector<std::byte> snapshot;
    std::vector<std::byte> killcam_payload;
    eventloop::http::webtransport_stream* killcam_stream {nullptr};
    std::uint32_t respawn_epoch {0};
    bool chatted {false};
    std::chrono::steady_clock::time_point last_chat {};

    std::array<std::unique_ptr<eventloop::task_handle<void>>, kChildSlotCount> children;
};

class game_server {
public:
    // killcam_speed: playback rate for killcam streams (0 = send them unpaced).
    game_server(std::size_t max_players, std::string cert_hash_json, double killcam_speed);
    game_server(const game_server&) = delete;
    auto operator=(const game_server&) -> game_server& = delete;

    [[nodiscard]] auto accepting() const noexcept -> bool { return !shutting_down_; }
    [[nodiscard]] auto cert_hash_json() const noexcept -> std::string_view { return cert_hash_json_; }
    [[nodiscard]] auto killcam_speed() const noexcept -> double { return killcam_speed_; }

    // Closes every session with code 4. Handlers finish as their sessions end.
    auto begin_shutdown() -> void;
    [[nodiscard]] auto reserve(eventloop::event_loop& loop) -> std::optional<std::uint8_t>;
    [[nodiscard]] auto client_at(std::uint8_t id) -> client& { return *clients_[id]; }
    auto release(std::uint8_t id) -> void;
    auto note_close(std::uint32_t code) noexcept -> void { ++stats_.closed[code]; }

    // Used by the coroutines in server.cc.
    auto spawn_child(eventloop::event_loop& loop, client& c, std::size_t slot,
                     eventloop::task<void>&& operation) -> bool;
    auto request_close(client& c, std::uint32_t code, std::string_view reason) -> void;
    auto end_session(client& c) -> void;
    auto push_event(client& c, std::vector<std::byte>&& message) -> void;
    auto broadcast(const std::vector<std::byte>& message) -> void;
    auto join_player(client& c, std::string_view name) -> void;
    auto scoreboard_payload() const -> std::vector<std::byte>;
    auto on_datagram(client& c, std::span<const std::byte> data) -> void;
    auto tick_once() -> void;
    auto print_stats(eventloop::event_loop& loop) -> void;
    [[nodiscard]] auto world() noexcept -> skirmish::world& { return world_; }
    [[nodiscard]] auto stats() noexcept -> counters& { return stats_; }

private:
    auto welcome_message(std::uint8_t id) const -> std::vector<std::byte>;

    skirmish::world world_;
    std::vector<std::unique_ptr<client>> clients_;
    std::string cert_hash_json_;
    double killcam_speed_;
    tick_events events_;
    counters stats_;
    bool shutting_down_ {false};
};

// Fixed-step 60 Hz simulation and broadcast, and five-second statistics.
auto tick_loop(eventloop::event_loop& loop, game_server& game) -> eventloop::task<void>;
auto stats_loop(eventloop::event_loop& loop, game_server& game) -> eventloop::task<void>;

// WebTransport route at /arena (CONNECT) and the certificate hash at /cert-hash.
auto arena_session(eventloop::event_loop& loop, eventloop::http::request& request,
                   eventloop::http::response& response) -> eventloop::task<void>;
auto cert_hash(eventloop::event_loop& loop, eventloop::http::request& request,
               eventloop::http::response& response) -> eventloop::task<void>;

} // namespace skirmish
