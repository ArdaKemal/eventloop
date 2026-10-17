// Authoritative Skirmish simulation. Pure C++ with no eventloop dependency:
// the network layer feeds inputs, calls tick(), and encodes snapshots.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace skirmish {

inline constexpr std::size_t kMaxPlayers = 64;
inline constexpr std::size_t kInputQueue = 16;
inline constexpr std::size_t kMaxProjectiles = 128;
inline constexpr std::size_t kHistoryTicks = 64;
inline constexpr std::uint32_t kLagCompensationTicks = 30;
inline constexpr std::size_t kKillcamFrames = 180;
inline constexpr std::uint32_t kTicksPerSecond = 60;
inline constexpr std::uint32_t kSnapshotEvery = 2;
inline constexpr std::uint32_t kRespawnTicks = 180;
inline constexpr int kMaxHealth = 100;
inline constexpr double kPlayerRadius = 0.25;
inline constexpr double kMoveSpeed = 4.0;
inline constexpr int kRifleCooldownTicks = 6;
inline constexpr int kRifleDamage = 15;
inline constexpr double kRifleRange = 30.0;
inline constexpr int kRocketCooldownTicks = 90;
inline constexpr double kRocketSpeed = 12.0;
inline constexpr double kRocketRadius = 0.1;
inline constexpr double kSplashRadius = 1.5;
inline constexpr int kSplashCenterDamage = 80;
inline constexpr int kSplashEdgeDamage = 20;
inline constexpr std::uint32_t kRocketLifeTicks = 180;
inline constexpr int kRocketSubsteps = 4;

inline constexpr std::uint8_t kButtonForward = 1 << 0;
inline constexpr std::uint8_t kButtonBack = 1 << 1;
inline constexpr std::uint8_t kButtonLeft = 1 << 2;
inline constexpr std::uint8_t kButtonRight = 1 << 3;
inline constexpr std::uint8_t kButtonFire = 1 << 4;
inline constexpr std::uint8_t kButtonRocket = 1 << 5;

enum class weapon : std::uint8_t { rifle = 1, rocket = 2 };
enum class effect_kind : std::uint8_t { tracer = 1, explosion = 2 };

struct input {
    std::uint32_t seq {0};
    std::uint8_t buttons {0};
    std::uint16_t yaw {0};
    std::uint32_t view_tick {0};
};

// Map cells are row-major, 0 = floor and 1..4 = wall styles. Points outside
// the map count as walls.
struct map {
    int width {0};
    int height {0};
    std::vector<std::uint8_t> cells;

    [[nodiscard]] auto wall(int cx, int cy) const noexcept -> bool;
};

[[nodiscard]] auto make_arena() -> map;
// True when the player's bounding box at (x, y) overlaps a wall cell.
[[nodiscard]] auto box_overlaps_wall(const map& arena, double x, double y) noexcept -> bool;

struct kill_event {
    std::uint8_t killer {0};
    std::uint8_t victim {0};
    weapon weapon_type {weapon::rifle};
};

// Events produced by one tick, reused by the caller to avoid allocation.
struct tick_events {
    std::vector<kill_event> kills;
    std::vector<std::uint8_t> respawns;

    auto clear() -> void
    {
        kills.clear();
        respawns.clear();
    }
};

struct sample {
    std::uint32_t tick {0};
    double x {0.0};
    double y {0.0};
    bool alive {false};
};

struct player {
    bool active {false};
    std::string name;
    double x {0.0};
    double y {0.0};
    std::uint16_t yaw {0};
    int hp {kMaxHealth};
    bool alive {true};
    std::uint32_t respawn_ticks {0};
    int rifle_cooldown {0};
    int rocket_cooldown {0};
    std::uint16_t kills {0};
    std::uint16_t deaths {0};

    std::uint32_t acked_seq {0};
    std::uint8_t buttons {0};
    std::uint32_t view_tick {0};
    std::array<input, kInputQueue> queue {};
    std::size_t queued {0};

    // Fire state since the previous tick, and since the previous snapshot.
    bool fired_now {false};
    bool fired_window {false};
    bool fired_snapshot {false};

    std::array<sample, kHistoryTicks> history {};
};

class world {
public:
    explicit world(map arena);

    [[nodiscard]] auto arena() const noexcept -> const map& { return arena_; }

    // Activates a slot with a fresh player at a spawn point far from the living.
    auto join(std::uint8_t id, std::string_view name) -> void;
    auto leave(std::uint8_t id) -> void;

    [[nodiscard]] auto player_at(std::uint8_t id) const noexcept -> const player&
    {
        return players_[id];
    }
    [[nodiscard]] auto player_at(std::uint8_t id) noexcept -> player& { return players_[id]; }
    [[nodiscard]] auto active_count() const noexcept -> std::size_t;
    [[nodiscard]] auto lost_inputs() const noexcept -> std::uint64_t { return lost_inputs_; }

    // Queues one input. False when the slot is inactive, the input was already
    // queued or applied, or the queue is full.
    auto queue_input(std::uint8_t id, input value) -> bool;

    auto tick(tick_events& events) -> void;
    [[nodiscard]] auto current_tick() const noexcept -> std::uint32_t { return tick_; }

    // Encodes the SNAPSHOT datagram for one player, at most max_bytes long.
    auto encode_snapshot(std::uint8_t id, std::size_t max_bytes, std::vector<std::byte>& out) const
        -> void;
    // Encodes the killcam payload from the last frames before a death.
    auto encode_killcam(std::uint8_t killer, std::uint8_t victim, std::vector<std::byte>& out) const
        -> void;

private:
    struct frame {
        std::uint32_t tick {0};
        std::vector<std::byte> body;
    };

    auto consume_inputs(std::uint8_t id, tick_events& events) -> void;
    auto step(std::uint8_t id, std::uint8_t buttons, std::uint16_t yaw, std::uint32_t view_tick,
              tick_events& events) -> void;
    auto fire_rifle(std::uint8_t id, std::uint32_t view_tick, tick_events& events) -> void;
    auto spawn_rocket(std::uint8_t id) -> bool;
    auto update_projectiles(tick_events& events) -> void;
    auto explode(double x, double y, std::uint8_t owner, tick_events& events) -> void;
    auto apply_damage(std::uint8_t victim, int amount, std::uint8_t killer, weapon weapon_type,
                      tick_events& events) -> void;
    auto respawn(std::uint8_t id) -> void;
    [[nodiscard]] auto spawn_point(std::uint8_t id) const -> std::pair<double, double>;
    [[nodiscard]] auto rewound_position(std::uint8_t id, std::uint32_t view_tick) const
        -> std::pair<bool, std::pair<double, double>>;
    auto add_effect(effect_kind kind, std::uint8_t owner, double x1, double y1, double x2,
                    double y2) -> void;
    auto encode_body(std::vector<std::byte>& out, std::size_t limit, bool snapshot) const -> void;

    struct effect {
        effect_kind kind {effect_kind::tracer};
        std::uint8_t owner {0};
        double x1 {0.0};
        double y1 {0.0};
        double x2 {0.0};
        double y2 {0.0};
    };

    struct projectile {
        bool used {false};
        std::uint16_t id {0};
        std::uint8_t owner {0};
        double x {0.0};
        double y {0.0};
        double dx {0.0};
        double dy {0.0};
        std::uint32_t age {0};
    };

    map arena_;
    std::array<player, kMaxPlayers> players_ {};
    std::array<projectile, kMaxProjectiles> projectiles_ {};
    std::uint16_t next_projectile_id_ {1};
    std::uint32_t tick_ {0};
    std::uint64_t lost_inputs_ {0};

    std::vector<effect> tick_effects_;
    std::vector<effect> pending_effects_;
    std::vector<effect> snapshot_effects_;

    std::array<frame, kKillcamFrames> frames_ {};
    std::size_t next_frame_ {0};
    std::size_t filled_frames_ {0};
};

} // namespace skirmish
