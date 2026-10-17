#include "world.h"

#include "protocol.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numbers>
#include <optional>
#include <utility>

namespace skirmish {
namespace {

struct cell {
    int x;
    int y;
};

struct rect {
    int x0;
    int y0;
    int x1;
    int y1;
    std::uint8_t style;
};

// Floor cells, each with clear space around it.
constexpr std::array<cell, 8> kSpawns {{{3, 3}, {28, 3}, {3, 28}, {28, 28},
                                        {3, 16}, {28, 16}, {16, 3}, {16, 28}}};

[[nodiscard]] auto cell_of(double value) noexcept -> int
{
    return static_cast<int>(std::floor(value));
}

[[nodiscard]] auto yaw_radians(std::uint16_t yaw16) noexcept -> double
{
    return static_cast<double>(yaw16) / 65536.0 * (2.0 * std::numbers::pi);
}

// Moves one axis, then clamps to the touching position when it hits a wall.
[[nodiscard]] auto move_axis(const map& arena, double x, double y, double delta, bool horizontal)
    -> double
{
    const double start = horizontal ? x : y;
    if (delta == 0) return start;
    const double next = start + delta;
    const bool blocked = horizontal ? box_overlaps_wall(arena, next, y)
                                    : box_overlaps_wall(arena, x, next);
    if (!blocked) return next;
    if (delta > 0) return std::floor(next + kPlayerRadius) - kPlayerRadius - 0.001;
    return std::floor(next - kPlayerRadius) + 1 + kPlayerRadius + 0.001;
}

// The movement rule from PROTOCOL.md; the browser client mirrors it exactly.
auto move_player(const map& arena, player& p, std::uint8_t buttons, std::uint16_t yaw16) -> void
{
    const double yaw = yaw_radians(yaw16);
    const double fx = std::cos(yaw);
    const double fy = std::sin(yaw);
    const double rx = -std::sin(yaw);
    const double ry = std::cos(yaw);
    const double forward = (buttons & kButtonForward) ? 1.0 : 0.0;
    const double back = (buttons & kButtonBack) ? 1.0 : 0.0;
    const double left = (buttons & kButtonLeft) ? 1.0 : 0.0;
    const double right = (buttons & kButtonRight) ? 1.0 : 0.0;
    double mx = (forward - back) * fx + (right - left) * rx;
    double my = (forward - back) * fy + (right - left) * ry;
    const double length = std::sqrt(mx * mx + my * my);
    if (length > 0) {
        mx /= length;
        my /= length;
    }
    const double dx = mx * kMoveSpeed / kTicksPerSecond;
    const double dy = my * kMoveSpeed / kTicksPerSecond;
    p.x = move_axis(arena, p.x, p.y, dx, true);
    p.y = move_axis(arena, p.x, p.y, dy, false);
}

// Distance along the ray to the first wall cell, or max_t when none is closer.
[[nodiscard]] auto ray_wall_distance(const map& arena, double ox, double oy, double dx, double dy,
                                     double max_t) -> double
{
    const double inf = std::numeric_limits<double>::infinity();
    int cx = cell_of(ox);
    int cy = cell_of(oy);
    if (arena.wall(cx, cy)) return 0.0;
    const int step_x = dx > 0 ? 1 : -1;
    const int step_y = dy > 0 ? 1 : -1;
    const double delta_x = dx != 0 ? std::abs(1.0 / dx) : inf;
    const double delta_y = dy != 0 ? std::abs(1.0 / dy) : inf;
    double next_x = dx > 0 ? (cx + 1 - ox) / dx : (dx < 0 ? (cx - ox) / dx : inf);
    double next_y = dy > 0 ? (cy + 1 - oy) / dy : (dy < 0 ? (cy - oy) / dy : inf);
    for (;;) {
        double t = 0.0;
        if (next_x < next_y) {
            t = next_x;
            cx += step_x;
            next_x += delta_x;
        } else {
            t = next_y;
            cy += step_y;
            next_y += delta_y;
        }
        if (t > max_t) return max_t;
        if (arena.wall(cx, cy)) return t;
    }
}

// Distance along a unit ray to a circle, or nothing when it misses.
[[nodiscard]] auto ray_circle(double ox, double oy, double dx, double dy, double cx, double cy,
                              double radius) -> std::optional<double>
{
    const double fx = ox - cx;
    const double fy = oy - cy;
    const double b = fx * dx + fy * dy;
    const double c = fx * fx + fy * fy - radius * radius;
    if (c <= 0) return 0.0;
    const double disc = b * b - c;
    if (disc < 0) return std::nullopt;
    const double t = -b - std::sqrt(disc);
    if (t < 0) return std::nullopt;
    return t;
}

} // namespace

auto map::wall(int cx, int cy) const noexcept -> bool
{
    if (cx < 0 || cy < 0 || cx >= width || cy >= height) return true;
    return cells[static_cast<std::size_t>(cy) * static_cast<std::size_t>(width) +
                 static_cast<std::size_t>(cx)] != 0;
}

auto make_arena() -> map
{
    constexpr int size = 32;
    constexpr std::array<rect, 18> rects {{
        {0, 0, 31, 0, 1}, {0, 31, 31, 31, 1}, {0, 0, 0, 31, 1}, {31, 0, 31, 31, 1},  // border
        {6, 6, 7, 7, 2}, {24, 6, 25, 7, 2}, {6, 24, 7, 25, 2}, {24, 24, 25, 25, 2},  // pillars
        {14, 2, 14, 6, 3}, {17, 2, 17, 6, 3}, {14, 25, 14, 29, 3}, {17, 25, 17, 29, 3},  // gates
        {9, 10, 12, 10, 4}, {19, 10, 22, 10, 4}, {9, 21, 12, 21, 4}, {19, 21, 22, 21, 4},  // bars
        {10, 14, 10, 17, 2}, {21, 14, 21, 17, 2},  // side barriers; the middle stays open
    }};
    map arena;
    arena.width = size;
    arena.height = size;
    arena.cells.assign(static_cast<std::size_t>(size) * size, 0);
    for (const auto& r : rects) {
        for (int y = r.y0; y <= r.y1; ++y) {
            for (int x = r.x0; x <= r.x1; ++x) {
                arena.cells[static_cast<std::size_t>(y) * size + static_cast<std::size_t>(x)] = r.style;
            }
        }
    }
    return arena;
}

auto box_overlaps_wall(const map& arena, double x, double y) noexcept -> bool
{
    const int x0 = cell_of(x - kPlayerRadius);
    const int x1 = static_cast<int>(std::ceil(x + kPlayerRadius)) - 1;
    const int y0 = cell_of(y - kPlayerRadius);
    const int y1 = static_cast<int>(std::ceil(y + kPlayerRadius)) - 1;
    for (int cy = y0; cy <= y1; ++cy) {
        for (int cx = x0; cx <= x1; ++cx) {
            if (arena.wall(cx, cy)) return true;
        }
    }
    return false;
}

world::world(map arena) : arena_(std::move(arena))
{
    tick_effects_.reserve(256);
    pending_effects_.reserve(512);
    snapshot_effects_.reserve(512);
}

auto world::active_count() const noexcept -> std::size_t
{
    return static_cast<std::size_t>(std::count_if(players_.begin(), players_.end(),
                                                  [](const player& p) { return p.active; }));
}

auto world::spawn_point(std::uint8_t id) const -> std::pair<double, double>
{
    std::pair<double, double> best {kSpawns[0].x + 0.5, kSpawns[0].y + 0.5};
    double best_distance = -1.0;
    for (const auto& spawn : kSpawns) {
        const double sx = spawn.x + 0.5;
        const double sy = spawn.y + 0.5;
        double nearest = std::numeric_limits<double>::infinity();
        for (std::size_t other = 0; other < kMaxPlayers; ++other) {
            const auto& p = players_[other];
            if (other == id || !p.active || !p.alive) continue;
            nearest = std::min(nearest, std::hypot(p.x - sx, p.y - sy));
        }
        if (nearest > best_distance) {
            best_distance = nearest;
            best = {sx, sy};
        }
    }
    return best;
}

auto world::join(std::uint8_t id, std::string_view name) -> void
{
    players_[id] = player {};
    const auto [x, y] = spawn_point(id);
    auto& p = players_[id];
    p.active = true;
    p.name = std::string(name);
    p.x = x;
    p.y = y;
}

auto world::leave(std::uint8_t id) -> void
{
    for (auto& pr : projectiles_) {
        if (pr.used && pr.owner == id) pr.used = false;
    }
    players_[id] = player {};
}

auto world::queue_input(std::uint8_t id, input value) -> bool
{
    auto& p = players_[id];
    if (!p.active || value.seq == 0 || value.seq <= p.acked_seq) return false;
    std::size_t position = 0;
    while (position < p.queued && p.queue[position].seq < value.seq) ++position;
    if (position < p.queued && p.queue[position].seq == value.seq) return false;
    if (p.queued == kInputQueue) return false;
    for (std::size_t i = p.queued; i > position; --i) p.queue[i] = p.queue[i - 1];
    p.queue[position] = value;
    ++p.queued;
    return true;
}

auto world::add_effect(effect_kind kind, std::uint8_t owner, double x1, double y1, double x2,
                       double y2) -> void
{
    const effect value {kind, owner, x1, y1, x2, y2};
    tick_effects_.push_back(value);
    pending_effects_.push_back(value);
}

auto world::consume_inputs(std::uint8_t id, tick_events& events) -> void
{
    auto& p = players_[id];
    const std::size_t take = p.queued > 4 ? 2 : (p.queued > 0 ? 1 : 0);
    if (take == 0) {
        step(id, p.buttons, p.yaw, p.view_tick, events);
        return;
    }
    for (std::size_t i = 0; i < take; ++i) {
        const input next = p.queue[0];
        for (std::size_t k = 1; k < p.queued; ++k) p.queue[k - 1] = p.queue[k];
        --p.queued;
        lost_inputs_ += next.seq - p.acked_seq - 1;
        p.acked_seq = next.seq;
        p.buttons = next.buttons;
        p.yaw = next.yaw;
        p.view_tick = next.view_tick;
        step(id, next.buttons, next.yaw, next.view_tick, events);
    }
}

auto world::step(std::uint8_t id, std::uint8_t buttons, std::uint16_t yaw, std::uint32_t view_tick,
                 tick_events& events) -> void
{
    auto& p = players_[id];
    p.yaw = yaw;
    if (!p.alive) return;
    move_player(arena_, p, buttons, yaw);
    if ((buttons & kButtonFire) && p.rifle_cooldown == 0) {
        p.rifle_cooldown = kRifleCooldownTicks;
        p.fired_now = true;
        p.fired_window = true;
        fire_rifle(id, view_tick, events);
    }
    if ((buttons & kButtonRocket) && p.rocket_cooldown == 0 && spawn_rocket(id)) {
        p.rocket_cooldown = kRocketCooldownTicks;
        p.fired_now = true;
        p.fired_window = true;
    }
}

auto world::rewound_position(std::uint8_t id, std::uint32_t view_tick) const
    -> std::pair<bool, std::pair<double, double>>
{
    const auto& p = players_[id];
    const std::uint32_t low = tick_ > kLagCompensationTicks ? tick_ - kLagCompensationTicks : 0;
    const std::uint32_t wanted = std::clamp(view_tick, low, tick_);
    const auto& recorded = p.history[wanted % kHistoryTicks];
    if (recorded.tick == wanted) return {recorded.alive, {recorded.x, recorded.y}};
    return {p.alive, {p.x, p.y}};
}

auto world::fire_rifle(std::uint8_t id, std::uint32_t view_tick, tick_events& events) -> void
{
    const auto& shooter = players_[id];
    const double yaw = yaw_radians(shooter.yaw);
    const double dx = std::cos(yaw);
    const double dy = std::sin(yaw);
    const double sx = shooter.x;
    const double sy = shooter.y;
    double best = ray_wall_distance(arena_, sx, sy, dx, dy, kRifleRange);
    int target = -1;
    for (std::size_t other = 0; other < kMaxPlayers; ++other) {
        if (other == id || !players_[other].active) continue;
        const auto [visible, position] = rewound_position(static_cast<std::uint8_t>(other), view_tick);
        if (!visible) continue;
        const auto distance = ray_circle(sx, sy, dx, dy, position.first, position.second, kPlayerRadius);
        if (distance && *distance < best) {
            best = *distance;
            target = static_cast<int>(other);
        }
    }
    add_effect(effect_kind::tracer, id, sx, sy, sx + dx * best, sy + dy * best);
    if (target >= 0) {
        apply_damage(static_cast<std::uint8_t>(target), kRifleDamage, id, weapon::rifle, events);
    }
}

auto world::spawn_rocket(std::uint8_t id) -> bool
{
    const auto& shooter = players_[id];
    const auto slot = std::find_if(projectiles_.begin(), projectiles_.end(),
                                   [](const projectile& pr) { return !pr.used; });
    if (slot == projectiles_.end()) return false;
    const double yaw = yaw_radians(shooter.yaw);
    slot->used = true;
    slot->id = next_projectile_id_;
    next_projectile_id_ = static_cast<std::uint16_t>(next_projectile_id_ + 1);
    if (next_projectile_id_ == 0) next_projectile_id_ = 1;
    slot->owner = id;
    slot->x = shooter.x;
    slot->y = shooter.y;
    slot->dx = std::cos(yaw) * kRocketSpeed / kTicksPerSecond;
    slot->dy = std::sin(yaw) * kRocketSpeed / kTicksPerSecond;
    slot->age = 0;
    return true;
}

auto world::update_projectiles(tick_events& events) -> void
{
    constexpr double contact = kPlayerRadius + kRocketRadius;
    for (auto& pr : projectiles_) {
        if (!pr.used) continue;
        if (++pr.age > kRocketLifeTicks) {
            pr.used = false;
            continue;
        }
        for (int s = 0; s < kRocketSubsteps; ++s) {
            const double px = pr.x;
            const double py = pr.y;
            const double nx = px + pr.dx / kRocketSubsteps;
            const double ny = py + pr.dy / kRocketSubsteps;
            if (arena_.wall(cell_of(nx), cell_of(ny))) {
                explode(px, py, pr.owner, events);
                pr.used = false;
                break;
            }
            pr.x = nx;
            pr.y = ny;
            // The owner is not a contact target; the splash still reaches it.
            const bool touched = std::any_of(players_.begin(), players_.end(), [&](const player& p) {
                return p.active && p.alive && &p != &players_[pr.owner] &&
                       std::hypot(p.x - nx, p.y - ny) <= contact;
            });
            if (touched) {
                explode(nx, ny, pr.owner, events);
                pr.used = false;
                break;
            }
        }
    }
}

auto world::explode(double x, double y, std::uint8_t owner, tick_events& events) -> void
{
    add_effect(effect_kind::explosion, owner, x, y, 0.0, 0.0);
    for (std::size_t q = 0; q < kMaxPlayers; ++q) {
        const auto& p = players_[q];
        if (!p.active || !p.alive) continue;
        const double distance = std::hypot(p.x - x, p.y - y);
        if (distance > kSplashRadius) continue;
        const double falloff = kSplashCenterDamage -
                               (kSplashCenterDamage - kSplashEdgeDamage) * distance / kSplashRadius;
        const double scale = q == owner ? 0.5 : 1.0;
        apply_damage(static_cast<std::uint8_t>(q), static_cast<int>(std::lround(falloff * scale)),
                     owner, weapon::rocket, events);
    }
}

auto world::apply_damage(std::uint8_t victim, int amount, std::uint8_t killer, weapon weapon_type,
                         tick_events& events) -> void
{
    auto& target = players_[victim];
    if (!target.alive || amount <= 0) return;
    target.hp = std::max(0, target.hp - amount);
    if (target.hp > 0) return;
    target.alive = false;
    target.respawn_ticks = kRespawnTicks;
    ++target.deaths;
    if (killer != victim && players_[killer].active) ++players_[killer].kills;
    events.kills.push_back({killer, victim, weapon_type});
}

auto world::respawn(std::uint8_t id) -> void
{
    const auto [x, y] = spawn_point(id);
    auto& p = players_[id];
    p.x = x;
    p.y = y;
    p.alive = true;
    p.hp = kMaxHealth;
    p.respawn_ticks = 0;
}

auto world::tick(tick_events& events) -> void
{
    events.clear();
    ++tick_;
    tick_effects_.clear();
    for (auto& p : players_) {
        p.fired_now = false;
        if (p.rifle_cooldown > 0) --p.rifle_cooldown;
        if (p.rocket_cooldown > 0) --p.rocket_cooldown;
    }
    // Positions at the start of the tick, for lag compensation.
    for (std::size_t id = 0; id < kMaxPlayers; ++id) {
        auto& p = players_[id];
        if (!p.active) continue;
        p.history[tick_ % kHistoryTicks] = sample {tick_, p.x, p.y, p.alive};
    }
    for (std::size_t id = 0; id < kMaxPlayers; ++id) {
        if (players_[id].active) consume_inputs(static_cast<std::uint8_t>(id), events);
    }
    update_projectiles(events);
    for (std::size_t id = 0; id < kMaxPlayers; ++id) {
        auto& p = players_[id];
        if (!p.active || p.alive) continue;
        if (p.respawn_ticks > 0) --p.respawn_ticks;
        if (p.respawn_ticks == 0) {
            respawn(static_cast<std::uint8_t>(id));
            events.respawns.push_back(static_cast<std::uint8_t>(id));
        }
    }
    if (tick_ % kSnapshotEvery == 0) {
        snapshot_effects_ = pending_effects_;
        pending_effects_.clear();
        for (auto& p : players_) {
            p.fired_snapshot = p.fired_window;
            p.fired_window = false;
        }
    }
    auto& recorded = frames_[next_frame_];
    recorded.tick = tick_;
    recorded.body.clear();
    encode_body(recorded.body, std::numeric_limits<std::size_t>::max(), false);
    next_frame_ = (next_frame_ + 1) % kKillcamFrames;
    if (filled_frames_ < kKillcamFrames) ++filled_frames_;
}

auto world::encode_body(std::vector<std::byte>& out, std::size_t limit, bool snapshot) const -> void
{
    proto::byte_writer w(out);
    const auto room = [&] { return limit > out.size() ? limit - out.size() : std::size_t {0}; };

    w.u8(static_cast<std::uint8_t>(active_count()));
    for (std::size_t id = 0; id < kMaxPlayers; ++id) {
        const auto& p = players_[id];
        if (!p.active) continue;
        const bool fired = snapshot ? p.fired_snapshot : p.fired_now;
        const auto flags = static_cast<std::uint8_t>((p.alive ? 1 : 0) | (fired ? 2 : 0));
        w.u8(static_cast<std::uint8_t>(id));
        w.q8(p.x);
        w.q8(p.y);
        w.u16(p.yaw);
        w.u8(static_cast<std::uint8_t>(std::clamp(p.hp, 0, kMaxHealth)));
        w.u8(flags);
    }

    const auto live_projectiles = static_cast<std::size_t>(
        std::count_if(projectiles_.begin(), projectiles_.end(),
                      [](const projectile& pr) { return pr.used; }));
    const std::size_t projectile_budget =
        room() >= 2 ? std::min(live_projectiles, (room() - 2) / 7) : 0;
    w.u8(static_cast<std::uint8_t>(projectile_budget));
    std::size_t written = 0;
    for (const auto& pr : projectiles_) {
        if (written == projectile_budget) break;
        if (!pr.used) continue;
        w.u16(pr.id);
        w.q8(pr.x);
        w.q8(pr.y);
        w.u8(pr.owner);
        ++written;
    }

    const auto& effects = snapshot ? snapshot_effects_ : tick_effects_;
    const std::size_t effect_budget =
        room() >= 1 ? std::min({effects.size(), std::size_t {255}, (room() - 1) / 10}) : 0;
    w.u8(static_cast<std::uint8_t>(effect_budget));
    for (std::size_t i = 0; i < effect_budget; ++i) {
        const auto& e = effects[i];
        w.u8(static_cast<std::uint8_t>(e.kind));
        w.u8(e.owner);
        w.q8(e.x1);
        w.q8(e.y1);
        w.q8(e.x2);
        w.q8(e.y2);
    }
}

auto world::encode_snapshot(std::uint8_t id, std::size_t max_bytes, std::vector<std::byte>& out) const
    -> void
{
    out.clear();
    proto::byte_writer w(out);
    const auto& p = players_[id];
    const auto respawn_ms = p.alive ? 0u : p.respawn_ticks * 1000u / kTicksPerSecond;
    const auto rocket_ms =
        static_cast<std::uint32_t>(std::max(0, p.rocket_cooldown)) * 1000u / kTicksPerSecond;
    w.u8(proto::kServerSnapshot);
    w.u32(tick_);
    w.u32(p.acked_seq);
    w.f64(p.x);
    w.f64(p.y);
    w.u8(static_cast<std::uint8_t>(std::clamp(p.hp, 0, kMaxHealth)));
    w.u8(p.alive ? 1 : 0);
    w.u16(static_cast<std::uint16_t>(respawn_ms));
    w.u16(static_cast<std::uint16_t>(rocket_ms));
    encode_body(out, max_bytes, true);
}

auto world::encode_killcam(std::uint8_t killer, std::uint8_t victim, std::vector<std::byte>& out) const
    -> void
{
    out.clear();
    proto::byte_writer w(out);
    w.u8(proto::kKillcamKind);
    w.u8(killer);
    w.u8(victim);
    w.u16(static_cast<std::uint16_t>(filled_frames_));
    const std::size_t start = (next_frame_ + kKillcamFrames - filled_frames_) % kKillcamFrames;
    for (std::size_t i = 0; i < filled_frames_; ++i) {
        const auto& f = frames_[(start + i) % kKillcamFrames];
        w.u16(static_cast<std::uint16_t>(4 + f.body.size()));
        w.u32(f.tick);
        w.bytes(f.body);
    }
}

} // namespace skirmish
