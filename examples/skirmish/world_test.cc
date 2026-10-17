// Simulation tests for skirmish_world_test. Each failed check prints a line and
// the process exits nonzero.
#include "protocol.h"
#include "world.h"

#include <cstdint>
#include <cstdio>
#include <vector>

namespace {

using namespace skirmish;

int failures = 0;

void check(bool condition, const char* what)
{
    if (condition) return;
    ++failures;
    std::fprintf(stderr, "FAILED: %s\n", what);
}

// Deterministic 64-bit LCG so the random walk is reproducible.
struct lcg {
    std::uint64_t state;
    auto next() -> std::uint32_t
    {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        return static_cast<std::uint32_t>(state >> 33);
    }
};

void test_walls_never_entered()
{
    const map arena = make_arena();
    world w(arena);
    w.join(0, "walker");
    lcg random {12345};
    for (std::uint32_t step = 1; step <= 4000; ++step) {
        input in;
        in.seq = step;
        in.buttons = static_cast<std::uint8_t>(random.next() & 0x0f);
        in.yaw = static_cast<std::uint16_t>(random.next() & 0xffff);
        in.view_tick = w.current_tick();
        (void)w.queue_input(0, in);
        tick_events events;
        w.tick(events);
        const auto& p = w.player_at(0);
        if (box_overlaps_wall(arena, p.x, p.y)) {
            check(false, "player box overlaps a wall after movement");
            return;
        }
    }
    check(true, "random walk stays out of walls");
}

void test_deterministic_script()
{
    world w(make_arena());
    w.join(0, "scripted");
    struct segment {
        int ticks;
        std::uint8_t buttons;
        std::uint16_t yaw;
    };
    // Forward along the spawn row, then diagonally, a turn left, then idle.
    const segment script[] = {
        {60, kButtonForward, 0},
        {60, kButtonForward | kButtonRight, 0},
        {30, kButtonLeft, 16384},
        {20, 0, 16384},
    };
    std::uint32_t seq = 1;
    for (const auto& s : script) {
        for (int i = 0; i < s.ticks; ++i, ++seq) {
            input in;
            in.seq = seq;
            in.buttons = s.buttons;
            in.yaw = s.yaw;
            in.view_tick = w.current_tick();
            (void)w.queue_input(0, in);
            tick_events events;
            w.tick(events);
        }
    }
    const auto& p = w.player_at(0);
    std::printf("deterministic final position x=%.17g y=%.17g acked=%u\n", p.x, p.y,
                static_cast<unsigned>(p.acked_seq));
    check(p.acked_seq == seq - 1, "every scripted input was applied");
    check(!box_overlaps_wall(w.arena(), p.x, p.y), "scripted end position is free");
}

// Shooter at (12.5, 16.5) fires east at a target that stood at (18.5, 16.5)
// and then moved to (18.5, 20.5). The fire carries view_tick 5, so the target
// is rewound to its old spot and the shot hits; with view_tick 7 it misses.
int rifle_damage_after_move(std::uint32_t view_tick)
{
    world w(make_arena());
    w.join(0, "shooter");
    w.join(1, "target");
    w.player_at(0).x = 12.5;
    w.player_at(0).y = 16.5;
    w.player_at(1).x = 18.5;
    w.player_at(1).y = 16.5;
    tick_events events;
    for (int i = 0; i < 5; ++i) w.tick(events);
    w.player_at(1).y = 20.5;
    w.tick(events);   // tick 6: target recorded at its new spot
    input in;
    in.seq = 1;
    in.buttons = kButtonFire;
    in.yaw = 0;
    in.view_tick = view_tick;
    (void)w.queue_input(0, in);
    w.tick(events);   // tick 7: the shot is resolved
    return w.player_at(1).hp;
}

void test_rifle_lag_compensation()
{
    check(rifle_damage_after_move(5) == kMaxHealth - kRifleDamage,
          "rewound shot hits the target's earlier position");
    check(rifle_damage_after_move(7) == kMaxHealth, "current-tick shot misses the moved target");
}

void test_rocket_splash_kills()
{
    world w(make_arena());
    w.join(0, "shooter");
    w.join(1, "victim");
    w.player_at(0).x = 12.5;
    w.player_at(0).y = 16.5;
    w.player_at(1).x = 18.5;
    w.player_at(1).y = 16.5;
    w.player_at(1).hp = 30;
    input fire;
    fire.seq = 1;
    fire.buttons = kButtonRocket;
    (void)w.queue_input(0, fire);
    input idle;
    idle.seq = 2;
    (void)w.queue_input(0, idle);
    bool killed = false;
    bool self_hit = false;
    for (int i = 0; i < 90 && !killed; ++i) {
        tick_events events;
        w.tick(events);
        for (const auto& kill : events.kills) {
            if (kill.killer == 0 && kill.victim == 1 && kill.weapon_type == weapon::rocket) killed = true;
            if (kill.victim == 0) self_hit = true;
        }
    }
    check(killed, "rocket splash kills the victim");
    check(!self_hit, "rocket splash does not kill the shooter at range");
    check(!w.player_at(1).alive, "victim is dead after the splash");
    check(w.player_at(0).kills == 1, "shooter is credited with the kill");
}

void test_duplicate_and_old_inputs()
{
    world w(make_arena());
    w.join(0, "queue");
    input in;
    in.seq = 3;
    check(w.queue_input(0, in), "new input is queued");
    check(!w.queue_input(0, in), "duplicate seq is ignored");
    tick_events events;
    w.tick(events);
    w.tick(events);
    w.tick(events);
    in.seq = 2;
    check(!w.queue_input(0, in), "input older than the applied seq is ignored");
    check(w.player_at(0).acked_seq == 3, "seq 3 was applied");
    check(w.lost_inputs() == 2, "seqs 1 and 2 count as lost");
}

void test_snapshot_fits_datagram()
{
    world w(make_arena());
    for (std::uint8_t id = 0; id < kMaxPlayers; ++id) {
        w.join(id, "p" + std::to_string(id));
    }
    // Everyone fires a rifle and a rocket in one tick, which overfills the budget.
    for (std::uint8_t id = 0; id < kMaxPlayers; ++id) {
        input in;
        in.seq = 1;
        in.buttons = kButtonFire | kButtonRocket;
        in.yaw = static_cast<std::uint16_t>(id * 1024);
        (void)w.queue_input(id, in);
    }
    tick_events events;
    w.tick(events);
    w.tick(events);
    std::vector<std::byte> snapshot;
    w.encode_snapshot(0, 1200, snapshot);
    check(snapshot.size() <= 1200, "snapshot fits 1200 bytes with max players");
    check(snapshot.size() > 31 + 1 + kMaxPlayers * 9, "snapshot carries every player");
    check(snapshot[0] == std::byte {proto::kServerSnapshot}, "snapshot has the snapshot type");
    std::printf("max-player snapshot bytes=%zu\n", snapshot.size());
}

void test_killcam_payload()
{
    world w(make_arena());
    w.join(0, "a");
    w.join(1, "b");
    tick_events events;
    for (int i = 0; i < 200; ++i) w.tick(events);
    std::vector<std::byte> payload;
    w.encode_killcam(0, 1, payload);
    check(payload.size() > 5, "killcam payload is not empty");
    check(payload[0] == std::byte {proto::kKillcamKind}, "killcam has the killcam kind");
    const auto frames = std::to_integer<unsigned>(payload[3]) | (std::to_integer<unsigned>(payload[4]) << 8);
    check(frames == kKillcamFrames, "killcam keeps the last 180 frames");
}

} // namespace

int main()
{
    test_walls_never_entered();
    test_deterministic_script();
    test_rifle_lag_compensation();
    test_rocket_splash_kills();
    test_duplicate_and_old_inputs();
    test_snapshot_fits_datagram();
    test_killcam_payload();
    if (failures != 0) {
        std::fprintf(stderr, "%d world test(s) failed\n", failures);
        return 1;
    }
    std::printf("world tests passed\n");
    return 0;
}
