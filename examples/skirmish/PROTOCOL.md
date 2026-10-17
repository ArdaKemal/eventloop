# Skirmish wire protocol

Skirmish is a server-authoritative multiplayer first-person arena shooter used
to stress eventloop's WebTransport server with real browsers. The server
(`examples/skirmish/*.cc`) and the browser client (`examples/skirmish/web/`)
both implement this document exactly. All integers are little-endian. `q8`
means an unsigned 16-bit fixed-point value `round(v * 256)` (map coordinates
are below 256). `yaw16` is an angle as `u16`: `yaw = v / 65536 * 2π`.

## Transport mapping

| WebTransport feature | Used for |
| --- | --- |
| Session | `CONNECT https://<host>:<port>/arena`, protocol `skirmish/1` |
| Client datagrams | 60 Hz input with redundancy; ping |
| Server datagrams | 30 Hz snapshots; pong |
| First client bidi stream | Control: HELLO, then server events (WELCOME, JOIN, LEAVE, KILL, CHAT, NOTICE) |
| Later client bidi streams | Scoreboard RPC: one request, one response, FIN both ways |
| Client uni streams | One chat message per stream |
| Server uni streams | Killcam replay (bulk, ~10–150 KB); client may cancel (STOP_SENDING), server resets it on respawn |
| Session close code/reason | Kicks and shutdown (codes below) |

The page is served over HTTPS on TCP port P (default 4443); WebTransport runs
on UDP port P. `GET /cert-hash` returns `{"sha256":"<base64 of SHA-256 of the
DER certificate>"}`; the client passes it in `serverCertificateHashes`. The
server generates a fresh P-256 certificate valid 13 days on every start (the
`serverCertificateHashes` rule requires ECDSA and at most 14 days).

The server rejects a CONNECT whose `Origin` is not `https://` + the request's
`:authority` with 403 before accepting.

## Simulation constants (both sides)

| Name | Value |
| --- | --- |
| Tick rate | 60 Hz, `dt = 1/60` s; snapshots every 2nd tick (30 Hz) |
| Player radius | 0.25 |
| Move speed | 4.0 units/s |
| Health | 100; respawn 3000 ms after death |
| Rifle | hitscan, 15 damage, 100 ms cooldown, range 30, lag compensated |
| Rocket | speed 12 units/s, 1500 ms cooldown, radius 0.1, splash radius 1.5, damage 80 at center falling linearly to 20 at the edge, shooter takes 50% |

Map: `w × h` cells (`u8` each, row-major, `y * w + x`), 0 = floor,
1–4 = wall styles. Cell `(cx, cy)` covers `[cx, cx+1) × [cy, cy+1)`. Points
outside the map count as walls.

Movement for one input (the client predicts with the identical algorithm in
float64; the server uses `double`):

```
yaw = yaw16 / 65536 * 2π
fx = cos(yaw), fy = sin(yaw)          // forward
rx = -sin(yaw), ry = cos(yaw)         // right
mx = (fwd - back) * fx + (right - left) * rx
my = (fwd - back) * fy + (right - left) * ry
len = sqrt(mx*mx + my*my); if len > 0: mx /= len; my /= len
dx = mx * 4.0 / 60, dy = my * 4.0 / 60
x = move_axis(x, y, dx, horizontal)
y = move_axis(x, y, dy, vertical)
```

`move_axis` moves along one axis, then if the circle's bounding box
`[x-r, x+r] × [y-r, y+r]` overlaps any wall cell, clamps to the touching
position: moving +: `pos = floor(pos + r) - r - 0.001`; moving −:
`pos = floor(pos - r) + 1 + r + 0.001`. Dead players do not move.

## Datagrams

### Client → server

`INPUT` (type 1), sent once per 1/60 s from a fixed-step accumulator:

```
u8  type = 1
u32 newest_seq            // first input is seq 1
u8  count                 // 1..4: newest_seq, newest_seq-1, ... (redundancy)
count × {
  u8  buttons             // bit0 fwd, bit1 back, bit2 left, bit3 right, bit4 fire, bit5 rocket
  u16 yaw16
  u32 view_tick           // server tick the client was rendering (for lag compensation)
}
```

The server keeps a bounded queue (16) of unprocessed inputs per player,
ignores seqs it already has or processed, and each tick consumes one input
(two when more than 4 are queued). With none queued it repeats the last
buttons/yaw without advancing the acked seq. Seqs skipped forever count as
lost inputs in the server statistics.

`PING` (type 2): `u8 type = 2, f64 client_time_ms`. The server echoes it
unchanged as `PONG`.

### Server → client

`SNAPSHOT` (type 3), every 2nd tick:

```
u8  type = 3
u32 tick
u32 ack_seq               // newest input seq applied for this client (0 = none)
f64 self_x, f64 self_y    // exact authoritative position after ack_seq
u8  self_hp
u8  self_flags            // bit0 alive
u16 respawn_ms            // remaining when dead, else 0
u16 rocket_cooldown_ms
<world frame body>
```

World frame body (also used by killcam frames):

```
u8 player_count, player_count × {        // 9 bytes, includes self
  u8 id, q8 x, q8 y, yaw16 yaw, u8 hp,
  u8 flags                                // bit0 alive, bit1 fired since previous frame
}
u8 projectile_count, projectile_count × { // 7 bytes
  u16 id, q8 x, q8 y, u8 owner
}
u8 effect_count, effect_count × {         // 10 bytes
  u8 kind,                                // 1 rifle tracer, 2 explosion (x2,y2 unused = 0)
  u8 owner, q8 x1, q8 y1, q8 x2, q8 y2
}
```

Effects are those created since the previous snapshot (for a killcam frame,
since the previous tick). The server drops projectiles, then effects, from a
snapshot that would exceed `max_datagram_size()`.

`PONG` (type 2): the PING bytes echoed.

## Streams

All control-stream messages in both directions are framed as
`u16 length` (of type + payload) `u8 type` payload. Names are UTF-8, 1..16 bytes.

### Control stream (first client bidirectional stream)

Client → server:

- `HELLO` (1): `u8 name_len, name`. Must arrive within 5 s of acceptance.
  The client keeps its side open; FIN means it is leaving.

Server → client:

- `WELCOME` (1): `u8 your_id, u16 tick_rate, u16 snapshot_rate, u8 map_w,
  u8 map_h, map_w*map_h cells, u8 player_count, player_count × {u8 id,
  u8 name_len, name, u16 kills, u16 deaths}` (others already in the game).
- `JOIN` (2): `u8 id, u8 name_len, name`
- `LEAVE` (3): `u8 id`
- `KILL` (4): `u8 killer, u8 victim, u8 weapon` (1 rifle, 2 rocket)
- `CHAT` (5): `u8 id, u8 len, text`
- `NOTICE` (6): `u8 len, text`

Each player's outgoing events go through a bounded queue (256). A player
whose queue overflows is closed with code 2.

### Scoreboard RPC (any later client bidirectional stream)

Request: `u8 1`, then FIN. Response: `u8 count, count × {u8 id, u8 name_len,
name, u16 kills, u16 deaths}`, then FIN. At most 4 in flight per player;
further ones are reset with code `0x12` (busy).

### Chat (client unidirectional stream)

UTF-8 text, 1..200 bytes, then FIN. Longer: server sends STOP_SENDING `0x11`
and drops it. More than one message per 500 ms: dropped with a NOTICE.
Accepted text is broadcast as `CHAT` to everyone, sender included.

### Killcam (server unidirectional stream)

Opened when the player dies:

```
u8  kind = 1
u8  killer_id, u8 victim_id
u16 frame_count                    // the last ≤180 ticks (3 s) before death
frame_count × { u16 len, u32 tick, <world frame body> }
```

then FIN. The client plays it from the killer's point of view while dead.
Frames are streamed at `--killcam-speed` × playback rate (default 1.25, so a
3 s replay takes about 2.4 s; `1` makes it race the 3 s respawn and be reset;
`0` sends it unpaced), so it can be cancelled mid-stream. The client may cancel it early (bots do so half the time), which
the server sees as STOP_SENDING. If the victim respawns before the write
finishes, the server calls `reset(0x10)`. A new death before that replaces a
replay still streaming: the old one is reset with `0x13`.

## Session close codes

| Code | Reason |
| --- | --- |
| 1 | server full |
| 2 | too slow (event queue overflow) |
| 3 | protocol error (bad message, no HELLO in 5 s) |
| 4 | server shutting down |
| 5 | invalid name |
