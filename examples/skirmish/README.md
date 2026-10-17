# Skirmish

Skirmish is a multiplayer first-person arena shooter that runs in the browser
and talks to an eventloop server over WebTransport (HTTP/3). It is a showcase
and a stress test: every WebTransport feature carries real game traffic, and
a bot swarm drives the same browser code path at scale.

- Server-authoritative 60 Hz simulation with 30 Hz snapshots, client-side
  prediction and reconciliation, interpolation, and lag-compensated hitscan.
- Rifle and rockets, kill feed, chat, scoreboard, and a killcam replayed from
  the killer's eye.
- WebGL rendering with three.js (loaded from jsDelivr, so the page needs
  internet access), plus a top-down minimap.

| WebTransport feature | Game traffic |
| --- | --- |
| Datagrams, client → server | 60 Hz input with 4× redundancy, pings |
| Datagrams, server → client | 30 Hz snapshots (up to ~1.2 KB), pongs |
| Long-lived bidirectional stream | Join handshake, then reliable game events |
| Short-lived bidirectional streams | Scoreboard requests |
| Client unidirectional streams | One chat message per stream |
| Server unidirectional streams | Paced killcam replays: completed, cancelled by the client (STOP_SENDING), or reset on respawn |
| Session close code and reason | Server full, too slow, protocol error, shutdown |

The byte-level contract is in [PROTOCOL.md](PROTOCOL.md).

## Build and run

```sh
cmake -S examples/skirmish -B /tmp/skirmish-build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/skirmish-build --target skirmish
/tmp/skirmish-build/skirmish            # https://127.0.0.1:4443/
```

On macOS, Apple clang 21 crashes compiling the QUIC sources; configure with
Homebrew GCC (`CXX=g++-16 CC=gcc-16`).

Open `https://127.0.0.1:4443/` in Chrome and accept the certificate warning.
The server generates a fresh P-256 certificate valid for 13 days on every
start and publishes its hash at `/cert-hash`, which the page passes to
`serverCertificateHashes`. A page opened on `localhost` reloads itself on
`127.0.0.1`: `localhost` resolves to `::1` first, Chrome's WebTransport does
not fall back to IPv4, and the server binds IPv4 by default.

| Option | Default | Meaning |
| --- | --- | --- |
| `--bind ADDRESS` | `127.0.0.1` | Numeric IPv4 or IPv6 listen address |
| `--port PORT` | `4443` | HTTPS (TCP) and WebTransport (UDP) port |
| `--max-players N` | `16` | 1..64; more sessions are closed with code 1 |
| `--killcam-speed X` | `1.25` | Replay pacing; `1` races the respawn so replays are reset, `0` sends unpaced |
| `--web DIR` | source `web/` | Browser client files |

Controls: WASD to move, mouse to look, left click for the rifle, right click
for rockets, T to chat, Tab for the scoreboard, M for the minimap, F3 for
network statistics (RTT, snapshot loss, unacked inputs, prediction error).

## Bots and load

`bots.html?n=N` runs N bots in one page, each with its own WebTransport
session (browsers negotiate draft-07, which allows one session per
connection). Bots move, aim, fire, chat, request scoreboards, and cancel half
of their killcams. `swarm.sh [bots] [pages] [port]` opens bot pages in
headless Chrome:

```sh
/tmp/skirmish-build/skirmish --max-players 64 &
examples/skirmish/swarm.sh 32 2
```

The server prints a statistics line every 5 seconds: players, inputs and lost
inputs, snapshots and send failures, killcams completed/cancelled/reset,
chats, scoreboard requests, sessions closed by code, and live coroutines.

Measured on macOS (kqueue) with headless Chrome 155 on the same machine,
2026-10-17: 64 bots for 60 s, every 5 s 19,200 inputs with none lost and
9,600 snapshots with no send failures or client-measured loss, no unexpected
session closes, about 10% of one core and 64 MB RSS for the server.
Prediction error stayed 0, so the JavaScript and C++ movement code agree.
These are loopback numbers, not network results.

`skirmish_world_test` covers the simulation: wall collision, deterministic
movement, rewound rifle hits, rocket splash, and snapshot size at 64 players.

## Repeatable WebTransport smoke test

From the repository root, with the build dependencies above and Python 3.11+:

```sh
python3 -m venv /tmp/skirmish-interop-venv
/tmp/skirmish-interop-venv/bin/python -m pip install aioquic==1.3.0
cmake -S examples/skirmish -B /tmp/skirmish-interop-build \
  -DCMAKE_BUILD_TYPE=Release -DSKIRMISH_INTEROP_TESTS=ON \
  -DPython3_EXECUTABLE=/tmp/skirmish-interop-venv/bin/python
cmake --build /tmp/skirmish-interop-build --target skirmish skirmish_world_test -j2
ctest --test-dir /tmp/skirmish-interop-build -R '^skirmish_' --output-on-failure
```

On macOS, add `-DCMAKE_CXX_COMPILER=g++-16` to the configure command.
To run only the wire check against an existing binary:

```sh
/tmp/skirmish-interop-venv/bin/python examples/skirmish/smoke_test.py \
  --server /tmp/skirmish-interop-build/skirmish
```

The optional `skirmish_webtransport` CTest starts the real demo on an ephemeral
IPv4 loopback TCP/UDP port with one player slot and stops it afterward. It
checks `/cert-hash` against the generated P-256 certificate, verifies that
certificate for QUIC, rejects missing/foreign origins, and negotiates
draft-07 (`:protocol webtransport`, `skirmish/1`). It then checks fragmented
HELLO/WELCOME and JOIN, ping/pong, an input acknowledged in a snapshot,
unidirectional chat, scoreboard data with FIN, and clean session close.
Receive buffers and waits are bounded; CTest has a 40-second outer timeout.
It needs no browser or CDN access and does not exercise JavaScript, rendering,
killcams, or load. The test is off by default and requires aioquic 1.3.0
when enabled, following the repository's optional HTTP/3 interop tests.
