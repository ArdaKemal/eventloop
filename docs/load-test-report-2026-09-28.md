# Event-loop connection load test report

Date: 2026-09-28

## Follow-up retest after the frame-pool and echo-session fixes

The Release build was rebuilt from the current worktree. Four idle loopback TCP
scales were run with the updated 512-byte echo-session buffer. All target
connections were accepted and spawned; there were no frame allocation failures,
spawn failures, or client poll events indicating a closed connection.

For comparable runs across all targets, the temporary measurement server set
the 1 KiB frame class's capacity to the target plus 32 slots. The other frame
classes kept their defaults. No repository code was changed for the load runs.
Clients remained idle after connect; this follow-up does not repeat the active
request tests in the original baseline below.

| Idle connections | Connect time | Server RSS; increase per connection | Live frames / high-water | Frames backed / configured | Epoll registrations / open FDs | Spawn / allocation failures |
|---:|---:|---:|---:|---:|---:|---:|
| 10,000 | 0.396 s | 20.84 MiB; +1.21 KiB | 10,000 / 10,001 | 10,150 / 10,150 | 10,005 / 10,009 | 0 / 0 |
| 25,000 | 11.107 s | 38.25 MiB; +1.20 KiB | 25,000 / 25,001 | 25,150 / 25,150 | 25,005 / 25,009 | 0 / 0 |
| 50,000 | 22.423 s | 67.18 MiB; +1.19 KiB | 50,000 / 50,001 | 50,150 / 50,150 | 50,005 / 50,009 | 0 / 0 |
| 100,000 | 56.475 s | 125.08 MiB; +1.19 KiB | 100,000 / 100,001 | 100,150 / 100,150 | 100,005 / 100,009 | 0 / 0 |

The reported live-frame count is the steady idle session count after the accept
coroutine returned. The high-water count includes that accept coroutine. Frame
occupancy at the idle snapshot was 98.52%, 99.40%, 99.70%, and 99.85% of backed
slots, respectively. RSS increase per connection is calculated from each
server's listening baseline and includes userspace connection and frame-pool
storage; it excludes kernel socket memory. `sizeof(tcp_stream)` was 96 bytes.

| Idle connections | Context switches at snapshot, voluntary / involuntary | Process CPU at snapshot | C++ `new` calls after ready |
|---:|---:|---:|---:|
| 10,000 | 9,782 / 36 | 0.194 s | 0 |
| 25,000 | 24,524 / 48 | 0.502 s | 0 |
| 50,000 | 49,017 / 143 | 0.998 s | 0 |
| 100,000 | 98,116 / 241 | 2.038 s | 0 |

Context-switch and CPU values are process totals sampled after all connections
were accepted, not deltas from a pre-connect snapshot. No echo requests were
sent, so request latency, CPU/request, and syscalls/request do not apply to
these idle cases. The client used multiple loopback source addresses above
24,000 connections to stay within the ephemeral-port range. The client and
server soft FD limit was raised to 250,000; the 100k case completed under the
host's 7,258,223 epoll-watch limit. The idle workload queued no executor or
post work and armed no coroutine timers; the post-queue high-water counter is
not exposed by the library.

## Follow-up active 100k run

The updated 512-byte echo session was exercised with 100,000 concurrent
loopback clients. Each client completed 100 sequential 64-byte echo round trips
with one request in flight, for 10,000,000 total requests. All replies matched
the sent payload; the preflight check found no closed sockets.

| Connections | Requests completed / expected | Throughput | p50 / p95 / p99 latency | Server CPU per request | Client failures |
|---:|---:|---:|---:|---:|---:|
| 100,000 | 10,000,000 / 10,000,000 | 75.1k req/s | 1,312 / 1,413 / 2,624 ms | 6.83 µs | 0 |

| Metric | Result |
|---|---:|
| Peak sampled server RSS | 125.08 MiB |
| Frame-pool peak live / backed | 100,001 / 100,150 (99.85%) |
| Epoll registrations / open FDs | 100,005 / 100,009 |
| `sizeof(tcp_stream)` | 96 bytes |
| Context-switch delta, voluntary / involuntary | +571,654 / +53,508 |
| C++ `operator new` calls after ready | 100,004 (0.0100 per completed request, inclusive) |
| Client echo failures / frame allocation failures | 0 / 0 |

The server reported 640,000,000 echoed bytes. CPU/request is based on server
process CPU time from the all-connections-ready snapshot (2.10093 s) through
the post-run snapshot (70.3773 s). Context-switch values use the same snapshot
interval. The client measured latency with Python on local loopback, so the
percentiles include client scheduling. The allocation counter stayed enabled
until the client closed its sockets and the server loop returned; its total
includes EOF cleanup and is not an isolated allocation count for request
handling. Syscalls/request were not collected for this 100k run. The workload
used no executor work or coroutine timers, and made no `event_loop::post`
calls; the library does not expose a post-queue high-water counter. After the
clients disconnected, all session frames retired and the pool released its
growth slabs.

## Original baseline before those fixes

The measurements below record the earlier implementation and are retained as
a baseline; the stock-example default-pool failure described there was fixed
by reducing the echo-session frame size.

## Summary

The 10k, 50k, and 100k idle cases all reached their requested connection count
when run with a larger coroutine-frame pool. The 1k, 5k, and 10k active cases
also completed 100 round trips per connection with no echo failures. The 10k
active case completed 1,000,000 requests.

In the original probe, the stock TCP echo example did not reach these counts
with its default frame pool. Its 1,024-byte session buffer placed the coroutine
in a larger class, whose default pool had only six slots. The updated 512-byte
session buffer fits the 1 KiB class and fixes the 10k stock-example failure.

## Test method

The tests used a temporary load driver in `/tmp`, linked against the current
Release `build/libeventloop.a`. Each accepted TCP stream had one coroutine
session using the then-current 1,024-byte echo buffer in `examples/tcp_echo.cc`. Active
clients sent 100 sequential 64-byte requests per connection, with one request
in flight per connection. The active runs were repeated with the client waiting
for the server's actual all-connections-accepted signal before sending traffic.

For the requested scale runs, the temporary driver set the public
`coroutine_frame_capacities[4]` and `[5]` options (2 KiB and 4 KiB classes) to
`target + 32`. The repository's source and library were not changed for these
runs. A separate run with default options and the stock echo example confirmed
the default-pool failure described above.

RSS, FDs, epoll registrations, context switches, and CPU time were sampled
from the server process. Frame-pool values came from
`event_loop::coroutine_statistics()`. A temporary global `operator new`
counter measured allocations after connection setup. Separate `strace -c`
passes counted server syscalls; they include startup, connection setup, and
shutdown, and their latency/throughput results are not used below because
tracing changes timing.

## Idle connections

RSS is shown as total server RSS and the increase over the listening-process
baseline divided by the connection count. The increase includes connection
objects, container nodes, and coroutine-frame slabs. RSS does not include
kernel socket-buffer memory.

| Connections | Server RSS; increase per connection | Frames live / peak; pool backed / configured | Epoll registrations / open FDs | Context-switch delta, voluntary / involuntary |
|---:|---:|---:|---:|---:|
| 10,000 | 31.1 MiB; +2.26 KiB | 10,000 / 10,001; 10,306 / 30,416 | 10,005 / 10,009 | +1 / +3 |
| 50,000 | 117.7 MiB; +2.23 KiB | 50,000 / 50,001; 50,306 / 110,416 | 50,005 / 50,009 | +1 / +22 |
| 100,000 | 226.0 MiB; +2.22 KiB | 100,000 / 100,001; 100,306 / 210,416 | 100,005 / 100,009 | +1 / +59 |

The peak frame count includes the accept coroutine; after it returned, the live
frame count equaled the number of open sessions. All three runs had zero frame
allocation failures and zero C++ `operator new` calls during the idle hold.
Idle context-switch deltas cover the ready-to-stop interval, which was not
identical across runs.

## Active 64-byte echo

All requests completed and matched the sent payload. Latency is measured by the
Python client over local loopback and includes client scheduling. Server CPU
per request uses the server's process CPU-time delta from the ready snapshot to
the post-traffic snapshot.

| Concurrent connections | Requests | Throughput | p50 / p95 / p99 latency | Server CPU per request | Server syscalls per request |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 100,000 | 113.2k req/s | 8.69 / 9.56 / 10.73 ms | 5.51 µs | 2.188 |
| 5,000 | 500,000 | 105.3k req/s | 44.75 / 66.88 / 92.56 ms | 5.62 µs | 2.172 |
| 10,000 | 1,000,000 | 92.9k req/s | 103.15 / 161.71 / 188.72 ms | 6.17 µs | 2.175 |

| Connections | Server RSS; increase per connection | Frames live / peak; pool backed / configured | Epoll registrations / open FDs | Context-switch delta, voluntary / involuntary | C++ allocations per request |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 11.7 MiB; +2.65 KiB | 1,000 / 1,001; 1,298 / 12,416 | 1,005 / 1,009 | +10,521 / +130 | 0 observed `new` calls |
| 5,000 | 20.3 MiB; +2.30 KiB | 5,000 / 5,001; 5,306 / 20,416 | 5,005 / 5,009 | +31,388 / +853 | 0 observed `new` calls |
| 10,000 | 31.1 MiB; +2.26 KiB | 10,000 / 10,001; 10,306 / 30,416 | 10,005 / 10,009 | +69,077 / +4,105 | 0 observed `new` calls |

The syscall totals from the separate traced runs were 218,767 for 100,000
requests, 1,086,023 for 500,000 requests, and 2,175,235 for 1,000,000
requests. These totals include server startup, accepts, connection setup, and
shutdown. The allocation counter covers C++ `operator new`; raw C `malloc` was
not separately interposed.

## Other tracked metrics

- `sizeof(tcp_stream)` was 96 bytes. This excludes the separately allocated
  coroutine frame, handler-container storage, and kernel socket state.
- The post-queue high-water mark was 0: this workload made no `event_loop::post`
  calls. The library does not expose a post-queue high-water counter.
- The executor had 0 queued work. With the default `worker_count == 0`, its
  single-thread executor executes work inline; this test submitted no executor
  work.
- The coroutine timer count was 0. No timer awaiters were used. The timerfd is
  still one of the event-loop backend registrations.
- Epoll registrations were `N + 5`: one per stream, the listener, and four
  event-loop backend descriptors. Open FDs were `N + 9`, including standard
  streams and those backend/listener descriptors.

## Host limits and scope

The host had 32,757,500 KiB total memory and 27,472,600 KiB available at the
start. The process soft FD limit was 1,024 (hard limit 524,288); the test
processes raised their soft limit to 250,000. The epoll watch limit was
7,258,223. The listener backlog limit was 4,096. The ephemeral-port range was
32,768–60,999; the 50k and 100k client runs used several loopback source
addresses to stay below the per-address port range.

These are local loopback measurements, not NIC or remote-network throughput
predictions. The RSS figures describe userspace process RSS and exclude kernel
socket memory. The active latency percentiles include the Python load
generator's scheduling cost. No repository source files were changed for the
tests; this report is the only file created in the repository for this work.
