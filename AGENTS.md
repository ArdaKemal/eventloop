# Agent guidance for eventloop

This file records constraints that are easy to break while changing the
library. Check the current code, CMake configuration, Git status, and relevant
documentation before relying on an old status claim. The user-facing entry
point is [README.md](README.md); API behavior is specified in
[docs/api-contract.md](docs/api-contract.md) and
[docs/api-conventions.md](docs/api-conventions.md).

## Design intent

Build a small networking library whose public operations are easy to use
correctly and whose memory use stays predictable under load. Preserve this
priority order when requirements compete:

1. Correct ownership, cancellation, protocol behavior, and loop affinity.
2. Explicit bounds and useful errors when those bounds are reached.
3. A small public API that follows the existing coroutine conventions.
4. Simple implementation with measured performance where it matters.

Before adding a type, layer, configuration switch, or dependency, identify
the caller and the concrete use case. Reuse an existing operation when it
covers that use case. Keep protocol and platform machinery private. Add a
public operation only when an application can use it without knowing internal
readiness, scheduling, or buffer state. Keep names and result types consistent
with neighboring APIs; update the API contract when behavior changes.

Treat allocation behavior as part of the design. Per-packet, per-frame,
per-read/write, and per-wakeup paths should use caller storage, frame-local
state, or explicitly bounded pools and queues. State the capacity and the
exhaustion result at the API boundary. Startup, configuration, and third-party
libraries such as OpenSSL may allocate; describe those separately and do not
claim allocation-free behavior without measuring the path in question. Avoid
adding a coroutine frame for a single readiness or syscall operation when a
direct awaiter fits.

Use the public API from examples and integration tests. A new feature should
have at least one realistic caller that does not include private headers or
reach into transport internals. Prefer a small end-to-end example over a
helper layer created only for hypothetical reuse. Before adding an abstraction,
check whether it removes repetition in actual callers and preserves capacity,
ownership, and error visibility.

## Project shape

- C++23 library with Linux epoll, macOS kqueue, and Windows IOCP backends.
- The event loop owns I/O, cancellation, and coroutine resumption on one
  thread. Workers post completion to the owner loop.
- Public TCP, TLS, UDP, and QUIC I/O is coroutine based. Keep readiness and
  platform poller APIs internal.
- Coroutine frames use bounded per-loop size classes. Keep operation state in
  the awaiting frame where practical; report capacity exhaustion instead of
  silently falling back to general-heap allocation.
- Bounded executor publication and waiter registration share a sequentially
  consistent handshake. Preserve it when editing queue or worker code.

## Ownership and cancellation

- A pending task is not cancelled merely by destroying its handle. Keep
  observed task handles alive until completion. Worker references must retire
  before a coroutine frame is released.
- Borrowed descriptors and buffers used by file or socket awaiters stay valid
  until completion, including after cancellation is requested.
- TCP streams own sockets; `tcp_acceptor::async_accept()` returns `unique_fd`.
  `tcp_stream::async_send_file()` takes file-descriptor ownership through
  completion. Use `close()` to cancel and remove registered socket handlers.
- Built-in HTTP connection tasks own their session state. Keep accepted
  descriptors and shared document roots alive across listener removal.
  Preserve the component-by-component `O_NOFOLLOW` path walk.
- `event_loop::shutdown()` requests cancellation of active roots immediately.
  Built-in socket handlers close in `on_shutdown()`; the grace timeout does
  not let unfinished HTTP responses drain.
- Wrong-loop coroutine use is a programming error. Timer and shutdown
  deadlines saturate at the latest representable time point.

## Protocol boundaries

- WebSocket parsing and outbound framing are bounded and shared across
  transports. Protocol or transport failures close the stream. A full
  recipient in broadcast drops that message without blocking healthy peers.
- TLS uses OpenSSL 3.5+ with fixed-capacity stream buffers. Steady-state
  HTTP/2 and HTTP/3 requests are measured to make no OpenSSL allocations,
  but handshakes allocate inside OpenSSL; do not claim more than that.
- HTTP/2 closed streams (`tests/http2_hardening.cc`): streams keep a 64-entry
  closure history, so frames after END_STREAM are a STREAM_CLOSED connection
  error, after the peer's RST_STREAM a stream error, and frames racing our own
  RST_STREAM are discarded; skipped lower stream IDs are PROTOCOL_ERROR. A
  content-length overrun is a stream PROTOCOL_ERROR. h2spec 2.6.0
  (`-t -k -S`) passes 147/147 with none skipped; `tests/run_h2spec.sh` runs it
  as CTest `http2_h2spec` when `h2spec` is on PATH or `-DH2SPEC_EXECUTABLE` is
  set (the binary is not vendored). Its index.html is 300 KB because h2spec
  skips the 6.9.2 window test against a small response. HTTP/2 has no idle,
  SETTINGS, write-stall, or flood limits: they were built and reverted because
  no failing test or measured problem justified them (see the change-value
  rule). `tls_stream::close()` frees the stream, so only the owning task may
  call it. `http2_routing_allocations`, `http2_file_transfer` and
  `http3_server` already failed on a clean `origin/main` on this host.
- HTTP/1.1, TLS HTTP/2, and HTTP/3 servers run `http::router` handlers and
  fall back to static files with secure resource traversal. Plain HTTP uses
  `sendfile` for larger files on Linux. Static HTTP/2 and HTTP/3 support
  bounded GET, HEAD, and OPTIONS operations. Routed handler frames must fit
  their size classes; steady-state routed requests on all three protocols,
  and static HTTP/2 and HTTP/3 file requests, are measured allocation-free,
  so keep them that way.
- QUIC v1/v2 public endpoints, streams, and DATAGRAMs are implemented. The
  Wayfarer and Stonegate examples exercise HTTP/1.1, HTTP/2, and HTTP/3 through
  public APIs. Root HTTP/3 test fixtures and optional aioquic v1/v2 tests are
  documented in [docs/http3-outbound-tests.md](docs/http3-outbound-tests.md).
  Transport release gates and remaining endpoint work are in
  [docs/quic-milestone.md](docs/quic-milestone.md). Keep public claims scoped to
  verified behavior.

## Working in this repository

- Do not commit, and stop working on, a large code addition that neither
  solves a demonstrated problem nor improves performance significantly. Before
  building something sizeable, name the failing test, spec case, bug, or
  measured bottleneck it fixes, and measure the result afterward. If it fails
  that test, drop it (or leave it uncommitted and report why) instead of
  polishing it. Feature volume, speculative hardening, and completeness alone
  are not reasons to commit.
- Before implementation, write down the intended public caller, ownership of
  every descriptor and buffer, capacity and exhaustion behavior, cancellation
  behavior, and affected platforms. Resolve unclear boundaries in the API
  contract before spreading assumptions through implementation files.
- Review new features through a public-header caller. For an installed-library
  change, check the exported `eventloop::eventloop` CMake target as well as
  in-tree examples. Keep private-header tests for protocol internals.
- Build dependencies: a C++23 compiler, CMake 3.20+, OpenSSL 3.5+, and
  threads. Optional HTTP/3 interop tests require Python and aioquic 1.3.0.
- Use Git-ignored or external build directories. Inspect `git status` before
  staging, and stage only intended files.
- After changing code, check warnings, `git diff --check`, and the relevant
  CTest subset; run the full suite when a cross-cutting change warrants it.
- Historical benchmark numbers from old worktrees are not current performance
  claims. `benchmark/file_io_benchmark.cc` uses a cached /tmp workload and
  measures runtime overhead, not storage throughput.
