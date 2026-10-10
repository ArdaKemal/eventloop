# Agent guidance for eventloop

## Read only what the change needs

Check Git status, current code, CMake, and relevant contracts; historical status
claims are not evidence. [README.md](README.md) is the user entry point;
[docs/api-contract.md](docs/api-contract.md) indexes behavioral contracts.
For async changes, read [coroutines](docs/coroutines.md); for public API changes,
read [conventions](docs/api-conventions.md). For HTTP, read
[shared HTTP](docs/http.md) plus only the affected protocol:
[1.1](docs/http1.1.md), [2](docs/http2.md), or [3](docs/http3.md).
Load additional contracts only when crossing their boundaries.

## Design priorities

1. Correct ownership, cancellation, protocol behavior, and loop affinity.
2. Explicit bounds and useful exhaustion errors.
3. Small public APIs following existing coroutine conventions.
4. Simple implementation; measured performance where it matters.

Before adding a type, layer, switch, dependency, or public operation, identify
an actual caller and use case. Reuse existing operations; keep protocol,
platform, readiness, and scheduling machinery private. Add abstractions only
when they remove repetition in actual callers without hiding ownership,
capacity, or errors. Keep names/results consistent with neighboring APIs and
update the relevant contract when behavior changes.

Per-packet/frame/read/write/wakeup state belongs in caller storage, awaiting
frames, or bounded pools/queues. State capacity and exhaustion results at the
API boundary. Prefer direct awaiters for single readiness/syscall operations.
Setup and third-party libraries may allocate; claim allocation-free behavior
only for measured paths, separately from startup and handshakes.

## Implementation invariants

- C++23; Linux epoll, macOS kqueue, Windows IOCP. Public TCP/TLS/UDP/QUIC I/O
  is coroutine based. I/O, cancellation, and resumption stay on the owner loop;
  workers post completions there. Wrong-loop use is a programming error.
- Frames use bounded per-loop size classes, with no individual-frame heap
  fallback. Workers must retire references before frames are released.
  Executor publication and waiter registration share a sequentially consistent
  handshake; preserve it in queue/worker changes.
- Destroying a pending task handle does not cancel work. Keep observed handles,
  borrowed descriptors, and buffers alive through completion, even after
  cancellation. TCP streams own sockets; accept returns `unique_fd`;
  `async_send_file` takes file ownership. Socket `close()` cancels and removes
  registered handlers; a loop-owned stream pointer may then be invalid.
- `shutdown()` cancels active roots immediately; built-in socket handlers close
  in `on_shutdown()`. The grace deadline does not drain HTTP responses.
  Timer/shutdown deadlines saturate at the latest representable time point.
- HTTP connection tasks own session state and share document roots/routers
  across listener removal. Preserve component-by-component `O_NOFOLLOW`
  traversal. Open-file-cache opens/revalidation go through `open_decoded()`;
  shared cached descriptors require explicit-offset reads. HTTP/1.1 sendfile
  duplicates cached descriptors because the TCP operation takes ownership.
- Only the owning task may call `tls_stream::close()` on a loop-owned stream;
  it frees the stream. Preserve bounded TLS buffers and measured request paths;
  OpenSSL handshakes allocate. See protocol contracts for allocation tests and
  HTTP/1.1's input-buffer exception above 256-byte request heads.
- Preserve HTTP/2 closure-history/error distinctions in
  [HTTP/2](docs/http2.md#closed-streams-and-errors) and
  `tests/http2_hardening.cc`. Do not add speculative SETTINGS,
  write-stall, or flood limits without evidence.
- WebSocket framing is bounded and shared across transports; failures close
  the stream. A full broadcast recipient drops that message without blocking
  healthy peers. QUIC stream/lifecycle rules belong in [QUIC](docs/quic.md),
  HTTP/3 behavior in its protocol contract. Scope public claims to verification.

## Change and validation rules

- Before sizeable implementation, name the failing test, spec case, bug, or
  measured bottleneck. Write down the public caller, descriptor/buffer owners,
  capacity/exhaustion, cancellation, and affected platforms; resolve unclear
  boundaries in the contract first. Measure the result afterward.
- Stop and drop a large addition that fails its target or whose complexity
  outweighs demonstrated correctness or significant performance benefit.
  Do not commit it; if left uncommitted, report why. Feature volume,
  speculative hardening, and completeness alone do not justify a change.
- Keep code lean; remove superseded code, temporary workarounds, redundant
  helpers, and speculative abstractions. Group related small changes into
  coherent commits; consolidate related local commits before publishing when
  it improves reviewability.
- Exercise features through realistic public-header examples/integration
  tests. Installed-library changes must also check the exported
  `eventloop::eventloop` CMake target; private-header tests cover internals.
- Dependencies: C++23 compiler, CMake 3.20+, OpenSSL 3.5+, threads. Optional
  HTTP/3 interop needs Python and aioquic 1.3.0; see CMake for test registration.
- Use ignored/external build directories. Before staging, inspect Git status
  and stage only intended files. After code changes, check warnings,
  `git diff --check`, and relevant CTest tests; run the full suite for
  cross-cutting changes. Reproduce failures before labeling them pre-existing.
- Redirect full benchmark output to logs; filter relevant results or targeted
  failures with `rg` before tool output enters context. Old-worktree numbers
  are not current performance claims. `file_io_benchmark` uses a cached `/tmp`
  workload and measures runtime overhead, not storage throughput.
