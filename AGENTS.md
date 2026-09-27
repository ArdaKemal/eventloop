# Agent handoff: eventloop

Updated 2026-09-27. Read this before continuing work after a machine or
session switch. Verify all status claims with `git status` and the tests below;
this file is a handoff snapshot, not a substitute for inspecting the code.
Commit or otherwise sync this file and the uncommitted implementation before
switching PCs; a fresh clone will not contain uncommitted work.

## Project intent and constraints

- This is a C++23 library with a Linux epoll event loop, bounded executor,
  WebSocket implementation, and a bounded, loop-affine coroutine runtime.
- Preserve the existing interfaces and implementation style where practical.
  The owner explicitly prefers small changes to the original WebSocket code.
- Coroutine frames come from bounded per-loop size classes. Keep operation
  state in the awaiting frame, avoid general-heap allocation on hot paths, and
  return resource-exhaustion errors instead of silently falling back to heap.
- Executor permit publication and waiter registration use one sequentially
  consistent handshake so an idle worker and a producer cannot both miss the
  other's state. Paired local handoff benchmarks showed similar median rates;
  contended runs remain noisy.
- I/O, cancellation, and coroutine resumption are serialized on the owning
  event-loop thread. Worker threads must post completions back to that loop.
- Relative timer and shutdown grace deadlines saturate at the latest
  representable time point; tests cover `duration::max()` without waiting for
  that delay.
- Coroutine `yield`, timer, and blocking awaiters check loop affinity before
  queuing work. Wrong-loop use terminates as a programming error.
- Do not treat destruction of an unfinished task as cancellation. Outstanding
  worker references must retire before a frame is destroyed.
- Accepted socket descriptors use `unique_fd` through the built-in TCP/TLS
  accept and stream construction paths. New subclasses should override the
  owning callback; the original `int` callbacks remain as compatibility paths
  and still require explicit descriptor ownership on every failure path.
- TCP streams own both their socket and any active sendfile descriptor via
  `unique_fd`. The owning `send_file` overload rejects an invalid file
  descriptor; the `int` overload transfers ownership on entry for compatibility.
- The epoll backend and TCP listener now keep their own descriptors in
  `unique_fd`. The epoll signal mask has a scope guard that restores it after
  all backend descriptors close, including constructor failures. Nested loops
  on one thread share a mask count; the mask is restored after the last loop
  closes. Construct, run, and destroy a loop on the same thread.
- Built-in HTTP connections share ownership of the document-root descriptor
  with their listener, so removing the listener cannot invalidate an accepted
  session. Redirect connections likewise retain their hostname after listener
  removal. `tests/http_test.cc` exercises both lifetimes. The request parser
  rejects control characters in targets and header values before redirects
  can place a target in a `Location` response header.
- A WebSocket message callback or underlying write exception now retires the
  parser/output state and closes its stream. Normal-path allocation reuse is
  still covered by `tests/web_socket.cc`.
- Direct TLS writes and close notifications retire the transport if a
  non-Botan exception interrupts output, since TLS record state may already
  have advanced. A loopback test fills the TCP queue during a TLS write.
- WebSocket outbound framing is capped at the configured maximum message size
  plus frame/control overhead. A saturated send throws `std::length_error`.
  Public `close()` retires the socket if a saturated queue cannot fit its
  close frame. A malformed inbound frame also retires without throwing if a
  saturated queue cannot fit the protocol close frame. Empty close reasons
  and empty HTTP receive spans are safe.
  Large inbound batches are parsed in 4 KiB chunks; reentrant `receive` is
  rejected to keep callback payload views valid.

## Current file-I/O slice

- `include/eventloop/file_io.h` exposes `async_openat`, `async_read_at`, and
  `async_write_at` for loop-affine tasks. They return `std::expected` with
  `std::error_code`. Paths are copied into a 256-byte awaiter buffer; read and
  write buffers remain caller-owned until completion, including cancellation.
- `src/event_loop.cc` runs file operations on a dedicated bounded worker and
  posts completions back to the owning loop. `file_io_depth` bounds accepted
  operations; there is no backend-selection option.
- `tests/file_io.cc` covers round-trip I/O, missing files, capacity, shutdown
  cancellation, wrong-loop use, and cancelled reads with frame-local buffers.
- `benchmark/file_io_benchmark.cc` measures 100,000 cached 4 KiB reads at
  16-way concurrency and records throughput, per-read latency, and timer
  lateness. It currently creates its file in `/tmp`.
- No production HTTP or WebSocket path uses the new file-I/O awaiters yet.
  HTTP still uses synchronous `openat`/`fstat`/small-file reads, and plain HTTP
  uses `sendfile` for larger files. Do not replace those paths blindly.
- HTTP path walking and response construction now hold intermediate file
  descriptors in `unique_fd`; `sendfile` and directory listing receive an
  explicit ownership release. The component-by-component `O_NOFOLLOW` walk
  remains in place.
- `task<T>`, fixed-arity composition, and `task_handle<T>` are available.
  The handle is a stable observed-root scope and must remain alive until its
  task completes. See `docs/api-contract.md` and `tests/task_handle.cc`.

## Important limits and decisions still open

1. Do not claim a storage-performance win from the file-I/O benchmark. On
   Fedora 44, three cached-read runs favored the bounded worker over the
   former io_uring path (median 608k vs 578k ops/s and 8.1 vs 234.1 us timer
   lateness p99). The benchmark uses `/tmp`, which is `tmpfs` on this host, so
   it measures runtime overhead rather than storage. The io_uring backend was
   removed on 2026-09-27 because no project workload justified its complexity.
2. An HTTP integration needs explicit session/coroutine lifetime ownership
   before a suspended operation may refer to a session. Preserve
   `open_beneath`'s component-by-component `O_NOFOLLOW` checks; replacing it
   with one unrestricted `openat` would change path security. Leave large-file
   `sendfile` in place until measured otherwise.
3. The overall library still compiles a Linux epoll backend unconditionally;
   other operating systems are **not** supported yet.
4. A recent lifetime audit fixed reentrant and throwing shutdown callbacks,
   and an ASan-confirmed use-after-free when a direct write callback closed its
   own stream. Direct transport callbacks now defer handler removal until they
   return. This is not a proof of memory safety across every transport and
   coroutine path; keep auditing ownership boundaries and use sanitizer runs
   for new exception or cancellation paths.
5. WebSocket output is bounded within its framing layer, but application
   broadcast fan-out still needs a policy for slow clients. Confirm the
   configured message and queue limits against the target workload before
   deployment.

## Environment and verification

Build dependencies include a C++23 compiler, CMake, Botan 3, and threads. The
current host is Fedora 44 on Linux 7.2.5 with the project on Btrfs and `/tmp`
on memory-backed `tmpfs`.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
./build/file_io_test
./build/file_io_benchmark
```

The fresh Release build succeeded on Fedora 44, and the file-I/O coroutine test
passed directly. The elevated full CTest run passed 9/10 tests; `tls_loopback`
failed during TLS negotiation with `bad_certificate` using its generated test
certificate. The other loopback tests passed when run with socket access. A
local HTTP `Connection: close` benchmark at 16 connections and one client
thread measured about 13.7k requests/s before and after the ownership change;
this is evidence of no detectable regression on this host, not a broader
performance claim.

Use build directories ignored by Git or outside the repository on the new
machine. Recheck warnings, `git diff --check`, and test results after changes.

## Worktree and commit scope

`docs/executor-implementation-plan.md` was untracked before the file-I/O
work; preserve it and do not stage all of `docs/` by accident. Before any
commit, inspect `git status` and stage only intended files. The file-I/O
slice remains experimental infrastructure, not a completed cross-platform or
performance improvement. After a commit, verify the commit and worktree with
`git status` rather than relying on this snapshot.
