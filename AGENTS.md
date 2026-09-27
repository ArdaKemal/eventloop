# Agent handoff: eventloop

Updated 2026-09-28. Read this before continuing work after a machine or
session switch. Verify all status claims with `git status` and the tests below;
this file is a handoff snapshot, not a substitute for inspecting the code.
Commit or otherwise sync this file and the uncommitted implementation before
switching PCs; a fresh clone will not contain uncommitted work.

## Project intent and constraints

- This is a C++23 library with a Linux epoll event loop, bounded executor,
  WebSocket implementation, and a bounded, loop-affine coroutine runtime.
- Public TCP, TLS, and UDP I/O is coroutine based. Keep the readiness layer
  internal and preserve the bounded coroutine runtime's ownership contracts.
- Keep WebSocket framing bounded and share one parser/output implementation
  across transport types.
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
- `tcp_acceptor::async_accept()` returns a `unique_fd`. Built-in TCP/TLS
  connection tasks retain it until stream construction transfers ownership.
- TCP streams own their sockets, and `async_send_file()` takes ownership of its
  file descriptor through completion.
- The epoll backend and TCP acceptor keep their own descriptors in
  `unique_fd`. The epoll signal mask has a scope guard that restores it after
  all backend descriptors close, including constructor failures. Nested loops
  on one thread share a mask count; the mask is restored after the last loop
  closes. Construct, run, and destroy a loop on the same thread.
- Built-in HTTP connection coroutines own their session state and share the
  document-root descriptor with their listener, so listener removal cannot
  invalidate an accepted session. Redirect connections likewise retain their
  hostname after listener removal. `tests/http_test.cc` exercises both
  lifetimes. The request parser
  rejects control characters in targets and header values before redirects
  can place a target in a `Location` response header.
- WebSocket receive and send are awaitable operations. Protocol or transport
  failures retire parser/output state and close the stream.
- TLS handshake, read, write, and close are awaitable operations. A transport
  failure closes the stream.
- WebSocket outbound framing is capped at the configured maximum message size
  plus frame/control overhead. A full output buffer returns
  `ws::errc::output_full`; protocol and transport failures retire the parser
  and close the stream. Empty close reasons and empty HTTP receive spans are
  safe. A received payload view remains valid until the next `async_receive()`
  or socket destruction.

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

## Current coroutine socket I/O slice

- `include/eventloop/tcp_acceptor.h` and `tcp_stream.h` provide loop-owned TCP
  acceptors/streams with awaitable accept, numeric IPv4 connect, partial
  read/write, and sendfile. `tls_stream.h` adds awaitable TLS operations.
  Accepted descriptors remain `unique_fd` until moved into a registered stream.
- `include/eventloop/udp_socket.h` provides loop-owned numeric IPv4 datagram
  send/receive operations. Datagrams remain atomic; oversized receives return
  `EMSGSIZE`, and zero-length datagrams succeed.
- Socket awaiters keep one pending operation per direction, use caller-owned
  buffers, and resume on the owning loop. Register handlers with
  `event_loop::add` before awaiting. Use `close()` to cancel pending operations
  and remove a handler; direct removal with a suspended awaiter is a programming
  error. A pending connect failure/cancellation removes its TCP socket; an
  immediate connect error leaves it registered for the caller to close.
- TLS permits one read and one write at a time, and those directions may
  overlap. A duplicate same-direction operation reports `EBUSY`; handshake and
  `async_close()` require an idle stream. The shared encrypted-output buffer
  uses one bounded flusher with one waiting operation.
- The epoll backend supports independently enabled read/write readiness. The
  socket APIs do not add DNS or IPv6.
- `tests/tcp_coroutine.cc` and `tests/udp_coroutine.cc` cover loopback I/O,
  duplicate waiters, cancellation, shutdown, readiness rearming, and descriptor
  closure. The focused CTest run passed both on 2026-09-27 with local socket
  access, and Valgrind Memcheck passed both after the refused-connect case was
  added. An AddressSanitizer build is unavailable on this host because GCC's
  `libasan.so` linker stub points to a missing `/usr/lib64/libasan.so.8.0.0`.
- `benchmark/coroutine_socket_benchmark.cc` runs concurrent 64-byte loopback
  echo clients for TCP or UDP. The 2026-09-27 16-client, 10,000-round-trip
  profiles measured 59.1k TCP and 74.3k UDP round trips/s before the current
  public API migration. They are historical baselines, not measurements of the
  current branch. Those runs included the local kernel network stack and do
  not predict NIC throughput. Kernel function symbols were unavailable in
  perf reports on this host. Three sequential runs after the migration on
  2026-09-28 measured medians of 60.7k TCP and 75.6k UDP round trips/s at the
  same settings. This is a small directional difference from separate-day
  measurements, not a controlled performance claim.

## Important limits and decisions still open

1. Do not claim a storage-performance win from the file-I/O benchmark. On
   Fedora 44, three cached-read runs favored the bounded worker over the
   former io_uring path (median 608k vs 578k ops/s and 8.1 vs 234.1 us timer
   lateness p99). The benchmark uses `/tmp`, which is `tmpfs` on this host, so
   it measures runtime overhead rather than storage. The io_uring backend was
   removed on 2026-09-27 because no project workload justified its complexity.
2. HTTP connection coroutines own their sessions while suspended. Preserve
   `open_beneath`'s component-by-component `O_NOFOLLOW` checks; replacing it
   with one unrestricted `openat` would change path security. Plain HTTP still
   uses `sendfile` for large files.
3. The overall library still compiles a Linux epoll backend unconditionally;
   other operating systems are **not** supported yet.
4. The historical lifetime audit predates the coroutine-native transport
   migration. `event_loop::shutdown()` requests cancellation of active roots
   immediately, and built-in socket handlers close in `on_shutdown()`. The
   timeout only bounds handlers still registered after notification; it does
   not let HTTP responses drain. Keep auditing ownership boundaries and use
   sanitizer runs for new exception or cancellation paths.
5. WebSocket output is bounded within its framing layer. The `ws::broadcast`
   and `ws::broadcast_binary` helpers use best-effort fan-out: a full recipient
   drops only the current message, the result counts drops, and healthy
   recipients continue. Callers own recipient lifetimes and may choose their
   own response to drops. Confirm the configured message and queue limits
   against the target workload before deployment.
6. TCP/TLS echo and HTTP examples use the coroutine socket APIs. UDP
   cancellation of an already-pending send is not
   directly covered because saturating the kernel's UDP send queue is not
   deterministic. Keep validating these APIs against their target workloads.

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
./build/coroutine_tcp_test
./build/coroutine_udp_test
./build/coroutine_socket_benchmark both 10000 16
```

On 2026-09-28, the Release build completed with `CCACHE_DISABLE=1` because the
configured ccache directory was read-only. The full CTest suite passed 12/12
with local loopback socket access; the non-socket tests passed 7/7 under the
restricted sandbox. A local HTTP `Connection: close` benchmark at 16
connections and one client
thread measured about 13.7k requests/s before and after the ownership change;
this is evidence of no detectable regression on this host, not a broader
performance claim, and predates the current coroutine-native API migration.

Use build directories ignored by Git or outside the repository on the new
machine. Recheck warnings, `git diff --check`, and test results after changes.

## Worktree and commit scope

Before any commit, inspect `git status` and stage only intended files. The
file-I/O slice remains experimental infrastructure, not a completed
cross-platform or performance improvement. After a commit, verify the commit
and worktree with `git status` rather than relying on this snapshot.
