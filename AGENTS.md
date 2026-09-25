# Agent handoff: eventloop

Updated 2026-09-25. Read this before continuing work after a machine or
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
- I/O, cancellation, and coroutine resumption are serialized on the owning
  event-loop thread. Worker threads must post completions back to that loop.
- Relative timer deadlines saturate at the latest representable time point;
  cancellation tests cover `duration::max()` without waiting for that delay.
- Do not treat destruction of an unfinished task as cancellation. Outstanding
  kernel or worker references must retire before a frame is destroyed.
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
  removal. `tests/http_test.cc` exercises both lifetimes.
- A WebSocket message callback or underlying write exception now retires the
  parser/output state and closes its stream. Normal-path allocation reuse is
  still covered by `tests/web_socket.cc`.
- WebSocket outbound framing is capped at the configured maximum message size
  plus frame/control overhead. A saturated send throws `std::length_error`.
  Large inbound batches are parsed in 4 KiB chunks; reentrant `receive` is
  rejected to keep callback payload views valid.

## Current file-I/O slice

- `include/eventloop/file_io.h` exposes `async_openat`, `async_read_at`, and
  `async_write_at` for loop-affine tasks. They return `std::expected` with
  `std::error_code`. Paths are copied into a 256-byte awaiter buffer; read and
  write buffers remain caller-owned until completion, including cancellation.
- `src/event_loop.cc` implements a liburing backend when available and a
  dedicated bounded worker fallback. `event_loop_options::file_backend` may
  force either backend; `automatic` currently prefers io_uring on Linux when
  ring setup succeeds. `file_io_depth` bounds accepted operations.
- Ring completions are processed in capped batches to protect other loop work.
  A failed/short submission reports an error; an unsubmitted SQE is changed
  into a NOP so it cannot retain a pointer into a destroyed coroutine frame.
- `tests/file_io.cc` covers both backends, round-trip I/O, missing files,
  capacity, shutdown cancellation, and an isolated seccomp-injected submission
  error. Link-wrapped one-shot negative and zero-count submission results
  check that a later ring operation flushes the NOP and completes. Forced-ring
  tests skip if the environment prohibits io_uring.
- `benchmark/file_io_benchmark.cc` compares 100,000 cached 4 KiB reads at
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

1. Do not claim a performance win yet. On this WSL2 machine, `/tmp` is
   `tmpfs`, so the existing benchmark is primarily an overhead test. In
   repeated local runs the worker fallback was faster and had lower timer
   lateness than the current one-submit-per-operation io_uring path. Measure
   representative files on the target filesystem/host before choosing a
   production default or integrating the path into HTTP.
2. Submission recovery is tested with one-shot synthetic negative and
   zero-count results when liburing and GNU/Clang linker wrapping are
   available. The production path
   relies on non-SQPOLL ordering and admits one new SQE only after flushing
   pending NOPs. Revisit these assumptions before adding SQPOLL or batching.
3. If optimizing io_uring, investigate safe submission batching and preserve
   the capped completion-drain/fairness behavior. Compare p99 timer latency as
   well as throughput. Do not optimize on one WSL/tmpfs result alone.
4. An HTTP integration needs explicit session/coroutine lifetime ownership
   before a suspended operation may refer to a session. Preserve
   `open_beneath`'s component-by-component `O_NOFOLLOW` checks; replacing it
   with one unrestricted `openat` would change path security. Leave large-file
   `sendfile` in place until measured otherwise.
5. The fallback handles Linux builds without liburing or systems where ring
   setup is denied. The overall library still compiles a Linux epoll backend
   unconditionally; other operating systems are **not** supported yet.
6. A recent lifetime audit fixed reentrant and throwing shutdown callbacks,
   and an ASan-confirmed use-after-free when a direct write callback closed its
   own stream. Direct transport callbacks now defer handler removal until they
   return. This is not a proof of memory safety across every transport and
   coroutine path; keep auditing ownership boundaries and use sanitizer runs
   for new exception or cancellation paths.
7. WebSocket output is bounded within its framing layer, but application
   broadcast fan-out still needs a policy for slow clients. Confirm the
   configured message and queue limits against the target workload before
   deployment.

## Environment and verification

Build dependencies include a C++23 compiler, CMake, Botan 3, threads, and
optionally `pkg-config` plus `liburing-dev`. On the WSL2 machine used for this
handoff, `io_uring_setup` returns `EPERM` inside the agent's command sandbox
but succeeds when the test is run outside that sandbox. Do not mistake that
for a kernel or liburing failure. `/home/anon/eventloop` is WSL ext4; `/tmp`
is memory-backed `tmpfs`. Windows-mounted `/mnt/...` paths have different I/O
characteristics.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
./build/file_io_test
./build/file_io_benchmark
```

Run the forced-ring test and benchmark outside a seccomp sandbox (or with the
necessary approval) to exercise io_uring. Loopback tests also require socket
access. The latest full elevated run passed all 10 tests. A fallback-only build
and ASan/UBSan file-I/O test also passed:

```sh
cmake -S . -B build-no-uring -DCMAKE_DISABLE_FIND_PACKAGE_PkgConfig=ON
cmake --build build-no-uring --target file_io_test -j2
ctest --test-dir build-no-uring --output-on-failure -R '^file_io$'

cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-asan --target file_io_test -j2
./build-asan/file_io_test
```

The event-loop test also passed under ASan/UBSan after the accepted-descriptor
failure-path test was added. A local HTTP `Connection: close` benchmark at
16 connections and one client thread measured about 13.7k requests/s before
and after the ownership change; this is evidence of no detectable regression
on this host, not a broader performance claim.

Use build directories ignored by Git or outside the repository on the new
machine. Recheck warnings, `git diff --check`, and test results after changes.

## Worktree and commit scope

`docs/executor-implementation-plan.md` was untracked before the file-I/O
work; preserve it and do not stage all of `docs/` by accident. Before any
commit, inspect `git status` and stage only intended files. The file-I/O
slice remains experimental infrastructure, not a completed cross-platform or
performance improvement. After a commit, verify the commit and worktree with
`git status` rather than relying on this snapshot.
