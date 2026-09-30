# Agent handoff: eventloop

Updated 2026-09-30. Read this before continuing work after a machine or
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
  acceptors/streams with awaitable accept, numeric IPv4 and IPv6 connect, partial
  read/write, and sendfile. `tls_stream.h` adds awaitable TLS operations.
  Accepted descriptors remain `unique_fd` until moved into a registered stream.
- `include/eventloop/ip_endpoint.h` provides the shared fixed-size IPv4/IPv6
  endpoint, including IPv6 scope IDs. IPv6 sockets are explicitly v6-only.
- `include/eventloop/udp_socket.h` provides loop-owned IPv4/IPv6 datagram
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
  socket APIs accept numeric endpoints and do not resolve DNS names.
- `examples/http_client` is a standalone HTTP/1.1 GET example. It resolves on
  the bounded blocking worker, uses system trust and hostname verification for
  HTTPS, and supports IPv4/IPv6 URLs. DNS candidates are tried sequentially;
  it does not implement Happy Eyeballs, response parsing, redirects, or a
  reusable client library API.
- HTTPS advertises HTTP/2 (`h2`) and HTTP/1.1 through ALPN by default;
  `http::server_options::enable_http2` disables HTTP/2. The bounded HTTP/2
  implementation lives under `src/http2`, shares HTTP/1.1's secure resource
  traversal, supports GET/HEAD/OPTIONS, and streams regular files within
  connection and stream flow control. It caps active streams at 32, request
  bodies at 1 MiB, HPACK blocks and header lists at 64 KiB, and queued inline
  responses at 4 MiB per connection. Cleartext HTTP/2, h2c, CONNECT tunnels,
  and extended CONNECT are not supported. `tests/http2_hpack.cc` covers RFC
  HPACK vectors and bounds; `tests/run_http_server.sh` exercises TLS HTTP/2
  requests when the existing curl binary has HTTP/2 support.
- `examples/tcp_echo.cc` uses a 512-byte frame-local buffer so its session fits
  the default 1 KiB frame class. The default pool then serves 10,000 sessions;
  a 10k-client probe completed 1,000,000 64-byte round trips without failures.
- Coroutine pool blocks now use a 32-byte header; owner/class metadata lives
  once per slab, and the free-list pointer shares storage with the allocated
  magic value. Preserve the `max_align_t` payload alignment and ASAN poisoning
  checks. `tests/task.cc` covers growth, exhaustion, and release for all six
  frame classes.
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

## QUIC milestone (active)

- Scope and release gates are tracked in `docs/quic-milestone.md`. The current
  target is in-house QUIC v1/v2 transport with RFC 9368 version negotiation,
  RFC 9221 DATAGRAM, RFC 9287 greasing, loop-affine APIs, bounded queues, and
  independent-stack interoperability. HTTP/3, WebTransport, video, 0-RTT, and
  unpublished drafts are excluded.
- `src/quic/varint.h`, `version.h`, `transport_parameters.h`,
  `packet_header.h`, and `frames.h` provide internal bounded wire codecs.
  `encode_frame()` validates supported frames and writes canonically into
  caller storage. `frame_policy.h` checks packet-kind and receiver-role
  restrictions.
- `src/quic/packet_protection.{h,cc}` uses OpenSSL EVP for QUIC v1/v2 Initial
  secrets, AES-128-GCM traffic keys, payload/header protection, Retry integrity,
  and v1/v2 1-RTT key-update derivation. The TLS adapter uses OpenSSL 3.5+'s
  supported external QUIC callbacks. Botan remains for the existing TCP/TLS
  paths; it is no longer in the QUIC crypto path.
- `src/quic/key_update.{h,cc}` tracks send/receive key phases, ACK gates, peer
  updates, and previous-key retention. The caller must authenticate candidate
  packets before committing updates and enforce AEAD usage limits and update
  rate limits.
- `packet_protection_context` reuses OpenSSL EVP contexts for payload and
  header protection; the context-aware protected-packet overloads use
  caller-owned authentication scratch and clear it after each attempt.
  Stateless compatibility wrappers still create per-call context/scratch.
- `src/quic/retry_token.{h,cc}` seals bounded Retry-only tokens with AES-GCM,
  binding issue time, canonical peer-address bytes, and original DCID. The
  caller owns nonce uniqueness, key rotation, and replay policy.
- `src/quic/retry_packet.{h,cc}` builds and validates v1/v2 Retry packets with
  the version-specific integrity tag and preserves output on build failure.
- `src/quic/transport_parameter_validation.h` revalidates parsed parameter
  sets and binds mandatory connection-ID, Retry, and version-negotiation
  parameters to authenticated handshake observations.
- `src/quic/stateless_reset.h` provides bounded reset encoding and token
  matching; callers must ensure the triggering packet is eligible and tokens
  belong to active connections.
- `src/quic/ecn_state.h` validates cumulative ACK_ECN feedback per packet-number
  space and reports newly observed CE counts. Callers supply first-time ACK
  accounting from validated sent history and preserve counters across paths.
- `src/quic/stream_state.h` and `connection_lifecycle.h` provide bounded stream
  and connection transition helpers, including final-size consistency, idle
  timeout, closing/draining, and transmit-permission decisions.
- `src/quic/protected_packet.{h,cc}` builds and opens caller-buffer v1/v2
  Initial, 0-RTT, Handshake, and 1-RTT packets with packet-number truncation,
  header protection, and authenticated payloads. It prepends sample padding
  so lengthless STREAM payloads stay unchanged. The RFC 9001 A.3 server Initial
  vector is covered. OpenSSL EVP provider internals may still allocate.
- `src/quic/crypto_send_buffer.h` tracks bounded CRYPTO send ranges, ACKs, and
  loss retransmission state. `crypto_buffer.h` provides bounded ordered CRYPTO
  receive reassembly.
- `src/quic/stream_receive_buffer.h` and `stream_send_buffer.h` provide
  bounded per-stream receive reassembly and send/retransmit state.
- `src/quic/stream_registry.h` tracks stream IDs, direction permissions,
  cumulative stream limits, implicit lower peer stream IDs, and closed-ID
  tombstones. `flow_control.h` tracks connection and stream credit, overlapping
  ranges, consumption/replenishment, and stable FIN/RESET_STREAM final sizes.
- `src/quic/datagram_queue.h` provides bounded RFC 9221 datagram queues and
  checks the complete encoded frame size against the configured limit.
- `src/quic/connection_id_registry.h` tracks peer-issued IDs, reset-token and
  sequence consistency, active-ID limits, monotonic retirement, and pending
  `RETIRE_CONNECTION_ID` work in fixed storage.
- `src/quic/connection_core.{h,cc}` composes OpenSSL QUIC TLS, CRYPTO send and
  receive buffers, packet protection, duplicate-packet tracking, ACK generation,
  frame-policy checks, and connection closing/draining on one owner thread.
  The owner still supplies transport-parameter observations, stream/recovery/
  path handling, routing, anti-amplification, and UDP transmission.
- `src/quic/local_connection_id_registry.h` tracks bounded server-issued IDs,
  reset-token uniqueness, `RETIRE_CONNECTION_ID` effects, and retired-ID
  routing tombstones.
- `src/quic/path_validation.h` tracks fixed-capacity path slots, matched
  `PATH_CHALLENGE` responses, and per-path server anti-amplification credit.
- `src/quic/version_negotiation.h` provides Version Negotiation packet
  encoding and RFC 9368 downgrade validation.
- `src/quic/recovery_timer.h` provides allocation-free RTT estimation,
  space-specific PTO calculation with exponential backoff, and earliest-loss-
  deadline selection that ignores absent entries. `recovery_orchestration.h`
  coordinates ACK/loss processing, NewReno, PTO requests, and persistent-
  congestion detection across the three packet-number spaces. PTO handling
  prioritizes armed loss deadlines, uses the last ack-eliciting send time,
  resets backoff when packet-number spaces are discarded, and exposes bounded
  client probe/server amplification controls.
- `src/quic/ack_ranges.h` traverses decoded ACK ranges in descending packet
  number order without allocating and validates manually constructed frames.
- `src/quic/received_packet_ranges.h` tracks received packet ranges, retires
  ranges after the carrying ACK is acknowledged, preserves a minimum accepted
  packet number, and emits the newest ranges that fit caller storage.
- `src/quic/loss_detection.h` implements RFC 9002's recommended packet and
  time thresholds as helpers. Its time delay uses the larger RTT, 9/8
  multiplier, and 1 ms floor. Packet threshold takes a count of later packets
  actually transmitted, not numeric packet-number distance.
- `src/quic/sent_packet_history.h` retains one packet-number space in fixed
  storage, processes ACK ranges and RTT samples, and removes packet/time-
  threshold losses atomically into caller storage. It reports the next relative
  loss deadline. Strictly increasing packet numbers may have gaps; a fixed
  sent-range ledger validates delayed ACKs after records are removed. Each gap
  permanently consumes one configured range slot until reset, and exhaustion
  rejects a new gapped record without changing state. Packet-threshold loss
  counts later packets actually sent, including retired ones.
- `src/quic/congestion_control.h` provides an allocation-free, path-scoped
  RFC 9002 NewReno controller with bounded flight accounting, slow start,
  congestion avoidance, recovery epochs, ECN and probe hooks, and the
  persistent-congestion response. Recovery orchestration applies the
  persistent-congestion response after detecting persistent congestion.
- CMake registers QUIC varint, transport-parameter, packet-header, frame,
  frame-encoder, frame-policy, CRYPTO receive/send, packet-protection,
  protected-packet/context, stream receive/send/registry/state, flow-control,
  DATAGRAM, peer/local connection-ID registries, path validation, Retry
  packet/token, transport-parameter validation,
  stateless reset, ECN state, connection lifecycle, key update, Version Negotiation, recovery
  timer/orchestration, ACK-range tracking, loss-detection,
  sent-packet-history, congestion-control, and connection-core tests on Linux
  and Windows. The
  packet-protection test uses always-active checks so RelWithDebInfo/NDEBUG
  runs its RFC vectors.
- On 2026-09-30, the integrated Visual Studio 18/MSVC RelWithDebInfo build
  with OpenSSL 3.5.6 and Botan 3.13 passed Windows CTest 61/61 using the
  Visual Studio generator (not NMake). A GCC 14.2 Release build on Linux
  (epoll) also passed 61/61. The Linux build previously failed in
  `src/http/file_operations.h` because `native_socket` was only included
  transitively on Windows; the include is now explicit (`native_socket.h` in
  `file_operations.h`, `http/session.h`, and `http/resource.h`). The earlier
  `quic_connection`, `quic_packet_scheduler`, and `quic_connection_driver`
  failures came from test callbacks rejecting the now-required RFC 9287
  `grease_quic_bit` advertisement; the tests were corrected.
- RFC 9287 is negotiated end to end: the TLS adapter advertises the empty
  `grease_quic_bit` parameter, peer support is recorded only after validated
  transport parameters, a zero QUIC bit is accepted only when advertised
  locally, and the bit is greased on send only after the peer advertised it.
  `tests/quic_grease_quic_bit.cc` covers parsing, opening, and routing;
  `tests/quic_connection_core.cc` covers negotiation and sending.
- `src/quic/path_recovery_state.h` provides bounded per-path recovery state.
  `bounded_connection` gates candidate promotion on validation and resets
  path-specific RTT/congestion state on promotion via
  `recovery_orchestration::reset_path_recovery()` while keeping packet-number
  spaces, ACK ranges, sent-packet history, and loss detection connection-wide.
  `tests/quic_path_recovery_state.cc` and `tests/quic_connection.cc` cover
  cancellation, failed promotion, promotion, and old-path retirement.
- `include/eventloop/quic.h` exposes a loop-affine public API: `quic_endpoint`
  (server and client), move-only `quic_connection` handles into fixed-capacity
  endpoint slots, stream open/accept/read/write, and RFC 9221 DATAGRAM
  send/receive. TLS contexts are built internally from cert/key (server) or a
  trust store (client). `src/quic/quic_endpoint.cc` implements it, keeping
  internals under `src/quic`. Awaiters are resumed by a `connection_driver`
  progress hook instead of polling. `tests/quic_public_api.cc` runs an
  in-house client/server handshake, bidirectional stream echo, and DATAGRAM
  exchange for both QUIC v1 and v2.
- Independent-stack interoperability is verified for **QUIC v1**: the OpenSSL
  3.5.6 `openssl s_client -quic` client completes a full handshake with the
  `examples/quic_echo_server` server and exchanges bidirectional stream data
  (the server reads the request and the client receives the echo). OpenSSL
  3.5.6 rejects `-min_protocol QUICv2`, so its CLI is v1-only and no other
  independent stack is installed; v2 interop is therefore verified only
  in-house. The remaining milestone gates are: independent-stack QUIC v2
  interop, automatic Retry/Version-Negotiation client restart, PMTU, ECN, and
  connection lifetime/shutdown auditing at the endpoint boundary. Do not
  describe the library as QUIC-capable until the milestone gates pass.

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

Build dependencies include a C++23 compiler, CMake, OpenSSL 3.5+, Botan 3 for
the existing TLS paths, and threads. The current host is Fedora 44 on Linux
7.2.5 with the project on Btrfs and `/tmp` on memory-backed `tmpfs`.

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

After adding IPv6 endpoints and outbound TLS on 2026-09-28, a clean Release
build completed in `/tmp/eventloop-release-review` and the full CTest suite
passed 12/12 with local loopback access. The HTTP client example also completed
GETs against the example server over IPv4 and IPv6 loopback. These checks do
not verify public-network DNS behavior or HTTPS against an external CA.

After the 2026-09-28 load-report investigation, the integrated Release build
and CTest passed 12/12 again. The stock TCP echo example held 10,000 default-
pool clients and completed one million 64-byte round trips with zero failures
(about 89.9k requests/s in that run). Its measured 10k idle RSS increase was
about 1,217 bytes per connection; this is a separate run from the report's
2,311-byte custom-pool baseline, so treat the difference as directional. A
same-driver allocator check measured the 32-byte block-header reduction at
32 bytes per connection. A separate Python-vs-C++ client comparison showed
Python contributes to observed latency, but server CPU/request also rises
slightly with concurrency. `perf` found no clear userspace hot spot and kernel
symbols were unavailable, so no event-loop optimization was justified. Under
Valgrind, `task_test` still hits an allocation-count assertion on both the
patched and untouched builds; do not treat that as a new regression.

After adding TLS HTTP/2 support on 2026-09-28, a Release build completed in
`/tmp/eventloop-http2-tests` and CTest passed 13/13 with local loopback access.
`http2_hpack` covers RFC Huffman and dynamic-table vectors, invalid encodings,
configured size limits, and the response encoder. `http_server` verifies ALPN
negotiation and GET/HEAD/OPTIONS, parallel same-host requests, and a 256 KiB
file response that exercises DATA flow-control updates. Its HTTP/2 checks are
skipped if the existing curl binary lacks HTTP/2 support. The HTTP/2 path
shares the secure resource walk with HTTP/1.1 and remains TLS-only.

Use build directories ignored by Git or outside the repository on the new
machine. Recheck warnings, `git diff --check`, and test results after changes.

## Worktree and commit scope

Before any commit, inspect `git status` and stage only intended files. The
file-I/O slice remains experimental infrastructure, not a completed
cross-platform or performance improvement. After a commit, verify the commit
and worktree with `git status` rather than relying on this snapshot.
