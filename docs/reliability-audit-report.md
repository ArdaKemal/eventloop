# Reliability and performance audit report

Date: 2026-09-26

Audited revision: `01fb250`

Scope: the experimental coroutine file I/O slice and the subsequent ownership,
error-path, bounded-resource, and performance review. The work spans 35 commits
from `23108ee` through `01fb250`.

Historical note: this report describes revision `01fb250`, before the
coroutine-native TCP/TLS/HTTP/WebSocket migration in the working tree. Its
callback interfaces, direct transport paths, and HTTP session-lifetime gap
describe that older revision, not the current API. The optional io_uring
backend documented below was removed on 2026-09-27; current file I/O uses the
dedicated bounded worker executor only. Current shutdown requests cancellation
of active coroutine roots immediately, and built-in handlers close on
notification; its timeout does not drain HTTP responses.

## Outcome

The planned audit is closed at this revision. The new file I/O API was committed
as experimental infrastructure in `23108ee`. It was not integrated into HTTP:
the HTTP file path used synchronous metadata and small-file reads and
`sendfile` for larger plain HTTP responses. The review fixed concrete lifetime,
error-path, and input-validation defects and added regression coverage. The
library cannot be certified free of all defects by this audit or its tests.

## Work completed

- **Coroutine and file I/O foundation:** `task<T>`, fixed-arity `when_all`,
  `race`, `with_timeout`, observed `task_handle<T>`, and bounded per-loop
  coroutine frames were documented and tested. `async_openat`, `async_read_at`,
  and `async_write_at` use either liburing or a bounded worker fallback.
  Cancellation retains operation and caller-owned buffer lifetimes until
  completion. Capacity exhaustion returns errors rather than allocating a
  replacement operation on the general heap.
- **Descriptors and callback lifetimes:** Accepted TCP/TLS sockets, active
  `sendfile` descriptors, epoll and listener descriptors, and HTTP file-walk
  descriptors gained explicit `unique_fd` ownership. Built-in HTTP sessions
  retain their document-root descriptor after listener removal. Deferred
  handler removal keeps a stream alive through direct callbacks, including
  reentrant close and shutdown paths. The original integer-descriptor callback
  interfaces remain as compatibility paths with an explicit ownership duty for
  subclasses.
- **Failure and cancellation paths:** The ring retires unsubmitted SQE pointers
  after failed submissions and re-signals its eventfd when a capped completion
  batch leaves work ready. A live coroutine frame is rejected before loop
  teardown. Timer insertion rolls back if arming fails, and shutdown forces
  handler retirement if its grace timer cannot arm. Oversized relative and
  shutdown deadlines saturate. The executor waiter and permit handshake was
  corrected to prevent a missed wakeup.
- **Transport and input handling:** WebSocket parser and output state retire
  after callback or write failures; outbound framing is bounded and saturated
  close paths are handled. TLS transport state retires after an interrupted
  direct write. HTTP request control characters are rejected, and server
  configuration rejects embedded NUL bytes. File I/O and immediate timeout
  operands enforce the documented loop-affinity rules.
- **Regression coverage:** Tests now exercise throwing and reentrant callbacks,
  descriptor ownership, timer arming failure, cancellation, pool exhaustion,
  io_uring submission recovery, 96 ready completions across the 64-completion
  drain cap, and 64 cancelled reads with frame-local buffers on both file
  backends. The final cancelled-read case passed 50 ASan/UBSan repetitions.

## Verification and performance evidence

- At revision `01fb250`, the full Release suite passed **10/10**, and the full
  ASan/UBSan suite passed **10/10**. The Release build had liburing enabled;
  forced-ring tests ran outside the command sandbox. `git diff --check` passed.
- The executor stress test passed 100 consecutive local runs. ThreadSanitizer
  could not start on this WSL host; it failed before the test with an
  `unexpected memory mapping` error. This is an untested concurrency angle,
  not a clean TSAN result.
- Five interleaved WSL event-loop benchmark pairs against `29d9088` measured
  median construction rates of about 15.8k/s baseline and 15.3k/s current,
  with overlapping run ranges. Median post round-trip rates were about
  1.97M/s baseline and 2.00M/s current. These data show no clear local
  regression, but are too noisy to establish equivalence on other hosts.
- A local HTTP `Connection: close` benchmark measured about 13.7k requests/s
  before and after the descriptor ownership change on this host. Existing
  cached 4 KiB file-I/O runs on `/tmp` favored the worker fallback over the
  one-submit-per-operation ring path and showed lower timer lateness. `/tmp`
  is memory-backed on this WSL machine, so those runs are not representative
  storage-performance evidence.

## Boundaries of this conclusion

The code remains Linux-only. File read and write buffers are caller-owned
through completion, including after cancellation is requested. An observed
`task_handle` must stay alive until its task completes. At the audited revision,
raw pointers inside the ring, cancellation nodes, and callbacks were constrained
by those lifetime rules; the default backend preferred io_uring when setup
succeeded. The ring-specific concerns no longer apply after its removal. The
HTTP file path still needs explicit session/coroutine lifetime ownership before
using the awaiters. The WebSocket broadcast helpers use best-effort fan-out:
they count a full recipient's dropped message and continue to other recipients
without retaining a retry queue. Callers own recipient lifetimes and decide
how to respond to drops. Message and queue limits still need workload-specific
validation.
