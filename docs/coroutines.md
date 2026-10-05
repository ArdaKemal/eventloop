# Coroutine and event-loop API contract

Public asynchronous I/O uses C++ coroutines. Core public names live in
`eventloop`, HTTP names in `eventloop::http`, and WebSocket names in
`eventloop::ws`. Platform readiness machinery is an internal implementation
detail; applications register the library's TCP, TLS, and UDP objects with
`eventloop::event_loop`, then await their operations. `post()` and executor
submissions remain bounded command and background-work APIs.

## Ownership and thread affinity

- A coroutine function returning `eventloop::task<T>` takes its owning
  `eventloop::event_loop&` as its first argument. Started tasks, their frames,
  awaiters, cancellation, and resumption stay on that loop's thread.
- A task is move-only. Start it once by awaiting or spawning it. Destroying an
  unfinished started task is a programming error. Coroutine frames come from
  bounded per-loop size classes. Each class has a warm reserve and a hard slot
  limit; the pool adds backing slabs on demand and releases growth slabs when
  they become empty. Individual frames never fall back to the general heap.
- `eventloop::event_loop::add` accepts owning pointers to
  `eventloop::tcp_acceptor`, `eventloop::tcp_stream` (including
  `eventloop::tls_stream`), and `eventloop::udp_socket`. It does not accept
  application readiness handlers. Call an object's `close()` to cancel its
  pending socket operations and deregister it. A pointer to a loop-owned object becomes invalid
  after `close()` removes it or after an operation removes it on failure.
- `eventloop::event_loop::spawn(eventloop::task<void>)` transfers a
  fire-and-forget root to the loop. Its overload taking `eventloop::task<T>`
  and `eventloop::task_handle<T>&` transfers an observed root. The handle is a
  stable scope and must remain alive until `done()`. It may have
  one awaiting coroutine; otherwise consume its result with `take_result()`.
- `eventloop::task_handle<T>::cancel`, `done`, `take_result`, and `co_await` are
  loop-thread operations. Other threads submit commands with bounded
  `eventloop::event_loop::post` and must check its return value.
- `task_executor()` runs independent work away from the loop. Worker code must
  not access loop-owned objects; use `post()` or the coroutine blocking/file
  operations to return work to the loop safely.
- On POSIX, an `event_loop` blocks SIGPIPE in the signal mask of the thread
  that constructs it, for as long as any loop lives on that thread. Socket
  writes that cannot pass `MSG_NOSIGNAL`, such as OpenSSL's kernel-TLS
  `write()` and `sendfile()`, then fail with EPIPE instead of ending the
  process when a peer disconnects. The last loop on the thread discards a
  pending SIGPIPE and unblocks it again. Other threads' masks and the
  process-wide disposition are unchanged.

## Results and errors

- Awaiting `eventloop::task<T>` yields
  `std::expected<T, eventloop::task_result>`. Awaiting
  `eventloop::task<void>` yields `eventloop::task_result`. A task whose value
  is itself an `std::expected` preserves that inner result; the outer result
  describes task infrastructure such as frame exhaustion.
  `eventloop::flatten_result` turns an
  `std::expected<std::expected<T, std::error_code>, task_result>` into the
  inner expected without allocating. It maps frame exhaustion to
  `not_enough_memory` and cancellation to `operation_canceled`, including for
  `void` and move-only values.
- Syscall-like socket and file operations return
  `std::expected<T, std::error_code>`. A cancelled pending I/O operation
  reports `ECANCELED`, equivalent to `std::errc::operation_canceled` in the
  generic error category. This is separate from
  `eventloop::task_result::cancelled`, which describes a task result. A full
  bounded queue or operation pool
  returns an error rather than allocating an unbounded replacement.
- `eventloop::task<T>::result()` and
  `eventloop::task_handle<T>::take_result()` consume stored
  values once. Unhandled exceptions in a task currently terminate the
  process; return anticipated application errors as values.
- Destroy the event loop only after all coroutine frames have retired. The
  loop checks this before destroying its worker and poller state.
- `eventloop::yield`, `eventloop::sleep_for`, `eventloop::sleep_until`, and
  `eventloop::run_blocking` check loop affinity. Wrong-loop use is a
  programming error.

## Cancellation and timers

- Cancellation is a request, not proof that work has stopped. A task may
  complete normally after cancellation; `eventloop::task_handle<T>::cancel()` does not mark
  its result as cancelled or release its frame.
- Cancelling a timer retires it immediately. A worker or file operation may
  still hold references into a coroutine frame; its completion must reach the
  loop before the frame is destroyed. `eventloop::race` and
  `eventloop::with_timeout` follow this rule and wait for losing branches to
  retire.
- `eventloop::sleep_for` and `eventloop::sleep_until` are the public timer
  interface. Positive relative durations saturate at the latest representable
  time point; zero or negative durations are immediately due. Callback timer scheduling is not a
  public API. A waiting timer lives in the awaiting coroutine frame and joins
  the loop's timer heap without allocating: registration costs O(1), and
  expiry or cancellation O(log n) amortized in the number of pending timers.
  Timers with equal deadlines fire in registration order.
- `eventloop::event_loop::shutdown(timeout)` stops new registrations and
  requests cancellation of every active root immediately. It then calls
  `on_shutdown()` on registered handlers; the built-in acceptors and streams close immediately.
  The timeout bounds only handlers still registered after notification and
  does not provide a response-draining period for built-in HTTP connections.
  A second call forces removal of any remaining handlers immediately.

## Task composition

- Include `eventloop/task_composition.h` for fixed-arity `eventloop::when_all`,
  `eventloop::race`, and `eventloop::with_timeout`. Operands must be unstarted
  tasks belonging to the same loop. Large combinations may exceed the largest
  frame class and report `frame_allocation_failure`.
