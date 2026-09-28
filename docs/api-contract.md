# Coroutine API contract

Public asynchronous I/O uses C++ coroutines. The epoll readiness machinery is
an internal implementation detail; applications register the library's TCP,
TLS, and UDP objects with `event_loop`, then await their operations. `post()`
and executor submissions remain bounded command and background-work APIs.

## Ownership and thread affinity

- A coroutine function returning `task<T>` takes its owning `event_loop&` as
  its first argument. Started tasks, their frames, awaiters, cancellation, and
  resumption stay on that loop's thread.
- A task is move-only. Start it once by awaiting or spawning it. Destroying an
  unfinished started task is a programming error. Coroutine frames come from
  bounded per-loop size classes. Each class has a warm reserve and a hard slot
  limit; the pool adds backing slabs on demand and releases growth slabs when
  they become empty. Individual frames never fall back to the general heap.
- `event_loop::add` accepts owning pointers to `tcp_acceptor`, `tcp_stream`
  (including `tls_stream`), and `udp_socket`. It does not accept application
  readiness handlers. Call an object's `close()` to cancel its pending socket
  operations and deregister it. A pointer to a loop-owned object becomes invalid
  after `close()` removes it or after an operation removes it on failure.
- `event_loop::spawn(task<void>)` transfers a fire-and-forget root to the loop.
  `event_loop::spawn(task<T>, task_handle<T>&)` transfers an observed root. The
  handle is a stable scope and must remain alive until `done()`. It may have
  one awaiting coroutine; otherwise consume its result with `take_result()`.
- `task_handle::cancel`, `done`, `take_result`, and `co_await` are loop-thread
  operations. Other threads submit commands with bounded `event_loop::post`
  and must check its return value.
- `task_executor()` runs independent work away from the loop. Worker code must
  not access loop-owned objects; use `post()` or the coroutine blocking/file
  operations to return work to the loop safely.

## Results and errors

- Awaiting `task<T>` yields `std::expected<T, task_result>`. Awaiting
  `task<void>` yields `task_result`. A task whose value is itself an
  `std::expected` preserves that inner result; the outer result describes task
  infrastructure such as frame exhaustion.
- Syscall-like socket and file operations return
  `std::expected<T, std::error_code>`. Cancellation is reported as
  `operation_canceled` (some older focused APIs use `ECANCELED`). A full
  bounded queue or operation pool returns an error rather than allocating an
  unbounded replacement.
- `task<T>::result()` and `task_handle<T>::take_result()` consume stored
  values once. Unhandled exceptions in a task currently terminate the
  process; return anticipated application errors as values.
- Destroy the event loop only after all coroutine frames have retired. The
  loop checks this before destroying its worker and poller state.
- `yield`, `sleep_for`, `sleep_until`, and `run_blocking` check loop affinity.
  Wrong-loop use is a programming error.

## Cancellation and timers

- Cancellation is a request, not proof that work has stopped. A task may
  complete normally after cancellation. `task_handle::cancel()` does not mark
  its result as cancelled or release its frame.
- Cancelling a timer retires it immediately. A worker or file operation may
  still hold references into a coroutine frame; its completion must reach the
  loop before the frame is destroyed. `race` and `with_timeout` follow this
  rule and wait for losing branches to retire.
- `sleep_for` and `sleep_until` are the public timer interface. Positive
  relative durations saturate at the latest representable time point; zero or
  negative durations are immediately due. Callback timer scheduling is not a
  public API.
- `event_loop::shutdown(timeout)` stops new registrations and requests
  cancellation of every active root immediately. It then calls `on_shutdown()`
  on registered handlers; the built-in acceptors and streams close immediately.
  The timeout bounds only handlers still registered after notification and
  does not provide a response-draining period for built-in HTTP connections.
  A second call forces removal of any remaining handlers immediately.

## TCP and TLS

- Include `eventloop/tcp_acceptor.h` and `eventloop/tcp_stream.h` for
  nonblocking IPv4 TCP. Add each object to its loop before awaiting it.
  `tcp_acceptor::async_accept()` returns an owned `unique_fd`;
  `tcp_stream::async_connect()`, `async_read_some()`, and `async_write_some()`
  return `std::expected` results. Reads and writes may complete partially.
- Caller-owned buffers remain valid until their await completes, including
  after cancellation is requested. At most one read, one write, one connect,
  and one send-file operation may be pending per TCP stream.
- An immediate connect error leaves the stream registered so the caller can
  inspect the result and close it. A pending connect failure or cancellation
  removes the stream. Check saved descriptors or task results before retaining
  a pointer after failure.
- `tcp_stream::async_send_file()` takes ownership of its file descriptor and
  sends the optional header followed by the requested file range. Plain HTTP
  uses it for larger files; preserve the component-by-component `O_NOFOLLOW`
  path walk that protects document-root access.
- `tls_stream` adds `async_handshake`, `async_read_some`, `async_write_some`,
  and `async_close`. Await `async_close()` to flush TLS `close_notify`, then
  call `close()` to retire the transport. `close()` itself immediately
  cancels operations and closes the transport. One TLS read and one TLS write
  may be pending together. A second read or second write returns `EBUSY`.
  Handshake and `async_close()` require all other TLS operations to be idle.

## UDP and WebSocket

- Include `eventloop/udp_socket.h` for IPv4 datagrams. Datagrams stay atomic:
  empty datagrams succeed with size zero, and a truncated receive consumes the
  datagram and reports `EMSGSIZE`. At most one receive and one send may be
  pending per socket; a duplicate same-direction operation reports `EAGAIN`.
- The WebSocket API is `ws::web_socket<Stream>` over a stream with coroutine
  read/write operations. Use `async_receive`, `async_send_text`,
  `async_send_binary`, and `async_close`. One receive and one send may run
  concurrently. A returned payload view remains valid until the next receive
  or socket destruction; send buffers remain caller-owned until completion.
- WebSocket framing is bounded by the configured message limit plus frame and
  control overhead. Errors retire the parser/output state and close the
  transport. Fan-out helpers are best-effort: a full recipient drops only the
  current message and the result counts those drops.

## Composition and file I/O

- Include `eventloop/task_composition.h` for fixed-arity `when_all`, `race`,
  and `with_timeout`. Operands must be unstarted tasks belonging to the same
  loop. Large combinations may exceed the largest frame class and report
  `frame_allocation_failure`.
- Include `eventloop/file_io.h` for `async_openat`, `async_read_at`, and
  `async_write_at`. Paths are copied into a bounded awaiter buffer. Read and
  write buffers remain caller-owned until completion, including after
  cancellation. Operations run on a dedicated bounded worker; a full
  `file_io_depth` returns an error.
- HTTP accept loops spawn connection tasks. Each task owns its session and I/O
  buffers while suspended; accepted connections share ownership of the
  document-root descriptor with the listener. Small file reads and metadata
  calls remain synchronous; large plain HTTP files use `sendfile`. Preserve
  the component-by-component `O_NOFOLLOW` path walk.
