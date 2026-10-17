# Coroutine and event-loop API contract

Public names below are in `eventloop`; include `event_loop.h` and `task.h`
under `eventloop/`. Platform readiness is private.

## Ownership and affinity

- `task<T>` coroutines take `event_loop&` first. Started tasks, frames,
  awaiters, cancellation, and resumption stay on its thread. Construct, run,
  and destroy the loop on that thread. Wrong-loop use is a programming error.
- Tasks are move-only and start once, by awaiting or spawning. Destroying an
  unfinished started task is a programming error. Frames use bounded per-loop
  size classes: warm reserves, hard slot limits, on-demand backing slabs,
  and reclamation of empty growth slabs. Individual frames have no heap fallback.
- `add()` takes owning pointers to acceptors, TCP/TLS streams, and UDP sockets,
  including Unix acceptors/streams on POSIX; application readiness handlers
  are not accepted. `close()` cancels pending I/O and deregisters the object.
  A loop-owned pointer becomes invalid after removal by close or failure.
- `spawn(task<void>)` transfers a fire-and-forget root. `spawn(task<T>,
  task_handle<T>&)` transfers an observed root; its stable handle must live
  until `done()`. One coroutine may await it; otherwise use `take_result()`.
  Handle `cancel`, `done`, `take_result`, and `co_await` run on the loop thread.
- `post()` and `stop()` are thread-safe while the loop lives. Check `post()`'s
  boolean result; empty tasks/full queues return false, leaving a named task
  intact. Stop posting before loop destruction. `task_executor()` runs
  independent work; workers must not access loop-owned objects. Return results
  through `post()` or blocking/file-operation completion.
- An owner `stop()` ends `run()` after one more pass over queued work and
  timers; a stop issued in that pass ends the next `run()`. A `run()` that
  starts with queued work, or ends on an owner stop, may skip that pass's
  zero-timeout readiness check; at most 8 are skipped in a row, so socket
  readiness, signals, and other-thread stops wait at most that many passes.
- Destroy the loop only after every frame retires; the loop checks this before
  destroying worker/poller state.
- POSIX loops block SIGPIPE on their constructing thread while any loop lives
  there, so writes without `MSG_NOSIGNAL` (including kTLS) fail with EPIPE.
  If loops changed the mask, the last discards pending SIGPIPE and unblocks it;
  an already blocked SIGPIPE stays blocked. Other threads and the process-wide
  disposition are unaffected.

## Results and capacity

| Operation | Result |
| --- | --- |
| Await `task<T>` | `std::expected<T, task_result>` |
| Await `task<void>` | `task_result` |
| Syscall-like socket/file I/O | `std::expected<T, std::error_code>` |

An inner expected remains distinct from the task result. `flatten_result`
maps `expected<expected<T, error_code>, task_result>` to the inner expected:
frame exhaustion becomes `not_enough_memory`, cancellation `operation_canceled`,
an unhandled exception `state_not_recoverable`.
It supports `void` and move-only values without allocating. Pending cancelled
I/O reports generic-category `ECANCELED`; this differs from
`task_result::cancelled`. `task::result()` and `task_handle::take_result()`
consume values once. An exception escaping a task fails only that task: its
frame completes and the awaiter, observer, or composition receives
`task_result::unhandled_exception`; the exception object is discarded. Other
tasks and the loop keep running. Return anticipated application errors as
values.

`event_loop_options` controls frame/queue limits; full pools/queues report
failure rather than allocating replacements. Frame payload classes are
128/256/512/1024/2048/4096 bytes, and 16 times larger on Windows
(2048 through 65536 bytes) because MSVC frames are about ten times larger
for the same coroutines. Default hard slots are
64/32/10240/10240/4/2, enough for 10k idle HTTPS connections per loop (a
1024-byte connection frame plus a 512-byte pending TLS read); warm slots
64/32/16/160/4/2. Zero disables a class;
warm counts clamp to hard limits. Frame state must not exceed `max_align_t`
alignment. `post_capacity` defaults to 1024, `coroutine_completion_capacity`
and `file_io_depth` to 128; each must be a power of two >= 2.
`run_blocking` reserves completion capacity before submitting work and reports
`blocking_error` for no workers, executor queue full, completion exhaustion,
cancellation, or shutdown. Accepted work retains its reservation until the
loop dequeues completion.

## Cancellation, timers, and shutdown

- Cancellation requests do not prove completion: a task may finish normally.
  Handle `cancel()` neither marks its result cancelled nor releases its frame.
- Timer cancellation retires immediately. Worker/file completion must reach
  the loop before referenced frames/buffers are released. `race` and
  `with_timeout` cancel losing branches and await their retirement.
- `sleep_for`/`sleep_until` are public timers; callback timers are private.
  Positive relative durations saturate at the latest time point; zero/negative
  durations are immediately due. Frame-local timer registration allocates
  nothing: O(1) registration, amortized O(log n) expiry/cancellation. Equal
  deadlines fire in registration order. Timers, `yield`, and `run_blocking`
  check loop affinity. Shutdown deadlines also saturate.
- `shutdown(timeout)` is terminal: it stops registrations, cancels all active
  roots immediately, and calls handlers' `on_shutdown()`. Built-in acceptors/
  streams close immediately. The deadline bounds remaining registered handlers;
  it does not drain HTTP responses. A second call removes remaining handlers
  immediately.

## Wakeups

Include `eventloop/wakeup.h`. `wakeup::async_wait()` wakes one coroutine and
returns `expected<void, error_code>`; the direct awaiter uses frame-local state
without allocation, another frame, or a capacity limit.

`notify()` queues a waiter for resumption after the notifier returns, in
notification order with posted work and the same per-iteration budget. With no
waiter, the next wait completes immediately. Notifications coalesce until the
waiter runs. A second waiter returns `EBUSY`; cancellation before notification
returns `ECANCELED` (including shutdown); an already queued waiter, or a wait
that consumes a stored notification, completes normally even if its task was
cancelled. Notify/wait are loop-thread operations. Destruction with a pending
waiter or a wait from another loop, even with a stored notification, is a
programming error.

For bounded value transfer between multiple senders/receivers, include
`eventloop/channel.h`; see the [channel contract](channel.md) for storage,
backpressure, close, and cancellation semantics.

For bounded concurrency, include `eventloop/semaphore.h`; the
[semaphore contract](semaphore.md) defines scoped permits, FIFO acquisition,
and cancellation before or after reservation.

## Composition

Include `eventloop/task_composition.h` for fixed-arity `when_all`, `race`, and
`with_timeout`. Operands must be unstarted tasks on the same loop.
`with_timeout` returns an awaiter, not a task: await it directly, or wrap it
in a coroutine to spawn or compose it. An operation that completes before
suspending never arms the timer. Large
combinations can exceed the largest frame class and return
`frame_allocation_failure`.
