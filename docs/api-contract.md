# Coroutine API contract

This document defines the contract for coroutine-facing additions to the
library. Existing callback transports remain supported. Apply these rules to
new operations and adapters without changing the measured fast paths by
default.

## Ownership and thread affinity

- A coroutine function returning `task<T>` takes its owning `event_loop&` as
  its first argument. The frame, its awaiters, cancellation, and resumption
  stay on that loop thread.
- A task is move-only. Start it once, by awaiting it or spawning it. Destroying
  an unfinished started task is a programming error, not cancellation.
- `event_loop::spawn(task<void>)` transfers a fire-and-forget root to the loop.
  `event_loop::spawn(task<T>, task_handle<T>&)` transfers an observed root. The
  handle is a stable, single-use scope and must remain alive until `done()`.
  Its destructor terminates if its task is still active. A handle may have one
  awaiting coroutine, or its result may be taken after completion. Observed
  value types must be nothrow movable so completion can store them inline.
- `task_handle::cancel`, `done`, `take_result`, and `co_await` are loop-thread
  operations. Other threads request work with the bounded `event_loop::post`;
  they must check its return value.

## Results and errors

- Awaiting `task<T>` yields `std::expected<T, task_result>`. Awaiting
  `task<void>` yields `task_result` for compatibility. An observed handle
  returns the same type. `task_result` describes task infrastructure such as
  frame exhaustion; it does not reinterpret a value returned by the task.
- A task whose `T` is itself `std::expected` preserves that inner result.
  The outer result describes task infrastructure; the inner result describes
  the application's operation. Combinators preserve this distinction.
- New syscall-like coroutine operations should return
  `std::expected<T, std::error_code>`, using `std::errc::operation_canceled`
  for cancellation and `std::errc::resource_unavailable_try_again` for a full
  bounded queue or operation pool. Existing APIs retain their documented
  result types until a compatible adapter is added.
- Invalid use (wrong loop, starting twice, destroying active state) is a
  programming error. Resource exhaustion is a returned result. Unhandled
  exceptions in a task currently terminate the process; task bodies should
  return anticipated application errors as values.

## Cancellation and lifetime

- Cancellation is a request, not proof that work stopped. A task may complete
  normally after a request. `task_handle::cancel()` requests cancellation of
  that root; it does not mark its result as cancelled or release its frame.
- When a coroutine awaiting an observed handle is cancelled, it requests
  cancellation of the observed root and resumes only after that root retires.
  Shutdown requests cancellation of every active root.
- A timer can retire immediately. Worker and file operations may still hold
  references into a coroutine frame; their completion must reach the loop
  before that frame is destroyed. `race` and `with_timeout` follow this rule.
- Caller-owned buffers passed to asynchronous file I/O remain valid until
  completion, including after cancellation is requested. New socket awaiters
  should use the same rule or explicitly copy into bounded storage.

## Capacity and performance

- Coroutine frames use the loop's fixed size classes with no heap fallback.
  Operation queues and completion queues have explicit capacities. A full
  resource reports failure; it does not silently allocate or wait forever.
- Keep inline completion and symmetric transfer when safe. Add an event-loop
  post only when a thread boundary or ownership rule requires it.
- Compare new adapters with the existing callback path for throughput,
  allocation count, memory per connection, and p99 latency and timer lateness.
  Measure file I/O on the target filesystem before changing the current HTTP
  path. Preserve `sendfile` while it remains the measured choice.
