# Semaphore

Include `eventloop/semaphore.h`. `semaphore` limits concurrent operations on
one event loop. A caller handling uploads, outbound requests, or file jobs
acquires a permit before starting an operation and retains it through completion,
including cancellation of any borrowed I/O. Returning the permit admits the
oldest waiting operation.

## Bounds and ownership

Construct with `semaphore(loop, capacity)`. Capacity must be positive; zero
throws `std::invalid_argument`. All permits are initially available. The fixed
capacity cannot be increased, and an acquisition always takes exactly one
permit. Only an owning permit can return its acquisition.

`semaphore::permit` owns one acquisition. It is move-only, default constructs
empty, and returns its acquisition on destruction or `release()`. Release is
idempotent and leaves the permit empty. Move construction empties the source;
move assignment first releases the destination's acquisition. Self-move leaves
the permit intact. `operator bool` reports whether it owns an acquisition.

The semaphore is neither copyable nor movable. It must outlive all held
permits and outstanding acquisitions, including queued error completions and
reserved permits awaiting resumption. Destruction with any of those outstanding
is a programming error. Do not destroy a pending acquire awaiter.
Each returned acquire awaiter can be awaited once; attempting to reuse it is
a programming error.

Waiter links, cancellation registration, and queued resumption nodes live in
the awaiting frames. There is no separate waiter pool, heap fallback, or
additional coroutine frame. Waiter count is bounded by the loop's frame limits;
the semaphore's capacity bounds held and reserved permits, rather than waiters.

Construct, operate, and destroy on the owning loop thread. Permit moves,
queries, release, and destruction of a nonempty permit are also loop-thread
operations. Empty permits have no affinity. Async acquisition checks the
awaiting task's loop even with capacity immediately available. Synchronous
operations check the constructing thread. Workers use the existing checked
`event_loop::post` to reach that thread rather than accessing the semaphore or
its permits directly.

## Operations

| Operation | Result |
| --- | --- |
| `try_acquire()` | `expected<permit, error_code>`; generic-category `EAGAIN` when all permits are held or reserved |
| `async_acquire()` | Direct awaiter returning `expected<permit, error_code>`; suspends until a permit is reserved or cancellation is requested |
| `capacity()` | Fixed maximum number of held/reserved permits |
| `available()` | Number available for immediate acquisition; excludes queued reservations |

Waiters are served FIFO. Releasing a permit while a waiter exists transfers
its reservation directly to the oldest waiter without making it available to
a newer acquisition. Resumption is queued on the existing loop wakeup queue
and happens after release returns. A semaphore with available permits needs
neither a wait nor a queued resumption.

## Cancellation

Async acquisition checks cancellation before taking an available permit. An
uncommitted wait cancelled by its task, a composition operation, or shutdown
is unlinked in O(1) and completes with generic-category `ECANCELED`. Its
resumption is queued, not inline in cancellation. Cancelling an uncommitted
wait does not take or return a permit.

An acquisition commits when an available permit is taken or a released permit
is reserved for a waiter. A reservation is detached from cancellation before
its resumption is queued. Cancellation after that point cannot revoke the
permit: the await returns it normally, and its eventual release returns exactly
one acquisition. Cancelling a task already holding a permit likewise does not
release it early; the caller must retain it through operation completion.

Shutdown cancels uncommitted acquisitions, rather than closing the semaphore
or invalidating held permits. There is no close, reset, weighted acquire, or
manual count adjustment operation. See [coroutines](coroutines.md) for task,
frame, and shutdown lifetime rules.

## Caller

```cpp
eventloop::semaphore uploads(loop, 4);

// Inside a coroutine on this loop:
auto slot = co_await uploads.async_acquire();
if (!slot) co_return;
// Keep slot alive across the upload's awaits, through final completion.
```

The public-header tests in `tests/semaphore.cc` use the installed
`eventloop::eventloop` target and exercise bounded concurrent jobs. Their
standalone project preserves the root CMake file's existing changes:

```sh
cmake --build /path/to/build --target eventloop
cmake --install /path/to/build --prefix /tmp/eventloop-semaphore-install
cmake -S tests/semaphore -B /tmp/eventloop-semaphore-tests \
  -DCMAKE_PREFIX_PATH=/tmp/eventloop-semaphore-install
cmake --build /tmp/eventloop-semaphore-tests
ctest --test-dir /tmp/eventloop-semaphore-tests --output-on-failure
```

On Linux, `tests/semaphore_allocations.cc` measures 10,000 contended acquisitions
across five coroutines sharing two permits, plus pending-acquisition
cancellation. These paths make zero counted heap allocations, grow no frame
pool slabs, and create no additional coroutine frames. Loop startup is excluded;
the simulated job yields without doing allocating application work.

Release and ASan/UBSan trap-mode tests exercise move ownership, FIFO handoff,
task/composition cancellation, shutdown, queued-resumption lifetime, and
bounded concurrent jobs. LeakSanitizer also passes with `detect_leaks=1` outside
the process-tracing sandbox. macOS and Windows have not been executed.
