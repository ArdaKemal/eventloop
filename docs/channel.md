# Bounded channel

Include `eventloop/channel.h`. `channel<T>` transfers values between coroutines
on one event loop. A concrete caller is a connection's bounded outgoing queue:
producers use `try_send`, and one writer awaits `async_receive`. A full recipient
can drop a message without delaying other recipients. Async producers can
instead await capacity with `async_send`.

## Storage and ownership

Construct with `channel<T>(loop, storage)`, where storage is a nonempty span of
disengaged `std::optional<T>` slots. Invalid storage throws `invalid_argument`.
The channel exclusively borrows the slots until its destruction; do not access
them or lend them to another channel meanwhile. Destruction destroys remaining
buffered values and leaves the slots disengaged. `T` must have nonthrowing move
construction and destruction; default construction and move assignment are not
required. Values may be move-only. Their alignment must not exceed `max_align_t`,
matching the coroutine-frame pool's alignment limit.
Moves and destructors of `T` must not reenter the channel. Ownership is of the
value itself; pointer/view members do not extend the lifetime of their targets.

The span's length is the buffer capacity. Each suspended sender additionally
owns one value in its awaiting frame; each committed receiver owns its received
value there until resumption. Waiter links live in awaiting frames, with no
separate waiter pool or heap fallback. Their number is bounded by the loop's
coroutine-frame limits. The channel does not create additional coroutine frames.
User-provided value construction, moves, and destruction may allocate.

Construct, operate, and destroy the channel on its owning loop thread. Async
operations check the awaiting task's loop, including when immediately ready.
Synchronous operations check the constructing thread. Workers must use the
existing checked `event_loop::post` to reach that thread. The channel and its
storage must outlive all outstanding operations, including queued resumptions.
Destroying either a pending awaiter or a channel with outstanding operations is
a programming error. The channel is neither copyable nor movable.

## Operations

| Operation | Result and ownership |
| --- | --- |
| `try_send(T&&)` | `expected<void, error_code>`; moves only on success |
| `try_receive()` | `expected<T, error_code>`; removes one value on success |
| `async_send(T)` | Direct awaiter returning `expected<void, error_code>`; takes ownership when called, including on failure/cancellation |
| `async_receive()` | Direct awaiter returning `expected<T, error_code>` |
| `close()` | Idempotent; rejects new sends and allows buffered values to drain |
| `capacity()`, `size()` | Buffer limit and current buffered count; exclude values in awaiters |

An open full send or empty receive returns generic-category `EAGAIN` from the
`try_*` operation; the async counterpart suspends. Waiting senders and receivers
are served FIFO. Removing a buffered value admits the oldest waiting sender
before a newer sender can claim that slot. A send to a waiting receiver transfers
directly without using a buffer slot.

Closing rejects uncommitted senders with generic-category `EPIPE`. Receivers
drain buffered values in order, then receive `EPIPE`. Waiting receivers on an
empty channel receive `EPIPE`. Close does not discard buffered messages or undo
committed transfers. There is no reopen/reset operation.

## Cancellation and scheduling

Async operations check cancellation before attempting a transfer, even with
available data/capacity or after close. An uncommitted wait cancelled by its
task or shutdown is unlinked and completes with generic-category `ECANCELED`.
It does not consume a slot or a value from the channel. Its owned send argument
is destroyed when its awaiter retires.

A transfer commits when the value moves into a buffer slot or receiving
awaiter, or out of the buffer into a receiving operation. Committed operations
are detached from cancellation and complete normally even if cancellation or
close occurs before resumption. Close/cancellation errors likewise become
fixed once queued. Completing a suspended operation queues its resumption on
the existing loop wakeup queue; it never resumes inline in send, receive,
close, or cancellation. Immediately available operations need not suspend.

## Example and validation

```cpp
std::array<std::optional<message>, 32> storage;
eventloop::channel<message> outgoing(loop, storage);

// On the loop thread; failure preserves event.
auto sent = outgoing.try_send(std::move(event));

// In the owning coroutine; the value moves out of the channel.
auto next = co_await outgoing.async_receive();
```

The public-header integration tests in `tests/channel.cc` use the installed
`eventloop::eventloop` target. Their standalone CMake project deliberately
avoids changes to the root build configuration:

```sh
cmake --build /path/to/build --target eventloop
cmake --install /path/to/build --prefix /tmp/eventloop-channel-install
cmake -S tests/channel -B /tmp/eventloop-channel-tests \
  -DCMAKE_PREFIX_PATH=/tmp/eventloop-channel-install
cmake --build /tmp/eventloop-channel-tests
ctest --test-dir /tmp/eventloop-channel-tests --output-on-failure
```

See [coroutines](coroutines.md) for task/frame lifetime and shutdown rules.

On Linux, the measured `int` path performs 10,000 ordered transfers plus
pending-send/receive cancellation and close with zero counted heap allocations,
no pool growth, and no additional coroutine frames (`tests/channel_allocations.cc`).
This excludes loop startup and allocations inside user-provided values.

Linux Release and ASan/UBSan trap-mode tests pass, including LeakSanitizer
with `detect_leaks=1` outside the process-tracing sandbox. macOS and Windows
have not been executed.
