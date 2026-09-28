# Public API conventions

Use this guide when adding or changing a public header. The behavioral contract
is in [api-contract.md](api-contract.md); preserve its ownership, cancellation,
and result rules when changing a signature.

## Names and layout

- Put public headers under `include/eventloop/`, named for the API they expose:
  `tcp_stream.h`, `file_io.h`, and `ws/web_socket.h`. Use lowercase snake_case
  for files, types, functions, and data members. Name awaitable operations
  `async_*` (for example, `eventloop::tcp_stream::async_read_some()` and
  `eventloop::async_openat()`).
- Put core public names in `eventloop`, HTTP names in `eventloop::http`, and
  WebSocket names in `eventloop::ws`. Keep poller hooks, cancellation nodes,
  awaiter helpers, and other implementation machinery in `eventloop::detail`.
  A public awaitable may have a concrete awaiter return type, but callers must
  not need to use internal readiness callbacks.
- Use `eventloop::ipv4_endpoint` for the shared numeric IPv4 address: four
  address octets and a host-order port. Do not invent a second endpoint type
  for another transport. Any HTTP text-address convenience constructor must
  delegate to `eventloop::ipv4_endpoint::parse()` instead of adding another
  parser. The
  socket API has no DNS or IPv6 support.
- Export the CMake consumer target as `eventloop::eventloop`.

## Ownership, affinity, and errors

- Make ownership visible in types. Passing or returning `eventloop::unique_fd`
  transfers descriptor ownership; for example,
  `eventloop::tcp_acceptor::async_accept()` returns an owned descriptor and
  `eventloop::tcp_stream::async_send_file()` takes one. A raw `int`
  descriptor is borrowed. A `std::span` is a borrowed buffer. Document exactly
  when borrowed objects may be closed, reused, or destroyed: pending file and
  socket operations require them through completion, including after a
  cancellation request. Document any returned view's validity period too.
- Keep I/O, cancellation, and resumption on the owning
  `eventloop::event_loop` thread. Coroutine functions returning
  `eventloop::task<T>` take their `eventloop::event_loop&` first.
  Wrong-loop use is a programming error. Workers post completion to the loop;
  they do not touch loop-owned objects. Do not expose readiness registration
  or callbacks as application APIs.
- Return anticipated syscall-like failures as
  `std::expected<T, std::error_code>`. A duplicate operation in a direction
  already pending reports `EBUSY`; a second TCP connect attempt reports
  `EALREADY`; cancellation or close of pending I/O reports `ECANCELED`. State
  any operation-specific limits and errors, such as `EMSGSIZE` for a truncated
  UDP receive or `eventloop::ws::errc::output_full` for a full WebSocket output
  buffer.
- Keep the outer task result distinct. Awaiting `eventloop::task<T>` yields
  `std::expected<T, eventloop::task_result>`; if `T` is itself an expected I/O
  result, inspect both layers. `eventloop::task_result` describes task
  infrastructure or task cancellation, while `std::error_code` describes the
  operation. Do not erase
  either layer or silently turn resource exhaustion into heap allocation.
- State capacity at the API boundary. Coroutine frames, queues, file
  operations, and WebSocket buffers are bounded; capacity exhaustion returns
  the applicable error. Cancellation is a request, and a worker may still hold
  references into a frame. Keep the frame and borrowed inputs alive until the
  operation retires.

## Choosing an async implementation

For one readiness or syscall operation, use a direct awaiter whose operation
state lives in the awaiting coroutine frame, as with
`eventloop::tcp_stream::async_read_some()` or
`eventloop::udp_socket::async_receive_from()`. This avoids allocating an
additional coroutine frame. Use `eventloop::task<T>` for multi-step coroutine
logic that needs to await and sequence other operations, as with
`eventloop::ws::web_socket<Stream>::async_receive()`. Keep its frame within the
bounded per-loop pool and preserve the nested task and operation results.

## Review before merging an API change

- Check the public header path, namespaces, snake_case names, `async_*` name,
  and `eventloop::eventloop` consumer usage.
- Check that ownership transfers and borrowed descriptor, buffer, and view
  lifetimes are explicit through completion and cancellation.
- Check loop affinity, pending-operation limits, `EBUSY`, `ECANCELED`, and
  bounded-capacity behavior. Document any exception to the established
  operation pattern.
- Check both error layers where a task wraps an I/O result. Keep readiness and
  cancellation machinery inside `eventloop::detail` and update
  [api-contract.md](api-contract.md) when the behavior changes.
