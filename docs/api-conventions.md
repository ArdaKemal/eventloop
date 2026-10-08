# Public API conventions

Apply to public-header changes; behavioral rules are in the
[contract index](api-contract.md). Names below are relative to `eventloop`
unless qualified.

## Names and layout

- Public headers: `include/eventloop/`, named for their API (`tcp_stream.h`,
  `file_io.h`, `ws/web_socket.h`). Files, types, functions, and members use
  lowercase snake_case. Awaitable I/O uses `async_*`.
- Namespaces: core `eventloop`, HTTP `eventloop::http`, WebSocket
  `eventloop::ws`, utilities `eventloop::util`. Keep poller hooks, cancellation
  nodes, and awaiter machinery in `detail`; concrete awaiter return types
  must not require callers to use readiness callbacks.
- Use numeric `ip_endpoint`: address octets in display order, ports/scope IDs
  in host order. HTTP text-address constructors delegate to `parse()`.
  No DNS resolution; IPv6 sockets are v6-only.
- Export the CMake target `eventloop::eventloop`.
- Synchronous configuration utilities live under `eventloop/util/`. Parsers
  take input views and explicit storage spans, return expected results with
  format errors/byte offsets, and document capacity and view lifetimes.
  They need neither a loop nor `async_*` naming.

## Ownership, affinity, and results

- `unique_fd` transfers ownership; raw descriptors and spans borrow storage.
  Document when borrowed descriptors/buffers can be closed, reused, or
  destroyed and when returned views expire. Pending operations retain loans
  through completion, including cancellation.
- `task<T>` coroutines take `event_loop&` first. I/O, cancellation, and
  resumption stay on that loop; workers post completion without touching
  loop-owned objects. Wrong-loop use is a programming error. Readiness
  registration/callbacks are private.
- Anticipated syscall-like failures use `std::expected<T, std::error_code>`.
  Usual errors: `EBUSY` for a duplicate pending direction, `EALREADY` for a
  second pending TCP connect, `ECANCELED` for cancelled pending I/O. Document
  exceptions and operation limits, e.g. UDP `EMSGSIZE` or WebSocket
  `ws::errc::output_full`.
- Awaiting `task<T>` yields `std::expected<T, task_result>`; `task<void>`
  yields `task_result`. If `T` is an expected I/O result, preserve both layers:
  outer task infrastructure/cancellation and inner operation error.
  `flatten_result` explicitly maps them as specified in [coroutines](coroutines.md).
- Expose bounds and exhaustion errors for frames, queues, operations, and
  buffers. Never hide exhaustion behind an unbounded allocation. Cancellation
  is a request; release frames/loans only after worker references retire.

## Implementation and review

Use a direct awaiter with state in the awaiting frame for one readiness/syscall
operation (`tcp_stream::async_read_some`, `udp_socket::async_receive_from`).
Use `task<T>` for multi-step logic (`ws::web_socket::async_receive`), keeping
its frame within the bounded pool and preserving task/operation results.

Before merging, check naming, exported-target/public-header usage, explicit
ownership/view lifetimes, affinity, pending-operation limits, errors, and
capacity. Keep internals private and update the affected contract; shared
rules need not be repeated in each topic.
