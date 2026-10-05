# API contract index

Read the contract for the API being changed. For asynchronous operations, also
read the [coroutine and event-loop contract](coroutines.md): it defines shared
task results, ownership, loop affinity, cancellation, and shutdown. Load other
contracts when the change crosses their boundaries.

[API conventions](api-conventions.md) describe public names, signatures, and
implementation conventions.

## Core and utilities

- [Coroutines and event loop](coroutines.md): task and handle lifetimes,
  frame capacity, results, executors, cancellation, timers, and composition.
- [File I/O](file-io.md): descriptor and buffer ownership, worker completion,
  and bounded operation capacity.
- [TOML configuration](toml.md): caller storage, view lifetimes, parser limits,
  errors, and document traversal. This synchronous API has no loop affinity.

## Transports

- [TCP](tcp.md): numeric endpoints, socket ownership, partial I/O, connect
  failures, and file sending.
- [TLS](tls.md): handshake, ALPN, close, concurrent-operation limits, record
  buffers, and Linux kTLS file sending; also read TCP for inherited operations.
- [Unix domain sockets](unix-sockets.md): Linux/macOS paths, listener cleanup,
  ownership, and TCP-compatible result and cancellation rules.
- [UDP](udp.md): atomic datagrams, truncation, and pending-operation limits.
- [QUIC](quic.md): stream reservations, receive windows, reset/stop-sending,
  and connection close.
- [WebSocket](websocket.md): payload views, borrowed send buffers, bounded
  framing, errors, and broadcast behavior.

## HTTP

Read the [shared HTTP contract](http.md) and the relevant protocol contract:

- [Shared HTTP](http.md): server options, resource ownership, routing,
  request/response operations, static files, and directory listings.
- [HTTP/1.1](http1.1.md): plain and TLS servers, chunked bodies, trailers,
  connection reuse, and allocation measurements.
- [HTTP/2](http2.md): TLS negotiation, stream limits, flow control,
  cancellation, priority scheduling, allocation measurements, and outbound client.
- [HTTP/3](http3.md): QUIC server lifetime, capacity, request framing,
  QPACK, protocol errors, and allocation measurements; also read QUIC for
  transport changes.
