# WebSocket API contract

Task results, loop affinity, and cancellation follow the
[coroutine and event-loop contract](coroutines.md). Read that contract
together with the rules below.

- The WebSocket API is `eventloop::ws::web_socket<Stream>` over a stream with
  coroutine read/write operations. Use `async_receive`, `async_send_text`,
  `async_send_binary`, and `async_close`. One receive and one send may run
  concurrently. A returned payload view remains valid until the next receive
  or socket destruction; send buffers remain caller-owned until completion.
- WebSocket framing is bounded by the configured message limit plus frame and
  control overhead. Errors retire the parser/output state and close the
  transport. Fan-out helpers are best-effort: a full recipient drops only the
  current message and the result counts those drops.

See the [WebSocket client guide](../examples/README-websocket-client.md) for
a public API example. Transport behavior is specified in the [TCP](tcp.md)
and [TLS](tls.md) contracts.
