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

## Routed HTTP/2 and HTTP/3 WebSockets

HTTP/2 and HTTP/3 servers with a router support Extended CONNECT from
[RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.html) and
[RFC 9220](https://www.rfc-editor.org/rfc/rfc9220.html). Register a CONNECT
route and call `request::async_accept_websocket(subprotocol)` before starting
the response or reading its body. `request::connect_protocol()` exposes
`:protocol` (empty on ordinary requests). Acceptance requires `websocket`,
version 13, no Content-Length, and, when selected, one subprotocol offered by
the peer. The subprotocol view is borrowed through acceptance. Invalid
handshakes return `invalid_argument` without sending a response; the handler
can send an HTTP rejection (include Sec-WebSocket-Version: 13 when rejecting
an unsupported version). HTTP/1.1 acceptance returns
`operation_not_supported`. Authentication and Origin policy are the handler's
responsibility. Extensions are not negotiated.

Acceptance sends status 200 without Content-Length or END_STREAM/FIN and
returns a move-only `http::websocket_stream` for `ws::web_socket`. It borrows
the server-owned exchange until the handler completes; it must not escape the
handler. Its read/write spans remain borrowed until completion, including
cancellation. One read and one write may run concurrently. Ordinary request
body and response operations are invalid after acceptance. Destroying or
calling `close()` on the stream aborts only that stream, using HTTP/2 CANCEL
or HTTP/3 H3_REQUEST_CANCELLED; locally aborted pending I/O reports
`operation_canceled`, while a peer reset reports `connection_reset`.
`async_close()` ends the send direction and
reads through peer END_STREAM/FIN before completing; cancel or abort it to
stop waiting. Do not start other I/O while `async_close()` is pending. Pending
operations must retire before destruction or moving.
Wrong-loop use remains a programming error.

The HTTP connection owns its descriptor, TLS/QUIC state, and HTTP buffers.
No descriptor is transferred to the handler. WebSocket DATA uses the existing
eight 16 KiB HTTP/2 body slots per connection (exhaustion refuses the stream
with REFUSED_STREAM) or an HTTP/3 request scratch slot (exhaustion uses
H3_REQUEST_REJECTED). Long-lived streams retain these slots. Accepted DATA is
not limited by the cumulative HTTP request body limit; individual messages
and pending WebSocket output retain the configured framing bounds and errors
above. The adapter allocates no buffers; the existing WebSocket framing
vectors may allocate within their bounds. Support is portable across the
existing TLS HTTP/2 and QUIC HTTP/3 platforms; cleartext HTTP/2 and HTTP/1.1
route upgrades are outside this operation.

[websocket_routing_server](../examples/websocket_routing_server.cc) is a
public-header echo server on TLS HTTP/2 and QUIC HTTP/3:

```sh
./build/websocket_routing_server certificate.pem private-key.pem 8443
```

Its `/chat` route echoes messages, and `/hello` serves ordinary HTTP. An
Extended CONNECT-capable peer is required; the example does not implement an
HTTP/1.1 WebSocket handshake. Session setup and framing storage may allocate.
As with other HTTP/3 handlers, size the loop's 2048-byte coroutine-frame class
for simultaneous long-lived requests.
