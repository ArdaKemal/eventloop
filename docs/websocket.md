# WebSocket API contract

Shared async rules: [coroutines](coroutines.md). Names are relative to
`eventloop`; transports follow [TCP](tcp.md)/[TLS](tls.md).

`ws::web_socket<Stream>` uses coroutine stream reads/writes. Operations:
`async_receive`, `async_send_text`, `async_send_binary`, `async_close`.
One receive and send may coexist. Payload views expire at next receive/socket
destruction; send buffers borrow through completion. Message/output limits
bound framing plus control overhead. Failures retire framing state and close
transport. Best-effort fan-out drops only the current message for a full
recipient and counts drops. [Client guide](../examples/basics/README.md).

## Routed WebSockets

Servers with routes accept WebSockets on every protocol: HTTP/1.1 Upgrade
([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html)) on GET routes, and
Extended CONNECT ([RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.html) /
[RFC 9220](https://www.rfc-editor.org/rfc/rfc9220.html)) on CONNECT routes for
HTTP/2 and HTTP/3. Call `request::async_accept_websocket(subprotocol)` before
response start/body read. `connect_protocol()` exposes :protocol (empty on
ordinary requests).

- Acceptance requires version 13 and any selected subprotocol offered by the
  peer. HTTP/1.1 also requires GET without a body, `Upgrade: websocket`,
  `Connection: upgrade`, and one `Sec-WebSocket-Key` encoding 16 bytes;
  HTTP/2 and HTTP/3 require CONNECT with :protocol websocket and no
  Content-Length. Borrow subprotocol through acceptance. Invalid handshake
  returns `invalid_argument` without responding; the handler can reject
  (include Sec-WebSocket-Version: 13 for unsupported version). Handler owns
  authentication/Origin policy; extensions are not negotiated.
- HTTP/1.1 success sends 101 Switching Protocols with
  `Sec-WebSocket-Accept`; the stream then carries the connection's raw bytes,
  starting with any the client sent after the request head. A read of zero is
  the client closing the connection. `async_close()` sends nothing (there is
  no half-close) and waits for that. The connection closes when the handler
  returns and never carries another request; the server's header and idle
  timeouts do not apply while the handler runs.
- HTTP/2 and HTTP/3 success sends 200 without Content-Length or END_STREAM/FIN, returning
  move-only `http::websocket_stream` for `ws::web_socket`. It borrows the
  server-owned exchange and must not escape the handler. Ordinary request/
  response operations become invalid. No descriptor transfers to the handler;
  the connection owns TLS/QUIC and HTTP buffers.
- One read/write may coexist, borrowing spans through completion/cancellation.
  Destruction/`close()` aborts only this stream (HTTP/2 CANCEL, HTTP/3
  H3_REQUEST_CANCELLED). Local abort returns `operation_canceled`; peer reset
  `connection_reset`. Pending operations must retire before moving/destruction.
- `async_close()` ends sending and reads through peer END_STREAM/FIN; cancel
  or abort to stop waiting. No other I/O while close is pending. Wrong-loop
  use is a programming error.
- Long-lived WebSockets retain one of eight 16 KiB HTTP/2 body slots
  (exhaustion REFUSED_STREAM) or one HTTP/3 scratch slot (H3_REQUEST_REJECTED).
  Accepted DATA has no cumulative request-body limit; configured WebSocket
  message/output bounds remain. The adapter allocates no buffers; framing
  vectors may allocate within bounds. Size HTTP/3's 2048-byte frame class
  for simultaneous requests.

Portable across HTTP/1.1 (plain or TLS), TLS HTTP/2, and QUIC HTTP/3
platforms; cleartext HTTP/2 is unsupported. Session/framing setup may
allocate.

[websocket_routing_server](../examples/basics/websocket_routing_server.cc) echoes
`/chat` and serves ordinary HTTP at `/hello`; peers need Extended CONNECT:

```sh
./build/websocket_routing_server certificate.pem private-key.pem 8443
```

`tests/run_http_websocket_interop.py` uses independent hyper-h2, wsproto, and
aioquic 1.3.0 peers. With those packages in `Python3_EXECUTABLE`, CMake registers
`http_websocket_interop`: negotiation, concurrent HTTP/WebSocket streams,
fragmentation/Ping/Pong, flow control, Close/FIN ordering, and reset isolation
on HTTP/2 and HTTP/3 QUIC v1/v2.
