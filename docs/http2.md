# HTTP/2 API contract

The [coroutine and event-loop contract](coroutines.md) defines task results, loop affinity,
borrowed-buffer lifetimes, and cancellation. The [shared HTTP contract](http.md)
defines routing and request/response operations. Read those rules together with
this protocol's limits and behavior; the other HTTP protocol contracts are not
required for changes confined to this protocol.

## TLS server and static responses

- `eventloop::http::https_server` advertises `h2` and `http/1.1` with ALPN by
  default. Set `eventloop::http::server_options::enable_http2` to `false` to
  disable HTTP/2. The HTTP/2 path serves static GET, HEAD, and OPTIONS over TLS and routed
  requests as described in the shared HTTP contract, supports up to 32 active
  streams per connection, decodes bounded HPACK header blocks, and observes connection and
  stream DATA flow control. Static request bodies are discarded and limited to
  1 MiB. File responses stream from their owned descriptors; inline
  response bodies are bounded to 4 MiB per connection. Responses are scheduled
  by RFC 9218 priority, taken from the request `priority` field and replaced
  by PRIORITY_UPDATE frames. Lower urgency goes first. Within one urgency,
  non-incremental responses are sent one at a time in stream order, then
  incremental responses share DATA frames round-robin. A stream blocked by flow
  control does not hold back others. Requests without a signal use urgency 3,
  non-incremental. A malformed Priority value keeps the defaults, and an update
  for a stream that is not open is ignored. The server advertises
  SETTINGS_NO_RFC7540_PRIORITIES and ignores RFC 7540 PRIORITY frames apart
  from their validity checks. On Linux, file response
  DATA uses OpenSSL `SSL_sendfile()` when transmit kTLS is active, and otherwise
  uses the bounded buffered path. Directory-root traversal uses the shared HTTP contract's
  component-by-component `O_NOFOLLOW` checks. Cleartext
  prior-knowledge HTTP/2, h2c upgrade, and ordinary CONNECT proxy tunnels are
  not supported. With a router, the server advertises
  SETTINGS_ENABLE_CONNECT_PROTOCOL and supports routed WebSockets through
  Extended CONNECT (RFC 8441). See the [WebSocket contract](websocket.md#routed-http2-and-http3-websockets)
  for acceptance, storage capacity, and stream closure. Plain `http::server`
  continues to serve HTTP/1.1.

## Routed handlers, flow control, and cancellation

A SETTINGS_INITIAL_WINDOW_SIZE change that overflows any stream's send window
ends the connection with FLOW_CONTROL_ERROR (RFC 9113 6.9.2). A stream's
WINDOW_UPDATE that overflows only that stream remains a stream error.

- HTTP/2 runs one handler task per stream, up to 32 per connection, next to
  a reader task and the connection task, which writes. A handler's
  `async_write` completes once its bytes enter the connection's 256 KiB
  output queue under flow control and RFC 9218 priority; `async_send_file`
  completes once the last range is queued. Each connection allocates its
  session, 32 handler slots, and their request views once.
  - Routed uploads use a pool of eight 16 KiB stream buffers, allocated the
    first time a routed request with a body arrives. With routes, the
    server advertises a 16 KiB initial stream window and returns credit as
    handlers read. An upload arriving while all eight buffers are busy is
    refused with RST_STREAM REFUSED_STREAM, which clients may retry.
  - A client may send up to the default 64 KiB window before it applies
    that SETTINGS. A DATA frame that does not fit its stream buffer pauses
    reading the connection until the handler reads, so other streams wait
    meanwhile; a handler that never reads is ended when it responds.
  - Cancelling a handler task, for example with `with_timeout` around
    `async_read_body`, resumes a waiting read or write with
    `operation_canceled`. A cancelled write or file send also resets the
    stream with CANCEL, so the connection stops borrowing its data.
    Connection loss resumes every waiting handler with `connection_reset`,
    and the connection waits for all handlers before it is released.

## Request bodies and responses

- HTTP/2 bodies may omit Content-Length. A read past
  `max_request_body` returns `message_size`, and the server answers 413 if
  the handler then returns without a response. A malformed body (DATA beyond
  Content-Length, or a body shorter than it at END_STREAM) resets the stream with PROTOCOL_ERROR, and reads
  return `connection_reset`. Request trailers are validated but not
  exposed.

- Without content-length, finishing a response ends the stream. Response
  trailers are always sent.
- A handler that returns after `async_start` but before `async_finish` resets
  the stream with INTERNAL_ERROR.
- An unread request body is ended with RST_STREAM NO_ERROR after the response
  (RFC 9113 8.1).

## Allocation measurements

HTTP/2 decodes request fields into the connection's existing strings, keeps
its HPACK dynamic table in one 4 KiB ring allocated with the first entry, and
encodes response fields from views into one reused buffer, so only a header
value longer than earlier ones on the connection can still allocate. `tests/http2_routing_allocations.cc` checks steady-state routed
requests and static-file requests, including OpenSSL's own allocations through
its allocator hook: those are zero per request in the measured paths. TLS
handshakes allocate inside OpenSSL for key exchange, transcript hashing, and
the key schedule on every new connection.

## Outbound client

- Include `eventloop/http2/client.h` for one outbound HTTPS HTTP/2 request.
  `http2::async_request(loop, endpoint, context, hostname, request)` owns the
  TLS socket from connect through close. `hostname` is used for certificate
  verification, SNI, and the default `:authority`; `endpoint` is a numeric
  address, so name resolution belongs to the caller. ALPN must select `h2`.
  Requests own their method, target, authority override, header strings, and
  body bytes or a `request_body_source` callback. Any valid HTTP method token
  is accepted, including GET, HEAD, POST, PUT, PATCH, DELETE, and OPTIONS.
  CONNECT returns `operation_not_supported` because a tunnel does not fit one
  buffered exchange.
  The owned body is limited to 4 MiB; a source can produce up to 1 TiB in
  chunks of at most 16 KiB. Set either the owned body or the source. The source
  is task-owned and called on the loop thread with a writable borrowed span;
  it returns 0 for EOF, a byte count within the span, or an operation error.
  Resources captured by the source must remain valid through completion,
  including cancellation. `Content-Length` is optional and can be supplied as
  a request header when known; it must be decimal and equal the owned body
  size or the source's total. A mismatch reports `invalid_argument`, before
  connecting for an owned body, or when a source exceeds the value or ends
  short of it. Connection-specific request fields and TE other than
  `trailers` are also `invalid_argument`. DATA transmission observes the peer's connection
  and stream flow-control windows. Responses own status and headers. The
  five-argument operation owns the response body, capped at 4 MiB. Passing a
  sixth `response_sink` argument
  streams DATA chunks synchronously to that callback on the loop thread;
  `response.body` is then empty. A sink receives a borrowed chunk valid only
  during the call and returns `std::error_code`; a nonzero result aborts the
  request and becomes the operation error. An optional seventh
  `response_header_sink` receives each complete header block before subsequent
  DATA: its status argument is 1xx for informational headers, the final HTTP
  status for final headers, and zero for trailers. The fields span is borrowed
  only during the call; a nonzero callback error aborts the request. Final
  response headers and trailers remain owned in the returned response.
  Responses are malformed, reporting `protocol_error`, when they carry
  connection-specific fields or any TE field, a non-numeric or
  conflicting Content-Length, DATA whose total differs from Content-Length,
  or any DATA content after a HEAD request or with status 204 or 304.
  Content-Length on those bodyless responses is not compared.
  RST_STREAM on the request stream returns `connection_reset`. A GOAWAY
  whose last stream ID is zero returns `connection_reset` because the request
  was not processed; otherwise the response continues to completion.
  A malformed RST_STREAM or GOAWAY frame is `protocol_error`.
  Streamed response bodies are limited to 1 TiB while buffering remains one
  16 KiB frame. The operation uses one
  stream per connection. Connection reuse and server push are outside its scope.
  Request and response header blocks are limited to 64 KiB and 128 fields.
  Frames from the server are limited to 16 KiB as advertised in client
  SETTINGS. Reaching
  a limit returns `message_size`; malformed HTTP/2 returns `protocol_error`.
  Each request allocates its own bounded frame, header, and response storage;
  TLS and OpenSSL may allocate separately.
  A TLS connect, handshake, read, or write error is returned directly; task
  cancellation closes the owned transport. All I/O and resumption occur on
  `loop`, and the outer task result remains distinct from the operation error.
