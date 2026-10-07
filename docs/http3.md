# HTTP/3 API contract

The [coroutine and event-loop contract](coroutines.md) defines task results, loop affinity,
borrowed-buffer lifetimes, and cancellation. The [shared HTTP contract](http.md)
defines routing and request/response operations. Read those rules together with
this protocol's limits and behavior; the other HTTP protocol contracts are not
required for changes confined to this protocol.

## Server lifetime and capacity

- `eventloop::http::http3_server` listens on a QUIC UDP endpoint with ALPN
  `h3`, a certificate/key pair, and an owned document-root descriptor when
  `document_root` is set. Its
  `run()` task accepts connections; `close()` stops acceptance and
  `async_close()` waits for endpoint retirement. Keep the server and its
  observed `run()` task alive until both operations complete. Routed
  requests run their handlers as described in the shared HTTP contract; other
  GET, HEAD, and OPTIONS requests serve static files or `index.html` using the shared secure
  resource walk. Request header blocks are capped at 16 KiB and 128 fields, dynamic
  QPACK tables are disabled, and QUIC caps each connection at 32 peer
  simultaneously active bidirectional and eight peer unidirectional streams.
  The server has eight
  concurrent connection slots by default; `server_options::connection_capacity`
  accepts 1 to 256. Endpoint routing, connection state,
  waiters, and HTTP/3 task handles are allocated at construction in proportion
  to that capacity. Connections beyond it are rejected. Each connection has
  storage for 40 concurrent stream tasks. Completed task slots are reused.
  `server_options::request_capacity` reserves reusable request scratch
  buffers at startup; zero selects four per connection, and explicit values
  from 1 to 8192 are accepted. A request arriving while every buffer is in
  use, or whose coroutine frame cannot be allocated, is refused with
  `H3_REQUEST_REJECTED` on its stream; the connection continues. A buffer is
  held until the request stream ends, the server stops reading it, or it
  fails.
  `server_options::max_udp_payload_size` bounds application datagrams
  to 1200..8192 bytes and is negotiated down to the peer's advertised limit;
  handshake packets remain at 1200 so anti-amplification is unaffected. It
  defaults to 1472 (the standard Ethernet payload) because path MTU discovery
  is not implemented; constrained paths may lower it.
  Each scratch buffer is about 52 KiB. Ordinary static-file responses use that
  storage for HTTP/3 headers and I/O; directory listing still allocates its
  bounded entry and output vectors, and OpenSSL may allocate separately.
  Each active request holds one
  coroutine frame from the loop's 2048-byte size class, so callers should size
  `eventloop::event_loop_options::coroutine_frame_capacities` for the expected
  request concurrency; the shipped HTTP/3 examples scale those frame caps with
  the configured capacity. A frame-allocation
  failure rejects only the affected connection instead of stopping the
  listener; one for a peer unidirectional stream closes that connection with
  `H3_INTERNAL_ERROR`.

## Routed handlers and request bodies

- HTTP/3 runs a handler inside each request's existing coroutine, using
  that request's scratch buffer. Request concurrency and refusal follow the
  server capacity above.
- Split Cookie field lines are joined with `; ` in their original order before
  reaching a handler. Joining uses the unused portion of the request's 16 KiB
  decoded-string storage; exhaustion resets the stream with `H3_EXCESSIVE_LOAD`.
- HTTP/3 bodies may omit Content-Length. A read past
  `max_request_body` returns `message_size`, and the server answers 413
  if the handler then returns without a response. A malformed body
  (DATA beyond Content-Length, a truncated frame, invalid trailers)
  returns `bad_message` and resets the stream with the RFC 9114 code.
  Request trailers are validated but not exposed.
- For a case-insensitive `100-continue` member in any `Expect` field's
  comma-separated list, a handler's body read sends
  an interim HEADERS section containing only `:status: 100` before waiting
  for content. It is omitted when content is already available, Content-Length
  is zero, or a final response has started. The interim section does not
  start the final response or end the stream.
- Decimal Content-Length values above QUIC's `2^62 - 1` stream-data limit
  are valid declarations but cannot be satisfied. Matched routed requests
  answer 413 without running the handler, even when `max_request_body` is
  larger. Smaller values remain exact; duplicate declarations compare
  numerically, including leading zeros. Static requests retain the unread-body
  policy below; a FIN that cannot match the declaration is `H3_MESSAGE_ERROR`.

- An unread request body is ended with STOP_SENDING `H3_NO_ERROR` after the
  response (RFC 9114 4.1).

## Routed responses

- Without content-length, finishing a response ends the stream. Response
  trailers are always sent. Response sections and trailers are limited to
  61 and 64 fields respectively; more is `message_size`.
- A handler that returns after `async_start` but before `async_finish` resets
  the stream with `H3_INTERNAL_ERROR`.

- With a router, the server advertises SETTINGS_ENABLE_CONNECT_PROTOCOL and
  accepts routed WebSockets through Extended CONNECT (RFC 9220). See the
  [WebSocket contract](websocket.md#routed-http2-and-http3-websockets) for
  acceptance, scratch-slot lifetimes, and stream closure. Unsupported
  Extended CONNECT protocols receive 501. Accepted tunnels carry DATA only
  (plus permitted unknown extension frames); trailing HEADERS are
  H3_FRAME_UNEXPECTED, a connection error.

## Control streams and QPACK

Each peer unidirectional stream is parsed by type with about 300 bytes of
fixed state in its reader frame; nothing is buffered beyond one partial
integer. A client push stream, or a second control, QPACK encoder, or QPACK
decoder stream, is `H3_STREAM_CREATION_ERROR`; FIN or reset of any of those
three is `H3_CLOSED_CRITICAL_STREAM`. The control stream must begin with
SETTINGS (`H3_MISSING_SETTINGS`); a second SETTINGS or a DATA, HEADERS,
PUSH_PROMISE, or reserved HTTP/2 frame is `H3_FRAME_UNEXPECTED`. SETTINGS
accepts at most 32 distinct identifiers (`H3_EXCESSIVE_LOAD` beyond that)
and rejects duplicate or HTTP/2-only identifiers, and
`ENABLE_CONNECT_PROTOCOL` or `H3_DATAGRAM` values above 1
(`H3_SETTINGS_ERROR`).
GOAWAY, MAX_PUSH_ID, and CANCEL_PUSH must hold exactly one push ID
(`H3_FRAME_ERROR`); an increasing GOAWAY, decreasing MAX_PUSH_ID, or
CANCEL_PUSH for an ID not previously sent in PUSH_PROMISE is `H3_ID_ERROR`.
The server does not support push, so every peer CANCEL_PUSH is unpromised.
Unknown frames are skipped by length. Because the server advertises a zero-capacity
dynamic table, the encoder stream accepts only Set Dynamic Table Capacity 0
(`QPACK_ENCODER_STREAM_ERROR`), and the decoder stream accepts only Stream
Cancellation (`QPACK_DECODER_STREAM_ERROR`). Unknown stream types are
refused with STOP_SENDING `H3_STREAM_CREATION_ERROR`. Each violation closes
the connection with that code in CONNECTION_CLOSE, as does a client whose stream limit leaves no room for the
server's three unidirectional streams (`H3_GENERAL_PROTOCOL_ERROR`). A
connection that ends normally is closed with `H3_NO_ERROR`.

## Request framing and protocol errors

Request streams are parsed as HTTP/3 frames: HEADERS, then DATA, then at
most one trailing HEADERS, with unknown and reserved extension frames
skipped by length anywhere. DATA before the request HEADERS, a frame after
trailers, or a control, PUSH_PROMISE, or reserved HTTP/2 frame is
`H3_FRAME_UNEXPECTED`; a FIN inside a frame is `H3_FRAME_ERROR`; a QPACK
section that uses the dynamic table or does not decode is
`QPACK_DECOMPRESSION_FAILED`. Those close the connection. Errors confined to
one request reset the response and send STOP_SENDING with the same code,
and the connection continues. A malformed request is `H3_MESSAGE_ERROR`:
missing, duplicate, unknown, or late pseudo-header fields (including
`:protocol` when Extended CONNECT is disabled), an invalid URI scheme, path,
or query (including relative paths, fragments, or invalid percent escapes),
`*` for a method other than OPTIONS, missing
authority or malformed host/port syntax (including userinfo, whitespace, or
invalid bracketed IPv6/IPvFuture literals)
in authority for `http`/`https` or Host, an ordinary CONNECT authority without
a host and nonempty numeric port, `:authority` and Host
that disagree, uppercase or non-token field names,
an empty or non-token method,
control bytes other than internal HTAB or leading/trailing SP/HTAB in values,
connection-specific fields, TE other than
`trailers`, a Content-Length that is non-numeric or conflicting,
DATA whose total differs from Content-Length, or a pseudo-header
in trailers. A stream ending before its request HEADERS is
`H3_REQUEST_INCOMPLETE`. A field
section above the 16 KiB header cap or the decode limits, or If-None-Match
values that do not fit request storage, is `H3_EXCESSIVE_LOAD`. A file read
failure is `H3_INTERNAL_ERROR`, and a response write that fails because the
peer stopped or reset the stream is `H3_REQUEST_CANCELLED`. Ordinary CONNECT is
answered 405 and a `:scheme` other than `https` (case-insensitively) 400.

For static requests, the response is sent once the request HEADERS are valid. The server then reads the rest of the
request: DATA is counted and dropped, and trailers are decoded into the
request's own storage. Violations found after the response reset a stream
whose response may already be complete. After 1 MiB of request DATA the
server stops reading with STOP_SENDING `H3_NO_ERROR` (RFC 9114 4.1), so
Content-Length is not checked past that point. These static request bodies
are discarded; routed request bodies follow the handler rules above. Directory listings are available when the server is
constructed with `directory_listing` and follow the shared bounded
renderer. Their HEAD responses preserve the GET representation length without
sending DATA. Generated static and automatic responses include Date.
HTTP/3 server push and WebTransport are not supported.

## Allocation measurements and transport references

`tests/http3_routing_allocations.cc` checks steady-state routed requests and
static-file requests, including OpenSSL's own allocations through its allocator
hook: those are zero per request in the measured paths. QUIC handshakes allocate
inside OpenSSL for key exchange, transcript hashing, and the key schedule on
every new connection. QUIC packet-protection keys are derived with one
per-thread HMAC-SHA256 context instead of an OpenSSL KDF context per derivation.

QUIC stream reservations, receive windows, reset/stop-sending behavior, and
connection-close ownership are specified in the [QUIC contract](quic.md).
