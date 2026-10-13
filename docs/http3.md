# HTTP/3 API contract

Shared results/affinity/cancellation: [coroutines](coroutines.md).
Routing, request/response ownership, static files, listings, and cache:
[shared HTTP](http.md). Names below are relative to `eventloop`.

## Server lifetime and capacity

`http::http3_server` listens on QUIC UDP with ALPN h3 and certificate/key,
owning the document-root descriptor when configured. `run()` accepts;
`close()` stops acceptance; `async_close()` waits for endpoint retirement.
Keep the server and observed run task alive through completion. Unmatched
GET/HEAD/OPTIONS use shared static-resource traversal. `reuse_port` lets one
server per loop share a port, with the delivery limits in
[QUIC port sharing](quic.md#port-sharing); `worker_index` and
`worker_group` encode the owner in connection IDs and forward misrouted packets
to it as described there.

| Capacity | Default / limit |
| --- | --- |
| `http::server_options::connection_capacity` | 8; 1..256 |
| `request_capacity` | 0 selects four scratch buffers per connection; explicit 1..8192 |
| Peer active bidirectional / unidirectional streams | 32 / 8 per connection |
| Reusable stream-task slots | 40 per connection |
| Request header block / decoded fields | 16 KiB / 128 |
| QPACK dynamic table | Disabled |
| `max_udp_payload_size` | 1472; clamped to 1200..8192, negotiated down to peer limit |

Startup allocates endpoint routes/state/waiters/handles proportional to
connection capacity, plus about 52 KiB per request scratch buffer. Excess
connections are rejected. Full scratch pool or request-frame exhaustion sends
H3_REQUEST_REJECTED only on that request; the connection continues. Scratch
stays held until the request ends, reading stops, or failure. Connection-frame
exhaustion rejects that connection without stopping the listener; peer
unidirectional-frame exhaustion closes it with H3_INTERNAL_ERROR.

Static headers/I/O use scratch; listings and OpenSSL may allocate separately.
Request frames use the 2048-byte class: size
`event_loop_options::coroutine_frame_capacities` for concurrency, as examples do.
Handshake datagrams stay bounded at 1200 bytes; path MTU discovery is absent, so lower
application payloads for constrained paths. Before address validation the server builds
a packet only when its remaining 3x anti-amplification credit covers a full datagram,
and pads only ack-eliciting Initials.

## Routed bodies and responses

Each request invokes its handler using its scratch buffer; concurrency/refusal
follows the capacities above.

- Cookie lines join with `; ` in arrival order in unused 16 KiB decoded-string
  storage; exhaustion resets with H3_EXCESSIVE_LOAD.
- Bodies may omit Content-Length. Reads beyond `max_request_body` return
  `message_size`; if the handler returns without responding, answer 413.
  Malformed bodies (overrun, truncated frame, invalid trailers) return
  `bad_message` with the RFC 9114 error below. Request trailers validate but
  are not exposed.
- A body read sends interim `:status: 100` for a case-insensitive
  `100-continue` member of any comma-separated Expect field, before waiting
  for content. Omit when content is available, length is zero, or final
  response has started; this does not start/end the final response.
- Decimal Content-Length > QUIC's `2^62-1` is valid but unsatisfiable: matched
  routes answer 413 even with a larger body limit. Smaller values stay exact;
  duplicates compare numerically (leading zeros allowed). Static unread-body
  policy remains below; mismatched FIN is H3_MESSAGE_ERROR.
- After response, unread bodies end with STOP_SENDING H3_NO_ERROR (RFC 9114 4.1).
- Without content-length, finish ends the stream. Response trailers are always
  sent. Sections/trailers allow 61/64 fields; overflow is `message_size`.
  Returning after start without finish resets with H3_INTERNAL_ERROR.

With routes, SETTINGS_ENABLE_CONNECT_PROTOCOL enables RFC 9220
[routed WebSockets](websocket.md#routed-http2-and-http3-websockets).
Unsupported Extended CONNECT protocols answer 501. Accepted tunnels allow DATA
and unknown extension frames; trailing HEADERS is a connection
H3_FRAME_UNEXPECTED.

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
Content-Length is not checked past that point. Routed bodies follow handler
rules above. Shared bounded listings preserve GET length on HEAD without DATA. Static/automatic responses include Date.
HTTP/3 server push and WebTransport are not supported.

## Allocation measurements

[http3_routing_allocations](../tests/http3_routing_allocations.cc) checks zero
per-request general-heap/OpenSSL allocations on warmed routed/static-file paths.
New QUIC handshakes allocate for key exchange, transcript hashing, and key
schedule. Packet-protection derivation reuses one per-thread HMAC-SHA256 context
rather than allocating a KDF context per derivation.

QUIC stream reservations, receive windows, reset/stop-sending behavior, and
connection-close ownership are specified in the [QUIC contract](quic.md).
