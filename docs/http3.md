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
| `request_capacity` | 0 selects ten scratch buffers per connection; explicit 1..8192 |
| Peer active bidirectional / unidirectional streams | 100 / 8 per connection (RFC 9114 6.1) |
| Reusable stream-task slots | 108 per connection |
| Request header block / decoded fields | 16 KiB / 128 |
| QPACK dynamic table | Disabled |
| `max_udp_payload_size` | 8192; clamped to 1200..8192, negotiated down to peer limit; reached by path MTU probing ([QUIC](quic.md#socket-and-path-mtu)) |

Startup allocates endpoint routes/state/waiters/handles proportional to
connection capacity, plus about 52 KiB per request scratch buffer. Connection
slots (about 2.3 MiB each) and scratch buffers are reserved but not written at
startup beyond a scratch buffer's first page, so resident memory grows with the
connections and requests actually served (about 15 MiB idle at 64 connections
and 640 buffers, measured on Linux). Excess
connections are rejected. When the scratch pool is full, a connection waits
for a buffer before accepting its next stream, in request order across
connections; later streams wait in QUIC's bounded buffers. Request-frame
exhaustion sends H3_REQUEST_REJECTED only on that request; the connection
continues. Scratch
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
  A routed section or trailer section larger than the client's
  SETTINGS_MAX_FIELD_SECTION_SIZE (names + values + 32 bytes per field,
  RFC 9114 4.2.2) is also `message_size` and is not sent; an unstarted
  response then gets the fallback 500. The limit applies once the client's
  SETTINGS have been read. Built-in static responses are not checked.
  Returning after start without finish resets with H3_INTERNAL_ERROR.

With routes, SETTINGS_ENABLE_CONNECT_PROTOCOL enables RFC 9220
[routed WebSockets](websocket.md#routed-http2-and-http3-websockets).
Unsupported Extended CONNECT protocols answer 501. Accepted tunnels allow DATA
and unknown extension frames; trailing HEADERS is a connection
H3_FRAME_UNEXPECTED.

With `server_options::webtransport` enabled (routes required), `webtransport-h3`
CONNECTs are routed rather than answered 501. The control stream's SETTINGS
additionally carry SETTINGS_H3_DATAGRAM = 1 (0x33), SETTINGS_WT_ENABLED = 1
(0x2c7cf000), and SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI, _UNI, and _MAX_DATA
(0x2b65, 0x2b64, 0x2b61) from the options. The QUIC transport parameters add
max_datagram_frame_size 1232 and reset_stream_at. With WebTransport disabled
the SETTINGS bytes are unchanged. Session behavior is in
[WebTransport](webtransport.md).

With WebTransport enabled, each request stream's reads return at most 16 bytes
until 16 bytes have been parsed, so the stream data after a WT_STREAM header is
at most 16 bytes. A client unidirectional stream is read in at most 16-byte
pieces until its type and session ID are complete, and the rest of that read
is handed to the session. Disabled, reads are unchanged.

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
(`H3_SETTINGS_ERROR`). The parser also records the WebTransport settings in
`peer_critical_streams`: `SETTINGS_WT_ENABLED` (draft-16 0x2c7cf000) is enabled
only for value 1, and a larger value means not enabled rather than an error, so
the server never rejects it there. The initial `WT_MAX_STREAMS` and `WT_MAX_DATA`
limits are stored as parsed. These fields and `settings_received` change only
when the whole SETTINGS frame has been parsed. The `on_settings` hook then runs
once.
GOAWAY, MAX_PUSH_ID, and CANCEL_PUSH must hold exactly one push ID
(`H3_FRAME_ERROR`); an increasing GOAWAY, decreasing MAX_PUSH_ID, or
CANCEL_PUSH for an ID not previously sent in PUSH_PROMISE is `H3_ID_ERROR`.
The server does not support push, so every peer CANCEL_PUSH is unpromised.
Unknown frames are skipped by length. Because the server advertises a zero-capacity
dynamic table, the encoder stream accepts only Set Dynamic Table Capacity 0
(`QPACK_ENCODER_STREAM_ERROR`), and the decoder stream accepts only Stream
Cancellation (`QPACK_DECODER_STREAM_ERROR`). Unknown stream types are
refused with STOP_SENDING `H3_STREAM_CREATION_ERROR`. With WebTransport
enabled, type 0x54 is a `webtransport` stream instead. Its session ID varint is
parsed, possibly across reads, and parsing stops after it. `bytes_consumed()`
gives the octets used, and the caller takes the rest as stream data. A FIN
before the session ID is not a connection error. Each violation closes
the connection with that code in CONNECTION_CLOSE, as does a client whose stream limit leaves no room for the
server's three unidirectional streams (`H3_GENERAL_PROTOCOL_ERROR`). A
connection that ends normally is closed with `H3_NO_ERROR`. The server sends
no GOAWAY: server close and loop shutdown cancel connections at once (RFC 9114
5.2 graceful shutdown is not implemented).

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
`H3_REQUEST_INCOMPLETE`. With WebTransport enabled, a stream whose first frame
type is WT_STREAM (0x41) yields a `webtransport_stream` event once its session
ID varint is complete. The caller takes the following octets as stream data,
and later `receive()` calls consume nothing. A 0x41 frame type anywhere else is
`H3_FRAME_ERROR`, and a FIN before the session ID is `H3_REQUEST_INCOMPLETE`.
A field
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
HTTP/3 server push is not supported. WebTransport over HTTP/3 is described in
[WebTransport](webtransport.md).

## Allocation measurements

[http3_routing_allocations](../tests/http3_routing_allocations.cc) checks zero
per-request general-heap/OpenSSL allocations on warmed routed/static-file paths.
New QUIC handshakes allocate for key exchange, transcript hashing, and key
schedule. Packet-protection derivation reuses one per-thread HMAC-SHA256 context
rather than allocating a KDF context per derivation.

QUIC stream reservations, receive windows, reset/stop-sending behavior, and
connection-close ownership are specified in the [QUIC contract](quic.md).
