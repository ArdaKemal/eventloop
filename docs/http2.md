# HTTP/2 API contract

Shared async rules: [coroutines](coroutines.md). Routing, ownership, static
resources, listings/cache: [shared HTTP](http.md). Names are relative to `eventloop`.

## TLS server and capacities

`http::https_server` advertises `h2`/`http/1.1` by default;
`http::server_options::enable_http2 = false` disables h2. Static GET/HEAD/OPTIONS and
routed requests run over TLS. Plain `http::server` stays HTTP/1.1. Cleartext
prior knowledge, h2c upgrade, and ordinary CONNECT tunnels are unsupported.
With routes, SETTINGS_ENABLE_CONNECT_PROTOCOL enables RFC 8441
[routed WebSockets](websocket.md#routed-http2-and-http3-websockets).

| Per connection | Bound |
| --- | --- |
| Active streams / handler slots | 100 (SETTINGS_MAX_CONCURRENT_STREAMS) |
| Request header blocks/lists | 64 KiB |
| Discarded static request body | 1 MiB |
| Queued inline response bodies | 4 MiB |
| Output byte queue | 256 KiB |
| Routed body pool | Eight 16 KiB slots |

Files stream from owned descriptors; Linux DATA can use `SSL_sendfile()` with
transmit kTLS, otherwise bounded buffering. HPACK decoding is bounded;
connection/stream DATA flow control is enforced. No idle, SETTINGS, write-stall,
or flood limits are implemented.

RFC 9218 scheduling uses request `priority`, replaced by PRIORITY_UPDATE.
Lower urgency wins; within an urgency, non-incremental responses run in stream
order, then incremental responses share DATA round-robin. Flow-blocked streams
do not block others. Defaults are urgency 3/non-incremental; malformed values
keep defaults, updates for unopened streams are ignored.
Across connections, a writer yields to the loop after 64 KiB of writes
that did not suspend, so one connection with queued responses on a fast
socket cannot starve others. SETTINGS_NO_RFC7540_PRIORITIES is advertised; RFC 7540 PRIORITY frames receive
validity checks but do not affect scheduling. A PRIORITY of the wrong length
is a stream FRAME_SIZE_ERROR.

## Handlers, flow control, and cancellation

One handler runs per stream, alongside a reader task and the connection writer.
The session allocates once per connection. Stream and handler slots allocate
when concurrency first needs them and are kept; a stream beyond the limit, or
whose slot cannot be allocated, is refused with REFUSED_STREAM. A 16 KiB
frame buffer allocates the first time a frame payload spans reads or arrives
while reading is paused, and is kept; failing that allocation is a connection
INTERNAL_ERROR. `async_write`
completes when bytes enter the output queue under flow control/priority;
`async_send_file` completes when its last range is queued.

- Body slots allocate on the first routed body. With routes, initial stream
  window is 16 KiB and handler reads return credit. All eight slots busy:
  RST_STREAM REFUSED_STREAM (retryable).
- Before acknowledging SETTINGS, clients may use the default 65535-byte window.
  DATA that cannot fit pauses connection reading until the handler reads,
  delaying other streams. The acknowledgement shrinks open streams' windows
  to 16 KiB; DATA beyond a window is then a FLOW_CONTROL_ERROR, not a pause.
  A non-reading handler's stream ends on response.
- Cancelling a waiting handler read/write returns `operation_canceled`;
  cancelled writes/file sends also reset with CANCEL to release borrowed data.
  Loss resumes waiters with `connection_reset`; release the connection only
  after all handlers retire.
- SETTINGS_INITIAL_WINDOW_SIZE overflow on any stream is a connection
  FLOW_CONTROL_ERROR; stream WINDOW_UPDATE overflow is a stream error.

## Bodies and responses

Handlers see split Cookie lines joined with `; ` in arrival order as one
field (RFC 9113 8.2.3); the join reuses the first line's string.

Bodies may omit Content-Length. Reads beyond `max_request_body` return
`message_size`; if the handler returns without a response, answer 413.
DATA overruns or short END_STREAM reset with PROTOCOL_ERROR; reads return
`connection_reset`. Request trailers are validated, not exposed.

Without content-length, finish ends the stream; response trailers are always
sent. Returning after start without finish resets with INTERNAL_ERROR. Unread
request bodies end with RST_STREAM NO_ERROR after the response (RFC 9113 8.1).

## Closed streams and errors

`src/http2/session.h` retains 64 closure reasons. For retired-stream DATA/HEADERS:
normal completion of both directions gives a STREAM_CLOSED connection error;
peer RST_STREAM gives a STREAM_CLOSED stream error; frames racing a local reset
are discarded. Lower IDs skipped by the peer give PROTOCOL_ERROR. A malformed
request header block gets a 400 HEADERS frame without END_STREAM, then
RST_STREAM PROTOCOL_ERROR (RFC 9113 8.1.1, 8.2.1). Evicted IDs
at/below the closure floor are treated as local resets. DATA after END_STREAM
on a still-active stream is a stream error; Content-Length overrun is stream
PROTOCOL_ERROR. A peer GOAWAY draws one GOAWAY NO_ERROR naming the highest
peer stream seen; the connection closes once active streams finish. Connection
errors send GOAWAY with their code. Idle timeout, server close and loop shutdown
cancel the connection without a GOAWAY.
Regression coverage: [http2_hardening](../tests/http2_hardening.cc).

CMake registers `http2_h2spec` when h2spec is on PATH or
`-DH2SPEC_EXECUTABLE=/path/to/h2spec` is set; the binary is not vendored.
`tests/run_h2spec.sh` runs
`-t -k -S`, requires zero failures/skips, and serves 300000 bytes so the window
case is exercised. Run it to establish conformance; old pass counts are not
current test results.

## Allocation measurements

[http2_routing_allocations](../tests/http2_routing_allocations.cc) checks warmed
routed/static-file requests, counting general-heap and OpenSSL allocations.
The general heap target is zero in these paths. With Linux transmit kTLS,
OpenSSL's is too, except its record buffers, which it allocates while records
are in flight and frees when the connection is idle. Userspace TLS, the only
transport on Windows and macOS, also makes about 8 small OpenSSL allocations
per request in record writes; the test bounds that path separately.
Request fields reuse existing strings;
HPACK's dynamic table uses a 4 KiB ring allocated with its first entry;
response fields encode from views into reused storage. Longer-than-warmed
header values may allocate. TLS handshake key exchange/transcript/key schedule
allocates on each new connection.

## Outbound client

Include `eventloop/http2/client.h`. `http2::async_request(loop, endpoint,
context, hostname, request, sink = {}, header_sink = {})` performs one HTTPS
request on one owned TLS connection. Numeric endpoint resolution belongs to
the caller; hostname supplies verification, SNI, and default `:authority`.
ALPN must select h2. General token methods work; CONNECT returns
`operation_not_supported`. No push.

### Connection reuse

`http2::client_connection(loop, endpoint, context, hostname)` carries
sequential requests on one connection (RFC 9113 9.1.1). `async_connect()`
connects, handshakes, and requires ALPN h2; `async_request()` takes the same
request/sink arguments, limits, and errors as `async_request`, on client
streams 1, 3, 5, and so on; `async_close()` sends GOAWAY and closes.
Connection state (HPACK decoder table, peer SETTINGS, connection send window)
persists across requests; the connection preface is sent with the first.
An empty `:authority` uses the connection hostname.

`can_reuse_for(hostname, endpoint)` is true while the connection is open, has
seen no GOAWAY, was made to `endpoint` (same address and port), and its
verified certificate is valid for `hostname` under the handshake's own checks
(DNS name without partial wildcards, or iPAddress SAN for numeric hosts).
Callers check it before sending a request for another origin; the library does
not pool connections. A server that is not authoritative there answers 421
(Misdirected Request), which is returned as a response; retry it on a new
connection.

| Situation | Result |
| --- | --- |
| Second operation while one is pending | `device_or_resource_busy` |
| Request before connect, after close/failure/GOAWAY, or after stream IDs run out | `not_connected` |
| Second `async_connect()` | `already_connected` |
| GOAWAY whose last stream precedes the request's | `connection_reset` (not processed) |
| Request failure after validation, including cancellation | Closes the connection |

Late RST_STREAM and WINDOW_UPDATE frames for earlier streams are ignored. A
response completed before its upload ends that stream with RST_STREAM
(CANCEL), keeping the connection usable. Idle connections read nothing, so a
GOAWAY or close that arrives while idle is seen by the next request.
Construct, use, and destroy a connection on its loop thread; keep it alive
and unmoved while an operation is pending, and destroy it before loop
shutdown. Destruction closes an open transport without GOAWAY.

Requests own method/target/authority/header strings and either body bytes or a
`request_body_source`. Requests/callbacks are move-only: move named values.
Captured resources remain task-owned through completion/cancellation; callback
construction may allocate. All callbacks run synchronously on the loop thread.

| Storage / data | Limit / behavior |
| --- | --- |
| Owned request / buffered response body | 4 MiB each |
| Streamed source / sink total | 1 TiB each |
| Source chunk / received frame | 16 KiB |
| Request / response header block | 64 KiB, 128 fields |
| `request_body_source(span<byte>)` | Borrowed writable chunk; return count, 0 EOF, or error |
| `response_sink(span<const byte>)` | Chunk borrowed only during call; returned response body empty |
| `response_header_sink(status, fields)` | Borrowed block before DATA: 1xx informational, final status, 0 trailers |

A nonzero sink/header-sink error aborts and becomes the operation error. Final
headers/trailers remain owned by the returned response. Source-captured loans
must remain valid through task completion. DATA obeys peer stream/connection
windows; streaming buffers one frame at a time.

Optional decimal Content-Length must equal owned body size or source total;
mismatch is `invalid_argument` before connecting for owned bodies, or on
source overrun/short EOF. Supplying both body/source, connection-specific
request fields, a Host field that differs from `:authority`, or TE other than
`trailers` is also invalid.

Malformed responses return `protocol_error`: connection-specific fields or any
TE, nonnumeric/conflicting Content-Length, mismatched DATA totals, DATA
content on HEAD/204/304, or SETTINGS_ENABLE_PUSH=1. Bodyless Content-Length is
not compared. Request-stream
RST_STREAM, or GOAWAY whose last stream precedes the request's (last stream 0
for a one-shot request), returns `connection_reset`; other GOAWAY permits
completion. Malformed RST_STREAM/GOAWAY is `protocol_error`.
The client ends every connection with GOAWAY (last stream 0; PROTOCOL_ERROR
after a protocol failure, otherwise NO_ERROR).
Limits return `message_size`; TLS errors pass through. Cancellation closes the
owned transport. Each request allocates bounded frame/header/response storage;
OpenSSL may allocate separately. Outer task results remain distinct from I/O
errors; ownership/resumption stay on `loop`.
