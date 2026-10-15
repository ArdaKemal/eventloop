# WebTransport API contract

WebTransport over HTTP/3, server role, implementing
[draft-ietf-webtrans-http3-16](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16)
(the latest revision; draft-version codepoint `SETTINGS_WT_ENABLED = 0x2c7cf000`)
with [RESET_STREAM_AT](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-11)
from QUIC. Shared async rules: [coroutines](coroutines.md); HTTP/3 server:
[HTTP/3](http3.md); QUIC streams/resets: [QUIC](quic.md). Include
`eventloop/http/webtransport.h`; names are relative to `eventloop::http`.
The library has no WebTransport client; tests use a raw test-only client
(`tests/fixtures/webtransport_client.h`).

## Enabling and accepting sessions

Set `server_options::webtransport.enabled` on an `http3_server` with routes
(without routes construction throws `std::invalid_argument`). Register a
CONNECT route and call `request::async_accept_webtransport(protocols)` before
reading the body or starting a response:

```cpp
auto session_handler(event_loop&, http::request& request, http::response& response)
    -> task<void>
{
    if (request.header_value("origin") != "https://app.example") {
        (void)co_await response.async_send(403, {});   // draft-16 3.2: verify Origin
        co_return;
    }
    const std::array<std::string_view, 1> protocols {"chat/1"};
    auto session = co_await request.async_accept_webtransport(protocols);
    if (!session) co_return;
    while (auto stream = co_await session->async_accept_stream()) { /* ... */ }
}
```

`examples/webtransport_echo_server.cc` is a complete echo server
(bidirectional, unidirectional and datagram echo); its handler logic in
`examples/webtransport_echo.h` is exercised by the `webtransport_example` test.

- Acceptance sends 200 and returns a `webtransport_session`. The client's
  `WT-Available-Protocols` (RFC 9651 List of Strings; a malformed field, a
  non-String member, or an escaped string is ignored) is matched in the
  client's preference order against `protocols`, and the choice is sent in
  `WT-Protocol` and exposed by `session.protocol()`. No match accepts without
  `WT-Protocol`; the handler can close the session itself.
- To reject, respond without accepting (403, 404, 429, ...). A matched path
  without a CONNECT route answers 405 with Allow; an unknown path 404; with
  WebTransport disabled `:protocol webtransport-h3` answers 501.
- HTTP/1.1 and HTTP/2 return `operation_not_supported`; a request that is not
  `CONNECT` with `:protocol webtransport-h3`, or already started or read,
  returns `invalid_argument`.
- Origin, authentication, and rate policy belong to the handler.

The session handle is borrowed from the handler: returning from the handler or
destroying the handle ends the session like `async_close(0)`. Session and
stream handles are move-only, loop-affine, and generation checked: operations on
a handle whose session ended return `session_closed`. Using a default-
constructed or moved-from handle's `async_*` operations is a programming error.

## Negotiation and admission

With WebTransport enabled the server's SETTINGS carry
`ENABLE_CONNECT_PROTOCOL=1`, `H3_DATAGRAM=1`, `WT_ENABLED=1`, and
`WT_INITIAL_MAX_STREAMS_BIDI/UNI` and `WT_INITIAL_MAX_DATA` from the options;
the QUIC transport parameters carry `max_datagram_frame_size=1232` and an empty
`reset_stream_at`. Without WebTransport none of these are sent.

A `webtransport-h3` CONNECT reserves a session slot and waits for the client's
SETTINGS before the handler runs (draft-16 3.1 and 8.1 for draft versions).
Then:

| Condition | Result |
| --- | --- |
| Client SETTINGS lack `H3_DATAGRAM=1` or `WT_ENABLED=1`, or its transport parameters lack `max_datagram_frame_size>0` or `reset_stream_at` | Malformed: CONNECT stream reset with `H3_MESSAGE_ERROR` |
| Client `H3_DATAGRAM=1` without QUIC DATAGRAM | Connection error `H3_SETTINGS_ERROR` (RFC 9297 2.1.1) |
| `max_sessions` reserved or open sessions on the connection | `H3_REQUEST_REJECTED` |
| Session flow control disabled and another session exists | `H3_REQUEST_REJECTED` (draft-16 5.1) |
| Scheme other than `https` | `H3_MESSAGE_ERROR` |

Session flow control is enabled when both endpoints send a nonzero
`WT_INITIAL_*` setting. `WT_ENABLED` values other than 1 from a client mean
"not supported" (the `H3_SETTINGS_ERROR` rule binds clients only).

## Streams

Peer streams are identified by the WT_STREAM signal `0x41` on client
bidirectional streams and the stream type `0x54` on unidirectional streams,
followed by the session ID. The server reads at most 16 bytes per read until
the header is parsed, so at most 16 body bytes are held per stream before the
application reads. `0x41` anywhere but the first bytes of a request stream is
`H3_FRAME_ERROR`. A session ID that is not a client bidirectional stream ID is
a connection `H3_ID_ERROR`.

`async_accept_stream()` returns peer streams in arrival order;
`async_open_stream(direction)` opens one and writes its header, waiting while
the peer's `WT_MAX_STREAMS` is reached (`WT_STREAMS_BLOCKED` is sent once per
limit); a QUIC stream-limit refusal returns `capacity_exceeded` at once.
`webtransport_stream` I/O follows `quic_connection`: `async_read` returns 0 at
FIN, `async_write` may accept fewer bytes than supplied, one read and one write
may be pending. Errors:

- Peer reset: `stream_reset`, with `error_code()` the 32-bit application code
  mapped from the WebTransport range (draft-16 4.4, see
  `http3_to_webtransport_error`), or `nullopt` for codes outside it. A reset
  with `WT_SESSION_GONE` reports `session_closed`.
- Peer STOP_SENDING on a write: `stream_reset` with `error_code()` likewise.
- After a local `reset()`/`stop_sending()`: `stream_closed`.

`reset(code)` sends RESET_STREAM_AT with the mapped code and the stream header
as reliable size, so the peer can still associate the stream with its session;
on a peer-initiated bidirectional stream nothing of ours precedes the body, so
the reliable size is 0. Destroying an unfinished stream handle resets and stops
it with application code 0.

## Datagrams

HTTP Datagrams carry the quarter stream ID followed by the payload (RFC 9297).
Payloads are limited to `max_datagram_size()`, at most 1200 bytes; larger sends
fail with `datagram_size`. Received datagrams queue per session
(`datagram_queue`); a full queue drops new ones. `async_receive_datagram`
fails with `datagram_size`, keeping the datagram, if the buffer is too small.
DATAGRAM capsules on the CONNECT stream are delivered the same way. A quarter
stream ID above 2^60-1 is a connection `H3_DATAGRAM_ERROR`.

## Buffering before establishment

Streams and datagrams whose session ID names a CONNECT stream that has not been
answered yet, or not yet received, are buffered per connection
(`buffered_streams`, `buffered_datagrams`) and delivered on acceptance.
Excess streams are refused with STOP_SENDING (and RESET_STREAM for
bidirectional streams) `WT_BUFFERED_STREAM_REJECTED`; excess datagrams are
dropped. When the request ends without a session, or names a session that has
ended, streams are refused with `WT_SESSION_GONE` and datagrams dropped.
Capsules sent before the response are processed once the session is accepted
and discarded on rejection.

## Flow control

When enabled, session data counts stream body bytes (not stream headers or
capsules) across all streams of the session. Writes take at most the peer's
remaining `WT_MAX_DATA` credit and wait for more (`WT_DATA_BLOCKED` is sent once
per limit); credit not accepted by QUIC is returned. Received body bytes are
counted when the application reads them, and the final size of a reset stream
counts in full. `WT_MAX_DATA` and `WT_MAX_STREAMS` are renewed (consumed or
closed + initial window) once half the window is used; peer streams count as
closed when their handle is destroyed. Receiving more data or streams than
advertised, a non-increasing `WT_MAX_DATA`/`WT_MAX_STREAMS`, a value above
2^60, or the prohibited `WT_MAX_STREAM_DATA`/`WT_STREAM_DATA_BLOCKED` capsules
ends the session: the CONNECT stream is reset and stopped with
`WT_FLOW_CONTROL_ERROR`. Without session flow control these capsules are
ignored (draft-16 5.1).

## Termination

A session ends when either side sends `WT_CLOSE_SESSION`, the CONNECT stream
ends or is reset, the handler returns, or the connection closes. Then every
stream of the session is reset (RESET_STREAM_AT, header reliable) and stopped
with `WT_SESSION_GONE`, queued streams and datagrams are dropped, no streams
or datagrams are sent, and pending operations complete with `session_closed`.
`close_info()` reports the code, reason, and whether the peer ended it.

- `async_close(code, reason)`: sends `WT_CLOSE_SESSION` (a reason that is not
  UTF-8 is `invalid_argument`; longer than 1024 bytes is truncated at a
  character boundary), then FIN, then STOP_SENDING `WT_SESSION_GONE` on the
  CONNECT stream.
- Peer `WT_CLOSE_SESSION`: the server answers with FIN. Any bytes after the
  capsule reset the CONNECT stream with `H3_MESSAGE_ERROR`, as does a close
  reason over 1024 bytes or not UTF-8. A clean FIN without the capsule is code 0.
- `async_drain()` sends `WT_DRAIN_SESSION`; `draining()` reports one from the
  peer. Both are advisory.
- HTTP/3 errors on the CONNECT stream that are connection errors (for example
  HEADERS after acceptance, `H3_FRAME_UNEXPECTED`) close the connection.
- Server close and loop shutdown end sessions with the connection; the engine
  cancels and awaits its tasks before the connection slot is reused.

## Capacity

Per connection, reserved when the server is constructed:

| Resource | Bound |
| --- | --- |
| `max_sessions` | 4 by default; 1..16 |
| Session buffers | about 6 KiB each (CONNECT read buffer, capsule send buffer, datagram scratch, close reason, protocol) |
| Received datagrams | `datagram_queue` (8; 1..64) x 1200 bytes per session |
| Stream table | 216 entries (QUIC's 100 + 8 streams per initiator), at most 16 unread body bytes each |
| Buffered streams / datagrams | `buffered_streams` / `buffered_datagrams` (8 each; 0..64) |
| Initial session limits | `initial_max_streams_bidi` 32, `initial_max_streams_uni` 8, `initial_max_data` 256 KiB; each < 2^60 |

Each open session runs a CONNECT reader and a capsule writer task, and each
connection a datagram dispatcher, in the loop's coroutine frame pool; frame
exhaustion fails `async_accept_webtransport` with `capacity_exceeded`, and
the CONNECT stream is reset with `H3_INTERNAL_ERROR`. One accept, one open, one
datagram send, and one datagram receive may be pending per session
(`operation_in_progress` otherwise). Nothing is allocated per stream,
datagram, or capsule; QUIC connection and stream flow control bound the data
held for unread streams.

## Compliance (draft-16)

| Section | Requirement | Status |
| --- | --- | --- |
| 3.1 | Server SETTINGS (WT_ENABLED, ENABLE_CONNECT_PROTOCOL, H3_DATAGRAM) and TPs (max_datagram_frame_size, reset_stream_at) | Implemented |
| 3.1 | Client requirements unmet → sessions malformed | Implemented (`H3_MESSAGE_ERROR`) |
| 3.1, 8.1 | No WebTransport request processed before client SETTINGS | Implemented |
| 3.2 | `:protocol webtransport-h3`, https, authority/path required | Implemented (validation of Extended CONNECT) |
| 3.2 | Verify Origin (MUST), 405/403 (SHOULD) | Handler responsibility; 405 from routing |
| 3.2 | Capsules before 2xx not processed until accepted | Implemented |
| 3.3 | WT-Available-Protocols / WT-Protocol | Implemented; escaped sf-strings ignored |
| 3.4 | Priorities (RFC 9218) | Not implemented (MAY/RECOMMENDED) |
| 4 | Session IDs must be client bidi IDs (`H3_ID_ERROR`) | Implemented |
| 4.2, 4.3 | Uni type 0x54; WT_STREAM 0x41 only first (`H3_FRAME_ERROR`) | Implemented |
| 4.4 | App error mapping; RESET_STREAM_AT with header reliable; codes outside range → no app code | Implemented |
| 4.5 | Datagrams with quarter stream ID | Implemented |
| 4.6 | Bounded buffering, `WT_BUFFERED_STREAM_REJECTED`, datagram drop | Implemented |
| 4.7 | GOAWAY / WT_DRAIN_SESSION | DRAIN sent/received; server sends no GOAWAY; client GOAWAY does not set `draining()` |
| 4.8 | TLS exporter per session | Not provided (no API) |
| 5.1 | Flow control negotiation; single session when disabled; ignore FC capsules when disabled | Implemented |
| 5.2–5.6 | WT_MAX_STREAMS / WT_MAX_DATA / BLOCKED capsules, limits, errors, prohibited capsules | Implemented; receive-side data limit checked when read (below) |
| 6 | Termination, WT_SESSION_GONE resets, CLOSE_SESSION format/limits, FIN after close, data after close | Implemented |
| 6 | Wait for CONNECT streams to close before CONNECTION_CLOSE (SHOULD) | Not implemented: server close cancels at once, as for HTTP/3 |
| 9 | Fairness between sessions (SHOULD) | Not implemented beyond QUIC scheduling |

RESET_STREAM_AT (reliable-stream-reset-11) is implemented in QUIC in both
directions; see [QUIC](quic.md#reset-and-stop-sending).

## Limitations

- Server role only; no public client.
- Receive-side session flow control counts body bytes as the application
  reads them. A peer that exceeds `WT_MAX_DATA` is detected when the excess
  is read and still exceeds the credit advertised by then; QUIC's own
  connection and stream windows bound buffered data regardless.
- Only draft-16 is negotiated; clients speaking earlier drafts (different
  `WT_ENABLED` codepoints) see no WebTransport support. Interop was verified
  with pywebtransport 0.20.1 (draft-16 settings) for session setup, protocol
  negotiation, bidirectional and unidirectional echo, datagrams, flow-control
  settings and close, using a local build that waived the `reset_stream_at`
  requirement, because its QUIC stack (quinn 0.11) does not advertise
  RESET_STREAM_AT. Unmodified, this server rejects such clients as draft-16
  requires. Browsers were not tested: none available here speaks draft-16.
- 0-RTT is not supported by the server, so the 0-RTT settings rules do not apply.
