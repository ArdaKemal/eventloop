# QUIC API contract

Shared async rules: [coroutines](coroutines.md). HTTP/3 behavior:
[HTTP/3](http3.md). Public names below are in `eventloop`; include `eventloop/quic.h`.

## Streams and I/O

Endpoints own connections in bounded slots. `quic_connection` is a move-only
handle that must not outlive its endpoint; it does not own the connection.

Endpoints reserve 80 active slots per connection: 32 bidirectional and eight
unidirectional for each initiator. Advertised counts cap to peer reservations;
local opens obey peer cumulative grants and local active reservations. Slots
retire after both directions finish and sent data is acknowledged; peer
retirement replenishes MAX_STREAMS. Bounded ordinal ranges retain retired IDs
against delayed reopening; sparse retirement can exhaust ranges and delay
reclamation. Aggregate receive window <=128 KiB, per-stream buffering <=4 KiB;
no unbounded fallback. These windows bound buffered data, not total transfers.

`quic_endpoint::async_accept()` returns an early failure/peer-close as that
connection's error; accept again to continue. Endpoint close or accept-task
cancellation returns `operation_canceled`.

`quic_connection::async_write()` returns bytes accepted into bounded send
storage, possibly partial. Retry remaining bytes; `fin` closes only when the
whole supplied span is accepted. Borrow the span through completion/cancellation.

## Reset and stop-sending

`reset_stream()`/`stop_sending()` synchronously queue application codes <=2^62-1
in fixed stream slots on the owner loop; retransmit until acknowledged.

- Reset drops unsent queued bytes; later writes return `stream_reset`.
  Peer STOP_SENDING has the same effect.
- Stop-sending drops buffered/later data and consumes peer RESET_STREAM
  internally, allowing retirement without reads; later reads return `invalid_state`.
- Finished directions stay unchanged. Unknown stream/missing unidirectional
  direction returns `invalid_argument`; closing connection returns
  `not_connected`; writing a retired stream returns `invalid_argument`.
  These errors are `quic_errc`.

## Connection and endpoint close

Local close sends CONNECTION_CLOSE at the highest keyed encryption level:
`close()`/endpoint close use transport NO_ERROR; `close_application()` uses its
code (APPLICATION_ERROR before 1-RTT); protocol failures use RFC 9000 codes
(PROTOCOL_VIOLATION for stream/flow violations, CRYPTO_ERROR plus TLS alert
for handshake failure). Initial closes are padded to 1200 bytes.

While the endpoint stays open, a closed connection retains driver/route/capacity
for three current PTOs. Application operations finish promptly. Closing only
resends the cached close on incoming packets, at most once/PTO and <=3 times
received bytes; draining discards without sending. Both reuse driver storage
and its frame-local timer. Deadlines saturate; packets do not extend retention.
A server endpoint keeps one slot free: when a connection enters retention and
no slot is free, the oldest retained connection's period ends early (RFC 9000
10.2 permits this; a late packet for it draws a stateless reset). Live
connections are never reclaimed, so capacity exhaustion by them is unchanged.

Endpoint close keeps UDP open until running connections send close and retire,
then closes it; it may shorten retention (RFC 9000 10.2). UDP failure/loop
cancellation retires immediately. Handles/tasks/borrowed buffers retain shared
ownership rules; delayed close processing stays on the owner loop on all
supported platforms.
