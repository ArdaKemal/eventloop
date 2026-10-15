# QUIC API contract

Shared async rules: [coroutines](coroutines.md). HTTP/3 behavior:
[HTTP/3](http3.md). Public names below are in `eventloop`; include `eventloop/quic.h`.

## Streams and I/O

Endpoints own connections in bounded slots. `quic_connection` is a move-only
handle that must not outlive its endpoint; it does not own the connection.

Endpoints reserve 216 active slots per connection: 100 bidirectional and eight
unidirectional for each initiator. A slot's storage (about 24 KiB of stream
buffers) is allocated when concurrency first needs it and kept for the
connection's lifetime, so an idle connection holds about 400 KiB. If that
allocation fails, a local open returns a capacity error and a peer stream
closes the connection with INTERNAL_ERROR. Advertised counts cap to peer reservations;
local opens obey peer cumulative grants and local active reservations. Slots
retire after both directions finish and sent data is acknowledged; peer
retirement replenishes MAX_STREAMS, advertised once the peer has opened half
of the last grant. MAX_STREAM_DATA is sent only while a stream's final size
is unknown (RFC 9000 3.2). Bounded ordinal ranges retain retired IDs
against delayed reopening; sparse retirement can exhaust ranges and delay
reclamation. Aggregate receive window <=128 KiB, per-stream buffering <=4 KiB;
no unbounded fallback. These windows bound buffered data, not total transfers.
Data held back by peer credit draws DATA_BLOCKED or STREAM_DATA_BLOCKED, and an
open refused by the peer's stream limit draws STREAMS_BLOCKED (RFC 9000 4.1,
4.6), once per limit value.

`quic_endpoint::async_accept()` returns an early failure/peer-close as that
connection's error; accept again to continue. Endpoint close or accept-task
cancellation returns `operation_canceled`. `quic_connection::async_accept_stream()`
returns peer streams lowest ID first among those with data, so a stream that
reuses a retired slot does not overtake older ones.

`quic_connection::async_write()` returns bytes accepted into bounded send
storage, possibly partial. Retry remaining bytes; `fin` closes only when the
whole supplied span is accepted. Borrow the span through completion/cancellation.

Pending operations resume on connection progress or at once on cancellation.
They share 256 waiters per connection slot; an operation that finds the pool
full returns `capacity_exceeded`; a cancelled operation returns its waiter at
once. After 1-RTT packets that want an ACK, the driver lets woken tasks run
for one loop turn before sending, so the ACK rides on their replies. 1-RTT
ACKs report that wait as ACK Delay, measured from the arrival of the largest
acknowledged packet (default exponent 3); Initial and Handshake ACKs send 0,
which peers ignore (RFC 9002 5.3). An idle
connection's driver sleeps until its
next loss, PTO, idle, key-retirement or path-probe deadline.

## Socket and path MTU

Application packets start at the Ethernet payload: 1472 bytes, or 1452 to an
IPv6 peer. On Linux endpoints set the don't-fragment bit, and after the
handshake is confirmed each connection probes larger sizes with a PING
padded to the probed size, outside congestion control, sent up to three times
a PTO apart (RFC 9000 14.3). The negotiated `max_udp_payload_size` (default
8192) goes first. An ACK raises the packet size to the probed size; EMSGSIZE
or three unacknowledged probes lower the upper bound, and the search halves
the remaining gap until it is under 64 bytes. If a send later fails with
EMSGSIZE because the kernel learned a smaller path MTU, the connection drops
to 1200 bytes and the lost packets are recovered as usual. If 1200-byte
datagrams fail with EMSGSIZE too, the path cannot carry QUIC and the
connection stops sending and fails (RFC 9000 14). Other platforms do not set
the bit, so they keep the start size.

A server answers a client's new address by validating it with PATH_CHALLENGE
and switches to it once validated; a client drops packets from any address but
the server's, and drops server Initials that carry a token. PATH_CHALLENGE and
PATH_RESPONSE datagrams are padded to 1200 bytes when the path's
anti-amplification credit allows (RFC 9000 8.2).

Once the handshake is confirmed each side issues NEW_CONNECTION_ID so the peer
holds up to three of its connection IDs, within the peer's
`active_connection_id_limit` (default 2). Each connection issues at most eight
IDs in its lifetime; a retired ID stops routing at once and is replaced while
that budget lasts. A server in a worker group keeps its index in the first
byte of every ID.

On Linux, endpoints enable UDP_GRO and request a 2 MiB socket receive buffer,
which the kernel caps at `net.core.rmem_max`. With the 208 KiB default, a
burst of 64 handshakes on one loop overflowed the buffer and the losses left
clients at minimum congestion windows; raise `rmem_max` if it is lower.

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
- `reset_stream_at()` sends RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset):
  the first `reliable_size` bytes stay reliable, sent and retransmitted until
  acknowledged, and the peer reads them before `stream_reset`. Later bytes are
  discarded, and the final size is the highest byte already sent or the reliable
  size. The send side completes once the frame and the reliable prefix are
  acknowledged. It needs the peer's `reset_stream_at` parameter (0x1d, empty) and
  is refused with `invalid_state` otherwise; a reliable size beyond the accepted
  bytes is `invalid_argument`. A later reset may only lower the reliable size,
  with the same code, and `reset_stream()` or a peer STOP_SENDING lowers it to
  zero. The frame waits until its final size fits flow credit.
- RESET_STREAM_AT on the receive side is valid only when this endpoint advertised
  `reset_stream_at`, and is otherwise FRAME_ENCODING_ERROR. A reliable size above
  the final size is FRAME_ENCODING_ERROR, a changed application code is
  STREAM_STATE_ERROR, and the smallest reliable size seen wins. Reads return data
  up to the reliable size, then `stream_reset`.
- Peer facts: `stream_reset_code()`, `stream_stop_sending_code()` and
  `stream_final_size()` stay readable after a `stream_reset` or stop-sending result
  until the stream's slot serves another stream; then, like unknown streams, they
  return nullopt. `peer_reset_stream_at()` and `peer_max_datagram_frame_size()`
  report the peer's transport parameters.

## Connection and endpoint close

Local close sends CONNECTION_CLOSE at the highest keyed encryption level:
`close()`/endpoint close use transport NO_ERROR; `close_application()` uses its
code (APPLICATION_ERROR before 1-RTT); protocol failures use RFC 9000 codes
(FLOW_CONTROL_ERROR, STREAM_LIMIT_ERROR, STREAM_STATE_ERROR, FINAL_SIZE_ERROR,
FRAME_ENCODING_ERROR, TRANSPORT_PARAMETER_ERROR and CONNECTION_ID_LIMIT_ERROR
where they apply, PROTOCOL_VIOLATION otherwise, CRYPTO_ERROR plus TLS alert for
handshake failure). Initial closes are padded to 1200 bytes.

While the endpoint stays open, a closed connection retains driver/route/capacity
for three current PTOs. Application operations finish promptly. Closing only
resends the cached close on incoming packets, at most once/PTO and <=3 times
received bytes; draining discards without sending. Both reuse driver storage
and its frame-local timer. Deadlines saturate; packets do not extend retention.
A server endpoint keeps one slot free: when a connection enters retention and
no slot is free, the oldest retained connection's period ends early, and a
late packet for it is dropped (the endpoint sends no stateless resets). Live
connections are never reclaimed, so capacity exhaustion by them is unchanged.

Endpoint close keeps UDP open until running connections send close and retire,
then closes it; it may shorten retention (RFC 9000 10.2). UDP failure/loop
cancellation retires immediately. Handles/tasks/borrowed buffers retain shared
ownership rules; delayed close processing stays on the owner loop on all
supported platforms.

## Port sharing

`quic_server_options::reuse_port` sets SO_REUSEPORT so several server
endpoints, one per loop, bind one port. Each endpoint keeps its own
connections, routes, and capacity. Linux picks the socket by hashing the
datagram's address pair, so a connection's packets reach its owner while the
client address and the set of bound endpoints stay unchanged. After NAT
rebinding or migration, or when an endpoint binds or closes, packets may reach
an endpoint that does not know the connection ID. Without a worker group (below)
it drops them without a stateless reset, so the connection stalls until it
recovers its path or idles out. Spreading is verified on Linux only; Windows
rejects the option.

`quic_server_options::worker_index` makes the first byte of every connection
ID the endpoint issues equal to the index; the other seven bytes stay random.
The endpoint issues one 8-byte ID per connection and no NEW_CONNECTION_ID
frames. Packets after the server's first Initial carry that ID, so a steering
layer can map them to the owner; the client's first Initial carries a
client-chosen ID and cannot be steered this way. The endpoint accepts the
peer's NEW_CONNECTION_ID frames: when Retire Prior To covers the ID in use, it
addresses the peer's next active ID and sends RETIRE_CONNECTION_ID for each
retired one. A datagram from the peer that cannot be routed, or a short-header
packet that cannot be decrypted, ending in the stateless reset token of the ID
in use makes the connection drain at once (RFC 9000 10.3.1). The endpoint
itself sends no stateless reset tokens or resets.

`quic_worker_group(workers)` (1..256) lets those endpoints forward misrouted
packets to each other. Give every endpoint the same
`quic_server_options::worker_group` and a distinct `worker_index` below
`workers`; a group without an index, an index out of range, or an index
another open endpoint holds throws `std::invalid_argument` at construction.
An endpoint forwards a short-header or Handshake packet whose connection ID it
does not know and whose first byte names another joined endpoint. The owner
processes it on its own loop as if it had arrived there, including path
validation after NAT rebinding, and replies from its own socket on the same
address and port. Initial and 0-RTT packets are never forwarded: their
connection ID can be client-chosen, so they follow the address hash as before.

Each endpoint's inbox holds 64 datagrams of up to its `max_udp_payload_size`
and is reserved at construction. A full inbox, a larger datagram, or an index
with no open endpoint drops the datagram; QUIC recovers it like any loss.
Forwarding copies the datagram once and wakes the owner through
`event_loop::post()` with at most one wakeup pending per inbox; if `post()`
fails the datagrams wait for the next forward. An endpoint leaves the group
when it closes, dropping datagrams still queued for it. Every packet of a
connection whose client address hashes to another endpoint is forwarded until
the address changes again.
