# QUIC API contract

Task results, loop affinity, and cancellation follow the
[coroutine and event-loop contract](coroutines.md). Read that contract
together with the rules below.

QUIC endpoints reserve 80 active stream slots per connection: 32 bidirectional
and 8 unidirectional streams for each initiator. Requested advertised counts
are capped to those peer reservations; local opens obey the peer's cumulative
grant and the separate local active reservation. A stream releases its slot
after both directions complete and sent data is acknowledged. Retired peer
streams replenish `MAX_STREAMS` credit. Retired IDs are kept in bounded
ordinal ranges so delayed packets cannot reopen them; pathological sparse
retirement can exhaust that range storage and delay further reclamation.
The aggregate receive-data window remains at most 128 KiB, independently
of stream count, with at most 4 KiB buffered per stream. No stream storage falls
back to an unbounded allocation.

`quic_connection::reset_stream()` and `stop_sending()` take an application
error code up to 2^62-1 and complete synchronously on the owner loop; the
frame is queued in the stream's fixed slot and retransmitted until
acknowledged. A reset discards queued bytes that were not yet sent, and later
writes fail with `quic_errc::stream_reset`; a peer STOP_SENDING has the same
effect. After `stop_sending()`, buffered and later data are discarded and the
peer's RESET_STREAM is consumed internally, so the stream retires without
further reads; reads fail with `quic_errc::invalid_state`. Both operations
leave an already finished direction unchanged, return
`quic_errc::invalid_argument` for an unknown stream or the missing direction of
a unidirectional stream, and return `quic_errc::not_connected` once the
connection is closing. A write to a stream that has already retired returns
`quic_errc::invalid_argument`. Every local close sends one CONNECTION_CLOSE
at the highest encryption level with keys: `close()` and `quic_endpoint::close()`
send transport `NO_ERROR`, `close_application()` sends its code (as
`APPLICATION_ERROR` before 1-RTT keys exist), and a local protocol failure
sends the RFC 9000 code (`PROTOCOL_VIOLATION` for stream and flow violations,
`CRYPTO_ERROR` with the TLS alert for handshake failures). Initial-level closes
are padded to 1200 bytes. The close is not retransmitted and no closing period
is kept, so a lost close leaves the peer to its idle timeout; a UDP failure or
event-loop cancellation sends none. Endpoint close keeps its socket open until
every running connection has sent its close and retired.

HTTP/3 application behavior is specified separately in the
[HTTP/3 contract](http3.md).
