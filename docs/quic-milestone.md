# QUIC transport milestone

**Status:** active  
**Implementation notes updated:** 2026-10-01

Deliver an in-house QUIC transport for `eventloop`. The library owns packet
formatting, connection state, stream multiplexing, loss recovery, congestion
control, version handling, and UDP integration. TLS 1.3 and cryptographic
primitives come from a maintained provider through a QUIC-TLS interface; they
are not reimplemented here.

## Standards baseline

Implement the published QUIC transport specifications:

- [RFC 8999](https://www.rfc-editor.org/rfc/rfc8999.html), QUIC invariants
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html), QUIC v1 transport
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html), TLS integration
- [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html), loss detection and congestion control
- [RFC 9368](https://www.rfc-editor.org/rfc/rfc9368.html), compatible version negotiation
- [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html), QUIC v2
- [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html), QUIC DATAGRAM extension
- [RFC 9287](https://www.rfc-editor.org/rfc/rfc9287.html), greasing the QUIC bit

Use [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html) and
[RFC 9312](https://www.rfc-editor.org/rfc/rfc9312.html) as applicability and
operational guidance. RFC 9114 (HTTP/3) and RFC 9204 (QPACK) are separate
application protocols. Wayfarer and Stonegate exercise HTTP/3 through public
client and server APIs; the root test fixtures are described in
[the outbound verification guide](http3-outbound-tests.md).

The [IETF QUIC working-group index](https://datatracker.ietf.org/wg/quic/documents/)
was rechecked on 2026-09-30. The published transport RFC baseline above remains
current. Multipath and partial-delivery stream reset are still in the RFC
Editor queue; drafts are excluded unless published before release.

Known errata to account for include verified RFC 9000 errata 6811, 7365, 7861,
and 8240. RFC 9002 erratum 7539 is verified; erratum 9169 remains **Reported**
(not verified) and identifies a zero-sentinel bug in loss-deadline selection.
Apply that correction in the recovery implementation unless its status or text
changes. All seven RFC Editor errata pages were rechecked on 2026-09-30: no
status changed, no new verified errata were published, RFC 9001 has only the
rejected erratum 7785, and RFC 9368/9369/9221/9287 have no errata. The published
versions remain current. Recheck all errata before release; do not infer an
empty list from an inaccessible page.

## Milestone gates

### 1. Wire and TLS foundation

- Create internal QUIC modules without changing the existing TCP, TLS, or UDP
  ownership contracts.
- Implement bounded codecs for QUIC variable-length integers, packet headers,
  transport parameters, and frames, with malformed and truncated input handled
  without unbounded allocation.
- Support v1 and v2 packet protection, QUIC key updates, and TLS 1.3 through
  raw QUIC CRYPTO input/output and per-encryption-level secrets. Do not route
  QUIC through `tls_stream` or use a third-party QUIC engine.
- Use OpenSSL 3.5 or later for QUIC TLS and EVP packet cryptography. Its
  external QUIC TLS callback API exposes handshake bytes, traffic secrets,
  transport parameters, ALPN, and alerts without a TLS-record shim. TCP/TLS
  streams also use OpenSSL.
- Validate codecs and packet protection against RFC vectors and negative
  cases.

### 2. Interoperable reliable transport

- Provide loop-affine client and server endpoints over a shared UDP socket, with
  connection-ID routing and bounded connection, packet, and stream queues.
- Complete TLS handshakes and provide bidirectional and unidirectional streams,
  stream and connection flow control, graceful and error close, idle timeout,
  address validation, and anti-amplification limits.
- Implement ACK processing, packet-number spaces, loss detection, PTO, and a
  congestion controller according to RFC 9002. Use the RFC's verified errata.
- Preserve event-loop affinity for I/O, cancellation, timers, and resumption.
  Exhausted bounded resources return errors; no hot-path fallback to unbounded
  heap allocation.

### 3. Current QUIC extensions

- Interoperate with v1 and v2, including compatible version negotiation.
- Implement RFC 9221 DATAGRAM negotiation, size limits, and bounded send/receive
  queues.
- Implement RFC 9287 grease behavior and retain the version-independent packet
  handling required by RFC 8999.
- Cover connection-ID rotation, NAT rebinding, and client migration required by
  the transport specification; rate-limit path validation work.

### 4. Release qualification

- Pass packet/frame/transport-parameter vectors, malformed-packet tests, and
  deterministic loss, duplication, reordering, and MTU tests.
- Interoperate as both client and server with at least one independently
  implemented QUIC stack. Use external stacks only as test peers; do not link
  their QUIC engines into `eventloop`.
- Demonstrate bounded behavior under connection, stream, datagram, and queue
  exhaustion, plus cancellation and event-loop shutdown with operations in
  flight.
- Verify Linux epoll, macOS kqueue, and Windows IOCP builds and loopback
  interoperability.
  Recheck RFC publication status and verified errata, document known limits,
  then mark the milestone complete.

## Current implementation

`include/eventloop/quic.h` exposes loop-affine client and server endpoints,
move-only connection handles, stream operations, and RFC 9221 DATAGRAMs. The
implementation uses bounded storage and OpenSSL's external QUIC TLS callbacks.
`examples/quic_echo_server.cc` exercises the public server API. Wayfarer uses
the public QUIC client API for bounded HTTP/3 GET and HEAD requests, and
Stonegate uses the public HTTP/3 server API. HTTP/3 remains outside the QUIC
transport release gate.

In-house v1/v2 client and server tests cover handshake, bidirectional echo,
and DATAGRAM exchange. OpenSSL 3.5.6 independently interoperated with the v1
echo server. The optional aioquic fixture verifies outbound HTTP/3 over v1
and v2, including concurrent requests and Retry handling; see
[the verification guide](http3-outbound-tests.md). These checks do not establish
that every endpoint or network supports both QUIC versions.

## Work remaining before transport release

- Automatic client restart after Version Negotiation.
- PMTU discovery and ECN handling at the public endpoint boundary.
- Connection lifetime, cancellation, and shutdown auditing under in-flight
  work, including error paths and resource exhaustion.
- Independent-stack checks for the full public transport API in both v1 and
  v2, including peer stream and DATAGRAM behavior. The HTTP/3 fixture covers
  an application subset.

The public QUIC API is available for evaluation while these gates remain
open. Recheck current RFCs and errata before a transport release.
