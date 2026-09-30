# QUIC transport milestone

**Status:** active  
**Scope reviewed:** 2026-09-30

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
application protocols and are outside this milestone.

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
  transport parameters, ALPN, and alerts without a TLS-record shim. Keep the
  existing TCP/TLS provider unchanged; Botan remains for those paths.
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
- Verify Linux epoll and Windows IOCP builds and loopback interoperability.
  Recheck RFC publication status and verified errata, document known limits,
  then mark the milestone complete.

## Public API target

Expose loop-affine `quic_endpoint`, connection, stream, and DATAGRAM operations
using the library's `task<T>` and `std::expected` conventions. Awaiters own
operation state in their coroutine frame; caller buffers stay valid until the
await completes, including cancellation. A single endpoint owns and demuxes
its UDP socket across connections. No public API shape is frozen until the
TLS-provider proof of concept and endpoint/connection lifetime design are
reviewed.

## Explicit exclusions

- Video capture/encoding, FFmpeg, media framing, chat, or application UI
- HTTP/3, QPACK, WebTransport, MASQUE, or application-specific protocols
- 0-RTT data in this milestone
- Unpublished QUIC extensions or drafts
- Third-party QUIC protocol engines or handwritten cryptographic primitives

## Current checkpoint

The wire and bounded transport groundwork is in progress. The current
workspace contains:

- QUIC v1/v2 version identifiers, packet-header parsing, bounded transport
  parameter codecs, frame decoding/encoding, and packet/frame placement rules.
- RFC 9368 Version Negotiation encode/validation helpers, including downgrade
  validation and reserved-version handling.
- OpenSSL EVP-backed v1/v2 Initial secrets, AES-128-GCM keys, payload and
  header protection, packet-number reconstruction, Retry integrity tags, and
  key-update secret derivation. A caller-buffer protected-packet codec covers
  Initial, 0-RTT, Handshake, and 1-RTT packets. It matches the RFC 9001
  Appendix A.3 server Initial vector.
- Bounded caller-storage CRYPTO receive reassembly and CRYPTO send/retransmit
  tracking.
- Bounded stream receive reassembly, send/retransmit buffering, cumulative
  stream-ID and `MAX_STREAMS` tracking, aggregate `MAX_DATA`/`MAX_STREAM_DATA`
  accounting, and final-size checks for FIN and RESET_STREAM.
- A received-packet ACK-range tracker with packet-number retirement floors,
  confirmed-ACK retirement, and newest-range generation that fits caller
  storage.
- A bounded RFC 9221 DATAGRAM queue that preserves datagram boundaries and
  enforces the negotiated complete-frame size.
- A bounded peer connection-ID registry with sequence/token consistency,
  active-limit enforcement, monotonic retirement, and atomic capacity errors.
- Semantic transport-parameter validation that binds required connection-ID,
  Retry, and version-negotiation fields to authenticated handshake observations.
- A bounded local connection-ID registry, authenticated and expiring Retry
  address-validation tokens, v1/v2 Retry packet encode/validation, and
  stateless-reset encoding/detection helpers.
- A bounded path-validation tracker with challenge matching and per-path server
  anti-amplification accounting.
- Stream and connection lifecycle helpers, including final-size checks,
  negotiated idle timeout, closing/draining deadlines, and send permissions.
- An internal `connection_core` that composes OpenSSL QUIC TLS, bounded CRYPTO
  send/receive, packet protection, duplicate tracking, ACK generation,
  frame-policy validation, and close/drain transitions. Its owner still supplies
  stream, recovery, path, routing, address-validation, and UDP handling.
- ACK_ECN validation/accounting and v1/v2 1-RTT key-phase updates with bounded
  previous-key retention.
- Reusable OpenSSL EVP contexts and context-aware packet build/open operations
  with caller-owned authentication scratch.
- RFC 9002 RTT/PTO helpers, fixed-capacity sent-packet history, loss
  classification, three-space recovery orchestration, persistent-congestion
  detection, and a path-scoped NewReno controller.
- RFC 9287 greasing end to end. The empty `grease_quic_bit` parameter is
  advertised by the TLS adapter, peer support is recorded only after the
  peer's authenticated transport parameters are validated, a zero QUIC bit is
  accepted on receive only when this endpoint advertised support, and the bit
  is greased on send only after the peer advertised support. Packet parsing,
  protected-packet opening, endpoint routing, negotiation, and sending are
  covered by `tests/quic_grease_quic_bit.cc` and `tests/quic_connection_core.cc`.
- Bounded per-path recovery state for migration
  (`src/quic/path_recovery_state.h`). A candidate cannot replace the active
  path until the caller confirms validation; promotion installs fresh
  path-specific RTT and congestion state while packet-number spaces, ACK
  ranges, sent-packet history, and loss detection stay connection-wide;
  cancellation and rejected transitions preserve the active path. Covered by
  `tests/quic_path_recovery_state.cc` and the migration section of
  `tests/quic_connection.cc`.
- A public loop-affine API (`include/eventloop/quic.h`, implemented in
  `src/quic/quic_endpoint.cc`): server and client `quic_endpoint`, move-only
  `quic_connection` handles in fixed-capacity slots, stream
  open/accept/read/write, and RFC 9221 DATAGRAM. TLS contexts are built from
  cert/key or a trust store. Awaiters are resumed by the `connection_driver`
  progress hook. `tests/quic_public_api.cc` covers an in-house client/server
  handshake, bidirectional stream echo, and DATAGRAM exchange for QUIC v1 and
  v2; `examples/quic_echo_server.cc` is a runnable server.

On 2026-09-30, the Visual Studio 18/MSVC RelWithDebInfo build with OpenSSL
3.5.6 and Botan 3.13 passed the full Windows CTest suite, 61/61. A GCC 14.2
Release build on Linux (epoll) passed the full suite 61/61 as well. The Linux
build previously failed because `src/http/file_operations.h` used
`native_socket` without including `eventloop/native_socket.h`; the missing
includes are now explicit. Earlier failures in `quic_connection`,
`quic_packet_scheduler`, and `quic_connection_driver` were caused by test
callbacks comparing transport parameters without the now-required
`grease_quic_bit` advertisement; the tests were corrected, not weakened.

Independent-stack interoperability is verified for **QUIC v1** with OpenSSL
3.5.6: `openssl s_client -quic` completes a handshake with
`examples/quic_echo_server` and a full duplex stream exchange (the server reads
the client's message and the client receives the echo). OpenSSL 3.5.6 rejects
`-min_protocol QUICv2`, so its CLI is v1-only and no other independent stack is
installed; v2 is therefore verified only with the in-house client. The
following gates remain unverified:

- Independent-stack QUIC v2 interop. OpenSSL 3.5.6 has no QUIC v2 client and no
  other test peer is available in this environment.
- Automatic Retry and Version Negotiation client restart, PMTU, and ECN wiring
  at the endpoint boundary, plus connection lifetime/ownership auditing. These
  remain unimplemented and unverified; DATAGRAM is verified in-house.

Do not describe the library as QUIC-capable until these gates pass.
