# Candidate work

Not contracts and not commitments. Each item names the evidence behind it, what
is still unverified, and why nothing has been built. Per the change rules in
`AGENTS.md`, an item needs a named failing case or measured bottleneck before
implementation; remove an item when it ships or is dropped.

Verification so far (2026-10-11): h2spec 2.6.0 passes 147/147 against
`http_server`; h3spec 0.1.14 passes 75/77 (1 skipped) against
`http3_file_server`; 47,142 hpack-test-case header blocks decode and
re-encode identically against the Python `hpack` 4.2.0 decoder; about 900k
mutated HPACK blocks showed no sanitizer findings and never produced an
accept where that decoder rejected. The two h3spec failures follow the RFC
text and are not defects (see the last section).

## Connection exhaustion by live connections

**Evidence.** With `http3_file_server` (connection capacity 16), h3spec's
"request with ... as malformed" cases leave their server connections live
because the client exits without closing. Replaying those cases back to back
dropped new Initials in about 28% of runs (20 of 72; the same on the build
before the closed-slot reclaim, 21 of 72). The server log showed every slot
live (none closing or retaining), so reclaiming closed connections cannot
help. The default idle timeout is 30 s (`max_idle_timeout_ms`,
`include/eventloop/quic.h`).

**RFC.** RFC 9000 10.1 defines the idle timeout the server already follows.
RFC 9000 21.6 says deployments SHOULD mitigate Slowloris-style attacks, which
keep connections open with minimal activity, and lists: raising the client
limit, limiting connections per IP address, a minimum transfer speed, and a
maximum connection lifetime.

**Candidates, in order of value.**
1. Per-source-address connection limit. The only item that addresses one
   address holding every slot; the others only shorten how long it can.
   Needs a bounded per-address table, a stated exhaustion result, and a
   policy for NAT-shared addresses.
2. Handshake deadline shorter than the idle timeout. **Unverified:** check
   first whether a connection that never completes its handshake is cut off
   before 30 s. Half-open connections are the cheapest slots to hold.
3. Maximum connection lifetime and minimum transfer rate. Both can disrupt
   legitimate long or slow transfers; add only against a measured case.
4. Shorter default `max_idle_timeout_ms`. A configuration choice, not code.

**Retry.** RFC 9000 21.1.1.2 describes Retry as the cheap way to validate an
address before the expensive handshake. `src/quic/quic_endpoint.cc` only
applies a Retry received as a client; no server option or code path that sends
one was found, though `src/quic/retry_packet.cc` and `retry_token.cc` exist
as codec and token helpers. Not confirmed by running a server against a
Retry-expecting client. Retry limits spoofed-source floods; it does not stop a
real address from holding live connections.

## Verification not yet done

- aioquic 1.3.0 interop. The repo's CMake supports it (an HTTP/3 interop
  option; see the top of `CMakeLists.txt`) but aioquic was not installed, so
  the HTTP/3 interop tests were not run. It is the only independent HTTP/3
  client check the repo has.
- HTTP/2 client against a reference server. `src/http2/client.cc` is covered
  only by `tests/http2_client_validation.cc`. `nghttpd` (package
  `nghttp2-server`) would give a reference server to point it at.
- QPACK malformed-input fuzzing with the method used for HPACK. Needs a
  reference decoder such as `pylsqpack`.
- HPACK state across blocks. The fuzz decoded each mutant with a fresh
  decoder, so mutations that depend on dynamic table contents from earlier
  blocks were not exercised, and the decoder's 128-field and 64 KiB limits
  were not reached.
- Sanitizer or libFuzzer harness on the frame parsers (HTTP/2, HTTP/3, QUIC).
  A robustness check rather than conformance; requires a named target first.

## Conformance tools in CTest

`tests/run_h2spec.sh` registers `http2_h2spec` when h2spec is on PATH or
`H2SPEC_EXECUTABLE` is set. There is no equivalent for h3spec. If added:
- Run with `-n -t 10000`. At h3spec's default 2 s per-case timeout, a different
  4 to 7 cases failed on each run before the closed-slot reclaim, and the
  stalls that caused them are fixed.
- Pace the cases or raise `connection_capacity`, for the live-connection
  exhaustion above.
- Skip the two cases below with a comment pointing here.
- The binary is not vendored; download a pinned release the way h2spec is.

## h3spec cases that are not defects

Both are deliberate, so do not change the server to satisfy them without
reopening the RFC reading.

- "MUST NOT buffer a frame longer than SETTINGS_MAX_FIELD_SECTION_SIZE":
  the server sends `H3_FRAME_ERROR`, h3spec expects `H3_EXCESSIVE_LOAD`. The
  frame is a GOAWAY with an oversized length, and RFC 9114 7.1 requires
  `H3_FRAME_ERROR` for a payload that does not match the frame's fields.
  `H3_EXCESSIVE_LOAD` is only a MAY (RFC 9114 10.5). The server does not
  buffer the frame.
- "H3_CLOSED_CRITICAL_STREAM if an encoder stream ends inside an
  instruction": the server sends `QPACK_ENCODER_STREAM_ERROR`. The test sends
  `0x3f`, a Set Dynamic Table Capacity of 31 or more, and the server
  advertises capacity 0, so RFC 9204 4.3.1 makes the instruction invalid at
  its first octet, before the stream ends. The test assumes a server that
  allows a nonzero table. Real closure of a critical stream does return
  `H3_CLOSED_CRITICAL_STREAM` (those h3spec cases pass).
