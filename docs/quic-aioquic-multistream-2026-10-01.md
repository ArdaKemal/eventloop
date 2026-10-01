# QUIC multi-stream interop probe — 2026-10-01

## Scope and method

This probe used aioquic 1.3.0 as an independent QUIC echo server and a
temporary C++ client linked against the current libeventloop.a. The client used
the public quic_endpoint / quic_connection API, verified a generated localhost
certificate, selected the requested QUIC version explicitly, opened multiple
bidirectional streams on one connection, interleaved writes in different chunk
sizes, sent FIN on each stream, and compared the echoed bytes exactly.

This first probe exercises raw QUIC transport streams, not HTTP/3 request
multiplexing. A separate follow-up added same-connection concurrent HTTP/3
requests; results are recorded below and in docs/http3-outbound-tests.md.

The test programs were temporary files under /tmp, not repository source.
The run required loopback UDP access.

## Results

### QUIC v1 boundary payloads — passed

One connection carried 18 streams with payload sizes:

0, 1, 2, 17, 63, 127, 255, 511, 512, 513, 1023, 4095, 4096, 4097,
65535, 65537, 131071, 262143

Total echoed and byte-for-byte verified: 539,598 bytes. This includes empty
streams, binary payloads with zero and 0xff bytes, buffer-boundary sizes, and
payloads larger than the advertised per-stream receive window.

aioquic observed all 18 streams, their expected byte counts, and FIN on each.

### QUIC v1 32-stream multiplex — passed after an aioquic fixture workaround

One connection opened 32 streams. Sizes repeated four times:

0, 17, 511, 512, 4095, 4096, 32769, 65537

Total sent: 430,148 bytes. The client reported that all payload bytes were
accepted and all 32 FINs were sent. aioquic observed every stream, the expected
byte count for every stream, and FIN on every stream.

The first run stalled awaiting the empty echoed response on stream ID 64. A
focused qlog and aioquic sender trace established that aioquic received the
client FIN but never emitted the response FIN. While preparing that response,
aioquic's stream sender cleared its pending EOF before the packet builder
reported that the packet had no remaining capacity. The next attempt therefore
lost the FIN permanently. This is a test-peer defect in aioquic 1.3.0, not an
eventloop receive failure.

A temporary server-side capacity precheck, applied before consuming the FIN,
made the unchanged eventloop client pass all 32 streams and verify all 430,148
bytes. Diagnostic traces are in /tmp/stream64-diagnostic2.log,
/tmp/stream64-qlog.json, and /tmp/stream64-preflight.log. The workaround was
not added to the repository or the installed aioquic package.

### QUIC v2 32-stream multiplex — not run

The independent investigation confirmed the v1 test-peer defect and passed the
32-stream scenario after a temporary aioquic workaround. The raw 32-stream
scenario was not repeated under v2, so no conclusion about raw QUIC v2
multi-stream behavior is supported by this probe.

## HTTP/3 multi-request follow-up

The client now shares SETTINGS, control streams, and QPACK state across
concurrent requests while keeping response parsing and body accounting per
request. The initial exact QUIC v1 and v2 aioquic tests passed 18 simultaneous
requests with 539,598 response bytes and 26 requests with 322,628 bytes. The matrix
checked binary payloads byte for byte, delayed headers, interleaved DATA,
out-of-order completion, sibling failure cleanup, and timeout cleanup. The
example initially rejected a batch of 32 paths before connecting. After the transport
capacity correction, the matrix also verifies 32 requests with 430,148 response
bytes for each version, and rejects 33 paths before connecting.

## QUIC stream-capacity correction

The initial HTTP/3 example cap of 26 accounted for six normal critical streams
within the former 32 shared lifetime slots. That exposed a transport/API
mismatch: defaults advertised 32 peer bidirectional and 8 peer unidirectional
streams, despite sharing those slots with local streams. Legal peer streams
could consequently exhaust storage and fail as a protocol violation.

The transport now reserves 80 lifetime slots: 32 bidirectional and 8
unidirectional for each initiator. Local opens obey both peer grants and their
own reservation; advertised peer limits are capped to reserved storage. This
supports 32 HTTP/3 request streams independently of critical unidirectional
streams, while retaining the 128 KiB aggregate receive-data window. Completed
and reset streams still retain slots. On this GCC build, connection storage
increased by 632,448 bytes (617.625 KiB); no allocation fallback was introduced.
The example's ceiling is now 32 requests. Bounded slot reclamation for repeated
batches remains separate work.

The raw QUIC reproduction and temporary aioquic capacity precheck stayed under
/tmp. The concurrent HTTP/3 feature and its deterministic tests changed the
example, aioquic fixtures, runner, and docs/http3-outbound-tests.md. Other
pre-existing uncommitted implementation and report files were left untouched.
