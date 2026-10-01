# Optional outbound HTTP/3 verification

The standalone `http3_client` performs HTTPS GETs over the explicitly selected
QUIC version (`v1` by default). It verifies the certificate identity using system
trust or `--ca-file PEM`. Status and headers go to stderr and the binary body goes
to stdout. A complete HTTP 404 response is a successful exchange and exits zero;
tests must assert the expected status separately. It does not follow redirects.

Pass repeated `--request-path` arguments and `--output-dir` to issue concurrent
GETs on a single connection. Paths use the origin from the URL; the URL's own
path is used only when no request paths are supplied. Each request has an
independent response parser, body accounting, coroutine, and output file
(`0.body`, `1.body`, and so on in argument order). Connection control streams,
SETTINGS, QPACK, and cleanup are shared once per batch.

```sh
./build/http3_client --version v2 --output-dir /tmp/http3-responses \
  --request-path / --request-path /large https://example.org/
```

The example accepts at most 32 requests per batch, matching the transport's
local bidirectional lifetime reservation. The transport reserves 80 total
stream slots: 32 bidirectional and 8 unidirectional for each initiator. HTTP/3's
local and peer control/QPACK streams use their respective unidirectional
reservations, independently of the request streams. The peer's stream grant
may impose a smaller request limit. The
example closes the connection after the batch and returns an error if any
request fails. Request and output views supplied to `perform_gets()` must remain
valid through task completion. Payloads stream directly to each file without
retaining complete response bodies.

Stream slots remain reserved for the connection lifetime after completion or
reset. Advertised peer limits are capped to the corresponding reservations;
larger peer `MAX_STREAMS` grants cannot enlarge the local reservation. The
aggregate receive-data window remains capped at 128 KiB. The former shared
32-slot limit, which left only 26 requests after normal HTTP/3 critical streams,
was corrected before raising this example's batch ceiling.

`--timeout-ms 1..3600000` sets the overall connection/exchange deadline (default
30000 ms). The existing HTTP session also has a 30-second response deadline.
Expiry closes the active endpoint and waits for transport cleanup. DNS runs on a
blocking worker: expiry prevents later connections, but an already-running system
resolver must return before its coroutine can retire safely. The test harness
also enforces a process timeout.

## Deterministic independent-stack matrix

Normal builds and CTest do not require Python or aioquic. Install the optional
dependency separately, then enable the matrix explicitly:

```sh
python3 -m venv /tmp/eventloop-aioquic
/tmp/eventloop-aioquic/bin/python -m pip install 'aioquic==1.3.0'
cmake -S . -B build -DEVENTLOOP_HTTP3_INTEROP_TESTS=ON \
  -DPython3_EXECUTABLE=/tmp/eventloop-aioquic/bin/python
cmake --build build --target http3_client -j2
ctest --test-dir build -R '^http3_outbound_v[12]$' --output-on-failure
```

The standalone equivalent, also usable on Windows with the relevant Python and
executable paths, is:

```sh
/tmp/eventloop-aioquic/bin/python tests/run_http3_outbound.py \
  --client build/http3_client --version both
```

The fixture binds an ephemeral IPv4 loopback UDP port and announces readiness
after binding. Its aioquic configuration permits exactly one QUIC version. It
asserts the negotiated version and `h3` ALPN, request method/scheme/authority,
and FIN. The runner verifies an omitted path, query-only URL, percent-encoded
path, repeated query parameters, discarded fragment, 32 KiB binary response,
204 and 404 status/body behavior, tolerance of `Content-Length: 0` on 204,
rejection of nonzero 204 lengths or bodies, rejected untrusted certificates and
wrong certificate IP identity, and deadlines during handshake and HTTP exchange.
It also requires and verifies a Retry handshake for both QUIC versions.
The large binary body exceeds the 4 KiB per-stream receive window and requires
credit replenishment. All success responses are compared byte for byte, and
server request records independently verify the path and exact wire version.

The same fixture verifies 18 simultaneous requests with boundary payload sizes
from 0 to 262,143 bytes (539,598 total bytes), then 26 and 32 requests using
repeated sizes through 65,537 bytes (322,628 and 430,148 total bytes). Delayed
headers and 317-byte DATA chunks force
interleaving and completion outside request order. Server records establish one
connection and distinct request stream IDs for each batch. Binary bodies are
compared exactly, including zero and 0xff bytes. QPACK cancellations include
multi-octet stream IDs split across delivery boundaries. A protocol failure in
one request wakes a stalled sibling, and an overall deadline closes concurrent
requests; 33 requested paths are explicitly rejected before connecting.

Certificates and ports are isolated per run. The generated certificate includes
`DNS:localhost` and `IP:127.0.0.1`; the matrix uses the numeric loopback address to
avoid dependence on local DNS ordering. The wrong-identity case instead includes
`IP:127.0.0.2`, while explicitly trusting that certificate. Failure diagnostics
include fixture records and stderr. aioquic 1.3.0 is pinned because obtaining the
negotiated version and bound port uses internal fixture-only attributes.

## Explicit public-network probes

Public probes are never registered in default CTest. Run them explicitly with
the version and expectations you want:

```sh
python3 tests/probe_http3_live.py --client build/http3_client \
  --version v1 --contains 'colo=' https://www.cloudflare.com/cdn-cgi/trace
python3 tests/probe_http3_live.py --client build/http3_client \
  --version v2 --timeout-ms 5000 https://www.haproxy.org/
python3 tests/probe_http3_live.py --client build/http3_client \
  --version v1 --expect-status 204 https://www.google.com/generate_204
```

Public support and routing can change. A failed v2 probe never retries with v1.
HTTP/3 ALPN and Alt-Svc alone do not prove a transport version. The live runner
prints the requested version, exit status, byte count, body hash, and client
diagnostics. Use `--expect-status`, `--contains`, or `--sha256` for stable assertions; avoid
hashes for changing public HTML. Network restrictions, remote changes, and DNS
failures make live results unsuitable as deterministic release gates.

The client tolerates `Content-Length: 0` on a 204 response for interoperability.
It rejects nonzero lengths and any body.

Sources: [aioquic configuration](https://github.com/aiortc/aioquic/blob/1.3.0/src/aioquic/quic/configuration.py),
[Cloudflare trace endpoint](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/),
[QUIC working group implementation list](https://github.com/quicwg/base-drafts/wiki/Implementations),
[RFC 9110 Content-Length rules](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6).
