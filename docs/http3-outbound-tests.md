# Optional outbound HTTP/3 verification

The standalone `http3_client` performs one HTTPS GET over the explicitly selected
QUIC version (`v1` by default). It verifies the certificate identity using system
trust or `--ca-file PEM`. Status and headers go to stderr and the binary body goes
to stdout. A complete HTTP 404 response is a successful exchange and exits zero;
tests must assert the expected status separately. It does not follow redirects.

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
204 and 404 status/body behavior, rejected untrusted certificates and wrong
certificate IP identity, and deadlines during handshake and HTTP exchange.
The large binary body exceeds the 4 KiB per-stream receive window and requires
credit replenishment. All success responses are compared byte for byte, and
server request records independently verify the path and exact wire version.

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
```

On 2026-10-01, explicit v1 and v2 GETs both passed against `www.haproxy.org`
and `quic.aiortc.org`; v1 also passed against Google and Cloudflare. Explicit v2
to Google and Cloudflare did not complete before the configured deadline. An
independent aioquic v2-only attempt to Google reported no common version. These
are point-in-time observations, not release gates; public support and routing
can change. A failed v2 probe never retries with v1. HTTP/3 ALPN and Alt-Svc
alone do not prove a transport version. The live runner prints the requested
version, exit status, byte count, body hash, and client diagnostics. Use
`--expect-status`, `--contains`, or `--sha256` for stable assertions; avoid
hashes for changing public HTML. Network restrictions, remote changes, and DNS
failures make live results unsuitable as deterministic release gates.

One additional v1 edge case surfaced during that pass: the client rejected
`https://www.google.com/generate_204` with a protocol error, while curl's
HTTP/3-only mode received a 204 with an empty body. Treat this as an outstanding
response-interoperability issue; it is separate from the successful v1/v2
version checks above.

Sources: [aioquic configuration](https://github.com/aiortc/aioquic/blob/1.3.0/src/aioquic/quic/configuration.py),
[Cloudflare trace endpoint](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/),
[QUIC working group implementation list](https://github.com/quicwg/base-drafts/wiki/Implementations).
