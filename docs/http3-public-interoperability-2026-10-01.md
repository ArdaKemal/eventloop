# Public HTTP/3 interoperability sweep — 2026-10-01

## Method

Sent explicit HTTP/3 GETs with the standalone `http3_client` built in
`/tmp/eventloop-http3-review`. Each of 24 public endpoint URLs received one
QUIC v1 request and one QUIC v2 request (48 initial probes total), with no
version fallback and a 6-second overall deadline. Responses were recorded by
exit code, HTTP status, body size, and SHA-256. Because six seconds was too
short for some production pages, previously successful cases and the fixed
`mew.org` case were repeated with a 15-second deadline. Then the entire v2
endpoint set was repeated with a 15-second deadline.

The endpoint candidates came from the current [QUIC Working Group
implementations list](https://quicwg.org/implementations) and the
[HTTP3-test server catalog](https://bagder.github.io/HTTP3-test/). The latter
describes its public test URLs as “usually” available, so a catalog entry is
not a guarantee that the endpoint is still online or supports both QUIC
versions. Several QUIC transport test servers do not claim HTTP/3 support; they
are included as exploratory probes and marked accordingly.

## Client finding and fix

`mew.org` returned a complete HTTP/3 200 response with a 137-byte body, but the
client then failed the exchange because it rejected every instruction on the
peer's QPACK decoder stream. A diagnostic run found the instruction byte was
`0x40`: a Stream Cancellation for request stream 0. The one-shot client uses
static-only QPACK for that stream, so this cancellation needs no table state and
is safe to consume. The client now accepts exactly one `0x40` cancellation for
request stream 0 while continuing to reject other decoder instructions. RFC
9204 allows decoders to signal stream cancellation when they abandon reading a
stream and explicitly permits cancellation instructions when the dynamic
table capacity is zero; see [Section 2.2.2.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.2.2).

The aioquic fixture now tests acceptance of that cancellation and rejection of
an invalid section acknowledgement (`0x80`) for the static-only request. Both
v1 and v2 fixture tests pass. After the fix, `mew.org` returned HTTP 200 and all
137 body bytes under both v1 and v2.

`www.facebook.com` initially completed after the 6-second deadline: it had
already returned HTTP 200 and about 451 KiB, but the client exited on timeout.
The 15-second rerun completed normally with HTTP 200 and about 464 KiB. This was
a probe timeout, not an HTTP/3 client defect.

## Endpoint results

`200 / N B` means the client completed the exchange and received an HTTP 200
with N body bytes. “No response in 6s” is deliberately limited to what this
probe established; it does not by itself prove that a server lacks that QUIC
version.

| Endpoint | QUIC v1 | QUIC v2 (15s follow-up) | Observation |
| --- | --- | --- | --- |
| [quic.aiortc.org:443](https://quic.aiortc.org/) | 200 / 1,196 B | 200 / 1,196 B | aioquic |
| [quic.aiortc.org:4434](https://quic.aiortc.org:4434/) | No response in 6s | No response in 15s | Catalog identifies this as the stateless Retry endpoint; automatic Retry restart remains unsupported by the client. |
| [quic.rocks:4433](https://quic.rocks:4433/) | DNS failure | DNS failure | Name did not resolve during the run. |
| [www.haproxy.org:443](https://www.haproxy.org/) | 200 / 85,323 B | 200 / 85,323 B | Both explicit versions completed. |
| [www.litespeedtech.com:443](https://www.litespeedtech.com/) | No response in 6s | No response in 15s | Handshake ended with peer-close diagnostics. |
| [http3-test.litespeedtech.com:4433](https://http3-test.litespeedtech.com:4433/) | No response in 6s | No response in 15s | Handshake ended with peer-close diagnostics. |
| [http3-test.litespeedtech.com:4434](https://http3-test.litespeedtech.com:4434/) | No response in 6s | No response in 15s | Retry test port; Retry restart is not implemented. |
| [http3-test.litespeedtech.com:4435](https://http3-test.litespeedtech.com:4435/) | No response in 6s | No response in 15s | Handshake ended with peer-close diagnostics. |
| [nghttp2.org:443](https://nghttp2.org/) | 200 / 6,324 B | 200 / 6,324 B | Both explicit versions completed. |
| [nghttp2.org:4433](https://nghttp2.org:4433/) | 200 / 6,324 B | 200 / 6,324 B | Both versions also completed with response trailers. |
| [test.privateoctopus.com:4433](https://test.privateoctopus.com:4433/) | TLS failure | TLS failure | Failed before receiving an HTTP response. |
| [quic.tech:8443](https://quic.tech:8443/) | 200 / 462 B | No response in 15s | Cloudflare quiche test endpoint. |
| [quic.tech:8444](https://quic.tech:8444/) | No response in 6s | No response in 15s | Catalog identifies this as a Retry test endpoint; Retry restart is unsupported. |
| [cloudflare-quic.com:443](https://cloudflare-quic.com/) | 200 / 125,959 B | No response in 15s | v2 did not complete within the longer probe deadline. |
| [fb.mvfst.net:443](https://fb.mvfst.net/) | No response in 6s | No response in 15s | QUIC Working Group transport test server. |
| [www.facebook.com:443](https://www.facebook.com/) | 200 / ~464 KiB (15s rerun) | No response in 15s | Initial v1 probe hit its short deadline after receiving most of the response. |
| [www.instagram.com:443](https://www.instagram.com/) | 200 / ~419 KiB | No response in 15s | v2 did not complete within the longer probe deadline. |
| [mew.org:443](https://mew.org/) | 200 / 137 B after fix | 200 / 137 B after fix | Before the fix, each returned the body and then failed on QPACK Stream Cancellation `0x40`. |
| [d.moritzbuhl.de/pub/:443](https://d.moritzbuhl.de/pub/) | Invalid connection state | Invalid connection state | Listed as a QUIC transport server; HTTP/3 support is not confirmed by the catalog. |
| [quic.westus.cloudapp.azure.com:443](https://quic.westus.cloudapp.azure.com/) | DNS failure | DNS failure | Name did not resolve during the run. |
| [h2o.examp1e.net:443](https://h2o.examp1e.net/) | 200 / 5,997 B | No response in 15s | v2 did not complete within the longer probe deadline. |
| [docs.trafficserver.apache.org:443](https://docs.trafficserver.apache.org/) | 200 / 14,896 B | No response in 15s | Apache Traffic Server. |
| [f5quic.com:443](https://f5quic.com/) | DNS failure | DNS failure | Name did not resolve during the run. |
| [quic.nginx.org:443](https://quic.nginx.org/) | 200 / 2,523 B | No response in 15s | v2 did not complete within the longer probe deadline. |

Additional regressions after the QPACK fix: `www.google.com/generate_204`
returned HTTP 204 with an empty body over v1; Cloudflare's trace endpoint
returned HTTP 200. The passing v1/v2 endpoints in this report were rerun after
the fix with the final client binary.

## Verification and remaining work

- Full CTest: **67/67 passed**, including `http3_outbound_v1` and
  `http3_outbound_v2`.
- Public regression set after the fix: all 14 v1 cases and all 5 v2 cases
  completed successfully, including the repaired `mew.org` response. The full
  v2 endpoint set was also retested with a 15-second deadline; only aioquic,
  HAProxy, nghttp2 (both ports), and mew.org completed.
- Retry-based public endpoints still fail because the client does not restart
  a handshake after Retry. This is a known QUIC client capability gap, not a
  regression from the QPACK fix.
- DNS failures, server-side handshake closures, and v2 timeouts need retesting
  from another network or against a confirmed current server before assigning
  them to the client. The six-second exploratory deadline also leaves some v2
  outcomes inconclusive.

The matrix is a point-in-time interoperability sample, not a claim that these
sites support every QUIC version or a release gate. The body hashes and full
probe diagnostics were captured during the run in
`/tmp/eventloop-http3-public-probes-2026-10-01.tsv`; dynamic production pages
can change between requests.
