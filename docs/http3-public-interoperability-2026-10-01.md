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
| [quic.aiortc.org:4434](https://quic.aiortc.org:4434/) | 200 / 1,196 B | 200 / 1,196 B | Stateless Retry endpoint; Retry restart now succeeds in both versions. |
| [quic.rocks:4433](https://quic.rocks:4433/) | DNS failure | DNS failure | Name did not resolve during the run. |
| [www.haproxy.org:443](https://www.haproxy.org/) | 200 / 85,323 B | 200 / 85,323 B | Both explicit versions completed. |
| [www.litespeedtech.com:443](https://www.litespeedtech.com/) | 200 / 68,801 B | No response in 15s | v2 attempts exposed missing required version information and malformed Retry-shaped packets; see follow-up. |
| [http3-test.litespeedtech.com:4433](https://http3-test.litespeedtech.com:4433/) | No response in 6s | No response in 15s | Earlier probe saw peer closes; later curl got UDP connection refused. Availability varied. |
| [http3-test.litespeedtech.com:4434](https://http3-test.litespeedtech.com:4434/) | No response in 6s | No response in 15s | Retry test port; later curl got UDP connection refused. Availability is unclear. |
| [http3-test.litespeedtech.com:4435](https://http3-test.litespeedtech.com:4435/) | No response in 6s | No response in 15s | Earlier probe saw peer closes; later curl got UDP connection refused. Availability varied. |
| [nghttp2.org:443](https://nghttp2.org/) | 200 / 6,324 B | Intermittent: 2/4 returned 200 / 6,324 B; 2/4 closed | Independent aioquic also sees v2 peer closes on this port; see follow-up. |
| [nghttp2.org:4433](https://nghttp2.org:4433/) | 200 / 6,324 B | 200 / 6,324 B | Both versions also completed with response trailers. |
| [test.privateoctopus.com:4433](https://test.privateoctopus.com:4433/) | TLS failure | TLS failure | Failed before receiving an HTTP response. |
| [quic.tech:8443](https://quic.tech:8443/) | 200 / 462 B | No response in 15s | Cloudflare quiche test endpoint. |
| [quic.tech:8444](https://quic.tech:8444/) | 200 / 462 B | No response in 15s | Retry restart succeeds under v1; v2 closes without an HTTP response. |
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

## Retry and peer-close follow-up

The client now validates and processes one QUIC Retry before any authenticated
server response. It verifies Retry integrity against the original destination
connection ID, retains the Retry source connection ID and token, and restarts
Initial protection while preserving the client's source connection ID, exact
ClientHello bytes, and Initial packet-number sequence. Initial CRYPTO data is
retransmitted and split across bounded packets when the token reduces available
payload space. An empty Retry source connection ID is also covered. These are
the client requirements in [RFC 9000 Section 17.2.5.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5.3)
and [Section 5.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1).

The local aioquic Retry fixture verified that both QUIC v1 and v2 send Retry,
accept the token-bearing restart, and complete ordinary and 32 KiB responses.
`quic.aiortc.org:4434` now returns HTTP 200 / 1,196 B under both versions;
`quic.tech:8444` returns HTTP 200 / 462 B under v1. The latter endpoint still
closes v2 connections without an HTTP response.

The client driver also now retires immediately after an authenticated peer
close, before processing any later queued packets or preparing another send.
This avoids turning a normal close into a misleading `invalid connection
state` error. A regression queues a close and a second authenticated packet
before the driver pumps, and passes for both versions.

The v2 result from `nghttp2.org:443` remains intermittent: four current-client
probes produced two HTTP 200 / 6,324 B responses and two authenticated
zero-error peer closes after about 5.3 seconds. An independent aioquic 1.3.0
client reproduced the distinction: v1 returned HTTP 200 / 6,324 B, four v2
requests to `:443` closed before an HTTP response, and v2 to `:4433` returned
HTTP 200 / 6,324 B. This isolates the observed close to the `:443` endpoint's
v2 behavior; it does not establish a general QUIC v2 client defect.

The post-Retry 15-second public matrix remains 15/24 HTTP responses for v1 and
5/24 for v2. `www.litespeedtech.com:443` now returns HTTP 200 / 68,801 B under
v1; its v2 connection closes without a response. The other unresolved rows
remain endpoint-specific: DNS lookup failures, certificate trust failure,
closed or silent handshakes, and versions that did not return an HTTP response.
The LiteSpeed test ports 4433 and 4434 also returned UDP connection-refused
errors in an independent curl/ngtcp2 check, so those results do not justify a
client workaround.

## Curl comparison of failed URLs

curl 8.18.0 was run with `--http3-only` against the 19 URLs where either
explicit client version had failed. Nine returned HTTP 200: Cloudflare's test
host, Apache Traffic Server, H2O, `nghttp2.org`, nginx, both `quic.tech`
ports, Facebook, and Instagram. The eventloop client's matching v1 requests
also succeeded for all nine; the failures in this subset were v2-specific.
curl's `--http3-only` forces HTTP/3 without fallback, but it does not let this
run pin QUIC v2, so those responses do not demonstrate v2 support ([curl
option documentation](https://curl.se/docs/manpage.html#--http3-only)).

curl also failed on the current v1 failures: the unresolved DNS names, refused
UDP endpoints, and `test.privateoctopus.com`'s untrusted certificate. The
complete command results are in
`/tmp/eventloop-http3-curl-recheck-2026-10-01.tsv`.

To compare versions directly, aioquic was forced to QUIC v2 with certificate
verification enabled. It found no mutually supported version at H2O,
`quic.nginx.org`, and Apache Traffic Server. It timed out against Cloudflare,
both `quic.tech` ports, Facebook, and Instagram. At `nghttp2.org:443`, four
attempts received a zero-error peer close; `nghttp2.org:4433` returned HTTP
200. The successful LiteSpeed attempt returned HTTP 200 / 68,801 B, but its
authenticated transport parameters omitted `version_information`. QUIC v2
requires this parameter, so eventloop correctly rejects that connection
([RFC 9369 Section 4](https://www.rfc-editor.org/rfc/rfc9369.html#section-4)).
Other LiteSpeed attempts sent 91-byte Retry-shaped packets with a v2 version
and type bits `11`, which identify Handshake packets; Retry uses type bits
`00` in QUIC v2 ([RFC 9369 Section
3.2](https://www.rfc-editor.org/rfc/rfc9369.html#section-3.2)). These are
server-side protocol violations, not client parsing failures.

## Verification and remaining work

- Full CTest: **67/67 passed**, including `http3_outbound_v1` and
  `http3_outbound_v2`.
- After the QPACK fix, the 14-case regression subset passed for v1 and the
  five-case subset passed for v2, including the repaired `mew.org` response.
  The original full v2 set was also retested with a 15-second deadline; its
  successful sites are listed in the table above and in the post-Retry update.
- Retry-based public endpoints now pass where the endpoint supports the
  selected QUIC version. Local independent-stack fixtures verify Retry under
  both versions; public Retry endpoints verified v1 and, for aioquic, v2.
- curl passed 9/19 URLs with HTTP/3; every such URL also passed eventloop v1.
  Exact-v2 comparisons found no client bug among the remaining failures:
  several endpoints do not advertise v2, others time out on aioquic too, and
  LiteSpeed's successful aioquic exchange omitted a required v2 parameter.
- DNS failures, server-side handshake closures, and v2 timeouts need retesting
  from another network or against a confirmed current server before assigning
  them to the client. The six-second exploratory deadline also leaves some v2
  outcomes inconclusive.

The matrix is a point-in-time interoperability sample, not a claim that these
sites support every QUIC version or a release gate. The initial body hashes and
probe diagnostics are in `/tmp/eventloop-http3-public-probes-2026-10-01.tsv`;
the post-Retry matrix is in
`/tmp/eventloop-http3-public-probes-post-retry-2026-10-01.tsv`. Dynamic
production pages can change between requests.
