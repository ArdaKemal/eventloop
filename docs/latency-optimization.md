# Latency optimization: findings and methodology

Evidence recorded 2026-10-17. Covers HTTP/2/3 p95/p99, connection setup,
time to first response, and pre-handler dispatch; includes a separate TCP/TLS
study. HTTP/2/3 changes were portable; TCP/TLS work includes platform code.
Results are historical observations, not guarantees for another revision or host.

Keep diffs small. Allow **at most three implementation/configuration trials per
proposed fix**; paired repetitions estimate variance. Drop unsuccessful changes;
do not rename an exhausted idea to reset its count.

## Retained HTTP/2/3 changes

| Change (trials) | Benefit and invariant |
| --- | --- |
| [HTTP/2 Date cache](../src/http2/connection.cc) (3) | Format once/second/thread; copy into response-owned storage. Refresh on clock change or formatting failure. HTTP/3 variant dropped. |
| [HTTP/2 final-DATA credit](../src/http2/client.cc) (1) | Immediate connection WINDOW_UPDATE on END_STREAM prevents reuse stalls after 65,535 bytes. Do not update the closed stream. |
| [QUIC ACK histories](../src/quic/recovery_orchestration.h) (1) | Avoid another copy of all packet-number spaces. Validate before committing history and synchronous pruning. |
| [QUIC receive credit](../src/quic/flow_control.h), [caller](../src/quic/connection.h) (1) | Remove flow-table copy/copy-back. Validate consumption and both limit overflows before mutation; preserve rejection atomicity and buffer invariants. |
| [QUIC Initial admission](../src/quic/udp_endpoint.cc) (2) | Retry refusal once after pending work and two wakeup generations. Reuse the existing receive buffer, recheck socket after suspension, preserve live capacity and retention policy. |

Cold QUIC cause: a receive burst could consume the one free slot before retained
closed drivers retired. Diagnostics counted 145 no-slot Initial drops in 2,400
connections, followed by roughly one-second initial PTOs (probe timeouts).
Admission retry lets retirement progress without reclaiming live connections.
Trial 1 scheduled after accepted Initials; larger-header cold tails persisted.

## Dropped experiments

| Experiment | Trials | Decision evidence |
| --- | ---: | --- |
| HTTP/2 static HPACK references | 1 | p95 did not improve. |
| Remove QUIC pre-ACK scheduling turn | 1 | Regression. |
| Skip inactive QUIC path tasks | 1 | No stable end-to-end gain. |
| QPACK name lookup: binary, then bounded linear | 2 | No useful end-to-end gain. |
| Reserve receive-burst retention headroom | 3 | Cold tail improved; warm p99 remained unresolved (+7.1% median). Dropped. |
| Remove TLS scratch initialization | 1 | Cold total p95 5489→5503 us; p99 6401→6392 us: no useful gain. |
| Huffman padding lookup, two-bit and four-bit tables | 3 | Correctness checks passed; tails mixed. Four-bit HPACK: warm p95/p99 −5.8%/−2.7%, cold p99 +4.1%; complexity unjustified. |
| Skip empty TLS flush work | 2 | Inconclusive first trial; second warm HTTP/2 p95/p99 1082/1472→1351/1942 us. Empty task completion does not inherently yield. |
| Batch final HTTP/2 credit with next HEADERS | 1 | Public-client warm p95 +2.4%; inconsistent p99. Immediate credit retained. |

Decoder equivalence or faster isolated operations do not establish request-tail
benefit. These outcomes apply to tested workloads, not every possible workload.

## Measurements and limits

Microseconds, **p95 / p99**. Three paired runs in AB/BA/AB order; medians of
per-run nearest-rank percentiles. Do not add gains across phases.

| Path | Before | After | Phase |
| --- | ---: | ---: | --- |
| HTTP/2 routed full response | 1064 / 1458 | 1007 / 1376 | A: Date cache |
| HTTP/3 cached-static full response | 1709 / 1802 | 1678 / 1742 | A: ACK copies |
| HTTP/3 established request→first response read | 1808 / 2374 | 1627 / 2280 | B: flow + admission |
| HTTP/3 established request→handler entry | 1639 / 2164 | 1460 / 2059 | B |
| HTTP/3 new connection→first response read | 6397 / 1004832 | 5905 / 6954 | B |
| HTTP/3 new connection setup | 3727 / 1002600 | 3334 / 3939 | B |

Setup: macOS, GCC 16.2 Release, OpenSSL 4.0.3, IPv4 loopback, one server loop,
four client processes, 1 KiB bodies, one outstanding request/connection.
A: 64 warm connections × 3,000 measured requests, 200 warmup/connection.
B warm: 64 × 10,000 measured, same warmup. B cold: 16 concurrent connections ×
150 measured new connections/lane, five warmup/lane; 2,400 measured total.
B baseline already includes A's Date/credit/ACK fixes, without extra headroom.
B's candidate included a later-dropped TLS guard unused by QUIC.

Caveats: A's HTTP/2 static controls varied +2.7%/+2.8%; HTTP/3 routed p99 +1.9%.
No additional HTTP/2 cold-setup/pre-handler gain was established in A/B. B's cold median
total rose 1216→4342 us and post-handshake dispatch p95 2016→2864 us. Removing
stalled connections keeps more fixed-concurrency work active; lower tails need
not improve every phase or percentile. Closed-loop results do not establish
open-loop or production performance.

## Measurement rules

- **Define endpoints.** Setup = numeric connect→handshake; cold total = connect→
  first response read; request = submit→first read; dispatch = submit→handler
  entry. DNS excluded. Dispatch includes client work, transport, queues and
  parsing. Use the same host's monotonic clock for cross-process timestamps.
  Headers-ready callbacks and successful reads are not wire-byte timestamps.
- **Freeze the other side.** Keep clients unchanged for server comparisons and
  vice versa. Record revision/patch, binary hashes, flags, library versions, workload
  and connection mode. Fix harness protocol bugs first: missing HTTP/2 credit
  can impersonate a server stall. Validate every response.
- **Hold concurrency.** Synchronize warmup/start across processes; keep warm
  connections open until every lane finishes. Teardown contaminated warm tails.
  Warm setup/total observations are not per-request measurements.
- **Exercise boundaries.** A 4 KiB body plus headers exceeded a client's 4 KiB
  QUIC window. Isolate dispatch with small bodies, then test multi-frame bodies,
  window crossings, retention and live capacity. Literal Huffman headers do not
  model dynamic-index reuse; routed and static paths differ.
- **Retain variance and failures.** Record p50/p95/p99 for every pair, controls,
  timeouts and exit diagnostics. Do not discard failures or select favorable
  medians. Run one comparison at a time, without competing builds or tests.
- **Profile before rewriting.** Investigate copies, wakeup ordering, drops,
  timers and flow-control stalls. HTTP/2 profiles here favored socket/OpenSSL
  record work over portable header validation. Less CPU or allocation alone
  does not prove lower p99.

## TCP/TLS study and review

Separately reported Linux study: 4-vCPU Xeon VM, GCC 14, OpenSSL 3.5.4, no kTLS;
Stonegate pinned to CPU 0, wrk on CPUs 1–3; three alternating six-second runs,
approximately 20% noise. Smaller differences are inconclusive. Linux performance
claims below were not independently reproduced; do not combine with A/B.

| Work | Outcome and verification limit |
| --- | --- |
| POSIX immediate shutdown before deferred descriptor release | Reported HTTP churn c=16 p99 7.03→1.02 ms. macOS FIN regression failed before and passed 25/25 after. POSIX-only: Windows with no pending I/O still defers release to batch end; scope any immediate-shutdown contract accordingly. |
| Linux server handshake starts from ClientHello readiness | Reported HTTPS churn p99 6.78→4.59 ms; concurrent keep-alive/churn 6.06→4.46 ms. Static review only; Linux needs already-readable input, cancellation-before-ClientHello and shutdown-while-waiting tests. |
| Outbound TCP_NODELAY | Implemented for Linux/macOS/FreeBSD/Windows; reported write-write-read p99 45.9→0.111 ms. macOS option regression failed before and passed 25/25 after; other backends not executed independently. |
| TLS read-ahead; disable SSL_MODE_RELEASE_BUFFERS | No demonstrated tail benefit; dropped. Preserve idle-buffer resource behavior. Read-ahead was later adopted for throughput (below). |
| TLS tickets/resumption | Reported improvement, not adopted: changes immutable/shared-context contract and requires key-lifecycle design. |
| Timers, handoff, batching, file I/O | Profiled; no changes justified. Loaded completions wait a dispatch batch; workers can inherit loop CPU affinity. Cold-file evidence did not justify a new I/O layer. Timer slack helped idle timers, not request tails. |

Independent macOS HTTP/2 follow-up (C): fixed server, identical native-client
source linked before/after the TCP/TLS changes; otherwise A/B's environment,
body, warmup and percentile method. Three AB/BA/AB pairs per workload, 10,000
measured warm requests/connection. IPv6: four processes, 64 warm connections;
lower-load IPv4: one process, 16. Cells below are **p95 / p99, microseconds**.

| Established path | Before | After |
| --- | ---: | ---: |
| IPv6 request→first response read | 1189 / 1633 | 875 / 1237 |
| IPv6 request→handler entry | 1165 / 1599 | 826 / 1207 |
| IPv4, 16 connections, request→first read | 307 / 340 | 329 / 352 |
| IPv4, 16 connections, request→handler entry | 281 / 310 | 26 / 41 |

IPv6 warm tails improved in every pair. This does not establish a universal
TTFB win: 64-connection IPv4 first-read tails were mixed, and four-connection
cold IPv4 total p95/p99 increased 1793/1987→1985/2052 us. Improving dispatch can
shift waiting elsewhere; measure end-to-end latency as well as individual phases.

## Syscalls per response against tokio (Linux, 2026-10-18)

Same 4-vCPU VM, one server thread against hyper 1 / tokio-rustls 0.26; harness
and report in the project's `beat-tokio` folder. strace counted two sends per
16 KiB HTTP/1.1 response (head, then body), two reads per TLS record (header,
then body), and one send per TLS record where hyper uses one `writev`.

| Change | Requests/s before → after (hyper) |
| --- | --- |
| HTTP/1.1 head and body in one gathered `sendmsg` | 16 KiB: 51.6k → 71.4k (60.3k) |
| TLS: records of one write sent with `MSG_MORE` but the last; read-ahead | HTTPS 16 KiB: 26.0k → 39.1k (41.1k); h2 16 KiB: 51.1k → 73.3k (60.7k) |
| All of the above, plus a per-thread HTTP/1.1 Date cache and a status line without `snprintf` | HTTPS 13 B: 51.4k → 59.3k (61.7k) |

Medians of three alternating 8 s runs; the VM varies about 10-20%. The
remaining HTTPS gap is user-space TLS cost per record, not syscalls.

Allocation scratch buffers (dropped): a full TLS handshake makes about 700
heap allocations, 98% inside OpenSSL and mostly for state that outlives the
call (keys, record layers, session); eventloop's own nine are
connection-lifetime objects. Keep-alive HTTPS makes about 7 per request,
from `SSL_MODE_RELEASE_BUFFERS`. As an upper bound on any thread-local
scratch or caching scheme, preloading jemalloc or raising glibc's tcache
(`GLIBC_TUNABLES=glibc.malloc.tcache_count=1000:glibc.malloc.tcache_max=4096`)
moved keep-alive HTTPS by 0% and handshakes by 2-10%, within VM noise. Only a
process-wide `CRYPTO_set_mem_functions` could reach OpenSSL's allocations,
which a library should not impose; deployments can use those allocator
settings instead.

## Guidance for further work

Follow [agent guidance](../AGENTS.md) and affected [HTTP](http.md),
[HTTP/2](http2.md), [HTTP/3](http3.md), [QUIC](quic.md), [TLS](tls.md) and
[coroutine](coroutines.md) contracts. For each candidate, state the bottleneck,
caller, owners, capacity/errors and cancellation; capture a fresh baseline;
record trials; compare both connection modes. Preserve bounded storage,
rejection atomicity, loop affinity, HTTP/2 closure history and borrowed lifetimes.

Run affected integration/allocation tests, full CTest for shared changes,
compiler warnings and whitespace checks; verify a public-header consumer against
the installed `eventloop::eventloop` target. Warm allocation claims exclude
setup/handshake. Useful regressions: [HTTP/2 client](../tests/http2_client_validation.cc),
[QUIC flow](../tests/quic_flow_control.cc), [admission](../tests/quic_udp_endpoint.cc),
[TCP/TLS socket API](../tests/socket_api.cc). Flow differential testing matched
100,000 operations; admission regression failed before and passed after.
The [routing benchmark](../benchmark/routing_benchmark_server.cc) is a starting
point for new instrumentation; no archived binaries or temporary files are needed.

A TCP cancellation test exposed a setup race: after raw send-queue saturation,
both async writes completed before close in 22/100 diagnostic runs. Filling
through bounded async writes instead keeps the first awaiter registered before
the duplicate check; 500/500 runs passed with all original assertions intact.
