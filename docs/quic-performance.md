# QUIC send/receive throughput

This records the single-threaded QUIC performance work: what was measured,
what was adopted, what was tried and reverted, and what remains. It covers the
Stonegate HTTP/3 path (one event-loop thread, one process per core not
involved here).

## Method

- Harness: `oha --http-version 3 --insecure -n 1000 -c 8 -p 1` against the
  256 KiB `payload.bin`, with 8 HTTP/3 connections and 64 requests per
  connection.
- Only per-request latency is used. `oha`'s `summary.total` and
  `requestsPerSec` include a ~30 s client-side QUIC shutdown
  (`h3`/`quinn` `shutdown(0)` + `poll_close`) and are not a throughput measure.
- Reference point: nginx 1.26 with `worker_processes 1` on the identical
  harness measures ~11.8 ms mean, so that is the single-core target.
- Reference implementations consulted: microsoft/msquic, facebook/mvfst, and
  ngtcp2/nghttp3. msquic and mvfst both track send state as intervals
  (`UnAckedOffset` + SACK ranges) rather than per-byte flags and batch
  datagrams with UDP GSO/GRO; ngtcp2 takes the current time as a `ts` argument
  and exposes cached timer expiry instead of reading the clock itself.

## Adopted

| change | outcome |
| --- | --- |
| Flow transaction in `packet_scheduler::prepare` | Replaces a ~6.4 KiB `flow_control` table copy per data packet with a read-only `send_transaction` that stages only touched streams. |
| Trusted sent commit in `record_sent` | Removes the second `range_has_flags` scan per range; the preflight pass still validates every range before mutation. |
| Stream pointers in sent-packet records | `retire` uses the recorded `stream_slot*` instead of a linear `stream(id)` lookup, as msquic stores `QUIC_STREAM*` in its frame metadata. |
| Active-slot list | `prepare`, `retire_closed_streams`, and the endpoint accept loop walk only occupied streams. The list is kept sorted by slot index so iteration order is unchanged. |
| GSO batch size 8 -> 32 | One sendmsg per up to 32 equal-sized datagrams (nvfst default 16, msquic 40). |
| UDP_GRO receive coalescing | The internal QUIC socket opts in; a coalesced receive is split into datagrams in the existing receive coroutine. The public `udp_socket` stays one datagram per receive. |
| Interval-based send buffer | Replaces the per-byte pending/sent/acked flag array with `base_` (SND.UNA) + `acked_` (SACK) + `sent_`/`lost_` interval sets. Direct A/B below. |
| One clock read per pump iteration | `steady_clock::now()` is read once in `pump` and threaded through `tick`, `prepare`, `complete`, and the candidate-probe check, matching ngtcp2's `ts` parameter. Also short-circuits `next_alarm()`'s in-flight scan. |

### Interval send buffer A/B

Two runs each, same harness and machine:

| representation | mean latency |
| --- | --- |
| interval sets (SACK) | 16.86 ms |
| per-byte flag array | 18.07 ms |

The interval representation is ~6.7% faster and also removes the
`Capacity`-byte flag array per stream, so it is kept.

### Clock cost

`__vdso_clock_gettime` + `clock_gettime` + `steady_clock::now` accounted for
2.55% of sampled userspace before reading the clock once per pump iteration,
and 0.69% after.

## Tried and reverted (did not pay off)

| attempt | result |
| --- | --- |
| Packing pending/sent/acked into three bit arrays | The scan line fell from 6.8% to ~1.8%, but the range writes (`mark_sent` clearing pending and setting sent across three arrays) cost more than the old single `memset`; net neutral. Reverted in favour of intervals. |
| Persistent `persistent_event` staging buffer in recovery | Neutral in latency; removed to avoid a 36 KiB member. |
| Word-scanning the `crypto_receive_buffer` coverage bitmap in `readable()` | Neutral: readable spans on this workload are short, so the byte tail scan dominates. Removed. |

## Present but not a measured win

Building packets directly into the GSO batch (`reserve_send` / `commit_send`
instead of copying the sealed packet into the batch) is kept, but the arm that
included it measured the same as before it, so its ~1% copy removal was not
observable. It is the next candidate for removal if it can be replaced by a
simpler staging path.

## Result

Cumulative mean request latency since the AEAD baseline `45f66b8`:

| state | mean latency |
| --- | --- |
| AEAD baseline | 20.3 ms |
| + flow transaction / trusted commit | 19.5 ms |
| + this commit (stream pointers, active slots, GSO 32, UDP_GRO, intervals, clock) | ~16.8-17.1 ms |
| nginx 1 worker | 11.8 ms |

## Remaining gap

nginx remains faster. The profile at this point is broad rather than dominated
by one function:

- Coroutine machinery (`task.h` cancellation check awaited in the
  accept/send/receive loops) plus the HTTP/3 stream coroutines.
- `recovery_orchestration::on_ack`, much of it `sent_packet_history` copies
  taken per ACK for failure atomicity.
- Crypto: `EVP_CIPHER_CTX_ctrl`, GCM init/tag/finish, header protection.
- `packet_scheduler::prepare` and `bounded_connection::record_sent`.

Closing the remaining gap likely needs several of these addressed rather than a
single change.

## Follow-up trials toward 10 ms

The follow-up harness remains `oha --http-version 3 --insecure -n 1000 -c 8 -p 1`
against Stonegate serving the same 256 KiB file. Measurements below use the
per-request mean; client shutdown time is excluded. The two baseline runs were
18.520 ms and 17.953 ms (18.237 ms average). All recorded runs completed 1,000
requests successfully.

| candidate | run 1 | run 2 | average | outcome |
| --- | ---: | ---: | ---: | --- |
| Baseline | 18.520 ms | 17.953 ms | 18.237 ms | reference |
| Remove the extra three-history snapshot and event scratch array from `on_ack` | 17.820 ms | 18.562 ms | 18.191 ms | Neutral within run-to-run variation; reverted |

The ACK experiment kept one local history transaction, staged late-ACK flags,
and evaluated persistent-congestion pruning through a logical event view before
compacting the bounded event list. The focused recovery test passed, including
overflow atomicity and retry after pruning. The average changed by about 0.2%,
so the implementation was removed. The full suite passed 68 of 70 tests on its
first run; `task_composition` and `http2_server` both passed when rerun alone.

Further work is guided by a CPU profile of the same Stonegate workload. No
performance claim is made for the reverted experiment.

A baseline `perf record` run captured 856 server-side CPU samples while the same
load was active. Top self costs included `read_stream` (7.95%),
`accept_stream` (5.32%), `crypto_receive_buffer::readable()` (4.66%),
`packet_scheduler::prepare` (4.41%), and `recovery_orchestration::on_ack`
(2.76%). The packet protection path also had 10.69% inclusive cost in
`seal_payload`, with `EVP_EncryptUpdate` at 8.96% and header protection at
6.61% inclusive. These overlapping inclusive values are profile guidance, not
additive percentages. The next trial targets the readable-prefix scan, which
was 4.66% self in this profile; a cached-prefix design differs from the prior
word-scan attempt.

For these follow-up trials I use a 5% lower mean as the retention target.
Smaller changes are retained only when repeated candidate runs all beat every
baseline run and the targeted work reduction supports the measured result.

| candidate | run 1 | run 2 | average | outcome |
| --- | ---: | ---: | ---: | --- |
| Cache the contiguous CRYPTO receive prefix for `readable()` | 17.837 ms | 17.843 ms | 17.840 ms | 2.2% lower mean, while p50 was slightly higher; reverted |
| Reuse request-header storage for contiguous HTTP/3 DATA frames | 17.295 ms | 17.381 ms | 17.338 ms | 4.9% lower mean; retained |
| Fixed-capacity stream-ID lookup index | 17.521 ms | 17.817 ms | 17.669 ms | 3.1% lower mean; reverted |
| Specialized fixed-form STREAM frame encoder | 17.344 ms | 17.560 ms | 17.452 ms | 4.3% lower mean; retained |
| HTTP/3 DATA + STREAM encoder | 17.109 ms | 17.014 ms | 17.061 ms | 6.4% below baseline |
| `--http3-max-datagram 8192` on loopback | 17.169 ms | 17.126 ms | 17.148 ms | No measurable gain; default retained |
| Add per-connection waiter wakeups | 16.685 ms | 16.858 ms | 16.772 ms | 8.0% below baseline; retained |
| Skip empty path-response/probe tasks | 16.677 ms | 16.893 ms | 16.785 ms | No measurable gain; reverted |
| Increase per-stream send capacity from 16 KiB to 32 KiB | — | — | — | Repeated HTTP/3 transfer regression; reverted before benchmarking |

Both runs completed 1,000 requests successfully. The focused crypto-buffer test
passed, including ring wrap and failed-insert atomicity. This cache was removed
because its latency change was below the retention threshold.

The HTTP/3 DATA change reuses the existing 16 KiB per-request header buffer
after request parsing. It reduces the 256 KiB file response from 64 file reads
and 128 `write_all` calls to 17 of each, without adding storage. Both means
beat both baseline runs, and the HTTP/3 loopback integration test passed. The
4.9% result is just below the nominal cutoff, but its repeatability and the
measured reduction in file and write operations support retaining it.

The stream index used 256 bytes per connection with linear probing and
backward-shift deletion. Its focused connection test passed for both endpoint
roles and QUIC versions, including wraparound collisions, deletion, retirement,
and slot reuse. The second run was only 0.136 ms below the lower baseline mean,
and p50 was nearly unchanged, so the index was removed as a non-significant
gain.

The scheduler encoder writes the common STREAM frame form directly, avoiding a
zero-initialized `decoded_frame` and generic frame-type dispatch while
preserving the same checks and canonical varints. Its focused scheduler test
passed. Both individual means beat both baseline means; with the HTTP/3 DATA
change together, the combined mean is 17.061 ms and all requests succeeded.
The explicit 8192-byte maximum UDP payload setting did not change the result,
so the normal 1472-byte setting remains the measurement configuration.

A second profile of the combined build captured 845 server samples with no
lost samples. The largest self costs were `read_stream` (7.41%),
`accept_stream` (5.87%), `packet_scheduler::prepare` (4.47%),
`crypto_receive_buffer::readable()` (3.50%), and `on_ack` (2.90%). Both stream
wait tasks appeared under the connection driver's progress callback. That
callback woke the endpoint-wide waiter queue for every connection, so unrelated
connections resumed each other's pending operations. Per-connection FIFO waiter
groups now share the original `slots × 256` fixed-capacity pool. Progress and
completion wake only the owning connection's group plus endpoint-accept waiters;
shutdown still wakes all groups. The change adds about 16.5 KiB at the default
eight connections and no steady-state allocations. Six focused QUIC and HTTP/3
tests passed. Both benchmark means beat both means from the previous build, for
an 8.0% reduction from baseline; the current mean is 16.772 ms and remains
above the 10 ms target.

The no-op task guards avoid constructing path-response and candidate-probe
coroutines when their work is absent. Their two means averaged 16.785 ms,
within 0.013 ms of the waiter-sharded build, so the change was reverted after
the focused driver and HTTP/3 tests passed. A 32 KiB per-stream send buffer
would add 1.25 MiB per QUIC connection (320 MiB at Stonegate's configured
256-connection maximum). Before any latency run, the HTTP/3 integration test
repeatedly stalled twelve overlapping 64 KiB transfers after about 27–32 KiB;
restoring the 16 KiB capacity made the test pass again. The candidate was
reverted and no performance result is claimed for it.

## Trials toward the sub-10 ms target

The best stable result before these trials used burst capacity 14: two runs
measured 10.986 ms and 11.128 ms (11.057 ms mean), with all 1,000 requests
successful. This is the comparison point below. Each run uses the documented
256 KiB file and `oha --http-version 3 --insecure -n 1000 -c 8 -p 1`.

| candidate | run 1 | run 2 | average | outcome |
| --- | ---: | ---: | ---: | --- |
| Remove the full slot reap from each progress callback; burst capacity 12 | 14.202 ms | 14.312 ms | 14.257 ms | 11.8% below the preceding hot-path build; retained |
| Raise burst capacity to 14 with queue capacity 16 | 10.986 ms | 11.128 ms | 11.057 ms | 22.4% below burst 12; retained |
| Burst capacity 15 | 11.023 ms | 11.002 ms | 11.013 ms | 0.4% below burst 14; not significant, reverted |
| Queue capacity 32 with burst 24 | 11.126 ms | 11.041 ms | 11.083 ms | No gain; reverted, adds 135,168 bytes per connection |
| Inline the partial-write loop for each HTTP/3 DATA chunk | 11.059 ms | 11.110 ms | 11.085 ms | No gain over burst 14; reverted |
| GSO short-tail batching + ordered-prefix ACK fast path | 10.301 ms | 10.347 ms | 10.324 ms | 6.6% lower mean; retained |
| Reduce application payload reserve from 100 to 48 bytes, alone | 10.965 ms | — | — | One run only; 0.8% lower than burst 14, not significant |
| 48-byte reserve with GSO + ordered ACK | 10.274 ms | 10.254 ms | 10.264 ms | 0.6% below the retained pair; not significant, reverted |
| Cancellation-aware, event-driven progress wakeups | 10.303 ms | 10.344 ms | 10.324 ms | No measurable gain; seven focused tests passed, reverted |
| 44-byte packet reserve with exact STREAM frame fitting | 10.220 ms | 10.269 ms | 10.245 ms | 0.8% lower mean; five focused tests passed, below the 5% retention bar, reverted |
| Fixed per-space sent-record indices and free list | 10.268 ms | 10.395 ms | 10.332 ms | No measurable gain; capacity/ACK/reuse test passed, reverted |
| Batched HTTP/3 HEADERS read alone | 10.466 ms | 10.227 ms | 10.347 ms | No measurable gain; fragmented and multi-read tests passed, reverted |
| Three-context receive-key cache alone | 10.352 ms | 10.304 ms | 10.328 ms | No measurable gain; key rotation/authentication test passed, reverted |
| HEADERS read + receive-key cache | 10.290 ms | 10.283 ms | 10.287 ms | 0.4% below reference; all 1,000 requests succeeded in both runs, reverted |
| Seal nonempty packets directly without copying into build scratch | 10.341 ms | 10.304 ms | 10.323 ms | No measurable gain; all 1,000 requests succeeded in both runs, packet-boundary tests passed, reverted |
| Gather STREAM payload across the send-ring wrap | 10.392 ms | 10.344 ms | 10.368 ms | 0.4% slower than reference; all requests succeeded and wrap/ACK/loss tests passed, reverted |
| Limit posted-task draining to eight before polling | 10.319 ms | 10.401 ms | 10.360 ms | 0.3% slower than reference; all 70 tests passed, reverted |
| Retire cumulative ACKed packets oldest first | 10.273 ms | 10.228 ms | 10.251 ms | 0.7% lower mean; v1/v2 ACK, loss, and retransmission regression passed, reverted |
| Preflight application congestion/history before packet sealing | 13.872 ms | 11.815 ms | 12.844 ms | 24.4% slower than reference; eight focused tests passed, reverted |
| Reuse successful QUIC receive-key candidate instead of opening it a fourth time | 10.560 ms | 13.633 ms | 12.097 ms | 17.2% slower than reference; nine focused tests passed, reverted |
| Share one unprotected header across receive-key attempts | 10.637 ms | 11.184 ms | 10.911 ms | 5.7% slower than reference; ten focused tests passed, reverted |
| Summarize ACK/path metadata during receive validation | 10.497 ms | 11.030 ms | 10.764 ms | 4.3% slower than reference; nine focused tests passed; optimization reverted |
| Skip generic re-decoding for scheduler-generated packets; encode common ACK/STREAM frames directly | 11.149 ms | 10.552 ms | 10.851 ms | 5.1% slower than reference; nine focused tests passed; reverted |

The GSO change appends a shorter datagram as the final segment of the current
uniform batch, avoiding a prefix flush, buffer move, and separate tail send.
Linux UDP segmentation permits a short final segment, and the portable fallback
uses the same segment boundaries. The ordered-ACK path advances the send-buffer
base directly when an ACK covers the current prefix and no out-of-order ACK
interval exists; all other ACK shapes retain the interval-based path. The
combined change passed the focused send-buffer, recovery, UDP endpoint,
packet-scheduler, and HTTP/3 tests. Both runs completed all requests. The two
changes were measured together, so no separate latency claim is made for either
one.

The 48-byte reserve remained safe in the focused scheduler test and the full
HTTP/3 transfer. It saves less than one percent in the repeated combined run,
so the 100-byte reserve remains. Inlining the per-chunk write loop removed a
helper coroutine but did not improve latency; the existing bounded DATA-frame
batching remains and the helper is restored.

The event-driven wakeup candidate passed the public cancellation, connection
driver, failure, UDP endpoint, send-buffer, scheduler, and HTTP/3 tests. It
replaced the 1 ms retry with protocol deadlines and woke only waiters affected
by each state change, but its two-run mean matched the retained GSO/ACK result;
the changes were reverted. Exact STREAM fitting used actual ID/OFFSET/LENGTH
varint widths and a 44-byte short-header reserve. Its two means were 10.220 ms
and 10.269 ms, with every request successful. The 0.8% reduction was below the
5% retention bar, so both sizing changes were reverted after the focused QUIC
and HTTP/3 tests passed.

The sent-record index replaced the 384-record free-slot scan with a bounded
free list and used sorted per-space 16-bit indices for retirement lookup. The
focused connection test passed at full history capacity and checked interior
ACK retirement, callback order, and slot reuse. The two latency means averaged
10.332 ms, effectively unchanged from the retained reference, so the 1,568-byte
per-connection index was reverted.

The batched HEADERS read parsed the complete frame from the existing request
buffer and charged any read-ahead to the existing 1 MiB body-discard limit.
Its v1/v2 fragmented non-minimal varint and >4 KiB QPACK tests passed, but its
isolated means averaged 10.347 ms. The receive-key cache retained three bounded
OpenSSL decrypt contexts for the current, next, and previous keys while
preserving all authentication attempts; its key-alternation, eviction, bad-tag,
and changed-IV tests passed. Its isolated means averaged 10.328 ms. Together
the candidates averaged 10.287 ms. None cleared the 5% retention bar, so both
were reverted.

The direct-sealing candidate avoided copying nonempty plaintext into the
packet-build scratch buffer when no leading PADDING was needed, while keeping
the scratch-capacity check and padded/empty-input paths unchanged. Its v1/v2
packet-number-length and padding-boundary tests passed, but its two means
averaged 10.323 ms, indistinguishable from the 10.324 ms retained reference;
it was reverted.

The wrapped STREAM selection gathered the two physical portions of one
contiguous pending logical interval into one frame, while retaining the same
send-buffer capacity and one transmitted-range record. Its focused send-buffer,
packet-scheduler, driver, and HTTP/3 tests passed, including FIN, flow-credit,
loss, and ACK-hole cases. Two Oha runs averaged 10.368 ms, 0.4% slower than the
retained reference, so it was reverted.

The event-loop fairness candidate limited posted-task draining to eight per
poll iteration while preserving the 64-item worker-completion and timer
limits. The full 70-test suite passed, but the two means averaged 10.360 ms,
0.3% slower than the retained reference, so the global scheduling change was
reverted.

The ACK-order candidate reversed only the leading ACKed prefix during
connection retirement, leaving recovery congestion ordering and the loss or
discard suffix unchanged. Its v1/v2 connection regression passed for
cumulative ACKs, sparse ACKs, and retransmissions. The Oha pair averaged
10.251 ms, 0.7% below the reference and below the 5% retention bar, so it was
reverted.

The preflight candidate predicted the exact padded short-header size and
checked application congestion and sent-history capacity before invoking
packet sealing. Its focused scheduler, connection, key-update, and protection
tests passed, including congestion rejection and PTO behavior. Both Oha runs
completed all requests, but the mean was 12.844 ms versus the 10.324 ms
reference. Since normal packets still need the same preflight and the workload
did not show a benefit from avoiding work on blocked sends, the change was
reverted.

The receive-key candidate kept all three fixed application-key authentication
attempts and reused their successful plaintext and metadata, while retaining
the fourth current-key open for all-failed input. Its v1/v2 core, key-update,
protection, scheduler, and driver tests passed, including failed-tag output
preservation and current/next/previous phase cases. Both Oha runs completed all
requests, but the mean was 12.097 ms versus the 10.324 ms reference and the
run-to-run spread was large. It was reverted as an unproven latency improvement.

The shared-header trial parsed and unprotected an application packet once,
then ran the same fixed current/next/previous AEAD attempts against the
borrowed header and ciphertext. Successful plaintext was reused, and the
all-failed path kept its current-key error precedence. Ten focused QUIC tests
passed for v1/v2, key phases, reserved-bit precedence, duplicates, retirement,
and caller-buffer preservation. Both Oha runs completed all requests, but the
mean was 10.911 ms versus the 10.324 ms reference, so this more complex path was
reverted.

The receive-metadata candidate summarized ACK-eliciting and path-frame bits
during the core's existing validation pass, letting the driver skip its extra
frame decode on packets without path frames. Its core and driver regressions
covered ACK-only packets, PINGs, duplicates, retired packet numbers, and
PATH_CHALLENGE/PATH_RESPONSE behavior; all nine focused QUIC and HTTP/3 tests
passed. Both Oha runs completed all requests, but their 10.497 ms and 11.030 ms
means averaged 10.764 ms, 4.3% slower than the 10.324 ms reference, so the
optimization was reverted.

The driver regression also exposed a timestamp-ordering bug after asynchronous
path sends: those sends recorded a later time than the same pump iteration's
subsequent packet burst, which could fail when the burst recorded its ACK.
Path sends now use the pump iteration's timestamp, matching ordinary packet
sends and preserving the one-clock-read path. The v1/v2 driver test exercises
two path challenges, their duplicate, four queued responses, and their ACK;
this correctness fix remains independently of the reverted optimization.

The scheduler-build candidate kept the generic `connection_core::build()`
validation pass, but routed canonically encoded scheduler payloads through a
private sealing path that skipped decoding them again. It also wrote the common
ACK and STREAM forms directly into the bounded packet buffer, while checking
selected control-frame placement and close-only packets. Generic malformed
input and output/packet-number preservation, v1/v2 control policy, close-only
padding, and mixed close/ACK/STREAM cases all passed in the nine-test focused
set. The two Oha runs completed all requests, but their 11.149 ms and 10.552 ms
means averaged 10.851 ms, 5.1% slower than the retained reference; the changes
were reverted.

A 586-sample `perf record` profile during the same load showed a broad CPU
distribution: `packet_scheduler::prepare` 5.25%, `connection_driver::pump`
4.79%, the endpoint progress callback 2.88%, packet retirement 2.84%, ACK
recovery 2.53%, sent-record commit 2.43%, and stream reads 2.36%. These are
user-space cycle samples for this profiled run, not additive latency shares.
The GSO/ACK pair currently averages 10.324 ms, above the sub-10 ms target; work
is paused with this measured state retained.
