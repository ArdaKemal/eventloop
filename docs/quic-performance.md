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
