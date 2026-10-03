# Worker executor measurements

The bounded worker scheduler now supports local submission and stealing while
the owner is busy, and a paused callable move no longer blocks unrelated
published work. It preserves one global task capacity, rejection ownership,
and completion on the owning event loop. These are verified behavior changes.
The first throughput results below were mixed. The
[regression fixes](#regression-fixes-2026-10-03) brought every measured
workload's median to or above the FIFO baseline on this host.

See [scheduling and ownership](executor-scheduling.md) for the implementation
boundaries and [raw trials](executor-performance-trials.csv) for every result.
The [single-thread handoff](single-thread-performance-handoff.md) covers the
separate inline executor and zero-worker loop task.

## Method

Measured on Linux x86_64, AMD Ryzen 7 5700X3D (8 cores, 16 logical CPUs), under
a Microsoft hypervisor, using GCC 14.2.0. Both binaries used
`-std=c++23 -O3 -DNDEBUG -pthread`, without LTO or architecture-specific flags,
and the same affinity set `0,2,4,6,8,10,12,14`. This task's builds and tests
finished before measurement; the benchmark binaries ran sequentially.
Host scheduling and other activity remain sources of variation; this is one
machine, not a cross-platform performance claim.

Seven trials alternated before/after order. Each binary ran the identical
current public-header [benchmark](../benchmark/executor_benchmark.cc). The
baseline worker source is from commit
`edd7abebbfb2a909a687cb35fec55c1194307ee6`; it uses the current bounded FIFO
helper, including the earlier nonwaiting publication work. Both binaries use
the same unchanged single-thread executor source. This isolates the worker
scheduler change from concurrent single-thread/loop work in the workspace.

Handoff uses 5,000,000 jobs and capacity 4096, with one producer/worker or
four producers/four workers. Workers increment one shared atomic completion
counter. Inline invocation and full-queue rejection use 20,000,000 operations;
rejection parks one worker and fills both slots of a capacity-two queue.
Each executor receives 10,000 warmup jobs except the rejection/progress probes.

Fanout has four parent jobs each submitting 65,536 children. When capacity is
exhausted, the parent invokes the retained task inline rather than blocking a
worker. Fine tasks write a validated result without additional CPU work. Mixed
tasks run 8,192 xorshift steps for every 32nd child and 64 otherwise. Results are
checked outside the timed region; parent submission and child completion are
both complete before the region ends. These workloads include saturation and
fallback behavior; they do not measure socket or storage throughput.

## Results

Rates are millions of operations/second. Brackets give minimum–maximum over
the seven trials; change compares medians. Aggregate ns/op is the inverse
median rate, not an individual task's latency.

| Workload | Before median [range], M/s | After median [range], M/s | Rate change | Aggregate ns/op, before → after |
|---|---:|---:|---:|---:|
| Inline executor, unchanged control | 282.749 [281.723–285.070] | 283.992 [282.025–285.198] | +0.4% | 3.54 → 3.52 |
| One producer / one background worker | 22.258 [22.027–22.578] | 30.830 [28.983–32.252] | +38.5% | 44.93 → 32.44 |
| Four producers / four workers | 5.532 [1.790–6.121] | 2.611 [1.526–11.267] | −52.8% | 180.76 → 382.95 |
| Full-queue rejection | 300.876 [281.220–304.924] | 257.724 [240.162–261.234] | −14.3% | 3.32 → 3.88 |
| Fine-task worker fanout | 20.948 [20.526–22.649] | 24.211 [22.638–49.313] | +15.6% | 47.74 → 41.30 |
| Mixed-work worker fanout | 7.929 [7.911–8.075] | 7.186 [7.089–7.417] | −9.4% | 126.11 → 139.16 |

The four-producer case has substantial, overlapping variation. Its lower
observed median must be reported, but the size of the regression is not a
stable estimate. The one-worker and mixed-work ranges do not overlap in this
sample. Fine fanout also has a large candidate outlier. No statistical or
end-to-end networking claim follows from these seven samples.

The progress probe deliberately pauses the first producer inside its callable
move for 100 ms, then submits a second task. The later task's median latency
fell from **100,146 µs** [100,142–100,157] to **32.272 µs** [26.925–33.428].
The earlier task still completes after its producer resumes. This demonstrates
progress past unpublished worker work; the 100 ms baseline is induced by the
probe, not an ordinary queue latency claim.

For four workers and capacity 4096, the
[construction allocation probe](../benchmark/executor_memory_benchmark.cc)
measured **393,776 bytes in 11 C++ allocation requests** before and
**399,048 bytes in 15 requests** after: **+5,272 bytes (+1.34%)**. It intercepts
regular and aligned `new`; allocator overhead, direct C allocation, and OS
thread stacks are excluded. The final payload slot is 96 bytes on this ABI.
Padding it to 128 bytes would have raised these requested bytes by 34.6%, so
the final implementation keeps payload alignment at 32 bytes and pads only
the frequently contended worker metadata to cache-line boundaries.

The runtime test records zero regular or aligned C++ allocation requests
across 10,000 external submissions and completions after construction. Private
queue fill/drain/reuse tests also record zero. This measures the library's
paths with the supplied callables, not arbitrary allocations inside user code.

## Correctness and limits

- `cmake --build build --target check -j2`: **69/69 passed** on the final layout.
- `executor` and `work_stealing`: **20 consecutive runs each passed**.
- ThreadSanitizer passed the complete work-stealing test executable, using
  non-PIE and `setarch x86_64 -R` to avoid this environment's address-map conflict.
- AddressSanitizer and UBSan passed the same tests. LeakSanitizer was disabled
  because the host runs under ptrace; this is not a leak-sanitizer result.
- A separately configured installed-library caller linked only
  `eventloop::eventloop`, exercised sparse external jobs and 128 coroutine
  `run_blocking()` completions, checked owner-thread resumption, and finished
  with no live coroutine frames. The in-tree TCP echo example also built.
- The new public regression tests fail if stealing is disabled or external
  tasks are routed through the local-only threshold. The paused-producer test
  fails against the old worker scheduler. These negative controls establish
  that the tests detect the intended behavior changes.
- No new queue/executor warnings were emitted. GCC still emits the existing
  coroutine allocation/deallocation diagnostic in the TCP echo example.
  `git diff --check` passed.

The tests cover a busy owner with one child left untouched, a second child
stolen on another thread, paused publication/dequeue moves, tiny global
capacities, concurrent slot reuse, rejection ownership, nested fallback,
exactly-once execution/destruction, sparse external work, idle wakeups, and
repeated shutdown with coalesced signals.

Local victim size is a concurrent hint: multiple racing consumers need not
leave exactly one task for the owner. External submissions have no worker
affinity and can always be taken by an idle peer, including a lone job. This
separation is necessary: applying the local threshold to external work stranded
a lone completion behind a blocked worker during integration testing.

The worker pool is unordered, with lock-free bitmap atomics. User callable
moves, invocations, and OS wakeups can block; the entire executor is not
claimed to be lock-free. Loop command/completion queues retain FIFO behavior
and their existing nonwaiting owner-loop drains. Only Linux x86_64 execution
was verified here; macOS and Windows retain portable C++ paths but have not
been run in this environment.

The improvement is bounded work stealing and progress past a paused slot,
plus faster measured one-worker handoff. The implementation has more metadata
and scheduling work than a shared FIFO. The follow-up diagnosis below identifies
an expensive rejection path in saturated workloads. The contended external
submission result still varies substantially. Mixed CPU work and rejection
are measured regressions, not promised improvements.

## Follow-up throughput diagnosis

Isolated probes on the same host used seven alternating trials per comparison.
They run one selected workload per process with the same optimization flags.
The rejection probe varies capacity and fills every slot while its sole worker
is parked. The mixed probe adds one counter per parent, on separate cache lines,
to count rejected children without an extra shared atomic on each rejection.
See the [diagnostic trials](executor-diagnosis-trials.csv). Production C++
sources were not changed for these experiments.

The full-pool scan is a concrete cost: `push()` reads up to ceil(C / 64) free
bitmap words before rejecting, whereas the old ring's full path checks one
slot. With capacity 4096 that means 64 words. Isolated median costs were:

| Queue capacity | Before, ns/rejected submit | Current, ns/rejected submit |
|---|---:|---:|
| 2 | 3.54 | 3.95 |
| 4096 | 4.91 | 67.14 |

These are aggregate costs from distinct trials, with host variation. The
capacity-two result exposes a small fixed path cost; failure also pays the
new worker-count branch and cursor/TLS handling. Failure returns before ready
publication, queued-count updates, or wakeups, so their atomic RMW costs do
not explain this rejection result.

In the mixed fanout probe, median rejection counts were **257,568 / 262,144**
before and **257,229 / 262,144** currently: approximately **98%** of children
run inline after a rejected submission. This benchmark therefore exercises
saturated submission heavily. Repeated full-pool scans are a major cost even
though those child jobs eventually run inline.

To isolate that cost further, a temporary variant reserves a bounded capacity
credit before scanning and returns the credit after freeing a payload slot.
A zero credit count rejects immediately. This adds a global atomic counter
and extra RMW operations on successful transfers. In seven alternating trials
against the current scheduler, mixed throughput rose from **7.115 to 8.263 M/s
(+16.1%)**. Rejection at capacity 4096 fell from **41.61 to 3.42 ns/op** in that
separate comparison. This supports the full scan as a principal cause of the
mixed-work slowdown. However, one-worker handoff fell from **25.970 to
17.402 M/s (−33.0%)**. The counter variant is a diagnostic experiment and was
not adopted; moving the cost into successful transfers is a poor general fix.

Successful publication/dequeue with multiple workers also performs **six queue
RMWs** (free-slot claim, queued increment, ready publication, ready claim,
queued decrement, free-slot release), versus **two queue RMWs** in the old
ring. This count excludes either scheduler's wakeup protocol and CAS retries.
The new external path may additionally signal peers when sleepers are
registered, and workers search multiple queues. `perf` samples show time in
the free bitmap claim, queued counters, and worker scans; they do not establish
that peer notification caused the original four-producer median decrease.

The original **−52.8%** four-producer result is not repeatable as a stable
regression. The original affinity constrained all threads to one eight-core
set; it did not pin each thread separately. A follow-up pins workers to
CPUs 0/2/4/6 and producers to 8/10/12/14. Median rates became **5.645 M/s before
and 6.743 M/s currently (+19.4%)**, still with overlapping ranges
**3.390–6.122** and **3.580–13.432 M/s**. A separate sampled run also reversed
the ordering. Neither sign supports a general contended-throughput claim.
Thread placement, initial cursor distribution, and host scheduling need
further isolation before assigning that variation to one cause.

The next optimization should make saturated rejection cheap without imposing
a new global RMW on every successful transfer, then address the multi-worker
metadata and wakeup costs. Preserve the sequentially consistent publication
and waiter-registration handshake; weakening it is not a valid shortcut.

The temporary selected-workload benchmark, per-parent counters, explicitly
pinned sources, capacity-counter variant, raw output, and `perf` recordings
are retained for this session in `/tmp/eventloop-executor-diagnosis/`. The CSV
labels the counter experiment separately and retains every trial. Its results
describe the temporary diagnostic binaries, not another shipped feature.

## Regression fixes, 2026-10-03

Three changes address the measured regressions; capacity, ownership, the
public API, and the SC publication/registration handshake are unchanged.

- **Full-pool cache** (`work_stealing_queue.h`, see
  [scheduling](executor-scheduling.md#repeated-rejection-when-full)). A
  submitter whose previous scan failed rejects without rescanning while a
  verified full result stands. Every slot release clears it.
- **Thin rejection front end.** `execute()` checks emptiness, shutdown, and the
  full cache, then tail-calls a non-inlined `dispatch()`. The rejection path
  previously saved six callee-saved registers before its first branch.
- **One idle peer per wakeup.** For external work or a local backlog, a
  publisher signalled every other worker whenever any was asleep. At most one
  woke to useful work and the rest slept again. Instrumented four-producer runs
  recorded 90,000–520,000 worker sleeps per 5 million jobs, against
  10,000–37,000 for the FIFO, and throughput fell as sleeps rose. A publisher
  now signals one registered idle peer, and none when the target owner is
  itself idle. A worker leaving the idle state with a task wakes one more peer
  if shareable work remains. This covers producers whose signals coalesced.

The table compares the FIFO scheduler from `edd7abe`, the work-stealing
scheduler before these fixes, and the current sources. Each binary ran the
current benchmark seven times in rotated order, pinned to the affinity set
above. The noisy multi-producer case adds 12 more rotations. Raw results are
in [executor-regression-trials.csv](executor-regression-trials.csv).

| Workload, M/s | FIFO median [range] | Stealing before fixes | Current | Current vs FIFO |
|---|---:|---:|---:|---:|
| One producer / one worker | 14.282 [4.043–15.866] | 15.768 [14.916–20.038] | 19.555 [16.299–21.575] | +36.9% |
| Four producers / four workers (19 trials) | 5.935 [3.593–6.175] | 3.528 [1.187–14.206] | 8.329 [2.789–23.677] | +40.3% |
| Full-queue rejection, capacity 2 | 283.286 [273.237–283.829] | 225.820 [213.828–231.582] | 310.097 [289.666–320.225] | +9.5% |
| Full-queue rejection, capacity 4096 | 283.677 [272.387–284.366] | 13.607 [13.065–13.890] | 313.782 [294.115–319.844] | +10.6% |
| Fine-task worker fanout | 21.312 [19.369–37.768] | 24.919 [20.631–46.193] | 23.583 [22.360–45.399] | +10.7% |
| Mixed-work worker fanout | 7.927 [7.807–8.182] | 7.162 [7.045–7.387] | 8.063 [7.935–8.327] | +1.7% |

Later-task latency behind a paused producer stays at 32.7 µs
[24.2–34.1], against 100,146 µs for the FIFO. The four-producer case remains
bimodal on this host: the current sources range from 2.8 to 23.7 M/s, and the
other bimodal rows have reversed order between runs. The improvement is a
median over these samples, not a guaranteed lower bound. Single-worker
rejection is sensitive to code placement. Identical instructions measured
230–265 M/s at different addresses before the front-end split. These are local
results on one virtualized Linux host.

`tests/work_stealing.cc` adds two cases. Three busy-worker children must
reach two distinct idle peers. Four external tasks must all run at once
across four workers, repeated over 50 cycles. Removing the publisher's peer
wakeup fails the existing stealing test, and removing only the chain wakeup
fails the new shareable-work test in 10 of 10 runs. The full `check` target
passed 69/69, the executor-related tests passed 20 consecutive repeats, and
ThreadSanitizer reported no races in five runs each of the executor,
work-stealing, task, event-loop, and single-thread loop tests.

## Reproduction

Run from the repository root with the final sources. The baseline source is
read from Git; both binaries use the same benchmark, public headers, and FIFO
helper. The construction probe is deliberately a standalone program because
its global allocation overrides should not enter normal application binaries.

```sh
measure_dir=$(mktemp -d /tmp/eventloop-executor.XXXXXX)
git show edd7abebbfb2a909a687cb35fec55c1194307ee6:src/executor/multi_thread_executor.cc > "$measure_dir/before.cc"
git show edd7abebbfb2a909a687cb35fec55c1194307ee6:src/executor/single_thread_executor.cc > "$measure_dir/inline.cc"
g++ -std=c++23 -O3 -DNDEBUG -pthread -Iinclude -Isrc/executor \
  benchmark/executor_benchmark.cc "$measure_dir/before.cc" "$measure_dir/inline.cc" \
  -o "$measure_dir/before"
g++ -std=c++23 -O3 -DNDEBUG -pthread -Iinclude \
  benchmark/executor_benchmark.cc src/executor/multi_thread_executor.cc "$measure_dir/inline.cc" \
  -o "$measure_dir/after"
for trial in 1 2 3 4 5 6 7; do
  if [ $((trial % 2)) -eq 1 ]; then variants='before after'; else variants='after before'; fi
  for variant in $variants; do
    taskset -c 0,2,4,6,8,10,12,14 "$measure_dir/$variant" > "$measure_dir/$variant-$trial.txt"
  done
done
g++ -std=c++23 -O3 -DNDEBUG -pthread -Iinclude -Isrc/executor \
  benchmark/executor_memory_benchmark.cc "$measure_dir/before.cc" "$measure_dir/inline.cc" \
  -o "$measure_dir/memory-before"
g++ -std=c++23 -O3 -DNDEBUG -pthread -Iinclude \
  benchmark/executor_memory_benchmark.cc src/executor/multi_thread_executor.cc "$measure_dir/inline.cc" \
  -o "$measure_dir/memory-after"
"$measure_dir/memory-before"
"$measure_dir/memory-after"
```

Adapt the affinity set to the host. Preserve every trial rather than selecting
the fastest. The CSV records the six printed rates and progress latency for
both variants in actual run order.

Source SHA-256 identifiers at measurement time:

```text
executor_benchmark.cc       aa51ea5e1ba54fd9bd1463ccb642635d5f914ff17951cf73991028c38978f6e4
before worker source        03415faa3c93338883de837c9d85f1948f8f2e2281751718cf07e3355e0de903
after worker source         343639c3ce85fb050233be947923430acd7df0355bc3f0200a37790411009200
work_stealing_queue.h        79ce6f6cc425b01b642feb9970786a3cfba8ea91854eb9a4460825ab9f97ce84
bounded_task_queue.h         a1e24bacefc3ea56b25ecba598a72e44e3504349ea6b0a719c20d96aafd546a8
single-thread source        f8ede6c9b7c039d963facd277a603fc06329f3470742911af65f7828763cb966
public executor.h           5eb2bab5916b88424d8eaa5fc06f92118182c714678bc36142a38163fbaebdc2
```
