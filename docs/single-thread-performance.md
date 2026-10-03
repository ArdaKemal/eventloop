# Single-thread performance investigation

The public caller is an application submitting a bounded `execution_task` to
the executor returned by `make_single_thread_executor()`. It runs immediately
on the submitting thread, including nested submissions. The benchmark uses
only installed public headers, realistic pointer/span/value captures, and
validated results. It also measures task lifetime and move costs separately
from invocation. Factory allocation is setup, outside steady-state accounting.

The task owns its inline callable; spans and state pointers borrow storage that
outlives execution and destruction. Callable storage remains 64 bytes with the
existing alignment and compile-time noexcept requirements. Empty submissions
return false. This executor has no queue, capacity exhaustion, or asynchronous
cancellation window. Nontrivial moves and destructor effects must be preserved.
Any loop measurements will use `worker_count = 0`, bounded frame/command storage,
and public APIs; socket objects own descriptors and coroutine-local buffers
remain alive until completion. Setup will be reported separately. Linux, macOS,
and Windows remain supported; measurements in this workspace qualify Linux only.

The baseline is a snapshot of the current working tree, including the existing
user changes, taken before this investigation. The same benchmark and Release
flags will be used for the snapshot and candidate. No LTO is used. Implementation
changes will be retained only after profiling and alternating, pinned trials
show a worthwhile benefit without semantic or workload regressions.

The timer experiment serves existing `sleep_for`/`sleep_until` callers with many
simultaneously pending timers. Inserting or cancelling a non-head coroutine
timer cannot change the next deadline, so those operations need no poller arm.
Changing the head still updates the poller. Due-timer dispatch already rearms
after its bounded batch of resumptions, including when more expired timers
remain. This adds no storage, capacity, or public API and preserves the timer
dispatch budget on every platform.

## Results, 2026-10-03

The retained implementation change is only the head check when registering and
cancelling coroutine timers in `src/event_loop.cc`. The inline executor and
`execution_task` are unchanged. Ownership, cancellation results, FIFO command
drains, frame capacities, affinity checks, and the 64-timer dispatch budget are
unchanged. No new runtime storage is required.

Measurements used GCC 14.2.0, CMake/Ninja Release (`-O3 -DNDEBUG`, C++23), static
linking, OpenSSL 3.5.6, and no LTO on a virtualized AMD Ryzen 7 5700X3D Linux
host. Both executables were pinned to CPU 2. Seven baseline/candidate pairs ran
in alternating order, reversing which build ran first each pair. The baseline
was the initial working-tree snapshot, including unrelated changes; the frozen
candidate differed in library sources only by the timer head checks. Ongoing
executor and QUIC work was excluded from this comparison.

Raw measurements are in
[single-thread-performance-trials.csv](single-thread-performance-trials.csv).
The table gives median ns/op and the complete min–max spread over seven trials.
All steady-state rows reported **zero C++ allocations**, counted by replacement
scalar, array, and aligned `operator new`. This does not instrument arbitrary
`malloc` calls or claim that setup or third-party libraries allocate nothing.

| Case | Baseline median [min, max], ns/op | Candidate median [min, max], ns/op | Change |
| --- | ---: | ---: | ---: |
| Direct captured callable | 2.784 [2.742, 2.803] | 2.786 [2.768, 2.802] | +0.1% |
| Task construct/destroy | 1.506 [1.506, 1.522] | 1.508 [1.504, 1.529] | +0.1% |
| Nontrivial construct/destroy | 7.270 [7.256, 7.647] | 7.266 [7.256, 7.361] | −0.1% |
| Trivial task move | 3.137 [3.059, 3.234] | 3.133 [3.108, 3.271] | −0.1% |
| Nontrivial task move | 14.278 [13.534, 15.515] | 13.569 [13.540, 15.272] | −5.0% |
| Move-only task move | 3.312 [3.276, 5.545] | 3.296 [3.292, 3.414] | −0.5% |
| Reused task invocation | 3.347 [2.744, 3.385] | 3.351 [3.345, 3.357] | +0.1% |
| Reused task through `executor&` | 3.024 [2.947, 3.665] | 2.566 [2.536, 2.619] | −15.1% |
| Task construct/invoke/destroy | 3.416 [3.365, 4.190] | 3.401 [3.384, 3.417] | −0.4% |
| Construct/invoke/destroy through `executor&` | 3.617 [3.564, 5.599] | 3.860 [3.813, 3.998] | +6.7% |
| Same-thread post chain | 13.759 [13.540, 14.526] | 13.850 [13.662, 17.335] | +0.7% |
| 32 concurrent timer coroutines | 4380.958 [4351.962, 4895.440] | 2392.471 [2355.666, 2422.822] | **−45.4%** |
| 64-byte UDP echo round trip | 12863.503 [12783.219, 15307.730] | 12873.138 [12766.520, 14887.293] | +0.1% |

Executor cases ran 20 million iterations, post chains 5 million commands, and
timer/UDP cases 100,000 operations per trial. Move rows include construction,
one wrapper move, and destruction, without invoking the payload. Nontrivial
counts validate every move/destructor and exactly-once resource retirement;
move-only captures transfer a `unique_ptr` with a stack-storage retirement
deleter. Invocation uses a pointer, mutable span, and value capture, with a
data-dependent word update and independently validated checksum. Executor
cases warm 10,000 iterations outside timing. Loop timing starts at `run()`
after construction, registration, and spawning.

The post workload uses the default 1,024-slot queue with one command pending.
Timer measurements reserve 64 warmed slots in each frame class for 32 roots;
UDP uses the default warmed pools for two roots and one receive/send per
socket. `post()` and `spawn()` rejection are checked and fail the workload
instead of growing an unbounded replacement. The UDP buffers are coroutine
local, and the loop owns both socket descriptors through task completion.

The timer workload has 32 coroutine roots repeatedly waiting 50 µs. Its wall
time includes the requested waiting, insertion, poller calls, and resumption;
it is not an isolated CPU-cost measurement. The disjoint baseline/candidate
timer spreads support retaining the small implementation change. Post and UDP
changes are below 1% at the median. The executor construct/invoke control
regressed 0.243 ns/op (6.7%); reused dispatch improved 0.458 ns/op (15.1%). The
benchmark and single-thread executor object files are byte-identical across
the frozen builds; in the linked binaries `single_thread_executor::execute`
only moves 32 bytes (0xda10 to 0xda30) because `event_loop.cc` grew. The gap
reproduced in five later alternating pairs (3.58–3.62 vs 3.82–3.86 ns/op).
These controls show the sensitivity of tiny timings to linked code layout and
host variation; no executor speedup is attributed to
the timer change. The timer benefit outweighs these measured control changes
without adding state or a public abstraction.

Initialization was measured separately, once per loop workload per trial:

| Setup case | Baseline median [min, max], µs | Candidate median [min, max], µs | C++ allocations |
| --- | ---: | ---: | ---: |
| Post loop and first command | 167.623 [161.471, 191.667] | 172.412 [166.039, 198.190] | 10 |
| Timer loop and 32 roots | 403.011 [387.723, 457.352] | 297.836 [295.361, 326.318] | 10 |
| UDP loop, two sockets, two roots | 199.372 [192.198, 205.072] | 198.099 [190.796, 232.603] | 15 |

## Profiling and rejected experiments

`perf record` and disassembly of the inline executor showed one emptiness
check and one indirect callable invocation. The compiler already combines
the wrapper/executor checks, and submission never moves the wrapper. The
caller's virtual dispatch remains. There is no queue, wakeup, or allocation
to remove from this executor.

A separate seven-pair experiment replaced trivial destruction thunks with
null pointers and added a conditional reset. Construct/destroy improved from
1.365 to 0.759 ns/op, trivial moves from 2.922 to 2.494 ns/op, and executor
construct/invoke from 3.615 to 3.399 ns/op. Nontrivial moves regressed from
13.584 to 14.922 ns/op (9.8%). That shared-wrapper change was discarded;
preserving the simple wrapper is preferable to adding a branch to every
nontrivial reset for this tradeoff. LTO was not tested or used.

The construct/invoke control was rechecked against the committed HEAD sources
in five alternating pinned pairs: 3.81–3.99 ns/op for HEAD and 3.83–4.54 for
the working tree, with every other executor case overlapping. The 3.58 ns/op
baseline above reflected a favorable placement, not executor code. Aligning
`single_thread_executor::execute` to 64 bytes moved construct/invoke to 3.743
but reused dispatch from 2.574 to 2.965 ns/op (+15.2%) over seven pairs. The
two loops trade places with layout, so the attribute was not retained.

The post trace had 1,564 `epoll_wait` calls for 100,000 commands, with no
per-command wake writes. This is consistent with the existing bounded drain
and same-thread post hint. The queue/drain implementation was left intact.

For 10,000 validated timer expiries, `strace -c` counted 10,157
`timerfd_settime` calls in the baseline and 314 in the candidate, a 96.9%
reduction. The initial unchanged-deadline caching experiment did not help
enough and was replaced with the head checks. Counts came from separate
traced runs; tracing changes scheduling and those timings are not benchmark
results. Kernel symbols in the timer `perf` samples were unavailable on this
host, so syscall counts supply the actionable evidence. Socket and timer
backends were not edited.

## Verification

- New public-header executor tests check immediate completion, submitting
  thread identity, recursive synchronous order, empty rejection, move-only
  captures, nontrivial move/destructor effects, self-assignment, exactly-once
  destruction, zero runtime C++ allocations, and compile-time storage,
  alignment, invocation, move, and destruction requirements.
- Four threads call `execute()` concurrently on one single-thread executor,
  20,000 times each with one nested submission. Every task runs exactly once
  on its submitting thread, with zero C++ allocations during submission.
  ThreadSanitizer reports no races in five runs each of the single-thread
  executor, single-thread loop, event loop, task, and executor tests. It flags
  a race when a shared counter is temporarily added to `execute()`.
- New public-header loop tests cover 160 equal-deadline timers across multiple
  dispatch batches; inserting a new head; cancelling head, middle, tail, and
  final timers; rearming after cancellation/expiry; and UDP/timer progress
  during a continuous post chain with an eight-slot command queue.
- The initial full check exposed a baseline deadlock in the existing completion
  capacity reuse fixture: a parked worker could strand a lone external task.
  This investigation temporarily weakened the fixture to post an early
  release. The concurrent executor work has since made external submissions
  takeable by any idle peer (see
  [executor-performance.md](executor-performance.md)), so the original fixture
  was restored: the parked operation holds its slot for all 16 resubmissions.
  It passed 700 stress runs and hangs when external stealing is disabled.
- `cmake --build build --target check -j2`: **69/69 tests passed**, Debug build.
  The focused tests also passed in Release.
- Installed the frozen Release library and built the benchmark and both focused
  tests in a separate consumer using only `find_package(eventloop CONFIG
  REQUIRED)` and `eventloop::eventloop`; executor, loop, and UDP smoke runs passed.
- `git diff --check` passed. New benchmark and focused tests compiled without
  warnings. Existing QUIC sign/template warnings, Debug coroutine allocation
  warnings, and unused task-test argument warnings remain outside this change.

Linux was executed. CMake registers the new targets on macOS and Windows too,
and the timer optimization is independent of the backend; those platforms
were not available for execution here. These are local workload results, not
network throughput guarantees.

## Reproduce on Linux

The original frozen trees, logs, profiling data, and build directories are in
`/tmp/eventloop-single-thread/`. The initial archive's SHA-256 is
`6871282a013f21a8becf54ca96f2b48118919ee589fd871a21604df9eeea4ac1`.
To repeat using that exact snapshot:

```sh
cmake --build /tmp/eventloop-single-thread/baseline-build --target single_thread_benchmark -j2
cmake --build /tmp/eventloop-single-thread/performance-build --target single_thread_benchmark -j2
```

To recreate a controlled pair from the current workspace, freeze both trees
and reverse only this investigation's timer changes in the baseline:

```sh
perf_dir="$(mktemp -d /tmp/eventloop-single-thread.XXXXXX)"
mkdir -p "$perf_dir/candidate-source" "$perf_dir/baseline-source"
tar --exclude=.git --exclude=build --exclude=.cache --exclude=.agents \
    --exclude=.codex --exclude=.aws -cf - . |
    tar -xf - -C "$perf_dir/candidate-source"
cp -a "$perf_dir/candidate-source/." "$perf_dir/baseline-source/"
patch -R -p1 -d "$perf_dir/baseline-source" <<'PATCH'
--- a/src/event_loop.cc
+++ b/src/event_loop.cc
@@ -632,7 +632,9 @@
         if (timer.next != nullptr) timer.next->previous = &timer;
         *position = &timer;
         try {
-            arm_next_timer();
+            // Only a new head can change the next deadline. Due-timer
+            // dispatch rearms after its bounded batch of resumptions.
+            if (timer.previous == nullptr) arm_next_timer();
         } catch (...) {
             unlink_coroutine_timer(timer);
             throw;
@@ -643,11 +645,12 @@
         detail::coroutine_timer_node& timer) noexcept -> void
     {
         if (timer.owner != owner) std::terminate();
+        const bool was_head = timer.previous == nullptr;
         unlink_coroutine_timer(timer);
         detail::coroutine_frame_access::detach_cancellation(
             timer.cancellation);
         try {
-            arm_next_timer();
+            if (was_head) arm_next_timer();
         } catch (...) {
             std::terminate();
         }
PATCH
for variant in baseline candidate; do
    cmake -S "$perf_dir/$variant-source" -B "$perf_dir/$variant-build" -G Ninja \
        -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
    cmake --build "$perf_dir/$variant-build" --target single_thread_benchmark -j2
done
```

Run seven alternating pairs. For the original frozen builds, set
`perf_dir=/tmp/eventloop-single-thread` and
`candidate_build=/tmp/eventloop-single-thread/performance-build` before this
block. Choose a CPU available in your affinity mask.

```sh
set -euo pipefail
candidate_build="${candidate_build:-$perf_dir/candidate-build}"
printf 'trial,build,case,operations,ns_per_op,allocations,checksum,status\n' > "$perf_dir/trials.csv"
for trial in 1 2 3 4 5 6 7; do
    variants="baseline candidate"
    if (( trial % 2 == 0 )); then variants="candidate baseline"; fi
    for variant in $variants; do
        binary="$perf_dir/$variant-build/single_thread_benchmark"
        if [[ "$variant" == candidate ]]; then binary="$candidate_build/single_thread_benchmark"; fi
        for workload in executor loop_post loop_timer loop_udp; do
            case "$workload" in
                executor) arguments=(20000000) ;;
                loop_post) arguments=(5000000 loop_post) ;;
                *) arguments=(100000 "$workload") ;;
            esac
            taskset -c 2 "$binary" "${arguments[@]}" |
                awk -v trial="$trial" -v variant="$variant" \
                    'NR > 1 { print trial "," variant "," $0 }' >> "$perf_dir/trials.csv"
        done
    done
done
```

The CSV contains all samples, including setup rows. Summarize each case/build
with the median and min/max. Keep setup rows separate and compare allocation,
checksum, and status columns. Useful profiling and verification commands:

```sh
perf record -e cycles:u -o "$perf_dir/executor.data" -- \
    taskset -c 2 "$candidate_build/single_thread_benchmark" 100000000 executor_construct_invoke
perf report -i "$perf_dir/executor.data" --stdio --no-children
strace -c -e timerfd_settime,epoll_wait,read,write \
    taskset -c 2 "$candidate_build/single_thread_benchmark" 10000 loop_timer
cmake --build build --target single_thread_executor_test single_thread_loop_test task_test -j2
ctest --test-dir build -R '^(single_thread_executor|single_thread_loop|event_loop|executor|task|coroutine_udp)$' --output-on-failure
cmake --build build --target check -j2
git diff --check
```
