# Single-thread performance task

Improve measured single-thread runtime overhead without changing ownership,
capacity, cancellation, coroutine conventions, or supported platforms. Check
AGENTS.md, the current Git diff, README.md, and the API contract first: this
workspace already contains unrelated user changes and active executor work.

## Scope and sequencing

1. Start with `make_single_thread_executor()` in
   `src/executor/single_thread_executor.cc`. It invokes the callable on the
   submitting thread before `execute()` returns. Empty tasks return false;
   nested calls remain synchronous. There is no queue or worker to optimize.
2. Add a dedicated public-header benchmark in
   `benchmark/single_thread_benchmark.cc`. Measure a direct callable baseline,
   task construction/destruction, nontrivial and move-only callable moves,
   invocation through `execution_task`, and invocation through `executor&`.
   Include realistic captures and observable validated results so the compiler
   cannot discard the workload. Measure allocations as well as time.
3. Profile the measured costs before changing implementation. Investigate
   redundant wrapper moves, type-erasure indirection, and virtual dispatch.
   Preserve the fixed 64-byte callable storage and compile-time noexcept and
   alignment requirements. Nontrivial move and destructor side effects must
   still occur correctly. Do not introduce a new public executor type solely
   to remove a virtual call, or add an abstraction without an actual caller.
4. Only after those results, investigate `event_loop` with `worker_count = 0`:
   same-thread post chains, timer-heavy coroutine workloads, and a public TCP
   or UDP loopback workload. Separate initialization from steady-state cost.
   Profile poller wakeups and drain/resumption overhead before editing them.
   Preserve FIFO loop commands, nonwaiting publication drains, bounded storage,
   loop affinity, and I/O/timer fairness.

One-worker `make_multi_thread_executor()` is a background worker and belongs
to the active multi-thread executor task, even though it has one worker.

## Coordination boundaries

Own the single-thread source, dedicated benchmark, and focused single-thread
tests. The other task owns `src/executor/multi_thread_executor.cc`,
`src/executor/work_stealing_queue.h`, `tests/work_stealing.cc`, and
`benchmark/executor_benchmark.cc`; leave those alone.

`include/eventloop/executor.h`, `src/event_loop.cc`,
`src/executor/bounded_task_queue.h`, `tests/executor.cc`, `tests/task.cc`,
`CMakeLists.txt`, and the API contract are shared files with existing changes.
Coordinate edits and preserve their current content. A new benchmark needs
only its own CMake target, registered for the supported platform branches.
Use a separate ignored Release build directory for measurements.

## Required evidence

- Build the same benchmark against a snapshot of the current baseline and
  the proposed code, with identical compiler, flags, workload, and CPU affinity.
  Alternate baseline and candidate for at least seven trials; report medians
  and spread, absolute ns/op or operations/s, allocations, and regressions.
  Keep LTO experiments separate from implementation improvements.
- Verify immediate completion, submitting-thread identity, recursive
  submission, empty rejection, move-only captures, exactly-once destruction,
  and no runtime allocations. Exercise any changed loop path through public
  headers, including I/O/timer progress and cancellation.
- Check the installed `eventloop::eventloop` target, warnings,
  `git diff --check`, relevant CTest tests, and the final
  `cmake --build build --target check -j2`.
- Deliver measured results and reproducible commands. Keep changes only when
  their benefit justifies their complexity; a measured conclusion that an
  already-small path needs no code change is acceptable.

The existing executor benchmark's inline invocation number is only a smoke
measurement. Its tiny increment workload is not sufficient evidence for
changing the public task wrapper or making end-to-end networking claims.
