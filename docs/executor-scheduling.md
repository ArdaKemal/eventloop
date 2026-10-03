# Bounded worker scheduling

The public caller remains `executor::execute(execution_task&&)`, including
`event_loop::task_executor()` and the executor used by `run_blocking()`.
External submitters distribute tasks across worker-associated injection queues;
any worker can take these tasks, including a single task behind a busy worker.
A worker submitting to its own executor prefers its local queue.
An idle worker checks other queues
and steals from a victim observed to have more than one queued task. A lone
local task is left to its owner for a short stall-detection delay (about
100 µs, a private constant): an idle peer takes it once the owner has started
no task during that delay. While a peer is idle, the wait is bounded but not
zero; sleep granularity can lengthen it, notably to milliseconds on Windows.
If every other worker is busy, the task waits for one to become idle, as any
other queued task does. Execution order and
worker affinity are unspecified; callers must not wait inside a worker for
child tasks to complete.
Victim size is a concurrent hint, not a guarantee that racing consumers always
leave a task for the owner.

One preallocated payload pool has exactly `queue_capacity` slots across all
workers. Preparing publication and moving a dequeued callable both retain a
slot. The slot becomes available before invocation, so running tasks do not
consume queued capacity. Empty tasks and exhausted capacity return `false`
without moving from the input. All queue storage is allocated at construction;
submission, dequeue, stealing, and wakeup add no heap allocation.

The executor owns an accepted callable and its captures until completion.
Borrowed buffers or descriptors captured by a callable remain the caller's
responsibility until the callable completes. Scheduling transfers no socket
or loop affinity: workers still post completion to the owner loop. Executor
destruction drains accepted tasks and joins workers. It cannot overlap a call
to `execute()` and cannot be called from one of its workers. Cancellation and
coroutine frame retirement retain their existing behavior.

Each payload slot transitions through free, privately preparing, published to
one queue, privately dequeuing, and free. Atomic bitmaps claim free slots and
published tasks. A successful clear of a ready bit gives exactly one consumer
access to the payload; it releases the free bit only after moving the callable
out. Consumers never read a payload before claiming it. No stale payload or
index is retained across a bitmap CAS, so slot reuse needs no generation tag.
A paused callable move occupies its slot but leaves all other slots usable.
This is unordered worker scheduling, not a linearizable FIFO queue.

For capacity C and W workers, bitmap storage is ceil(C / 64) words for the free
pool and 2W ready bitmaps (local and external), each padded to a cache-line boundary. Worker counts
and wake signals add O(W) storage. Exactly C callable slots are allocated,
independently of W. The bitmaps use lock-free 64-bit atomics, checked at compile
time. This targets the library's 64-bit Linux, macOS, and Windows backends.
User callable moves and invocations can themselves block, and operating-system
wakeups have no lock-free progress guarantee.

Publication, sleeper registration, and the registered sleeper's second queue
check use a sequentially consistent handshake. Each worker has a coalescing
wake signal; stealing cannot consume another worker's task permit. A publisher
always signals its queue's owner. For external work or a local backlog, if the
owner is not registered idle, it also signals one registered idle peer rather
than every sleeper. A worker registers idle after the sleeper count and clears
it before taking a task. On leaving the idle state with a task, it signals one
more idle peer if any external task or stealable local backlog remains. Any
producer that saw this worker idle published before that clear, so coalesced
signals are covered. Workers that register after a publisher's idle scan
observe its task in their second check.
The second check covers publication immediately before sleeper registration.
Shutdown signals every worker.

Signalling an idle peer removes its registration with an atomic exchange, and
the remover also removes it from the sleeper count. Wakeup takes tens of
microseconds, so without this every push of a burst would select the same
sleeper until it ran, and the other sleepers would wake one after another
through the hand-off above. Successive pushes now wake distinct sleepers in
parallel: at most one wake per sleeper, so at most W - 1 for a burst from one
worker, and none once every sleeper has been woken. Only the worker sets its
registration; the worker or its waker clears it, and exactly one of them
decrements the count. A woken worker that finds no task registers again and
repeats its queue check before waiting or claiming a watch. A registration
removed after the worker looked at it leaves a pending signal, so the worker
cannot wait while unregistered. An owner woken this way no longer counts as
idle to producers that later target its queue; they signal another sleeper.

## Lone task behind a stalled owner

The stealing threshold keeps a lone nested task with the worker that submitted
it, which usually reaches it next. If that owner is blocked in a long task,
an idle peer takes the task after the stall-detection delay instead of
leaving it for the whole stall.

Each worker publishes a count of tasks it has started, written only by that
worker with a relaxed store, on a cache line of its own beside a per-owner
`watched` flag. An idle peer that finds a local queue holding work after its
registered queue check claims that owner's flag, records the count, and leaves
the idle state. It then checks every queue once more (covering producers that
signalled it while idle), sleeps for the delay, and takes the owner's task only
if the count is unchanged. It clears the flag and checks the queues again
before registering idle or running a task. At most one peer watches an owner.

The delay is measured from when any thief first saw the owner's current count,
not from when this watcher started. A worker that wakes and finds work records,
beside the flag, the count it sees and the time; thieves write these fields
and the owner never does. A later watcher that finds the same count at least
one delay old takes the task without sleeping, so the tail of a burst waits
one delay after the first sighting instead of one delay per idle peer. The
fields are hints: a stale value only moves a task to another worker.

The watch is not an idle wait: producers wake other registered idle peers
meanwhile, and parked workers still wait without a timeout. No timer thread
or timed wake primitive is added; a watcher sleeps for the delay as a running
task would occupy its worker.

A lone local push wakes one registered idle peer when its owner is unwatched.
This is the only new wake. Because a watch lasts at least the delay and blocks
further lone wakes for that owner, an owner causes at most one such wake per
delay rather than one per task. The pusher publishes before its SC load of
the flag; a watcher clears the flag before its SC queue check, so either the
pusher wakes a peer or the watcher observes the task. A worker leaving the
idle state with a task also wakes one idle peer if an unwatched local queue
holds work, like the shareable-work chain above, so a peer woken for a lone
task that finds other work passes the wakeup on.

A stale count can only move a task to another worker, which scheduling
already permits. The cost falls on owners that keep their local queue at one
task while peers are idle, such as long single-child chains: one peer sleeps
and wakes about once per delay per such owner, and each watch can cost the
owner one wake. Measured on one host, a single chain of fine tasks ran 4-10%
slower with about 11,000 extra voluntary context switches per second; fan-out
and handoff benchmarks stayed within run-to-run variation.

Loop command and completion queues remain FIFO and retain their existing
nonwaiting owner-loop drain. This change concerns worker scheduling only.

## Repeated rejection when full

The caller, callable ownership, shared payload capacity, rejection result,
cancellation, loop affinity, and supported platforms stay the same. There are
no descriptors or buffers owned by this optimization and no runtime allocation.

Cache a verified full pool so repeated rejected submissions do not scan all
free bitmap words. A submitting cursor records that its previous scan failed;
only these cursors consult the cache. Ordinary successful submissions retain
their existing atomic updates. After freeing a slot, a consumer checks the
cache and invalidates an active check or cached full result before returning.
This adds a read, with an extra RMW only while a full check/result is active.
Register a full check only after consecutive failed scans, so isolated
rejections during a drain do not register a cache probe.

A slow full check registers an opaque identifier from a live stack object,
then verifies every free word and publishes the full result only if its
registration is still current. Free-bit changes, verification, and cache
registration/invalidation use SC ordering. A release either invalidates the
registered check or precedes its verification. Different live checks have
different identifiers; identifiers are compared as integers and never
dereferenced. This avoids generation wrap and lifetime-based reclamation.
A paused checker leaves an unverified state that never rejects other
submitters by itself. Its only effect is to delay warming this optional cache.

Validate full-to-available transitions, slot reuse, concurrent invalidation,
and progress with an incomplete check, alongside the existing ownership and
stealing tests. Compare rejection at both small and large capacities, mixed
fanout, and successful handoff with the saved pre-optimization scheduler.
Retain the optimization only if these measurements justify its added work.

Validation must cover paused producers and consumers, stealing while the
owner is busy, the victim threshold, lone tasks behind stalled owners, global
capacity, rejection ownership, exactly-once execution, nested submission, zero
runtime allocations, idle wakeup, destruction with stolen work, coroutine
completion and cancellation, and installed public-header callers. Compare the same optimized benchmark
against the previous shared queue, including fine tasks and worker-generated
fan-out. Report regressions as well as improvements.
