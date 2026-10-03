#include "eventloop/executor.h"

#include "executor/work_stealing_queue.h"
#include "publication_pause.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <new>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <malloc.h>
#endif

namespace eventloop {
// Force the scheduling points of a cache check without adding a runtime
// callback or a test configuration to the queue.
struct work_stealing_queue_test_access {
    static auto state(work_stealing_queue& queue)
        -> std::atomic<std::uintptr_t>& { return queue.full_; }
    static constexpr auto failed_cursor() -> std::size_t
    { return work_stealing_queue::failed_scan_; }
    static constexpr auto full_result() -> std::uintptr_t
    { return work_stealing_queue::full_pool_; }
};
}

namespace {
std::atomic<std::size_t> allocations {0};
}

auto operator new(std::size_t size) -> void*
{
    allocations.fetch_add(1, std::memory_order_relaxed);
    if (auto* memory = std::malloc(size)) return memory;
    throw std::bad_alloc {};
}
auto operator new[](std::size_t size) -> void* { return ::operator new(size); }
auto operator delete(void* memory) noexcept -> void { std::free(memory); }
auto operator delete[](void* memory) noexcept -> void { std::free(memory); }
auto operator delete(void* memory, std::size_t) noexcept -> void { std::free(memory); }
auto operator delete[](void* memory, std::size_t) noexcept -> void { std::free(memory); }

auto operator new(std::size_t size, std::align_val_t alignment) -> void*
{
    allocations.fetch_add(1, std::memory_order_relaxed);
    const auto align = static_cast<std::size_t>(alignment);
#ifdef _WIN32
    auto* memory = _aligned_malloc(size, align);
#else
    auto* memory = std::aligned_alloc(align, ((size + align - 1) / align) * align);
#endif
    if (memory) return memory;
    throw std::bad_alloc {};
}
auto operator new[](std::size_t size, std::align_val_t alignment) -> void*
{
    return ::operator new(size, alignment);
}
auto operator delete(void* memory, std::align_val_t) noexcept -> void
{
#ifdef _WIN32
    _aligned_free(memory);
#else
    std::free(memory);
#endif
}
auto operator delete[](void* memory, std::align_val_t alignment) noexcept -> void
{
    ::operator delete(memory, alignment);
}
auto operator delete(void* memory, std::size_t, std::align_val_t alignment) noexcept -> void
{
    ::operator delete(memory, alignment);
}
auto operator delete[](void* memory, std::size_t, std::align_val_t alignment) noexcept -> void
{
    ::operator delete(memory, alignment);
}

using namespace eventloop;
using test_publication::wait_until;

namespace {

auto check(bool condition, const char* message) -> bool
{
    if (!condition) std::cerr << "FAILED: " << message << '\n';
    return condition;
}

auto bitmap_capacity_test(std::size_t capacity) -> bool
{
    work_stealing_queue queue(capacity, 8);
    std::size_t producer = 0;
    std::size_t consumer = 0;
    std::size_t completed = 0;
    bool ok = true;
    const auto before = allocations.load();
    for (int cycle = 0; cycle < 100; ++cycle) {
        for (std::size_t index = 0; index < capacity; ++index) {
            ok &= check(queue.try_push(3, execution_task([&]() noexcept {
                            ++completed;
                        }), producer), "all global slots usable by one worker");
        }
        execution_task rejected([]() noexcept {});
        ok &= check(!queue.try_push(7, std::move(rejected), producer) && rejected,
                    "global capacity and rejection ownership");
        execution_task output;
        for (std::size_t index = 1; index < capacity; ++index) {
            if (!queue.try_steal(3, output, consumer)) return false;
            output();
        }
        ok &= check(!queue.try_steal(3, output, consumer), "single task not stolen");
        ok &= check(queue.try_pop(3, output, consumer), "owner takes final task");
        output();
        ok &= check(!queue.try_pop(3, output, consumer), "drained worker queue");
    }
    ok &= check(completed == capacity * 100, "slot reuse executes every task");
    ok &= check(allocations.load() == before, "queue operations allocate nothing");
    return ok;
}

auto paused_move_test(bool consumer_pause) -> bool
{
    work_stealing_queue queue(2, 2);
    test_publication::pause gate;
    std::atomic<int> completed {0};
    auto first = test_publication::make_task(gate, [&]() noexcept {
        completed.fetch_add(1);
    });
    std::size_t producer_cursor = 0;
    std::size_t consumer_cursor = 0;
    if (consumer_pause && !queue.try_push(0, std::move(first), producer_cursor)) {
        return false;
    }
    gate.armed.store(true);
    bool moved = false;
    std::thread paused([&] {
        if (consumer_pause) {
            execution_task output;
            moved = queue.try_pop(0, output, consumer_cursor);
            if (moved) output();
        } else {
            moved = queue.try_push(0, std::move(first), producer_cursor);
        }
    });
    bool ok = check(wait_until([&] { return gate.entered.load(); }),
                    "callable move paused inside queue");
    std::size_t cursor = 0;
    ok &= check(queue.try_push(0, execution_task([&]() noexcept {
                    completed.fetch_add(1);
                }), cursor), "publication succeeds beside paused move");
    execution_task third([&]() noexcept { completed.fetch_add(1); });
    ok &= check(!queue.try_push(1, std::move(third), cursor) && third,
                "moving payload retains capacity and failed input");
    execution_task output;
    const bool popped = queue.try_pop(0, output, cursor);
    ok &= check(popped, "consumer advances beside paused move");
    if (popped) output();
    ok &= check(completed.load() == 1, "published task runs before move resumes");
    ok &= check(queue.try_push(1, std::move(third), cursor),
                "freed storage can be reused while other move is paused");
    gate.open();
    paused.join();
    ok &= check(moved, "paused queue operation completes");
    if (!consumer_pause && queue.try_pop(0, output, cursor)) output();
    if (queue.try_pop(1, output, cursor)) output();
    return ok && check(completed.load() == 3, "paused move loses no task");
}

auto full_cache_transition_test(std::size_t capacity) -> bool
{
    work_stealing_queue queue(capacity, 2);
    std::size_t producer = 0;
    std::size_t consumer = 0;
    std::size_t completed = 0;
    const auto before = allocations.load();
    for (std::size_t slot = 0; slot < capacity; ++slot) {
        if (!queue.try_push(0, execution_task([&]() noexcept { ++completed; }),
                            producer)) return false;
    }
    bool ok = true;
    for (std::size_t cycle = 0; cycle < 64; ++cycle) {
        execution_task rejected([&]() noexcept { ++completed; });
        for (int attempt = 0; attempt < 4; ++attempt) {
            ok &= check(!queue.try_push(1, std::move(rejected), producer) && rejected,
                        "cold and cached full rejection retain the task");
        }
        ok &= check(work_stealing_queue_test_access::state(queue).load() ==
                        work_stealing_queue_test_access::full_result(),
                    "full pool verification warms rejection cache");
        // Exercise a free slot in different bitmap words, including the last.
        consumer = (capacity - 1 - cycle * 64) & (capacity - 1);
        execution_task output;
        if (!queue.try_pop(0, output, consumer)) return false;
        output();
        ok &= check(work_stealing_queue_test_access::state(queue).load() == 0,
                    "a completed dequeue invalidates the full cache");
        ok &= check(queue.try_push(0, std::move(rejected), producer),
                    "same rejecting cursor accepts the newly freed slot");
    }
    execution_task output;
    while (queue.try_pop(0, output, consumer)) output();
    return ok && check(completed == capacity + 64, "full-cache reuse loses no task") &&
           check(allocations.load() == before, "full-cache transitions allocate nothing");
}

auto incomplete_full_check_test() -> bool
{
    using access = work_stealing_queue_test_access;
    work_stealing_queue queue(2, 2);
    alignas(2) std::byte first_probe;
    alignas(2) std::byte second_probe;
    const auto first = reinterpret_cast<std::uintptr_t>(&first_probe);
    const auto second = reinterpret_cast<std::uintptr_t>(&second_probe);
    auto& state = access::state(queue);
    state.store(first);
    std::size_t cursor = access::failed_cursor();
    bool ok = check(queue.try_push(0, execution_task([]() noexcept {}), cursor),
                    "paused unverified checker does not block available capacity");
    ok &= check(queue.try_push(0, execution_task([]() noexcept {}), cursor),
                "another slot remains usable beside paused checker");
    execution_task rejected([]() noexcept {});
    ok &= check(!queue.try_push(0, std::move(rejected), cursor) && rejected,
                "busy checker does not change the capacity bound");
    execution_task output;
    ok &= check(queue.try_pop(0, output, cursor), "consumer frees beside paused checker");
    ok &= check(state.load() == 0, "freeing invalidates the in-progress check");
    // The original checker is still alive when a different checker registers.
    state.store(second);
    auto stale = first;
    ok &= check(!state.compare_exchange_strong(stale, access::full_result()),
                "invalidated checker cannot publish over a newer check");
    ok &= check(queue.try_push(0, std::move(rejected), cursor),
                "new incomplete checker also permits the available slot");
    while (queue.try_pop(0, output, cursor)) output();
    return ok && check(state.load() == 0, "completed releases clear a suspended check");
}

auto concurrent_reuse_test(std::size_t capacity) -> bool
{
    constexpr std::size_t producers = 4;
    constexpr std::size_t each = 4000;
    work_stealing_queue queue(capacity, 4);
    auto seen = std::make_unique<std::atomic<int>[]>(producers * each);
    std::atomic<std::size_t> finished {0};
    std::vector<std::thread> threads;
    for (std::size_t worker = 0; worker < 4; ++worker) {
        threads.emplace_back([&, worker] {
            std::size_t cursor = worker * 64;
            execution_task output;
            for (;;) {
                if (queue.try_pop(worker, output, cursor)) {
                    output();
                } else if (finished.load(std::memory_order_acquire) == producers) {
                    return;
                } else {
                    std::this_thread::yield();
                }
            }
        });
    }
    for (std::size_t producer = 0; producer < producers; ++producer) {
        threads.emplace_back([&, producer] {
            std::size_t cursor = producer * 64;
            for (std::size_t index = 0; index < each; ++index) {
                const auto id = producer * each + index;
                execution_task task([&, id]() noexcept { seen[id].fetch_add(1); });
                while (!queue.try_push(index % 4, std::move(task), cursor)) {
                    std::this_thread::yield();
                }
            }
            finished.fetch_add(1, std::memory_order_release);
        });
    }
    for (auto& thread : threads) thread.join();
    for (std::size_t id = 0; id < producers * each; ++id) {
        if (!check(seen[id].load() == 1, "concurrent slot reuse exactly once")) {
            return false;
        }
    }
    return true;
}

auto busy_owner_stealing_test() -> bool
{
    auto target = make_multi_thread_executor({.worker_count = 2, .queue_capacity = 8});
    test_publication::pause release_owner;
    std::atomic<int> completed {0};
    std::atomic<int> accepted {0};
    std::atomic<int> stolen {0};
    const bool parent = target->execute(execution_task([&]() noexcept {
        const auto owner = std::this_thread::get_id();
        for (int child = 0; child < 2; ++child) {
            if (target->execute(execution_task([&, owner]() noexcept {
                    if (std::this_thread::get_id() != owner) stolen.fetch_add(1);
                    completed.fetch_add(1);
                }))) accepted.fetch_add(1);
        }
        while (!release_owner.released.load()) release_owner.released.wait(false);
    }));
    bool ok = check(parent && wait_until([&] { return completed.load() == 2; }),
                    "idle worker takes backlog and lone task while owner remains busy");
    ok &= check(stolen.load() == 2 && accepted.load() == 2,
                "both children run on another worker exactly once");
    release_owner.open();
    target.reset();
    return ok && check(completed.load() == 2, "destruction leaves no extra work");
}

// A lone local task is left to its owner briefly, then taken by an idle peer
// once the owner starts no task. The executor's private delay is 100 us; the
// lower bound below only checks that the wait is not zero.
auto stalled_owner_lone_task_test() -> bool
{
    constexpr auto minimum_wait = std::chrono::microseconds {50};
    constexpr auto maximum_wait = std::chrono::milliseconds {500};
    for (const std::size_t workers : {std::size_t {2}, std::size_t {4}}) {
        auto target = make_multi_thread_executor({.worker_count = workers,
                                                  .queue_capacity = 8});
        for (int cycle = 0; cycle < 50; ++cycle) {
            std::atomic<bool> done {false};
            std::atomic<bool> accepted {false};
            std::atomic<bool> stolen {false};
            std::atomic<bool> timed_out {false};
            std::atomic<std::int64_t> waited_ns {-1};
            std::atomic<bool> parent_done {false};
            const bool parent = target->execute(execution_task([&]() noexcept {
                const auto owner = std::this_thread::get_id();
                const auto submitted = std::chrono::steady_clock::now();
                accepted.store(target->execute(execution_task([&, owner, submitted]() noexcept {
                    waited_ns.store(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                        std::chrono::steady_clock::now() - submitted).count());
                    stolen.store(std::this_thread::get_id() != owner);
                    done.store(true);
                })));
                // Block without starting another task, as a stalled owner.
                if (!wait_until([&] { return done.load(); })) timed_out.store(true);
                parent_done.store(true);
            }));
            const bool ran = parent && wait_until([&] { return done.load(); });
            if (!check(ran, "lone task behind a stalled owner runs")) std::_Exit(1);
            // The parent's last access to this cycle's state is its store.
            if (!check(wait_until([&] { return parent_done.load(); }),
                       "stalled parent returns")) std::_Exit(1);
            if (!check(accepted.load() && stolen.load() && !timed_out.load(),
                       "a peer takes the stalled owner's lone task")) std::_Exit(1);
            const auto waited = std::chrono::nanoseconds {waited_ns.load()};
            if (!check(waited >= minimum_wait && waited < maximum_wait,
                       "lone task waits a bounded nonzero stall delay")) {
                std::cerr << "  waited " << waited.count() << " ns\n";
                std::_Exit(1);
            }
        }
    }
    return true;
}

// Fewer idle peers than stalled owners: one peer handles each lone task in
// turn.
auto stalled_owners_share_one_peer_test() -> bool
{
    for (int cycle = 0; cycle < 20; ++cycle) {
        auto target = make_multi_thread_executor({.worker_count = 3, .queue_capacity = 8});
        test_publication::pause release;
        std::atomic<int> parents {0};
        std::atomic<int> children {0};
        for (int parent = 0; parent < 2; ++parent) {
            if (!target->execute(execution_task([&]() noexcept {
                    parents.fetch_add(1);
                    // Wait for both parents, so neither runs the other's child.
                    while (parents.load() != 2) std::this_thread::yield();
                    if (!target->execute(execution_task([&]() noexcept {
                            children.fetch_add(1);
                        }))) children.fetch_add(100);
                    while (!release.released.load()) release.released.wait(false);
                }))) return check(false, "stalled parent accepted");
        }
        const bool ran = check(wait_until([&] { return children.load() == 2; }),
                               "one idle peer runs both stalled owners' lone tasks");
        release.open();
        target.reset();
        if (!ran || !check(children.load() == 2, "lone tasks run exactly once")) return false;
    }
    return true;
}

// Owners that keep making progress through long single-task chains. Lone
// tasks may move to watching peers, but none may be lost or duplicated.
constexpr std::size_t chain_links = 20000;

struct chain_link {
    executor* target;
    std::atomic<int>* seen;
    std::atomic<std::size_t>* finished;
    std::size_t chain;
    std::size_t index;

    auto operator()() noexcept -> void
    {
        seen[chain * chain_links + index].fetch_add(1);
        if (index + 1 == chain_links) {
            finished->fetch_add(1);
            return;
        }
        execution_task next(chain_link {target, seen, finished, chain, index + 1});
        if (!target->execute(std::move(next))) next();
    }
};

auto progressing_owner_chain_test() -> bool
{
    constexpr std::size_t chains = 3;
    auto target = make_multi_thread_executor({.worker_count = 4, .queue_capacity = 16});
    auto seen = std::make_unique<std::atomic<int>[]>(chains * chain_links);
    std::atomic<std::size_t> finished {0};
    for (std::size_t chain = 0; chain < chains; ++chain) {
        if (!target->execute(execution_task(chain_link {target.get(), seen.get(),
                                                        &finished, chain, 0}))) {
            return false;
        }
    }
    const bool done = wait_until([&] { return finished.load() == chains; });
    target.reset();
    bool ok = check(done, "progressing chains finish");
    for (std::size_t id = 0; id < chains * chain_links; ++id) {
        if (!check(seen[id].load() == 1, "chain links run exactly once")) return false;
    }
    return ok;
}

auto executor_global_capacity_test() -> bool
{
    auto target = make_multi_thread_executor({.worker_count = 4, .queue_capacity = 2});
    test_publication::pause release;
    std::atomic<int> started {0};
    std::atomic<int> completed {0};
    bool ok = true;
    for (int count = 1; count <= 4; ++count) {
        ok &= check(target->execute(execution_task([&]() noexcept {
                        started.fetch_add(1);
                        while (!release.released.load()) release.released.wait(false);
                    })) && wait_until([&] { return started.load() == count; }),
                    "all workers active with capacity smaller than worker count");
    }
    for (int index = 0; index < 2; ++index) {
        ok &= check(target->execute(execution_task([&]() noexcept {
                        completed.fetch_add(1);
                    })), "global capacity accepts queued task");
    }
    execution_task rejected([&]() noexcept { completed.fetch_add(1); });
    ok &= check(!target->execute(std::move(rejected)) && rejected,
                "worker count does not multiply global queue capacity");
    release.open();
    target.reset();
    return ok && check(completed.load() == 2, "all globally bounded work drains");
}

auto sparse_external_submission_test() -> bool
{
    auto target = make_multi_thread_executor({.worker_count = 2, .queue_capacity = 2});
    test_publication::pause release;
    std::atomic<bool> started {false};
    std::atomic<int> completed {0};
    if (!target->execute(execution_task([&]() noexcept {
            started.store(true);
            while (!release.released.load()) release.released.wait(false);
        }))) return false;
    bool ok = check(wait_until([&] { return started.load(); }), "one worker is busy");
    for (int index = 0; index < 2; ++index) {
        ok &= check(target->execute(execution_task([&]() noexcept {
                        completed.fetch_add(1);
                    })), "sparse external job accepted");
    }
    ok &= check(wait_until([&] { return completed.load() == 2; }),
                "idle peer runs lone external jobs behind a busy worker");
    release.open();
    target.reset();
    return ok && check(completed.load() == 2, "external jobs execute exactly once");
}

auto executor_runtime_allocation_test() -> bool
{
    auto target = make_multi_thread_executor({.worker_count = 2, .queue_capacity = 64});
    std::atomic<int> completed {0};
    const auto before = allocations.load();
    for (int index = 0; index < 10000; ++index) {
        execution_task task([&]() noexcept { completed.fetch_add(1); });
        while (!target->execute(std::move(task))) std::this_thread::yield();
    }
    const bool finished = wait_until([&] { return completed.load() == 10000; });
    const bool unchanged = allocations.load() == before;
    target.reset();
    return check(finished, "runtime allocation workload finishes") &&
           check(unchanged, "submission dequeue stealing and wakeup allocate nothing");
}

struct tracked_job {
    std::atomic<int>* seen;
    std::atomic<int>* destroyed;
    std::size_t id;

    tracked_job(std::atomic<int>* input, std::atomic<int>& counter,
                std::size_t index) noexcept
        : seen(input), destroyed(&counter), id(index) {}
    tracked_job(tracked_job&& other) noexcept
        : seen(other.seen), destroyed(std::exchange(other.destroyed, nullptr)), id(other.id) {}
    ~tracked_job() { if (destroyed) destroyed->fetch_add(1); }
    auto operator()() noexcept -> void { seen[id].fetch_add(1); }
};

auto nested_ownership_test() -> bool
{
    constexpr std::size_t parents = 32;
    constexpr std::size_t children = 1000;
    auto seen = std::make_unique<std::atomic<int>[]>(parents * children);
    std::atomic<int> destroyed {0};
    std::atomic<std::size_t> parents_done {0};
    auto target = make_multi_thread_executor({.worker_count = 4, .queue_capacity = 64});
    for (std::size_t parent = 0; parent < parents; ++parent) {
        execution_task root([&, parent]() noexcept {
            for (std::size_t child = 0; child < children; ++child) {
                execution_task task(tracked_job(seen.get(), destroyed,
                                               parent * children + child));
                if (!target->execute(std::move(task))) task();
            }
            parents_done.fetch_add(1, std::memory_order_release);
        });
        while (!target->execute(std::move(root))) std::this_thread::yield();
    }
    const bool finished = wait_until([&] {
        return parents_done.load(std::memory_order_acquire) == parents;
    });
    target.reset();
    bool ok = check(finished, "nested producers finish without blocking on capacity");
    ok &= check(destroyed.load() == static_cast<int>(parents * children),
                "nested queued stolen and fallback jobs destroyed exactly once");
    for (std::size_t id = 0; id < parents * children; ++id) {
        if (!check(seen[id].load() == 1, "nested submissions execute exactly once")) {
            return false;
        }
    }
    return ok;
}

auto idle_worker_wakeup_test() -> bool
{
    auto target = make_multi_thread_executor({.worker_count = 4, .queue_capacity = 2});
    std::atomic<int> completed {0};
    for (int index = 1; index <= 500; ++index) {
        std::this_thread::sleep_for(std::chrono::microseconds {20});
        if (!target->execute(execution_task([&, index]() noexcept {
                completed.store(index, std::memory_order_release);
            }))) return check(false, "idle worker accepts its handoff");
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {2};
        while (completed.load(std::memory_order_acquire) != index) {
            if (std::chrono::steady_clock::now() >= deadline) {
                std::cerr << "FAILED: idle worker notification lost\n";
                std::_Exit(1);
            }
            std::this_thread::yield();
        }
    }
    return true;
}

// Submissions wake one idle peer rather than every sleeper. A busy worker's
// shareable children must still reach two distinct idle peers.
auto idle_peers_take_shareable_work_test() -> bool
{
    for (int cycle = 0; cycle < 50; ++cycle) {
        auto target = make_multi_thread_executor({.worker_count = 3, .queue_capacity = 8});
        test_publication::pause release;
        std::atomic<int> running {0};
        std::atomic<bool> accepted {true};
        const auto wait_for_release = [&]() noexcept {
            while (!release.released.load()) release.released.wait(false);
        };
        if (!target->execute(execution_task([&]() noexcept {
                for (int child = 0; child < 3; ++child) {
                    if (!target->execute(execution_task([&]() noexcept {
                            running.fetch_add(1);
                            wait_for_release();
                        }))) accepted.store(false);
                }
                wait_for_release();
            }))) return check(false, "parent accepted");
        const bool joined = check(wait_until([&] { return running.load() == 2; }),
                                  "both idle peers take shareable children");
        release.open();
        target.reset();
        if (!joined || !check(accepted.load() && running.load() == 3,
                              "children run exactly once")) return false;
    }
    return true;
}

// Every worker must be running one external task at the same time.
auto external_rendezvous_test() -> bool
{
    constexpr int workers = 4;
    for (int cycle = 0; cycle < 50; ++cycle) {
        auto target = make_multi_thread_executor({.worker_count = workers, .queue_capacity = 8});
        std::atomic<int> arrived {0};
        std::atomic<bool> timed_out {false};
        for (int index = 0; index < workers; ++index) {
            if (!target->execute(execution_task([&]() noexcept {
                    arrived.fetch_add(1);
                    if (!wait_until([&] { return arrived.load() == workers; })) {
                        timed_out.store(true);
                    }
                }))) return check(false, "rendezvous task accepted");
        }
        target.reset();
        if (!check(!timed_out.load() && arrived.load() == workers,
                   "every idle worker joins the external rendezvous")) return false;
    }
    return true;
}

auto shutdown_signal_test() -> bool
{
    for (int cycle = 0; cycle < 200; ++cycle) {
        std::atomic<int> completed {0};
        auto target = make_multi_thread_executor({.worker_count = 4, .queue_capacity = 64});
        for (int index = 0; index < 32; ++index) {
            if (!target->execute(execution_task([&]() noexcept {
                    completed.fetch_add(1);
                }))) return false;
        }
        target.reset();
        if (!check(completed.load() == 32, "coalesced signals drain and shut down")) {
            return false;
        }
    }
    return true;
}

} // namespace

auto main(int argc, char** argv) -> int
{
    if (argc == 2 && std::string_view(argv[1]) == "--stealing") {
        return busy_owner_stealing_test() ? 0 : 1;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--external") {
        return sparse_external_submission_test() ? 0 : 1;
    }
    for (const auto capacity : {std::size_t {2}, std::size_t {64}, std::size_t {128}}) {
        if (!bitmap_capacity_test(capacity) || !concurrent_reuse_test(capacity)) return 1;
    }
    for (const auto capacity : {std::size_t {2}, std::size_t {128},
                                std::size_t {4096}, std::size_t {65536}}) {
        if (!full_cache_transition_test(capacity)) return 1;
    }
    if (!incomplete_full_check_test() ||
        !paused_move_test(false) || !paused_move_test(true) ||
        !busy_owner_stealing_test() || !stalled_owner_lone_task_test() ||
        !stalled_owners_share_one_peer_test() || !progressing_owner_chain_test() ||
        !executor_global_capacity_test() ||
        !sparse_external_submission_test() ||
        !executor_runtime_allocation_test() || !nested_ownership_test() ||
        !idle_worker_wakeup_test() || !idle_peers_take_shareable_work_test() ||
        !external_rendezvous_test() || !shutdown_signal_test()) return 1;
    return 0;
}
