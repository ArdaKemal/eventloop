#include "eventloop/semaphore.h"
#include "eventloop/task.h"
#include "eventloop/task_composition.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <thread>
#include <string_view>
#include <system_error>
#include <utility>

using namespace eventloop;
using namespace std::chrono_literals;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "semaphore: " << message << '\n';
    std::exit(1);
}

template<typename T>
auto is(const std::expected<T, std::error_code>& result, std::errc error) -> bool
{
    return !result && result.error() == std::make_error_code(error);
}

auto ownership(event_loop& loop) -> task<void>
{
    semaphore slots(loop, 2);
    check(slots.capacity() == 2 && slots.available() == 2, "fixed capacity");
    {
        auto first = slots.try_acquire();
        auto second = slots.try_acquire();
        check(first && second && slots.available() == 0, "take all permits");
        check(is(slots.try_acquire(), std::errc::resource_unavailable_try_again), "exhaustion is EAGAIN");
        semaphore::permit moved(std::move(*first));
        check(moved && !*first && slots.available() == 0, "move transfers exactly one acquisition");
        moved = std::move(*second);
        check(moved && !*second && slots.available() == 1, "assignment releases destination");
        auto& alias = moved;
        moved = std::move(alias);
        check(moved && slots.available() == 1, "self-move preserves acquisition");
        moved.release();
        moved.release();
        check(!moved && slots.available() == 2, "release is idempotent");
        auto last = slots.try_acquire();
        check(last.has_value() && slots.available() == 1, "reacquire released permit");
        (void)last;
    }
    check(slots.available() == 2, "destruction returns remaining acquisition");
    semaphore::permit empty;
    check(!empty, "default permit empty");
    empty.release();
    {
        semaphore left(loop, 1), right(loop, 1);
        auto destination = left.try_acquire();
        auto source = right.try_acquire();
        check(destination && source, "acquire from distinct semaphores");
        *destination = std::move(*source);
        check(left.available() == 1 && right.available() == 0 && !*source, "move assignment preserves original owner");
        destination->release();
        check(right.available() == 1, "moved permit releases to correct semaphore");
    }
    loop.stop();
    co_return;
}

auto capacities(event_loop& loop) -> task<void>
{
    try {
        semaphore invalid(loop, 0);
        check(false, "zero capacity must fail");
    } catch (const std::invalid_argument&) {}
    semaphore slots(loop, std::numeric_limits<std::size_t>::max());
    {
        auto permit = slots.try_acquire();
        check(permit && slots.available() == slots.capacity() - 1, "maximum capacity acquisition");
    }
    check(slots.available() == slots.capacity(), "maximum capacity release does not overflow");
    loop.stop();
    co_return;
}

auto acquire(event_loop&, semaphore& slots,
             std::expected<semaphore::permit, std::error_code>& result) -> task<void>
{
    result = co_await slots.async_acquire();
}

auto immediate_acquisition(event_loop& loop) -> task<void>
{
    semaphore slots(loop, 1);
    const auto frames = loop.coroutine_statistics().live;
    {
        auto held = co_await slots.async_acquire();
        check(held.has_value() && slots.available() == 0, "async acquisition ready immediately");
        check(loop.coroutine_statistics().live == frames, "direct acquire uses no additional frame");
    }
    check(slots.available() == 1, "async permit returned on scope exit");
    {
        auto unused = slots.async_acquire();
        (void)unused;
        check(slots.available() == 1, "unawaited acquire takes nothing");
    }
    loop.stop();
}

auto fifo(event_loop& loop) -> task<void>
{
    semaphore slots(loop, 1);
    auto held = slots.try_acquire();
    check(held.has_value(), "take permit before waits");
    std::array<task_handle<void>, 3> waiting;
    std::array<std::expected<semaphore::permit, std::error_code>, 3> results;
    for (std::size_t index = 0; index < waiting.size(); ++index) {
        check(loop.spawn(acquire(loop, slots, results[index]), waiting[index])
                  == task_spawn_result::accepted, "spawn FIFO waiter");
        check(!waiting[index].done(), "exhaustion suspends");
    }
    held->release();
    for (std::size_t index = 0; index < waiting.size(); ++index) {
        check(!waiting[index].done(), "handoff defers resumption");
        check(slots.available() == 0, "reservation unavailable before resumption");
        check(is(slots.try_acquire(), std::errc::resource_unavailable_try_again), "new acquisition cannot barge");
        check(co_await waiting[index] == task_result::success && results[index] && static_cast<bool>(*results[index]), "oldest waiter owns permit");
        for (std::size_t later = index + 1; later < waiting.size(); ++later)
            check(!waiting[later].done(), "later waiter cannot pass held permit");
        results[index]->release();
    }
    check(slots.available() == 1, "all handoffs return exactly one permit");
    loop.stop();
}

auto cancellation(event_loop& loop) -> task<void>
{
    semaphore slots(loop, 1);
    auto held = slots.try_acquire();
    check(held.has_value(), "take permit before cancellation");
    std::array<task_handle<void>, 5> waiting;
    std::array<std::expected<semaphore::permit, std::error_code>, 5> results;
    for (std::size_t index = 0; index < waiting.size(); ++index)
        check(loop.spawn(acquire(loop, slots, results[index]), waiting[index])
                  == task_spawn_result::accepted, "spawn cancellable waiter");
    for (auto index : {2u, 0u, 4u}) {
        check(waiting[index].cancel(), "cancel middle/head/tail");
        check(!waiting[index].done(), "cancellation deferred");
    }
    check(slots.available() == 0, "cancelled waits do not release a held permit");
    held->release();
    for (std::size_t index = 0; index < waiting.size(); ++index) {
        check(co_await waiting[index] == task_result::success, "waiter retires");
        if (index % 2 == 0) check(is(results[index], std::errc::operation_canceled), "cancel result");
        else {
            check(results[index].has_value(), "surviving waiter owns reservation");
            check(slots.available() == 0, "cancelled waits have not inflated availability");
            results[index]->release();
        }
    }
    check(slots.available() == 1, "cancelled nodes removed without losing permits");
    auto next = co_await slots.async_acquire();
    check(next.has_value(), "acquire after cancellations");
    loop.stop();
}

auto committed_reservation(event_loop& loop) -> task<void>
{
    semaphore slots(loop, 1);
    auto held = slots.try_acquire();
    check(held.has_value(), "take permit before reservation");
    task_handle<void> waiting;
    std::expected<semaphore::permit, std::error_code> result;
    check(loop.spawn(acquire(loop, slots, result), waiting) == task_spawn_result::accepted, "spawn reservation waiter");
    held->release();
    check(!waiting.done() && slots.available() == 0, "reserve before resumption");
    check(waiting.cancel(), "cancel after reservation");
    check(co_await waiting == task_result::success && result.has_value(), "reservation wins cancellation");
    check(slots.available() == 0, "successful cancelled waiter owns exactly one permit");
    result->release();
    check(slots.available() == 1, "committed reservation returned");
    loop.stop();
}

auto acquire_after_cancel(event_loop& loop, semaphore& slots,
                          std::expected<semaphore::permit, std::error_code>& result) -> task<void>
{
    (void)co_await sleep_for(loop, 1h);
    result = co_await slots.async_acquire();
}

auto already_cancelled(event_loop& loop) -> task<void>
{
    semaphore slots(loop, 1);
    task_handle<void> waiting;
    std::expected<semaphore::permit, std::error_code> result;
    check(loop.spawn(acquire_after_cancel(loop, slots, result), waiting) == task_spawn_result::accepted, "spawn before cancelled acquire");
    check(waiting.cancel() && waiting.done(), "timer cancellation retires task");
    check(is(result, std::errc::operation_canceled) && slots.available() == 1, "cancellation precedes available permit");
    loop.stop();
    co_return;
}

auto holding(event_loop& loop, semaphore& slots, bool& entered, bool& saw_cancel) -> task<void>
{
    auto held = co_await slots.async_acquire();
    check(held.has_value(), "acquire for cancellable operation");
    entered = true;
    saw_cancel = co_await sleep_for(loop, 1h) == timer_wait_result::cancelled;
    check(slots.available() == 0, "cancellation cannot release live scope's permit");
}

auto cancel_holder(event_loop& loop) -> task<void>
{
    semaphore slots(loop, 1);
    task_handle<void> operation;
    bool entered = false, saw_cancel = false;
    check(loop.spawn(holding(loop, slots, entered, saw_cancel), operation) == task_spawn_result::accepted, "spawn permit holder");
    check(entered && slots.available() == 0, "operation holds permit across await");
    check(operation.cancel(), "cancel permit holder");
    check(co_await operation == task_result::success && saw_cancel, "holder retires after cancellation");
    check(slots.available() == 1, "holder releases on scope exit");
    loop.stop();
}

auto shutdown_waiters(event_loop& loop) -> task<void>
{
    semaphore slots(loop, 1);
    auto held = slots.try_acquire();
    check(held.has_value(), "take permit before shutdown");
    task_handle<void> a, b;
    std::expected<semaphore::permit, std::error_code> a_result, b_result;
    check(loop.spawn(acquire(loop, slots, a_result), a) == task_spawn_result::accepted, "shutdown waiter a");
    check(loop.spawn(acquire(loop, slots, b_result), b) == task_spawn_result::accepted, "shutdown waiter b");
    loop.shutdown(0s);
    held->release();
    check(slots.available() == 1, "shutdown removed all uncommitted waits");
    check(co_await a == task_result::success && is(a_result, std::errc::operation_canceled), "shutdown cancels first acquire");
    check(co_await b == task_result::success && is(b_result, std::errc::operation_canceled), "shutdown cancels second acquire");
}

auto shutdown_reserved(event_loop& loop) -> task<void>
{
    semaphore slots(loop, 1);
    auto held = slots.try_acquire();
    check(held.has_value(), "take permit before shutdown reservation");
    task_handle<void> a, b;
    std::expected<semaphore::permit, std::error_code> a_result, b_result;
    check(loop.spawn(acquire(loop, slots, a_result), a) == task_spawn_result::accepted, "reserved shutdown waiter");
    check(loop.spawn(acquire(loop, slots, b_result), b) == task_spawn_result::accepted, "uncommitted shutdown waiter");
    held->release();
    loop.shutdown(0s);
    check(co_await a == task_result::success && a_result.has_value(), "queued reservation survives shutdown");
    check(co_await b == task_result::success && is(b_result, std::errc::operation_canceled), "uncommitted reservation cancelled");
    check(slots.available() == 0, "reserved permit still held after shutdown");
    a_result->release();
    check(slots.available() == 1, "release after shutdown");
}

auto immediate(event_loop&) -> task<int> { co_return 7; }

auto composition_cancellation(event_loop& loop) -> task<void>
{
    semaphore slots(loop, 1);
    auto held = slots.try_acquire();
    check(held.has_value(), "take permit before race");
    std::expected<semaphore::permit, std::error_code> result;
    auto winner = co_await race(acquire(loop, slots, result), immediate(loop));
    check(winner && winner->index == 1, "immediate branch wins race");
    check(is(result, std::errc::operation_canceled), "race retires cancelled acquisition");
    check(slots.available() == 0, "losing branch took and released nothing");
    held->release();
    check(slots.available() == 1, "permit remains reusable after race");
    loop.stop();
}

auto result_task(event_loop&, semaphore& slots)
    -> task<std::expected<semaphore::permit, std::error_code>>
{
    co_return co_await slots.async_acquire();
}

auto observed_result(event_loop& loop) -> task<void>
{
    semaphore slots(loop, 1);
    task_handle<std::expected<semaphore::permit, std::error_code>> result;
    check(loop.spawn(result_task(loop, slots), result) == task_spawn_result::accepted, "spawn observed permit task");
    check(result.done() && slots.available() == 0, "completed task result still owns permit");
    auto held = flatten_result(co_await result);
    check(held.has_value() && slots.available() == 0, "awaiting result moves ownership without releasing");
    held->release();
    check(slots.available() == 1, "observed result releases exactly once");
    loop.stop();
}

struct job_counts {
    int active {0};
    int peak {0};
    std::array<int, 9> completed {};
};

auto job(event_loop& loop, semaphore& slots, job_counts& counts, std::size_t id) -> task<void>
{
    for (int operation = 0; operation < 100; ++operation) {
        auto held = co_await slots.async_acquire();
        check(held.has_value(), "job acquisition");
        ++counts.active;
        if (counts.active > counts.peak) counts.peak = counts.active;
        check(counts.active <= static_cast<int>(slots.capacity()), "jobs respect concurrency bound");
        check(co_await yield(loop), "simulate pending operation");
        check(static_cast<bool>(*held), "permit retained through operation completion");
        --counts.active;
        ++counts.completed[id];
    }
}

auto bounded_jobs(event_loop& loop) -> task<void>
{
    semaphore slots(loop, 3);
    job_counts counts;
    std::array<task_handle<void>, 9> jobs;
    for (std::size_t id = 0; id < jobs.size(); ++id)
        check(loop.spawn(job(loop, slots, counts, id), jobs[id]) == task_spawn_result::accepted, "spawn bounded job");
    for (auto& operation : jobs) check(co_await operation == task_result::success, "job retires");
    check(counts.active == 0 && counts.peak == 3 && slots.available() == 3, "all concurrent jobs release permits");
    for (int completed : counts.completed) check(completed == 100, "all callers make progress");
    loop.stop();
}

auto wrong_loop(event_loop&, semaphore& slots) -> task<void>
{
    (void)co_await slots.async_acquire();
    std::_Exit(1);
}

auto reuse_awaiter(event_loop&, semaphore& slots) -> task<void>
{
    auto waiting = slots.async_acquire();
    {
        auto held = co_await waiting;
        check(held.has_value(), "first await");
    }
    (void)co_await waiting;
    std::_Exit(1);
}

[[noreturn]] auto programming_error(std::string_view mode) -> void
{
    // Deliberate misuse must call terminate rather than crash or succeed.
    std::set_terminate([] { std::_Exit(0); });
    event_loop loop;
    if (mode == "wrong_loop" || mode == "reuse_awaiter") {
        semaphore slots(loop, 1);
        if (mode == "wrong_loop") {
            event_loop other;
            (void)other.spawn(wrong_loop(other, slots));
        } else {
            (void)loop.spawn(reuse_awaiter(loop, slots));
        }
    } else if (mode == "wrong_thread_acquire" || mode == "wrong_thread_release" ||
               mode == "wrong_thread_move" || mode == "wrong_thread_self_move") {
        semaphore slots(loop, 1);
        auto held = slots.try_acquire();
        check(held.has_value(), "permit before thread misuse");
        std::thread worker([&] {
            if (mode == "wrong_thread_acquire") (void)slots.try_acquire();
            else if (mode == "wrong_thread_release") held->release();
            else if (mode == "wrong_thread_move") {
                semaphore::permit moved(std::move(*held));
                (void)moved;
            } else {
                auto& alias = *held;
                *held = std::move(alias);
            }
            std::_Exit(1);
        });
        worker.join();
    } else if (mode == "destroy_held") {
        semaphore::permit held;
        {
            semaphore slots(loop, 1);
            auto result = slots.try_acquire();
            check(result.has_value(), "permit before destruction");
            held = std::move(*result);
        }
    } else if (mode == "destroy_reserved" || mode == "destroy_cancelled") {
        task_handle<void> waiting;
        std::expected<semaphore::permit, std::error_code> result;
        {
            semaphore slots(loop, 1);
            auto held = slots.try_acquire();
            check(held.has_value(), "held before waiter destruction");
            check(loop.spawn(acquire(loop, slots, result), waiting) == task_spawn_result::accepted, "lifetime waiter");
            if (mode == "destroy_cancelled") check(waiting.cancel(), "queue error before destruction");
            held->release();
            check(!waiting.done(), "resumption still pending");
        }
    }
    std::_Exit(1);
}

auto watchdog(event_loop& loop) -> task<void>
{
    if (co_await sleep_for(loop, 5s) == timer_wait_result::expired)
        check(false, "test did not finish");
}

auto run(event_loop& loop) -> void
{
    while (loop.run() == event_loop_result::interrupted) {}
}

auto run_case(task<void> (*test)(event_loop&), std::string_view name) -> void
{
    event_loop loop;
    task_handle<void> driver, timeout;
    check(loop.spawn(watchdog(loop), timeout) == task_spawn_result::accepted, "spawn watchdog");
    check(loop.spawn(test(loop), driver) == task_spawn_result::accepted, name);
    run(loop);
    check(driver.done() && driver.take_result() == task_result::success, "test retires");
    loop.shutdown(0s);
    run(loop);
}

} // namespace

auto main(int argc, char** argv) -> int
{
    if (argc == 2) programming_error(argv[1]);
    run_case(&ownership, "ownership");
    run_case(&capacities, "capacities");
    run_case(&immediate_acquisition, "immediate_acquisition");
    run_case(&fifo, "fifo");
    run_case(&cancellation, "cancellation");
    run_case(&committed_reservation, "committed_reservation");
    run_case(&already_cancelled, "already_cancelled");
    run_case(&cancel_holder, "cancel_holder");
    run_case(&shutdown_waiters, "shutdown_waiters");
    run_case(&shutdown_reserved, "shutdown_reserved");
    run_case(&composition_cancellation, "composition_cancellation");
    run_case(&observed_result, "observed_result");
    run_case(&bounded_jobs, "bounded_jobs");
}
