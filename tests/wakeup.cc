// eventloop::wakeup: deferred resumption, stored and collapsed
// notifications, EBUSY for a second waiter, cancellation, shutdown, and
// wrong-loop waits (run as `wakeup_test wrong_loop`).
#include "eventloop/event_loop.h"
#include "eventloop/task.h"
#include "eventloop/wakeup.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace eventloop;
using namespace std::chrono_literals;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "wakeup: " << message << '\n';
    std::exit(1);
}

auto is(const std::expected<void, std::error_code>& result, std::errc error) -> bool
{
    return !result && result.error() == std::make_error_code(error);
}

// Waits, records each outcome, and stops after `count` wakes.
auto waiter(event_loop& loop, wakeup& ready, std::vector<std::string>& log, int count)
    -> task<void>
{
    (void)loop;
    for (int index = 0; index < count; ++index) {
        const auto woken = co_await ready.async_wait();
        log.push_back(woken ? "woken" : woken.error().message());
    }
}

auto notifier(event_loop& loop, wakeup& ready, std::vector<std::string>& log) -> task<void>
{
    (void)co_await sleep_for(loop, 1ms);
    ready.notify();
    ready.notify(); // collapses into the queued wake
    log.push_back("notified");
}

auto run(event_loop& loop) -> void
{
    while (loop.run() == event_loop_result::interrupted) {}
}

// A stored notification must not bypass the loop check.
auto wrong_loop(event_loop&, wakeup& ready) -> task<void>
{
    (void)co_await ready.async_wait();
    std::_Exit(1);
}

[[noreturn]] auto programming_error(std::string_view mode) -> void
{
    std::set_terminate([] { std::_Exit(0); });
    if (mode == "wrong_loop") {
        event_loop owner;
        event_loop other;
        wakeup ready(owner);
        ready.notify();
        (void)other.spawn(wrong_loop(other, ready));
    }
    std::_Exit(2);
}

} // namespace

auto main(int argc, char** argv) -> int
{
    if (argc == 2) programming_error(argv[1]);

    // The waiter runs after the notifier returns, once per batch of notifies.
    {
        event_loop loop;
        wakeup ready(loop);
        std::vector<std::string> log;
        task_handle<void> waiting;
        check(loop.spawn(waiter(loop, ready, log, 2), waiting) == task_spawn_result::accepted, "spawn");
        check(loop.spawn(notifier(loop, ready, log)) == task_spawn_result::accepted, "spawn");
        struct stopper {
            static auto run(event_loop& loop, task_handle<void>& waiting, wakeup& ready) -> task<void>
            {
                (void)co_await sleep_for(loop, 20ms);
                check(!waiting.done(), "a collapsed notification wakes once");
                ready.notify();
                (void)co_await waiting;
                loop.stop();
            }
        };
        check(loop.spawn(stopper::run(loop, waiting, ready)) == task_spawn_result::accepted, "spawn");
        run(loop);
        check(log == std::vector<std::string> {"notified", "woken", "woken"}, "deferred order");
    }

    // A stored notification completes the next wait without suspending, and
    // waiting needs no coroutine frame.
    {
        event_loop loop;
        wakeup ready(loop);
        std::vector<std::string> log;
        ready.notify();
        ready.notify();
        struct probe {
            static auto run(event_loop& loop, wakeup& ready, std::vector<std::string>& log) -> task<void>
            {
                const auto live = loop.coroutine_statistics().live;
                const auto first = co_await ready.async_wait();
                log.push_back(first ? "immediate" : "failed");
                check(loop.coroutine_statistics().live == live, "no frame for a wait");
                // Two notifies stored one wake: this wait suspends.
                struct later {
                    static auto run(event_loop& loop, wakeup& ready) -> task<void>
                    {
                        (void)co_await sleep_for(loop, 5ms);
                        ready.notify();
                    }
                };
                check(loop.spawn(later::run(loop, ready)) == task_spawn_result::accepted, "spawn");
                const auto second = co_await ready.async_wait();
                log.push_back(second ? "woken" : "failed");
                loop.stop();
            }
        };
        check(loop.spawn(probe::run(loop, ready, log)) == task_spawn_result::accepted, "spawn");
        run(loop);
        check(log == std::vector<std::string> {"immediate", "woken"}, "stored notification");
    }

    // A stored notification completes a wait even after the task was
    // cancelled, and is consumed: the next cancelled wait reports ECANCELED.
    {
        event_loop loop;
        wakeup ready(loop);
        std::expected<void, std::error_code> first = std::unexpected(std::error_code {});
        std::expected<void, std::error_code> second;
        struct cancelled {
            static auto run(event_loop& loop, wakeup& ready,
                            std::expected<void, std::error_code>& first,
                            std::expected<void, std::error_code>& second) -> task<void>
            {
                (void)co_await sleep_for(loop, 1h);
                ready.notify();
                first = co_await ready.async_wait();
                second = co_await ready.async_wait();
            }
            static auto drive(event_loop& loop, wakeup& ready,
                              std::expected<void, std::error_code>& first,
                              std::expected<void, std::error_code>& second) -> task<void>
            {
                task_handle<void> waiting;
                check(loop.spawn(run(loop, ready, first, second), waiting) ==
                          task_spawn_result::accepted, "spawn");
                (void)waiting.cancel();
                (void)co_await waiting;
                loop.stop();
            }
        };
        check(loop.spawn(cancelled::drive(loop, ready, first, second)) ==
                  task_spawn_result::accepted, "spawn");
        run(loop);
        check(first.has_value(), "stored notification wins over cancellation");
        check(is(second, std::errc::operation_canceled), "stored notification consumed");
    }

    // A second waiter reports EBUSY; cancelling the first reports ECANCELED.
    {
        event_loop loop;
        wakeup ready(loop);
        std::expected<void, std::error_code> first;
        std::expected<void, std::error_code> second;
        struct waits {
            static auto one(event_loop&, wakeup& ready, std::expected<void, std::error_code>& out)
                -> task<void>
            {
                out = co_await ready.async_wait();
            }
            static auto drive(event_loop& loop, wakeup& ready,
                              std::expected<void, std::error_code>& first,
                              std::expected<void, std::error_code>& second) -> task<void>
            {
                task_handle<void> waiting;
                check(loop.spawn(one(loop, ready, first), waiting) == task_spawn_result::accepted, "spawn");
                (void)co_await sleep_for(loop, 1ms);
                second = co_await ready.async_wait();
                check(!waiting.done(), "first waiter still waits");
                (void)waiting.cancel();
                (void)co_await waiting;
                // The cancelled waiter left nothing behind: a new wait works.
                ready.notify();
                check(static_cast<bool>(co_await ready.async_wait()), "wait after cancellation");
                loop.stop();
            }
        };
        check(loop.spawn(waits::drive(loop, ready, first, second)) == task_spawn_result::accepted, "spawn");
        run(loop);
        check(is(second, std::errc::device_or_resource_busy), "second waiter is EBUSY");
        check(is(first, std::errc::operation_canceled), "cancelled waiter is ECANCELED");
    }

    // A queued notification wins over a later cancellation.
    {
        event_loop loop;
        wakeup ready(loop);
        std::expected<void, std::error_code> result = std::unexpected(std::error_code {});
        struct race {
            static auto one(event_loop&, wakeup& ready, std::expected<void, std::error_code>& out)
                -> task<void>
            {
                out = co_await ready.async_wait();
            }
            static auto drive(event_loop& loop, wakeup& ready,
                              std::expected<void, std::error_code>& out) -> task<void>
            {
                task_handle<void> waiting;
                check(loop.spawn(one(loop, ready, out), waiting) == task_spawn_result::accepted, "spawn");
                (void)co_await sleep_for(loop, 1ms);
                ready.notify();
                (void)waiting.cancel();
                (void)co_await waiting;
                loop.stop();
            }
        };
        check(loop.spawn(race::drive(loop, ready, result)) == task_spawn_result::accepted, "spawn");
        run(loop);
        check(result.has_value(), "queued notification wins");
    }

    // Shutdown cancels a waiting root.
    {
        event_loop loop;
        wakeup ready(loop);
        std::expected<void, std::error_code> result;
        struct idle {
            static auto run(event_loop&, wakeup& ready, std::expected<void, std::error_code>& out)
                -> task<void>
            {
                out = co_await ready.async_wait();
            }
            static auto stop(event_loop& loop) -> task<void>
            {
                (void)co_await sleep_for(loop, 1ms);
                loop.shutdown(0ms);
            }
        };
        check(loop.spawn(idle::run(loop, ready, result)) == task_spawn_result::accepted, "spawn");
        check(loop.spawn(idle::stop(loop)) == task_spawn_result::accepted, "spawn");
        run(loop);
        check(is(result, std::errc::operation_canceled), "shutdown ends the wait");
    }
}
