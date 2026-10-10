#include "eventloop/task_composition.h"

#include <chrono>
#include <atomic>
#include <array>
#include <cstdlib>
#include <expected>
#include <exception>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace eventloop;

using namespace std::chrono_literals;

namespace {
#ifdef _WIN32
auto child_exits_77(const wchar_t* argument) -> bool
{
    std::array<wchar_t, MAX_PATH> path {};
    const auto length = ::GetModuleFileNameW(nullptr, path.data(),
                                              static_cast<DWORD>(path.size()));
    if (length == 0 || length == path.size()) return false;
    std::wstring command = L"\"" + std::wstring(path.data()) + L"\" " + argument;
    STARTUPINFOW startup {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process {};
    if (!::CreateProcessW(path.data(), command.data(), nullptr, nullptr, FALSE,
                          CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                          &process)) return false;
    ::CloseHandle(process.hThread);
    const auto wait = ::WaitForSingleObject(process.hProcess, 5000);
    if (wait != WAIT_OBJECT_0) {
        ::TerminateProcess(process.hProcess, 1);
        ::WaitForSingleObject(process.hProcess, INFINITE);
    }
    DWORD code = 0;
    const bool passed = wait == WAIT_OBJECT_0 &&
                        ::GetExitCodeProcess(process.hProcess, &code) && code == 77;
    ::CloseHandle(process.hProcess);
    return passed;
}
#endif
auto value(event_loop&, int number) -> task<int> { co_return number; }
auto no_value(event_loop&) -> task<void> { co_return; }
auto later(event_loop& loop, int number, std::chrono::milliseconds delay,
           bool& cancelled) -> task<int>
{
    const auto result = co_await sleep_for(loop, delay);
    cancelled = result == timer_wait_result::cancelled;
    co_return number;
}
auto release_after(event_loop& loop, std::atomic<bool>& release,
                   std::chrono::milliseconds delay) -> task<void>
{
    if (co_await sleep_for(loop, delay) == timer_wait_result::expired) {
        release.store(true, std::memory_order_release);
    }
}
// Stops the loop when `root` finishes, however late coarse timers fire.
auto stop_when_done(event_loop& loop, task<void> root) -> task<void>
{
    (void)co_await std::move(root);
    loop.stop();
}
auto error_value(event_loop&) -> task<std::expected<int, std::error_code>>
{
    co_return std::unexpected(std::make_error_code(std::errc::invalid_argument));
}
auto all_root(event_loop& loop, bool& passed) -> task<void>
{
    auto results = co_await when_all(value(loop, 3), no_value(loop), error_value(loop));
    passed = std::get<0>(results) && *std::get<0>(results) == 3 &&
             std::get<1>(results) == task_result::success &&
             std::get<2>(results) && !*std::get<2>(results);
}
auto delayed_all_root(event_loop& loop, bool& passed) -> task<void>
{
    bool first_cancelled = false;
    bool second_cancelled = false;
    auto results = co_await when_all(later(loop, 3, 1ms, first_cancelled),
                                     later(loop, 4, 2ms, second_cancelled));
    passed = std::get<0>(results) && std::get<1>(results) &&
             *std::get<0>(results) == 3 && *std::get<1>(results) == 4 &&
             !first_cancelled && !second_cancelled;
}
auto race_root(event_loop& loop, bool& passed) -> task<void>
{
    bool cancelled = false;
    auto result = co_await race(value(loop, 7), later(loop, 9, 1h, cancelled));
    passed = result && result->index == 0 &&
             *std::get<0>(result->result) == 7 && cancelled;
}
auto error_race_root(event_loop& loop, bool& passed) -> task<void>
{
    bool cancelled = false;
    auto result = co_await race(error_value(loop),
                                later(loop, 9, 1h, cancelled));
    passed = result && result->index == 0 && cancelled &&
             std::get<0>(result->result) &&
             !*std::get<0>(result->result);
}
auto timeout_root(event_loop& loop, bool& passed) -> task<void>
{
    bool cancelled = false;
    auto first = co_await with_timeout(loop, later(loop, 4, 1h, cancelled), 1ms);
    auto second = co_await with_timeout(loop, value(loop, 5), 1h);
    auto immediate = co_await with_timeout(loop, value(loop, 6), 0ms);
    bool late_cancelled = false;
    auto late = co_await with_timeout(loop, later(loop, 7, 1ms, late_cancelled), 1h);
    passed = first && first->state == timeout_result<int>::outcome::timed_out &&
             late && late->state == timeout_result<int>::outcome::completed &&
             late->result && **late->result == 7 && !late_cancelled &&
             cancelled && second &&
             second->state == timeout_result<int>::outcome::completed &&
             second->result && **second->result == 5 && immediate &&
             immediate->state == timeout_result<int>::outcome::timed_out;
}
auto invalid_immediate_timeout_root(event_loop& loop, event_loop& foreign,
                                    bool started) -> task<void>
{
    auto operation = value(started ? loop : foreign, 1);
    if (started) (void)operation.start();
    (void)co_await with_timeout(loop, std::move(operation), 0ms);
}
#ifndef _WIN32
auto immediate_timeout_validation_test() -> bool
{
    for (const bool started : {false, true}) {
        const pid_t child = ::fork();
        if (child < 0) return false;
        if (child == 0) {
            std::set_terminate([] { std::_Exit(77); });
            event_loop loop;
            event_loop foreign;
            (void)loop.spawn(invalid_immediate_timeout_root(loop, foreign,
                                                            started));
            std::_Exit(1);
        }
        int status = 0;
        if (::waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 77) return false;
    }
    return true;
}
#else
auto immediate_timeout_validation_test() -> bool
{
    return child_exits_77(L"--invalid-immediate-foreign") &&
           child_exits_77(L"--invalid-immediate-started");
}
#endif
auto blocking_child(event_loop& loop, std::atomic<bool>& release,
                    bool& cancelled, std::atomic<bool>* started = nullptr)
    -> task<int>
{
    auto result = co_await run_blocking(loop, [&release, started]() noexcept {
        if (started) started->store(true, std::memory_order_release);
        while (!release.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        return 8;
    });
    cancelled = !result && result.error() == blocking_error::cancelled;
    co_return 8;
}
auto worker_race_root(event_loop& loop, std::atomic<bool>& release,
                      std::atomic<bool>& started, bool& cancelled, bool& passed)
    -> task<void>
{
    auto result = co_await race(blocking_child(loop, release, cancelled, &started),
                                later(loop, 2, 1ms, passed));
    passed = result && result->index == 1 && cancelled &&
             release.load(std::memory_order_acquire);
}
auto worker_race_test() -> bool
{
    event_loop_options options;
    options.worker_count = 1;
    event_loop loop(options);
    std::atomic<bool> release {false};
    std::atomic<bool> started {false};
    bool cancelled = false;
    bool passed = false;
    if (loop.spawn(stop_when_done(
            loop, worker_race_root(loop, release, started, cancelled, passed))) !=
        task_spawn_result::accepted) return false;
    // Cancel while the worker runs the function, as in timeout_shutdown_test.
    while (!started.load(std::memory_order_acquire)) std::this_thread::yield();
    if (loop.spawn(release_after(loop, release, 5ms)) !=
        task_spawn_result::accepted) return false;
    (void)loop.run();
    return passed && loop.coroutine_statistics().active_roots == 0;
}
// Expiry cancels the worker operation and resumes only after it retires.
auto worker_timeout_root(event_loop& loop, std::atomic<bool>& release,
                         std::atomic<bool>& started, bool& cancelled, bool& passed)
    -> task<void>
{
    auto result = co_await with_timeout(
        loop, blocking_child(loop, release, cancelled, &started), 1ms);
    passed = result && result->state == timeout_result<int>::outcome::timed_out &&
             cancelled && release.load(std::memory_order_acquire);
}
auto worker_timeout_test() -> bool
{
    event_loop_options options;
    options.worker_count = 1;
    event_loop loop(options);
    std::atomic<bool> release {false};
    std::atomic<bool> started {false};
    bool cancelled = false;
    bool passed = false;
    if (loop.spawn(stop_when_done(
            loop, worker_timeout_root(loop, release, started, cancelled, passed))) !=
        task_spawn_result::accepted) return false;
    // Cancel while the worker runs the function, as in timeout_shutdown_test.
    while (!started.load(std::memory_order_acquire)) std::this_thread::yield();
    if (loop.spawn(release_after(loop, release, 5ms)) !=
        task_spawn_result::accepted) return false;
    (void)loop.run();
    return passed && loop.coroutine_statistics().active_roots == 0;
}
auto cancelled_timeout_root(event_loop& loop, std::atomic<bool>& release,
                            std::atomic<bool>& started, bool& cancelled,
                            bool& reached) -> task<void>
{
    auto result = co_await with_timeout(
        loop, blocking_child(loop, release, cancelled, &started), 1h);
    reached = result && result->state == timeout_result<int>::outcome::cancelled &&
              cancelled && release.load(std::memory_order_acquire);
}
auto timeout_shutdown_test() -> bool
{
    event_loop_options options;
    options.worker_count = 1;
    event_loop loop(options);
    std::atomic<bool> release {false};
    std::atomic<bool> started {false};
    bool cancelled = false;
    bool reached = false;
    if (loop.spawn(cancelled_timeout_root(loop, release, started, cancelled,
                                          reached)) !=
        task_spawn_result::accepted) return false;
    // Shut down while the worker runs the operation; cancelling it before
    // the worker starts skips the function, and release is never observed.
    while (!started.load(std::memory_order_acquire)) std::this_thread::yield();
    std::thread worker_release([&release] {
        std::this_thread::sleep_for(5ms);
        release.store(true, std::memory_order_release);
    });
    loop.shutdown(event_loop::clock::duration::zero());
    (void)loop.run();
    worker_release.join();
    return reached && loop.coroutine_statistics().active_roots == 0;
}
auto cancellation_root(event_loop& loop, bool& first, bool& second,
                       bool& reached) -> task<void>
{
    auto result = co_await when_all(later(loop, 1, 1h, first),
                                    later(loop, 2, 1h, second));
    reached = std::get<0>(result) && std::get<1>(result);
}
auto shutdown_test() -> bool
{
    event_loop loop;
    bool first = false;
    bool second = false;
    bool reached = false;
    auto root = cancellation_root(loop, first, second, reached);
    if (loop.spawn(std::move(root)) != task_spawn_result::accepted) return false;
    loop.shutdown(event_loop::clock::duration::zero());
    (void)loop.run();
    return first && second && reached &&
           loop.coroutine_statistics().active_roots == 0;
}
auto cancelled_race_root(event_loop& loop, bool& first, bool& second,
                         bool& reached) -> task<void>
{
    auto result = co_await race(later(loop, 1, 1h, first),
                                later(loop, 2, 1h, second));
    reached = !result && result.error() == task_result::cancelled;
}
auto race_shutdown_test() -> bool
{
    event_loop loop;
    bool first = false;
    bool second = false;
    bool reached = false;
    auto root = cancelled_race_root(loop, first, second, reached);
    if (loop.spawn(std::move(root)) != task_spawn_result::accepted) return false;
    loop.shutdown(event_loop::clock::duration::zero());
    (void)loop.run();
    return first && second && reached &&
           loop.coroutine_statistics().active_roots == 0;
}
auto worker_shutdown_root(event_loop& loop, std::atomic<bool>& release,
                          bool& cancelled, bool& reached) -> task<void>
{
    bool timer_cancelled = false;
    auto result = co_await race(blocking_child(loop, release, cancelled),
                                later(loop, 2, 1h, timer_cancelled));
    reached = !result && result.error() == task_result::cancelled &&
              timer_cancelled && cancelled;
}
auto worker_shutdown_test() -> bool
{
    event_loop_options options;
    options.worker_count = 1;
    event_loop loop(options);
    std::atomic<bool> release {false};
    bool cancelled = false;
    bool reached = false;
    auto root = worker_shutdown_root(loop, release, cancelled, reached);
    if (loop.spawn(std::move(root)) != task_spawn_result::accepted) return false;
    std::thread worker_release([&release] {
        std::this_thread::sleep_for(5ms);
        release.store(true, std::memory_order_release);
    });
    loop.shutdown(event_loop::clock::duration::zero());
    (void)loop.run();
    worker_release.join();
    return reached && loop.coroutine_statistics().active_roots == 0;
}
auto exhaustion_root(event_loop& loop, bool& passed) -> task<void>
{
    auto result = co_await when_all(value(loop, 1), value(loop, 2));
    passed = !std::get<0>(result) && !std::get<1>(result) &&
             std::get<0>(result).error() == task_result::frame_allocation_failure &&
             std::get<1>(result).error() == task_result::frame_allocation_failure;
}
auto exhaustion_test() -> bool
{
    event_loop_options options;
    options.coroutine_frame_capacities.fill(0);
    options.coroutine_frame_capacities.back() = 1;
    event_loop loop(options);
    bool passed = false;
    auto root = exhaustion_root(loop, passed);
    return loop.spawn(std::move(root)) == task_spawn_result::accepted &&
           passed && loop.coroutine_statistics().live == 0;
}
auto run_case(auto factory) -> bool
{
    event_loop loop;
    bool passed = false;
    if (loop.spawn(stop_when_done(loop, factory(loop, passed))) !=
        task_spawn_result::accepted) return false;
    if (loop.coroutine_statistics().active_roots != 0) (void)loop.run();
    return passed && loop.coroutine_statistics().live == 0;
}
}
int main(int argc, char** argv)
{
#ifdef _WIN32
    if (argc == 2) {
        const std::string_view mode = argv[1];
        if (mode == "--invalid-immediate-foreign" ||
            mode == "--invalid-immediate-started") {
            std::set_terminate([] { std::_Exit(77); });
            event_loop loop;
            event_loop foreign;
            (void)loop.spawn(invalid_immediate_timeout_root(
                loop, foreign, mode == "--invalid-immediate-started"));
            return 1;
        }
        return 1;
    }
#endif
    bool a = run_case(all_root);
    bool b = run_case(delayed_all_root);
    bool c = run_case(race_root);
    bool d = run_case(error_race_root);
    bool e = run_case(timeout_root);
    bool f = worker_race_test();
    bool g = shutdown_test();
    bool h = race_shutdown_test();
    bool i = worker_shutdown_test();
    bool j = exhaustion_test();
    bool k = immediate_timeout_validation_test();
    bool l = worker_timeout_test();
    bool m = timeout_shutdown_test();
    if (!a || !b || !c || !d || !e || !f || !g || !h || !i || !j || !k ||
        !l || !m) {
        std::cerr << "task composition test failed\n";
        return 1;
    }
}
