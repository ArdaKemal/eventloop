// Ports of the tokio-rs/tokio `benches/` suite that have an eventloop
// equivalent. Workload shapes, sizes, and names follow the Rust files; the
// harness follows Criterion's defaults (3 s warm-up, 100 linearly growing
// samples over ~5 s, slope estimate) so the two sides are measured alike.
// Linux only: it uses POSIX sockets and /dev/zero.
//
// Usage: tokio_comparison_benchmark [--quick] [--list] [filter...]
// A filter is a substring of "group/name"; with none, every benchmark runs.
// Each result is also printed as a tab-separated RESULT line (nanoseconds
// per iteration: slope, median, mean, min, max).

#include "eventloop/file_io.h"
#include "eventloop/task.h"
#include "eventloop/task_composition.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <numeric>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace eventloop;

namespace {

using steady = std::chrono::steady_clock;

struct settings {
    double warmup_seconds {3.0};
    double measure_seconds {5.0};
    std::uint64_t samples {100};
    bool list_only {false};
    std::vector<std::string> filters;
} config;

template<typename T>
inline auto keep(const T& value) -> void
{
    asm volatile("" : : "g"(&value) : "memory");
}

[[nodiscard]] auto selected(const std::string& name) -> bool
{
    if (config.filters.empty()) return true;
    return std::ranges::any_of(config.filters, [&](const std::string& filter) {
        return name.find(filter) != std::string::npos;
    });
}

// True when any benchmark of the group can match, so an unselected group
// builds no loop, threads, or sockets.
[[nodiscard]] auto group_enabled(const std::string& group) -> bool
{
    if (config.filters.empty() || config.list_only) return true;
    return std::ranges::any_of(config.filters, [&](const std::string& filter) {
        return filter.find(group) != std::string::npos ||
               group.find(filter) != std::string::npos;
    });
}

[[nodiscard]] auto nanoseconds(steady::duration duration) -> double
{
    return std::chrono::duration<double, std::nano>(duration).count();
}

[[nodiscard]] auto format_time(double ns) -> std::string
{
    char text[32];
    if (ns < 1e3) std::snprintf(text, sizeof text, "%.2f ns", ns);
    else if (ns < 1e6) std::snprintf(text, sizeof text, "%.3f us", ns / 1e3);
    else if (ns < 1e9) std::snprintf(text, sizeof text, "%.3f ms", ns / 1e6);
    else std::snprintf(text, sizeof text, "%.3f s", ns / 1e9);
    return text;
}

// run(iterations) returns the time spent in the measured section for that
// many iterations, like Criterion's iter_custom.
template<typename Run>
auto bench(const std::string& name, Run&& run) -> void
{
    if (!selected(name)) return;
    if (config.list_only) {
        std::cout << name << '\n';
        return;
    }

    double warmup_ns = 0;
    std::uint64_t warmup_iterations = 0;
    for (std::uint64_t count = 1; warmup_ns < config.warmup_seconds * 1e9;
         count *= 2) {
        warmup_ns += nanoseconds(run(count));
        warmup_iterations += count;
    }
    const double mean_ns = warmup_ns / static_cast<double>(warmup_iterations);

    const double runs = static_cast<double>(config.samples) *
                        static_cast<double>(config.samples + 1) / 2.0;
    const auto step = static_cast<std::uint64_t>(std::max(
        1.0, std::ceil(config.measure_seconds * 1e9 / mean_ns / runs)));

    std::vector<double> iterations;
    std::vector<double> times;
    std::vector<double> per_iteration;
    for (std::uint64_t sample = 1; sample <= config.samples; ++sample) {
        const auto count = sample * step;
        const double time = nanoseconds(run(count));
        iterations.push_back(static_cast<double>(count));
        times.push_back(time);
        per_iteration.push_back(time / static_cast<double>(count));
    }

    double cross = 0;
    double squares = 0;
    for (std::size_t index = 0; index < iterations.size(); ++index) {
        cross += iterations[index] * times[index];
        squares += iterations[index] * iterations[index];
    }
    const double slope = cross / squares;
    const double mean = std::accumulate(times.begin(), times.end(), 0.0) /
                        std::accumulate(iterations.begin(), iterations.end(), 0.0);
    std::ranges::sort(per_iteration);
    const double median = per_iteration[per_iteration.size() / 2];

    std::cout << name << "\n    time:   [slope " << format_time(slope)
              << "]  median " << format_time(median) << "  mean "
              << format_time(mean) << "  range ["
              << format_time(per_iteration.front()) << " .. "
              << format_time(per_iteration.back()) << "]\n"
              << "RESULT\t" << name << '\t' << slope << '\t' << median << '\t'
              << mean << '\t' << per_iteration.front() << '\t'
              << per_iteration.back() << std::endl;
}

// Large enough for the biggest workload (10,000 live tasks); pools are
// preallocated so frame growth never lands in a measurement.
[[nodiscard]] auto bench_options(std::size_t workers = 0,
                                 std::size_t completions = 128)
    -> event_loop_options
{
    event_loop_options options;
    options.worker_count = workers;
    options.post_capacity = 16384;
    options.coroutine_completion_capacity = completions;
    options.coroutine_frame_capacities = {16384, 16384, 16384, 16384, 64, 64};
    options.coroutine_frame_initial_capacities =
        options.coroutine_frame_capacities;
    return options;
}

// ---------------------------------------------------------------------------
// block_on: run one root to completion, then return from run().

auto stopper(event_loop& loop, task<void> body) -> task<void>
{
    (void)co_await std::move(body);
    loop.stop();
}

auto block_on(event_loop& loop, task<void> body) -> void
{
    if (loop.spawn(stopper(loop, std::move(body))) !=
        task_spawn_result::accepted) {
        std::terminate();
    }
    (void)loop.run();
}

template<typename Make>
auto repeat(event_loop& loop, std::uint64_t iterations, Make make) -> task<void>
{
    for (std::uint64_t index = 0; index < iterations; ++index) {
        (void)co_await make(loop);
    }
}

// Tokio calls block_on once per iteration. "[in-loop]" repeats the body
// inside one run() instead, which amortises the stop/wake of each run().
template<typename Make>
auto bench_task(const std::string& name, event_loop& loop, Make make) -> void
{
    bench(name, [&](std::uint64_t iterations) {
        const auto start = steady::now();
        for (std::uint64_t index = 0; index < iterations; ++index) {
            block_on(loop, make(loop));
        }
        return steady::now() - start;
    });
    bench(name + " [in-loop]", [&](std::uint64_t iterations) {
        const auto start = steady::now();
        block_on(loop, repeat(loop, iterations, make));
        return steady::now() - start;
    });
}

using void_slot = std::optional<task_handle<void>>;

auto empty_task(event_loop&) -> task<void> { co_return; }

auto spawn_and_await(event_loop& loop, std::vector<void_slot>& slots)
    -> task<void>
{
    for (auto& slot : slots) {
        slot.emplace();
        if (loop.spawn(empty_task(loop), *slot) != task_spawn_result::accepted) {
            std::terminate();
        }
    }
    for (auto& slot : slots) {
        (void)co_await *slot;
        slot.reset();
    }
}

// Posted work stands in for tokio's remote spawn: it runs on the loop and
// there spawns the task. The last completion stops the loop.
struct remote_count {
    event_loop& loop;
    std::size_t total;
    std::size_t completed {0};
};

auto counted_task(event_loop& loop, remote_count& count) -> task<void>
{
    if (++count.completed == count.total) loop.stop();
    co_return;
}

auto post_counted(event_loop& loop, remote_count& count) -> void
{
    execution_task spawn_it([&loop, &count]() noexcept {
        if (loop.spawn(counted_task(loop, count)) !=
            task_spawn_result::accepted) {
            std::terminate();
        }
    });
    if (!loop.post(std::move(spawn_it))) std::terminate();
}

auto remote_spawn_and_wait(event_loop& loop, std::size_t spawns) -> void
{
    remote_count count {loop, spawns};
    for (std::size_t index = 0; index < spawns; ++index) {
        post_counted(loop, count);
    }
    (void)loop.run();
}

// Keeps the loop busy: every tick spawns a task and queues the next tick.
struct busy_chain {
    event_loop& loop;
    bool running {true};

    auto tick() noexcept -> void
    {
        if (!running) return;
        (void)loop.spawn(empty_task(loop));
        if (!loop.post(execution_task([this]() noexcept { tick(); }))) {
            std::terminate();
        }
    }
};

auto rt_current_thread() -> void
{
    constexpr std::size_t num_spawn = 1'000;
    if (!group_enabled("rt_current_thread")) return;
    event_loop loop(bench_options());
    std::vector<void_slot> slots(num_spawn);

    bench_task("rt_current_thread/spawn_many_local", loop,
               [&](event_loop& owner) { return spawn_and_await(owner, slots); });

    bench("rt_current_thread/spawn_many_remote_idle",
          [&](std::uint64_t iterations) {
              const auto start = steady::now();
              for (std::uint64_t index = 0; index < iterations; ++index) {
                  remote_spawn_and_wait(loop, num_spawn);
              }
              return steady::now() - start;
          });

    busy_chain busy {loop};
    busy.tick();
    bench("rt_current_thread/spawn_many_remote_busy",
          [&](std::uint64_t iterations) {
              const auto start = steady::now();
              for (std::uint64_t index = 0; index < iterations; ++index) {
                  remote_spawn_and_wait(loop, num_spawn);
              }
              return steady::now() - start;
          });
    busy.running = false;
    block_on(loop, empty_task(loop));
}

// ---------------------------------------------------------------------------

auto yielding_work(event_loop& loop) -> task<int>
{
    const int value = 1 + 1;
    (void)co_await yield(loop);
    keep(value);
    co_return value;
}

auto spawn_one(event_loop& loop) -> task<void>
{
    task_handle<int> handle;
    if (loop.spawn(yielding_work(loop), handle) != task_spawn_result::accepted) {
        std::terminate();
    }
    const auto result = co_await handle;
    if (!result || *result != 2) std::terminate();
}

auto spawn_ten(event_loop& loop) -> task<void>
{
    std::array<std::optional<task_handle<int>>, 10> handles;
    for (auto& handle : handles) {
        handle.emplace();
        if (loop.spawn(yielding_work(loop), *handle) !=
            task_spawn_result::accepted) {
            std::terminate();
        }
    }
    for (auto& handle : handles) {
        const auto result = co_await *handle;
        if (!result || *result != 2) std::terminate();
    }
}

auto spawn_group() -> void
{
    if (!group_enabled("spawn/")) return;
    event_loop loop(bench_options());
    bench_task("spawn/basic_scheduler_spawn", loop, spawn_one);
    bench_task("spawn/basic_scheduler_spawn10", loop, spawn_ten);
}

// ---------------------------------------------------------------------------

auto read_clock(event_loop&) -> task<void>
{
    const auto now = event_loop::clock::now();
    keep(now);
    co_return;
}

auto time_now_group() -> void
{
    if (!group_enabled("time_now")) return;
    event_loop loop(bench_options());
    bench_task("time_now/time_now_current_thread", loop, read_clock);
}

auto quick_job(event_loop&) -> task<int> { co_return 1; }

auto timeout_job(event_loop& loop, std::uint64_t iterations) -> task<void>
{
    for (std::uint64_t index = 0; index < iterations; ++index) {
        auto result = co_await with_timeout(loop, quick_job(loop),
                                            std::chrono::seconds(1));
        if (!result ||
            result->state != timeout_result<int>::outcome::completed ||
            !result->result || **result->result != 1) {
            std::terminate();
        }
        keep(result);
    }
}

auto sleep_job(event_loop& loop, std::uint64_t iterations) -> task<void>
{
    for (std::uint64_t index = 0; index < iterations; ++index) {
        keep(sleep_for(loop, std::chrono::seconds(1)));
    }
    co_return;
}

auto time_timeout_group() -> void
{
    if (!group_enabled("time_timeout")) return;
    event_loop loop(bench_options());
    bench("time_timeout/single_thread_timeout", [&](std::uint64_t iterations) {
        const auto start = steady::now();
        block_on(loop, timeout_job(loop, iterations));
        return steady::now() - start;
    });
    bench("time_timeout/single_thread_sleep", [&](std::uint64_t iterations) {
        const auto start = steady::now();
        block_on(loop, sleep_job(loop, iterations));
        return steady::now() - start;
    });
}

// ---------------------------------------------------------------------------

constexpr std::size_t blocking_batches_per_task = 100;
constexpr std::size_t blocking_batch_size = 16;

auto blocking_unit(event_loop& loop) -> task<void>
{
    const auto result = co_await run_blocking(loop, []() noexcept {
        const int value = 0;
        keep(value);
    });
    if (!result) std::terminate();
}

auto blocking_batches(event_loop& loop) -> task<void>
{
    std::array<void_slot, blocking_batch_size> batch;
    for (std::size_t round = 0; round < blocking_batches_per_task; ++round) {
        for (auto& slot : batch) {
            slot.emplace();
            if (loop.spawn(blocking_unit(loop), *slot) !=
                task_spawn_result::accepted) {
                std::terminate();
            }
        }
        for (auto& slot : batch) {
            (void)co_await *slot;
            slot.reset();
        }
    }
}

auto blocking_concurrency(event_loop& loop, std::size_t tasks) -> task<void>
{
    std::vector<void_slot> roots(tasks);
    for (auto& slot : roots) {
        slot.emplace();
        if (loop.spawn(blocking_batches(loop), *slot) !=
            task_spawn_result::accepted) {
            std::terminate();
        }
    }
    for (auto& slot : roots) (void)co_await *slot;
}

[[nodiscard]] auto parallelism_levels() -> std::vector<std::size_t>
{
    const std::size_t available =
        std::max(1U, std::thread::hardware_concurrency());
    std::vector<std::size_t> levels;
    for (const std::size_t level : {1, 2, 4, 8, 16, 32, 64}) {
        if (level <= available) levels.push_back(level);
    }
    return levels;
}

auto spawn_blocking_group() -> void
{
    if (!group_enabled("spawn_blocking")) return;
    // Tokio's default runtime has one worker per core; give the loop the same
    // number of blocking workers and enough completion slots for 64 x 16
    // outstanding operations.
    const std::size_t workers = std::max(1U, std::thread::hardware_concurrency());
    event_loop loop(bench_options(workers, 1024));
    for (const auto level : parallelism_levels()) {
        bench("spawn_blocking/concurrency/" + std::to_string(level),
              [&, level](std::uint64_t iterations) {
                  const auto start = steady::now();
                  for (std::uint64_t index = 0; index < iterations; ++index) {
                      block_on(loop, blocking_concurrency(loop, level));
                  }
                  return steady::now() - start;
              });
    }
}

// ---------------------------------------------------------------------------

// The loop runs on its own thread while external threads post.
class loop_thread {
public:
    explicit loop_thread(event_loop_options options)
        : thread_([this, options] {
              event_loop loop(options);
              loop_.store(&loop, std::memory_order_release);
              (void)loop.run();
          })
    {
        while (loop_.load(std::memory_order_acquire) == nullptr) {
            std::this_thread::yield();
        }
    }
    ~loop_thread()
    {
        loop_.load(std::memory_order_acquire)->stop();
        thread_.join();
    }
    loop_thread(const loop_thread&) = delete;
    auto operator=(const loop_thread&) -> loop_thread& = delete;

    [[nodiscard]] auto loop() const noexcept -> event_loop&
    {
        return *loop_.load(std::memory_order_acquire);
    }

private:
    std::atomic<event_loop*> loop_ {nullptr};
    std::thread thread_;
};

auto touch_task(event_loop&, std::atomic<std::size_t>& done) -> task<void>
{
    done.fetch_add(1, std::memory_order_release);
    co_return;
}

constexpr std::size_t remote_total_tasks = 12'800;

auto remote_spawn_group() -> void
{
    if (!group_enabled("remote_spawn")) return;
    loop_thread runner(bench_options());
    event_loop& loop = runner.loop();
    std::atomic<std::size_t> done {0};

    for (const auto threads : parallelism_levels()) {
        bench("remote_spawn/threads/" + std::to_string(threads),
              [&, threads](std::uint64_t iterations) {
                  const std::size_t per_thread = remote_total_tasks / threads;
                  std::barrier ready(static_cast<std::ptrdiff_t>(threads));
                  auto total = steady::duration::zero();
                  for (std::uint64_t index = 0; index < iterations; ++index) {
                      const auto start = steady::now();
                      {
                          std::vector<std::thread> producers;
                          producers.reserve(threads);
                          for (std::size_t t = 0; t < threads; ++t) {
                              producers.emplace_back([&] {
                                  ready.arrive_and_wait();
                                  for (std::size_t n = 0; n < per_thread; ++n) {
                                      execution_task spawn_it(
                                          [&loop, &done]() noexcept {
                                              (void)loop.spawn(
                                                  touch_task(loop, done));
                                          });
                                      while (!loop.post(std::move(spawn_it))) {
                                          std::this_thread::yield();
                                      }
                                  }
                              });
                          }
                          for (auto& producer : producers) producer.join();
                      }
                      total += steady::now() - start;
                      while (done.load(std::memory_order_acquire) !=
                             per_thread * threads) {
                          std::this_thread::yield();
                      }
                      done.store(0, std::memory_order_relaxed);
                  }
                  return total;
              });
    }
}

// ---------------------------------------------------------------------------
// rt_multi_threaded: the cases that need no oneshot channel. Tokio runs these
// on 4 worker threads; eventloop runs them on one loop thread.

constexpr std::size_t multi_num_spawn = 10'000;

struct countdown {
    std::size_t remaining;
};

auto countdown_task(event_loop& loop, countdown& state) -> task<void>
{
    if (--state.remaining == 0) loop.stop();
    co_return;
}

auto multi_spawn_many_local(event_loop& loop) -> void
{
    countdown state {multi_num_spawn};
    for (std::size_t index = 0; index < multi_num_spawn; ++index) {
        if (loop.spawn(countdown_task(loop, state)) !=
            task_spawn_result::accepted) {
            std::terminate();
        }
    }
    (void)loop.run();
}

auto yield_task(event_loop& loop, countdown& state) -> task<void>
{
    for (std::size_t index = 0; index < 1'000; ++index) {
        (void)co_await yield(loop);
    }
    if (--state.remaining == 0) loop.stop();
}

auto multi_yield_many(event_loop& loop) -> void
{
    constexpr std::size_t tasks = 200;
    countdown state {tasks};
    for (std::size_t index = 0; index < tasks; ++index) {
        if (loop.spawn(yield_task(loop, state)) != task_spawn_result::accepted) {
            std::terminate();
        }
    }
    (void)loop.run();
}

auto chained_task(event_loop& loop, std::size_t remaining) -> task<void>
{
    if (remaining == 0) {
        loop.stop();
    } else if (loop.spawn(chained_task(loop, remaining - 1)) !=
               task_spawn_result::accepted) {
        std::terminate();
    }
    co_return;
}

auto multi_chained_spawn(event_loop& loop) -> void
{
    if (loop.spawn(chained_task(loop, 1'000)) != task_spawn_result::accepted) {
        std::terminate();
    }
    (void)loop.run();
}

template<typename Body>
auto bench_run(const std::string& name, event_loop& loop, Body body) -> void
{
    bench(name, [&](std::uint64_t iterations) {
        const auto start = steady::now();
        for (std::uint64_t index = 0; index < iterations; ++index) body(loop);
        return steady::now() - start;
    });
}

auto rt_multi_threaded_group() -> void
{
    if (!group_enabled("rt_multi_threaded")) return;
    event_loop loop(bench_options());
    bench_run("rt_multi_threaded/spawn_many_local", loop, multi_spawn_many_local);
    bench_run("rt_multi_threaded/spawn_many_remote_idle", loop,
              [](event_loop& owner) {
                  remote_spawn_and_wait(owner, multi_num_spawn);
              });
    bench_run("rt_multi_threaded/yield_many", loop, multi_yield_many);
    bench_run("rt_multi_threaded/chained_spawn", loop, multi_chained_spawn);
}

// ---------------------------------------------------------------------------

constexpr std::size_t accept_request_size = 64;
constexpr std::uint64_t accept_batch = 64;

class client_socket {
public:
    explicit client_socket(std::uint16_t port)
        : descriptor_(::socket(AF_INET, SOCK_STREAM, 0))
    {
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        const int one = 1;
        std::array<char, accept_request_size> request {};
        request.fill(1);
        if (descriptor_ < 0 ||
            ::connect(descriptor_, reinterpret_cast<sockaddr*>(&address),
                      sizeof address) != 0 ||
            ::setsockopt(descriptor_, IPPROTO_TCP, TCP_NODELAY, &one,
                         sizeof one) != 0 ||
            ::send(descriptor_, request.data(), request.size(), 0) !=
                static_cast<ssize_t>(request.size())) {
            std::perror("client");
            std::abort();
        }
    }
    ~client_socket()
    {
        if (descriptor_ >= 0) ::close(descriptor_);
    }
    client_socket(client_socket&& other) noexcept
        : descriptor_(std::exchange(other.descriptor_, -1)) {}
    client_socket(const client_socket&) = delete;
    auto operator=(const client_socket&) -> client_socket& = delete;
    auto operator=(client_socket&&) -> client_socket& = delete;

private:
    int descriptor_;
};

[[nodiscard]] auto bound_port(int descriptor) -> std::uint16_t
{
    sockaddr_in address {};
    socklen_t length = sizeof address;
    if (::getsockname(descriptor, reinterpret_cast<sockaddr*>(&address),
                      &length) != 0) {
        std::abort();
    }
    return ntohs(address.sin_port);
}

// Reads the request, answers "ok", and closes, as tokio's `serve` does.
auto serve(event_loop& loop, unique_fd descriptor) -> task<void>
{
    auto owned = std::make_unique<tcp_stream>(loop, std::move(descriptor));
    tcp_stream* stream = owned.get();
    loop.add(std::move(owned));

    std::array<std::byte, accept_request_size> request;
    std::size_t received = 0;
    while (received < request.size()) {
        const auto result = co_await stream->async_read_some(
            std::span<std::byte>(request).subspan(received));
        if (!result || *result == 0) std::terminate();
        received += *result;
    }
    static constexpr std::array<std::byte, 2> reply {std::byte {'o'},
                                                     std::byte {'k'}};
    std::size_t sent = 0;
    while (sent < reply.size()) {
        const auto result = co_await stream->async_write_some(
            std::span<const std::byte>(reply).subspan(sent));
        if (!result || *result == 0) std::terminate();
        sent += *result;
    }
    stream->close();
}

auto accept_one(event_loop& loop, tcp_acceptor& acceptor) -> task<void>
{
    auto accepted = co_await acceptor.async_accept();
    if (!accepted) std::terminate();
    (void)co_await serve(loop, std::move(*accepted));
}

auto serial_task(event_loop& loop, tcp_acceptor& acceptor, std::uint64_t count)
    -> task<void>
{
    for (std::uint64_t index = 0; index < count; ++index) {
        (void)co_await accept_one(loop, acceptor);
    }
}

auto task_per_conn(event_loop& loop, tcp_acceptor& acceptor, std::uint64_t count)
    -> task<void>
{
    std::vector<void_slot> handlers(count);
    for (auto& slot : handlers) {
        auto accepted = co_await acceptor.async_accept();
        if (!accepted) std::terminate();
        slot.emplace();
        if (loop.spawn(serve(loop, std::move(*accepted)), *slot) !=
            task_spawn_result::accepted) {
            std::terminate();
        }
    }
    for (auto& slot : handlers) (void)co_await *slot;
}

template<typename Server>
auto bench_accept_batches(const std::string& name, event_loop& loop,
                          tcp_acceptor& acceptor, std::uint16_t port,
                          Server server) -> void
{
    bench(name, [&](std::uint64_t iterations) {
        auto total = steady::duration::zero();
        for (std::uint64_t left = iterations; left > 0;) {
            const auto count = std::min(left, accept_batch);
            left -= count;
            std::vector<client_socket> clients;
            clients.reserve(count);
            for (std::uint64_t index = 0; index < count; ++index) {
                clients.emplace_back(port);
            }
            const auto start = steady::now();
            block_on(loop, server(loop, acceptor, count));
            total += steady::now() - start;
        }
        return total;
    });
}

// Multicore: one loop per thread. `reuse_port` gives each loop its own
// SO_REUSEPORT acceptor on one port; the kernel picks the listener for each
// connection, so loops are not assigned clients. `handoff` accepts on loop 0
// only and posts each accepted descriptor round-robin to the loops (loop 0
// serves its own share), as tokio's single accept loop spreads its tasks.
constexpr std::size_t accept_loop_count = 4;

enum class accept_mode {
    reuse_port_serial, reuse_port_spawn, handoff, handoff_others
};

struct accept_round {
    std::atomic<std::uint64_t> served {0};
    std::uint64_t total {0};
    std::atomic<std::size_t> finished {0};
    steady::time_point start;
};

// Untimed per-loop counters, written on the loop thread.
struct accept_loop_stats {
    std::uint64_t total {0};
    std::uint64_t batch {0};
    steady::time_point first;
    steady::time_point last;
};

auto serve_counted(event_loop& loop, unique_fd descriptor,
                   accept_round& round, accept_loop_stats& stats) -> task<void>
{
    if (stats.batch++ == 0) stats.first = steady::now();
    ++stats.total;
    (void)co_await serve(loop, std::move(descriptor));
    stats.last = steady::now();
    if (round.served.fetch_add(1, std::memory_order_acq_rel) + 1 ==
        round.total) {
        round.served.notify_one();
    }
}

class accept_loops {
public:
    accept_loops()
    {
        for (std::size_t index = 0; index < accept_loop_count; ++index) {
            threads_.emplace_back([this, index] { run(index); });
            while (slots_[index].acceptor.load(std::memory_order_acquire) ==
                   nullptr) {
                std::this_thread::yield();
            }
        }
    }
    ~accept_loops()
    {
        for (auto& slot : slots_) slot.loop->stop();
        for (auto& thread : threads_) thread.join();
    }
    accept_loops(const accept_loops&) = delete;
    auto operator=(const accept_loops&) -> accept_loops& = delete;

    [[nodiscard]] auto port(accept_mode mode) const noexcept -> std::uint16_t
    {
        return handing_off(mode) ? handoff_port_ : port_;
    }

    // Untimed setup is the caller's; this times start to the last reply.
    auto serve_batch(std::uint64_t count, accept_mode mode) -> steady::duration
    {
        accept_round round;
        round.total = count;
        for (auto& slot : slots_) slot.stats.batch = 0;
        const std::size_t accepting =
            handing_off(mode) ? 1 : accept_loop_count;
        round.start = steady::now();
        for (std::size_t index = 0; index < accepting; ++index) {
            auto& slot = slots_[index];
            post(slot, [this, &round, &slot, mode]() noexcept {
                slot.handle.reset();
                slot.handle.emplace();
                if (slot.loop->spawn(accept_until_cancelled(*slot.loop, slots_,
                                                            slot, round, mode),
                                     *slot.handle) !=
                    task_spawn_result::accepted) {
                    std::terminate();
                }
            });
        }
        for (auto served = round.served.load(std::memory_order_acquire);
             served != count;
             served = round.served.load(std::memory_order_acquire)) {
            round.served.wait(served, std::memory_order_acquire);
        }
        const auto end = steady::now();
        // Untimed: release the accepts still pending.
        for (std::size_t index = 0; index < accepting; ++index) {
            auto& slot = slots_[index];
            post(slot, [&slot]() noexcept { (void)slot.handle->cancel(); });
        }
        for (auto finished = round.finished.load(std::memory_order_acquire);
             finished != accepting;
             finished = round.finished.load(std::memory_order_acquire)) {
            round.finished.wait(finished, std::memory_order_acquire);
        }
        record(round, end);
        return end - round.start;
    }

    auto print_stats(const std::string& name) -> void
    {
        // Read after every round finished; the counters are loop-thread state.
        if (batches_ == 0) return;
        const auto batches = static_cast<double>(std::max<std::uint64_t>(batches_, 1));
        const auto us = [batches](double ns) { return ns / batches / 1000.0; };
        std::cout << "    " << name << " connections per loop:";
        for (auto& slot : slots_) {
            std::cout << ' ' << slot.stats.total;
            slot.stats.total = 0;
        }
        std::cout << "\n    per batch: max " << max_sum_ / batches << " min "
                  << min_sum_ / batches << " connections; first serve after "
                  << us(first_sum_) << " us (mean over loops), last serve at "
                  << us(last_max_sum_) << " us (slowest loop) / "
                  << us(last_mean_sum_) << " us (mean), batch end "
                  << us(end_sum_) << " us\n";
        batches_ = 0;
        max_sum_ = min_sum_ = 0;
        first_sum_ = last_max_sum_ = last_mean_sum_ = end_sum_ = 0;
    }

private:
    [[nodiscard]] static constexpr auto handing_off(accept_mode mode) noexcept
        -> bool
    {
        return mode == accept_mode::handoff ||
               mode == accept_mode::handoff_others;
    }

    struct loop_slot {
        event_loop* loop {nullptr};
        std::atomic<tcp_acceptor*> acceptor {nullptr};
        tcp_acceptor* handoff_acceptor {nullptr};
        void_slot handle;
        accept_loop_stats stats;
    };

    // Accepts until cancelled once the shared total has been served.
    static auto accept_until_cancelled(
        event_loop& loop, std::array<loop_slot, accept_loop_count>& slots,
        loop_slot& slot, accept_round& round, accept_mode mode) -> task<void>
    {
        tcp_acceptor& acceptor = handing_off(mode)
            ? *slot.handoff_acceptor : *slot.acceptor.load();
        std::size_t next = 0;
        for (;;) {
            auto connection = co_await acceptor.async_accept();
            if (!connection) break;
            if (mode == accept_mode::reuse_port_serial) {
                (void)co_await serve_counted(loop, std::move(*connection),
                                             round, slot.stats);
                continue;
            }
            // handoff_others leaves loop 0 accepting only.
            auto& target = mode == accept_mode::handoff
                ? slots[next++ % accept_loop_count]
                : mode == accept_mode::handoff_others
                ? slots[1 + next++ % (accept_loop_count - 1)] : slot;
            if (&target == &slot) {
                spawn_serve(slot, std::move(*connection), round);
                continue;
            }
            const int descriptor = connection->release();
            post(target, [&target, &round, descriptor]() noexcept {
                spawn_serve(target, unique_fd(descriptor), round);
            });
        }
        round.finished.fetch_add(1, std::memory_order_release);
        round.finished.notify_one();
    }

    static auto spawn_serve(loop_slot& slot, unique_fd descriptor,
                            accept_round& round) -> void
    {
        if (slot.loop->spawn(serve_counted(*slot.loop, std::move(descriptor),
                                           round, slot.stats)) !=
            task_spawn_result::accepted) {
            std::terminate();
        }
    }

    template<typename Function>
    static auto post(loop_slot& slot, Function function) -> void
    {
        if (!slot.loop->post(execution_task(std::move(function)))) {
            std::terminate();
        }
    }

    auto record(const accept_round& round, steady::time_point end) -> void
    {
        const auto ns = [&round](steady::time_point at) {
            return static_cast<double>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    at - round.start).count());
        };
        std::uint64_t most = 0;
        std::uint64_t least = round.total;
        double first = 0;
        double last_max = 0;
        double last_sum = 0;
        std::size_t active = 0;
        for (const auto& slot : slots_) {
            most = std::max(most, slot.stats.batch);
            least = std::min(least, slot.stats.batch);
            if (slot.stats.batch == 0) continue;
            ++active;
            first += ns(slot.stats.first);
            last_max = std::max(last_max, ns(slot.stats.last));
            last_sum += ns(slot.stats.last);
        }
        ++batches_;
        max_sum_ += static_cast<double>(most);
        min_sum_ += static_cast<double>(least);
        if (active != 0) {
            first_sum_ += first / static_cast<double>(active);
            last_mean_sum_ += last_sum / static_cast<double>(active);
        }
        last_max_sum_ += last_max;
        end_sum_ += ns(end);
    }

    auto run(std::size_t index) -> void
    {
        auto& slot = slots_[index];
        event_loop loop(bench_options());
        auto owned = std::make_unique<tcp_acceptor>(
            loop, ip_endpoint::loopback_v4(port_), true);
        tcp_acceptor* acceptor = owned.get();
        loop.add(std::move(owned));
        if (index == 0) {
            port_ = bound_port(acceptor->descriptor());
            auto handoff = std::make_unique<tcp_acceptor>(
                loop, ip_endpoint::loopback_v4());
            slot.handoff_acceptor = handoff.get();
            handoff_port_ = bound_port(handoff->descriptor());
            loop.add(std::move(handoff));
        }
        slot.loop = &loop;
        slot.acceptor.store(acceptor, std::memory_order_release);
        (void)loop.run();
        slot.handle.reset();
    }

    // Written by the first loop thread before its acceptor is published.
    std::uint16_t port_ {0};
    std::uint16_t handoff_port_ {0};
    std::array<loop_slot, accept_loop_count> slots_ {};
    std::vector<std::thread> threads_;
    std::uint64_t batches_ {0};
    double max_sum_ {0};
    double min_sum_ {0};
    double first_sum_ {0};
    double last_max_sum_ {0};
    double last_mean_sum_ {0};
    double end_sum_ {0};
};

auto bench_accept_loops(const std::string& name, accept_loops& loops,
                        accept_mode mode) -> void
{
    bench(name, [&](std::uint64_t iterations) {
        auto total = steady::duration::zero();
        for (std::uint64_t left = iterations; left > 0;) {
            const auto count = std::min(left, accept_batch);
            left -= count;
            std::vector<client_socket> clients;
            clients.reserve(count);
            for (std::uint64_t index = 0; index < count; ++index) {
                clients.emplace_back(loops.port(mode));
            }
            total += loops.serve_batch(count, mode);
        }
        return total;
    });
    loops.print_stats(name);
}

auto net_accept_group() -> void
{
    if (!group_enabled("net_accept")) return;
    event_loop loop(bench_options());
    auto owned = std::make_unique<tcp_acceptor>(loop, ip_endpoint::loopback_v4());
    tcp_acceptor& acceptor = *owned;
    const auto port = bound_port(acceptor.descriptor());
    loop.add(std::move(owned));

    bench("net_accept/block_on/current_thread", [&](std::uint64_t iterations) {
        auto total = steady::duration::zero();
        for (std::uint64_t index = 0; index < iterations; ++index) {
            client_socket client(port);
            const auto start = steady::now();
            block_on(loop, accept_one(loop, acceptor));
            total += steady::now() - start;
        }
        return total;
    });
    bench_accept_batches("net_accept/serial_task", loop, acceptor, port,
                         serial_task);
    bench_accept_batches("net_accept/task_per_conn", loop, acceptor, port,
                         task_per_conn);

    accept_loops loops;
    bench_accept_loops("net_accept/serial_task/loops_4", loops,
                       accept_mode::reuse_port_serial);
    bench_accept_loops("net_accept/task_per_conn/loops_4", loops,
                       accept_mode::reuse_port_spawn);
    bench_accept_loops("net_accept/task_per_conn/handoff_4", loops,
                       accept_mode::handoff);
    bench_accept_loops("net_accept/task_per_conn/handoff_1_to_3", loops,
                       accept_mode::handoff_others);
}

// ---------------------------------------------------------------------------

constexpr std::size_t fs_block_count = 1'000;
constexpr std::size_t fs_buffer_size = 4096;
alignas(64) std::array<std::byte, fs_buffer_size> fs_buffer;

auto read_dev_zero(event_loop& loop) -> task<void>
{
    auto file = co_await async_openat(loop, AT_FDCWD, "/dev/zero", O_RDONLY);
    if (!file) std::terminate();
    for (std::size_t index = 0; index < fs_block_count; ++index) {
        const auto count =
            co_await async_read_at(loop, file->get(), fs_buffer, 0);
        if (!count) std::terminate();
        if (*count == 0) break;
    }
}

auto fs_group() -> void
{
    if (!group_enabled("fs/")) return;
    event_loop loop(bench_options());
    bench("fs/async_read_buf", [&](std::uint64_t iterations) {
        const auto start = steady::now();
        for (std::uint64_t index = 0; index < iterations; ++index) {
            block_on(loop, read_dev_zero(loop));
        }
        return steady::now() - start;
    });
    bench("fs/sync_read", [&](std::uint64_t iterations) {
        const auto start = steady::now();
        for (std::uint64_t index = 0; index < iterations; ++index) {
            const int file = ::open("/dev/zero", O_RDONLY | O_CLOEXEC);
            if (file < 0) std::abort();
            for (std::size_t block = 0; block < fs_block_count; ++block) {
                if (::read(file, fs_buffer.data(), fs_buffer.size()) !=
                    static_cast<ssize_t>(fs_buffer.size())) {
                    std::abort();
                }
            }
            ::close(file);
        }
        return steady::now() - start;
    });
}

} // namespace

auto main(int argc, char* argv[]) -> int
{
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--quick") {
            config.warmup_seconds = 0.2;
            config.measure_seconds = 0.5;
            config.samples = 20;
        } else if (argument == "--list") {
            config.list_only = true;
        } else {
            config.filters.push_back(argument);
        }
    }

    rt_current_thread();
    spawn_group();
    time_now_group();
    time_timeout_group();
    spawn_blocking_group();
    remote_spawn_group();
    rt_multi_threaded_group();
    net_accept_group();
    fs_group();
    return 0;
}
