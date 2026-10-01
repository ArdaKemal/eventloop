#include "eventloop/event_loop.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <thread>
#include <utility>
#include <vector>

using namespace eventloop;

namespace {

constexpr std::size_t construction_iterations = 20'000;
constexpr std::size_t post_iterations = 1'000'000;
constexpr std::size_t cross_thread_iterations = 100'000;

template<typename Function>
auto measure(const char* name, std::size_t operations, Function&& function) -> void
{
    const auto started = std::chrono::steady_clock::now();
    function();
    const auto elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started);
    std::cout << name << ": " << operations << " operations in "
              << elapsed.count() << " s ("
              << static_cast<double>(operations) / elapsed.count()
              << " operations/s)\n";
}

struct post_chain {
    auto run() noexcept -> void
    {
        ++completed;
        if (completed == target) {
            loop.stop();
            return;
        }
        if (!loop.post(execution_task([this]() noexcept { run(); }))) {
            std::terminate();
        }
    }

    event_loop& loop;
    std::size_t target;
    std::size_t completed {0};
};

auto construction() -> void
{
    measure("event-loop construct/destroy", construction_iterations,
            [] {
                for (std::size_t index = 0; index < construction_iterations;
                     ++index) {
                    event_loop loop;
                }
            });
}

auto post_round_trip() -> void
{
    event_loop loop;
    post_chain chain {loop, post_iterations};
    if (!loop.post(execution_task([&chain]() noexcept { chain.run(); }))) {
        std::terminate();
    }
    measure("event-loop post round-trip", post_iterations,
            [&loop] { (void)loop.run(); });
}

auto cross_thread_post() -> void
{
    using clock = std::chrono::steady_clock;
    event_loop loop;
    // Allocate a fixed number of samples before starting either measurement.
    std::vector<clock::duration> latency(cross_thread_iterations);
    clock::time_point started;
    clock::time_point finished;
    std::size_t completed = 0;
    std::size_t queue_full_retries = 0;
    std::thread producer([&] {
        // Let the owner enter its blocking poll before the first wakeup.
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        started = clock::now();
        for (std::size_t index = 0; index < cross_thread_iterations; ++index) {
            const auto posted = clock::now();
            execution_task task([&, index, posted]() noexcept {
                const auto dispatched = clock::now();
                latency[index] = dispatched - posted;
                if (++completed == cross_thread_iterations) {
                    finished = dispatched;
                    loop.stop();
                }
            });
            // post() preserves a named task on failure. Retry it without
            // dropping work; the owner keeps draining while we yield.
            while (!loop.post(std::move(task))) {
                ++queue_full_retries;
                std::this_thread::yield();
            }
        }
    });
    (void)loop.run();
    // Even the final callback may precede the producer's return from post().
    // Join before accessing producer state or destroying the loop.
    producer.join();
    if (completed != cross_thread_iterations) std::terminate();
    const auto elapsed = std::chrono::duration<double>(finished - started);
    const auto zero_samples = std::count(latency.begin(), latency.end(),
                                         clock::duration::zero());
    std::sort(latency.begin(), latency.end());
    const auto nanoseconds = [](clock::duration duration) {
        return std::chrono::duration<double, std::nano>(duration).count();
    };
    // Nearest-rank percentiles; queue-full retry time is included in latency.
    std::cout << "event-loop cross-thread post/wake: " << completed
              << " operations in " << elapsed.count() << " s ("
              << static_cast<double>(completed) / elapsed.count()
              << " operations/s), post-to-dispatch min "
              << nanoseconds(latency.front()) << " ns, p50 "
              << nanoseconds(latency[cross_thread_iterations / 2 - 1])
              << " ns, p99 "
              << nanoseconds(latency[cross_thread_iterations * 99 / 100 - 1])
              << " ns, zero-duration samples " << zero_samples << '/' << completed
              << ", queue-full retries " << queue_full_retries
              << " (latency includes retry time)\n";
}

auto clock_observations() -> void
{
    using clock = std::chrono::steady_clock;
    constexpr std::size_t reads = 100'000;
    auto minimum_step = clock::duration::max();
    std::size_t equal_reads = 0;
    std::size_t backwards_reads = 0;
    auto previous = clock::now();
    for (std::size_t index = 0; index < reads; ++index) {
        const auto current = clock::now();
        const auto step = current - previous;
        if (step > clock::duration::zero()) {
            minimum_step = std::min(minimum_step, step);
        } else if (step == clock::duration::zero()) {
            ++equal_reads;
        } else {
            ++backwards_reads;
        }
        previous = current;
    }
    std::cout << "steady_clock: nominal tick "
              << std::chrono::duration<double, std::nano>(clock::duration(1)).count()
              << " ns, minimum observed positive step ";
    if (minimum_step == clock::duration::max()) {
        std::cout << "none";
    } else {
        std::cout << std::chrono::duration<double, std::nano>(minimum_step).count()
                  << " ns";
    }
    std::cout << ", equal consecutive reads " << equal_reads << '/' << reads
              << ", backwards reads " << backwards_reads
              << " (observed steps are not a resolution guarantee; zero latency"
                 " means equal clock readings)\n";
}

} // namespace

auto main() -> int
{
    construction();
    post_round_trip();
    cross_thread_post();
    clock_observations();
    return 0;
}
