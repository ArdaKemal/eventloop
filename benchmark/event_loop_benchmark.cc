#include "eventloop/event_loop.h"

#include <chrono>
#include <cstddef>
#include <iostream>

namespace {

constexpr std::size_t construction_iterations = 20'000;
constexpr std::size_t post_iterations = 1'000'000;

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

} // namespace

auto main() -> int
{
    construction();
    post_round_trip();
    return 0;
}
