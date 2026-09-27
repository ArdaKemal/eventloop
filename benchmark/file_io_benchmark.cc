#include "eventloop/file_io.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <span>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace {

using clock = std::chrono::steady_clock;
constexpr std::size_t operation_count = 100'000;
constexpr std::size_t concurrent_tasks = 16;

struct temporary_file {
    std::array<char, 40> path {"/tmp/eventloop-file-bench-XXXXXX"};
    int descriptor {-1};

    temporary_file()
    {
        descriptor = ::mkstemp(path.data());
        if (descriptor == -1) {
            throw std::system_error(errno, std::generic_category(), "mkstemp");
        }
        std::array<std::byte, 4096> block {};
        if (::write(descriptor, block.data(), block.size()) !=
            static_cast<ssize_t>(block.size())) {
            throw std::system_error(errno, std::generic_category(), "write");
        }
    }

    ~temporary_file()
    {
        if (descriptor != -1) (void)::close(descriptor);
        (void)::unlink(path.data());
    }
};

struct measurements {
    event_loop& loop;
    int descriptor;
    std::array<std::array<std::byte, 4096>, concurrent_tasks> buffers {};
    std::vector<double> operation_us;
    std::vector<double> timer_lateness_us;
    std::size_t next {0};
    std::size_t completed {0};
    bool failed {false};
};

auto read_task(event_loop& loop, measurements& data, std::size_t slot)
    -> task<void>
{
    auto& buffer = data.buffers[slot];
    while (data.next < operation_count) {
        const std::size_t index = data.next++;
        const auto start = clock::now();
        const auto result = co_await async_read_at(loop, data.descriptor,
                                                   buffer, 0);
        data.operation_us[index] = std::chrono::duration<double, std::micro>(
            clock::now() - start).count();
        if (!result || *result != buffer.size()) data.failed = true;
        if (++data.completed == operation_count) loop.shutdown({});
    }
}

auto timer_probe(event_loop& loop, measurements& data) -> task<void>
{
    while (true) {
        const auto due = clock::now() + std::chrono::milliseconds {1};
        const auto result = co_await sleep_for(loop, due - clock::now());
        if (result != timer_wait_result::expired) co_return;
        data.timer_lateness_us.push_back(
            std::chrono::duration<double, std::micro>(clock::now() - due)
                .count());
    }
}

auto percentile(std::vector<double>& values, double fraction) -> double
{
    if (values.empty()) return 0.0;
    std::sort(values.begin(), values.end());
    const auto index = static_cast<std::size_t>(
        fraction * static_cast<double>(values.size() - 1));
    return values[index];
}

auto run_case(int descriptor) -> bool
{
    event_loop_options options;
    options.coroutine_frame_capacities.fill(32);
    event_loop loop(options);
    measurements data {.loop = loop,
                       .descriptor = descriptor,
                       .buffers = {},
                       .operation_us = {},
                       .timer_lateness_us = {}};
    data.operation_us.resize(operation_count);
    data.timer_lateness_us.reserve(10'000);
    if (loop.spawn(timer_probe(loop, data)) != task_spawn_result::accepted) {
        return false;
    }
    const auto start = clock::now();
    for (std::size_t i = 0; i < concurrent_tasks; ++i) {
        if (loop.spawn(read_task(loop, data, i)) !=
            task_spawn_result::accepted) {
            loop.shutdown({});
            (void)loop.run();
            return false;
        }
    }
    (void)loop.run();
    const double seconds = std::chrono::duration<double>(clock::now() - start)
                               .count();
    std::cout << "executor: " << std::fixed << std::setprecision(1)
              << static_cast<double>(data.completed) / seconds << " ops/s, "
              << "read p50/p99 " << percentile(data.operation_us, 0.5)
              << "/" << percentile(data.operation_us, 0.99) << " us, "
              << "timer lateness p99 "
              << percentile(data.timer_lateness_us, 0.99) << " us ("
              << data.timer_lateness_us.size() << " samples)\n";
    return !data.failed && data.completed == operation_count &&
           loop.coroutine_statistics().live == 0;
}

} // namespace

auto main() -> int
{
    temporary_file file;
    return run_case(file.descriptor) ? 0 : 1;
}
