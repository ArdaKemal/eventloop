#include "eventloop/file_io.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <io.h>
#include <share.h>
#include <sys/stat.h>
#else
#include <unistd.h>
#endif

using namespace eventloop;

namespace {

using clock = std::chrono::steady_clock;
constexpr std::size_t operation_count = 100'000;
constexpr std::size_t concurrent_tasks = 16;

struct temporary_file {
    std::filesystem::path path;
    int descriptor {-1};

    temporary_file()
    {
#ifdef _WIN32
        const auto directory = std::filesystem::temp_directory_path();
        const auto seed = clock::now().time_since_epoch().count();
        for (unsigned attempt = 0; attempt < 100 && descriptor == -1;
             ++attempt) {
            path = directory /
                   ("eventloop-file-bench-" + std::to_string(seed) + "-" +
                    std::to_string(attempt));
            const auto error = ::_wsopen_s(
                &descriptor, path.c_str(),
                _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY,
                _SH_DENYNO, _S_IREAD | _S_IWRITE);
            if (error != 0 && error != EEXIST) {
                throw std::system_error(error, std::generic_category(),
                                        "create benchmark file");
            }
        }
#else
        path = "/tmp/eventloop-file-bench-XXXXXX";
        auto native_path = path.string();
        descriptor = ::mkstemp(native_path.data());
        if (descriptor != -1) path = native_path;
#endif
        if (descriptor == -1) {
            throw std::system_error(errno, std::generic_category(),
                                    "create benchmark file");
        }
        std::array<std::byte, 4096> block {};
#ifdef _WIN32
        const auto written = ::_write(descriptor, block.data(),
                                     static_cast<unsigned int>(block.size()));
#else
        const auto written = ::write(descriptor, block.data(), block.size());
#endif
        if (written != static_cast<decltype(written)>(block.size())) {
            const auto error = errno;
            close_descriptor();
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
            throw std::system_error(error, std::generic_category(), "write");
        }
    }

    ~temporary_file()
    {
        close_descriptor();
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

private:
    auto close_descriptor() noexcept -> void
    {
        if (descriptor == -1) return;
#ifdef _WIN32
        (void)::_close(descriptor);
#else
        (void)::close(descriptor);
#endif
        descriptor = -1;
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
