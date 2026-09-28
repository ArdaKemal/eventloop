#include "eventloop/file_io.h"
#include "eventloop/unique_fd.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <exception>
#include <fcntl.h>
#include <iostream>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>

using namespace eventloop;

namespace {

struct temporary_file {
    std::array<char, 32> path {"/tmp/eventloop-file-XXXXXX"};
    bool valid {false};

    temporary_file()
    {
        const int fd = ::mkstemp(path.data());
        if (fd >= 0) {
            valid = true;
            (void)::close(fd);
        }
    }

    ~temporary_file()
    {
        if (valid) (void)::unlink(path.data());
    }
};

auto roundtrip(event_loop& loop, std::string_view path, bool& passed)
    -> task<void>
{
    int descriptor = -1;
    {
        const auto opened = co_await async_openat(loop, AT_FDCWD, path, O_RDWR);
        if (!opened) {
            loop.stop();
            co_return;
        }

        descriptor = opened->get();
        constexpr std::array<std::byte, 5> input {
            std::byte {'h'}, std::byte {'e'}, std::byte {'l'}, std::byte {'l'},
            std::byte {'o'},
        };
        std::array<std::byte, 5> output {};
        const auto written = co_await async_write_at(loop, descriptor, input, 0);
        const auto read = co_await async_read_at(loop, descriptor, output, 0);
        passed = written && *written == input.size() && read &&
                 *read == output.size() && input == output;
    }
    passed = passed && ::fcntl(descriptor, F_GETFD) == -1 && errno == EBADF;
    loop.stop();
}

auto missing_file(event_loop& loop, bool& passed) -> task<void>
{
    const auto result = co_await async_openat(
        loop, AT_FDCWD, "/tmp/eventloop-file-absent-8573126", O_RDONLY);
    passed = !result && result.error().value() == ENOENT;
    loop.stop();
}

auto depth_probe(event_loop& loop, std::string_view path, int& completed,
                 int& rejected) -> task<void>
{
    const auto opened = co_await async_openat(loop, AT_FDCWD, path, O_RDONLY);
    if (!opened && opened.error().value() == EAGAIN) ++rejected;
    if (++completed == 3) loop.stop();
}

auto cancelled_open(event_loop& loop, std::string_view path, bool& passed)
    -> task<void>
{
    const auto opened = co_await async_openat(loop, AT_FDCWD, path, O_RDONLY);
    passed = !opened && opened.error().value() == ECANCELED;
}

auto cancelled_read(event_loop& loop, int descriptor, int& completed,
                    bool& passed) -> task<void>
{
    std::array<std::byte, 32> buffer {};
    const auto result = co_await async_read_at(loop, descriptor, buffer, 0);
    if (result || result.error().value() != ECANCELED) passed = false;
    ++completed;
}

auto foreign_file_awaiter(event_loop& owner, event_loop& foreign,
                          bool invalid_path) -> task<void>
{
    (void)owner;
    const auto path = invalid_path ? std::string_view {} : "/dev/null";
    (void)co_await async_openat(foreign, AT_FDCWD, path, O_RDONLY);
}

auto test_wrong_loop() -> bool
{
    for (const bool invalid_path : {false, true}) {
        const pid_t child = ::fork();
        if (child < 0) return false;
        if (child == 0) {
            std::set_terminate([] { std::_Exit(77); });
            event_loop owner;
            event_loop foreign;
            (void)owner.spawn(foreign_file_awaiter(owner, foreign,
                                                   invalid_path));
            std::_Exit(1);
        }
        int status = 0;
        if (::waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 77) return false;
    }
    return true;
}

auto test_roundtrip() -> bool
{
    temporary_file file;
    if (!file.valid) return false;
    event_loop loop;
    bool passed = false;
    if (loop.spawn(roundtrip(loop, file.path.data(), passed)) !=
        task_spawn_result::accepted) return false;
    if (loop.run() != event_loop_result::stopped) return false;
    return passed && loop.coroutine_statistics().live == 0;
}

auto test_errors() -> bool
{
    event_loop loop;
    bool passed = false;
    if (loop.spawn(missing_file(loop, passed)) != task_spawn_result::accepted) {
        return false;
    }
    return loop.run() == event_loop_result::stopped && passed;
}

auto test_depth() -> bool
{
    temporary_file file;
    if (!file.valid) return false;
    event_loop_options options;
    options.file_io_depth = 2;
    event_loop loop(options);
    int completed = 0;
    int rejected = 0;
    for (int i = 0; i != 3; ++i) {
        if (loop.spawn(depth_probe(loop, file.path.data(), completed,
                                   rejected)) != task_spawn_result::accepted) {
            return false;
        }
    }
    return loop.run() == event_loop_result::stopped && completed == 3 &&
           rejected == 1 && loop.coroutine_statistics().live == 0;
}

auto test_cancellation() -> bool
{
    temporary_file file;
    if (!file.valid) return false;
    event_loop loop;
    bool passed = false;
    if (loop.spawn(cancelled_open(loop, file.path.data(), passed)) !=
        task_spawn_result::accepted) return false;
    loop.shutdown(event_loop::clock::duration::zero());
    return loop.run() == event_loop_result::stopped && passed &&
           loop.coroutine_statistics().live == 0;
}

auto test_cancelled_read_batch() -> bool
{
    temporary_file file;
    if (!file.valid) return false;
    unique_fd descriptor(::open(file.path.data(), O_RDONLY | O_CLOEXEC));
    if (!descriptor) return false;
    event_loop_options options;
    options.file_io_depth = 128;
    options.coroutine_completion_capacity = 128;
    options.coroutine_frame_capacities.fill(128);
    event_loop loop(options);
    int completed = 0;
    bool passed = true;
    constexpr int operation_count = 64;
    for (int index = 0; index < operation_count; ++index) {
        if (loop.spawn(cancelled_read(loop, descriptor.get(), completed,
                                      passed)) != task_spawn_result::accepted) {
            loop.shutdown(event_loop::clock::duration::zero());
            (void)loop.run();
            return false;
        }
    }
    loop.shutdown(event_loop::clock::duration::zero());
    return loop.run() == event_loop_result::stopped && passed &&
           completed == operation_count &&
           loop.coroutine_statistics().live == 0;
}

} // namespace

int main()
{
    const bool passed = test_wrong_loop() && test_roundtrip() && test_errors() &&
                        test_depth() && test_cancellation() &&
                        test_cancelled_read_batch();
    if (!passed) std::cerr << "file I/O coroutine test failed\n";
    return passed ? 0 : 1;
}
