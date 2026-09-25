#include "eventloop/file_io.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <string_view>
#include <system_error>
#include <unistd.h>

#if defined(EVENTLOOP_TEST_HAS_LIBURING)
#include <liburing.h>

namespace {
int injected_ring_submit_result = std::numeric_limits<int>::max();
int injected_ring_submissions = 0;
}

extern "C" auto __real_io_uring_submit(io_uring* ring) -> int;

extern "C" auto __wrap_io_uring_submit(io_uring* ring) -> int
{
    if (injected_ring_submit_result != std::numeric_limits<int>::max()) {
        const int result = injected_ring_submit_result;
        injected_ring_submit_result = std::numeric_limits<int>::max();
        ++injected_ring_submissions;
        return result;
    }
    return __real_io_uring_submit(ring);
}
#endif

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
    const auto opened = co_await async_openat(loop, AT_FDCWD, path, O_RDWR);
    if (!opened) {
        loop.stop();
        co_return;
    }

    constexpr std::array<std::byte, 5> input {
        std::byte {'h'}, std::byte {'e'}, std::byte {'l'}, std::byte {'l'},
        std::byte {'o'},
    };
    std::array<std::byte, 5> output {};
    const auto written = co_await async_write_at(loop, *opened, input, 0);
    const auto read = co_await async_read_at(loop, *opened, output, 0);
    passed = written && *written == input.size() && read &&
             *read == output.size() && input == output;
    (void)::close(*opened);
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
    if (opened) (void)::close(*opened);
    if (!opened && opened.error().value() == EAGAIN) ++rejected;
    if (++completed == 3) loop.stop();
}

auto cancelled_open(event_loop& loop, std::string_view path, bool& passed)
    -> task<void>
{
    const auto opened = co_await async_openat(loop, AT_FDCWD, path, O_RDONLY);
    if (opened) (void)::close(*opened);
    passed = !opened && opened.error().value() == ECANCELED;
}

auto denied_submission(event_loop& loop, bool& passed) -> task<void>
{
    const auto result = co_await async_openat(loop, AT_FDCWD, "/dev/null",
                                              O_RDONLY);
    if (result) (void)::close(*result);
    passed = !result && result.error().value() == EPERM;
    loop.stop();
}

#if defined(EVENTLOOP_TEST_HAS_LIBURING)
auto recovered_submission(event_loop& loop, bool& passed) -> task<void>
{
    const auto first = co_await async_openat(loop, AT_FDCWD, "/dev/null",
                                             O_RDONLY);
    if (first) (void)::close(*first);
    const auto second = co_await async_openat(loop, AT_FDCWD, "/dev/null",
                                              O_RDONLY);
    if (second) (void)::close(*second);
    passed = !first && first.error().value() == EAGAIN && second.has_value();
    loop.stop();
}

auto ready_batch_open(event_loop& loop, int& completed, bool& passed)
    -> task<void>
{
    const auto result = co_await async_openat(
        loop, AT_FDCWD, "/tmp/eventloop-file-absent-8573126", O_RDONLY);
    if (result || result.error().value() != ENOENT) passed = false;
    if (result) (void)::close(*result);
    if (++completed == 96) loop.stop();
}

auto test_ring_ready_batch() -> bool
{
    const pid_t child = ::fork();
    if (child < 0) return false;
    if (child == 0) {
        ::alarm(3);
        event_loop_options options;
        options.file_backend = file_io_backend::io_uring;
        options.file_io_depth = 128;
        options.coroutine_frame_capacities.fill(128);
        event_loop loop(options);
        int completed = 0;
        bool passed = true;
        for (int index = 0; index < 96; ++index) {
            if (loop.spawn(ready_batch_open(loop, completed, passed)) !=
                task_spawn_result::accepted) {
                ::_exit(1);
            }
        }
        ::usleep(20000);
        const bool drained = loop.run() == event_loop_result::stopped &&
                             completed == 96 && passed &&
                             loop.coroutine_statistics().live == 0;
        ::_exit(drained ? 0 : 1);
    }
    int status = 0;
    return ::waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0;
}

auto test_ring_submit_recovery(int injected_result) -> bool
{
    event_loop_options options;
    options.file_backend = file_io_backend::io_uring;
    event_loop loop(options);
    bool passed = false;
    const int before = injected_ring_submissions;
    injected_ring_submit_result = injected_result;
    if (loop.spawn(recovered_submission(loop, passed)) !=
        task_spawn_result::accepted) return false;
    const auto stopped = loop.run();
    injected_ring_submit_result = std::numeric_limits<int>::max();
    return stopped == event_loop_result::stopped && passed &&
           injected_ring_submissions == before + 1 &&
           loop.coroutine_statistics().live == 0;
}
#endif

auto test_ring_submit_error_in_child() -> bool
{
    const pid_t child = ::fork();
    if (child < 0) return false;
    if (child == 0) {
        int outcome = 1;
        try {
            event_loop_options options;
            options.file_backend = file_io_backend::io_uring;
            event_loop loop(options);
            sock_filter filter[] {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                         offsetof(seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_enter,
                         0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            };
            sock_fprog program {static_cast<unsigned short>(
                                    std::size(filter)), filter};
            if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
                ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
                outcome = 77;
            } else {
                bool passed = false;
                if (loop.spawn(denied_submission(loop, passed)) ==
                        task_spawn_result::accepted &&
                    loop.run() == event_loop_result::stopped && passed &&
                    loop.coroutine_statistics().live == 0) {
                    outcome = 0;
                }
            }
        } catch (const std::system_error& error) {
            if (error.code().value() == EPERM ||
                error.code().value() == EACCES ||
                error.code().value() == ENOSYS) outcome = 77;
        } catch (const std::invalid_argument&) {
            outcome = 77;
        }
        ::_exit(outcome);
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child || !WIFEXITED(status)) {
        return false;
    }
    if (WEXITSTATUS(status) == 77) {
        std::cerr << "io_uring submission failure injection unavailable\n";
    }
    return WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 77;
}

auto test_roundtrip(file_io_backend backend) -> bool
{
    temporary_file file;
    if (!file.valid) return false;
    event_loop_options options;
    options.file_backend = backend;
    event_loop loop(options);
    const auto active = loop.file_backend();
    if (backend == file_io_backend::executor &&
        active != active_file_io_backend::executor) return false;
    bool passed = false;
    if (loop.spawn(roundtrip(loop, file.path.data(), passed)) !=
        task_spawn_result::accepted) return false;
    if (loop.run() != event_loop_result::stopped) return false;
    return passed && loop.coroutine_statistics().live == 0;
}

auto test_errors(file_io_backend backend) -> bool
{
    event_loop_options options;
    options.file_backend = backend;
    event_loop loop(options);
    bool passed = false;
    if (loop.spawn(missing_file(loop, passed)) != task_spawn_result::accepted) {
        return false;
    }
    return loop.run() == event_loop_result::stopped && passed;
}

auto test_depth(file_io_backend backend) -> bool
{
    temporary_file file;
    if (!file.valid) return false;
    event_loop_options options;
    options.file_backend = backend;
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

auto test_cancellation(file_io_backend backend) -> bool
{
    temporary_file file;
    if (!file.valid) return false;
    event_loop_options options;
    options.file_backend = backend;
    event_loop loop(options);
    bool passed = false;
    if (loop.spawn(cancelled_open(loop, file.path.data(), passed)) !=
        task_spawn_result::accepted) return false;
    loop.shutdown(event_loop::clock::duration::zero());
    return loop.run() == event_loop_result::stopped && passed &&
           loop.coroutine_statistics().live == 0;
}

} // namespace

int main()
{
    bool ring_passed = true;
    try {
        ring_passed =
#if defined(EVENTLOOP_TEST_HAS_LIBURING)
                      test_ring_submit_recovery(-EAGAIN) &&
                      test_ring_submit_recovery(0) &&
                      test_ring_ready_batch() &&
#endif
                      test_roundtrip(file_io_backend::io_uring) &&
                      test_errors(file_io_backend::io_uring) &&
                      test_depth(file_io_backend::io_uring) &&
                      test_cancellation(file_io_backend::io_uring);
    } catch (const std::system_error& error) {
        if (error.code().value() != EPERM && error.code().value() != EACCES &&
            error.code().value() != ENOSYS &&
            error.code().value() != EOPNOTSUPP) {
            throw;
        }
        std::cerr << "io_uring unavailable in this environment: "
                  << error.code().message() << '\n';
    } catch (const std::invalid_argument&) {
        std::cerr << "io_uring unavailable in this build\n";
    }
    const bool passed = ring_passed && test_ring_submit_error_in_child() &&
                        test_roundtrip(file_io_backend::executor) &&
                        test_roundtrip(file_io_backend::automatic) &&
                        test_errors(file_io_backend::executor) &&
                        test_depth(file_io_backend::executor) &&
                        test_cancellation(file_io_backend::executor);
    if (!passed) std::cerr << "file I/O coroutine test failed\n";
    return passed ? 0 : 1;
}
