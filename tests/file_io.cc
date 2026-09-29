#include "eventloop/file_io.h"
#include "eventloop/unique_fd.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <string_view>
#ifdef _WIN32
#include <io.h>
#include <share.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace eventloop;

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

struct temporary_file {
    std::filesystem::path native_path;
    std::string path;
    bool valid {false};

    temporary_file()
    {
#ifdef _WIN32
        const auto directory = std::filesystem::temp_directory_path();
        int fd = -1;
        for (unsigned attempt = 0; attempt < 100 && fd == -1; ++attempt) {
            native_path = directory /
                ("eventloop-file-" + std::to_string(
                    event_loop::clock::now().time_since_epoch().count()) +
                 "-" + std::to_string(attempt));
            const auto error = ::_wsopen_s(
                &fd, native_path.c_str(),
                _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY,
                _SH_DENYNO, _S_IREAD | _S_IWRITE);
            if (error != 0 && error != EEXIST) break;
        }
#else
        native_path = std::filesystem::temp_directory_path() /
                      "eventloop-file-XXXXXX";
        path = native_path.string();
        const int fd = ::mkstemp(path.data());
        if (fd >= 0) native_path = path;
#endif
        if (fd >= 0) {
            valid = true;
#ifdef _WIN32
            path = native_path.string();
            (void)::_close(fd);
#else
            (void)::close(fd);
#endif
        }
    }

    ~temporary_file()
    {
        if (valid) {
            std::error_code ignored;
            std::filesystem::remove(native_path, ignored);
        }
    }
};

[[nodiscard]] auto closed_descriptor(int descriptor) -> bool
{
#ifdef _WIN32
    const auto previous = ::_set_thread_local_invalid_parameter_handler(
        [](const wchar_t*, const wchar_t*, const wchar_t*, unsigned,
           uintptr_t) noexcept {});
    const auto handle = ::_get_osfhandle(descriptor);
    ::_set_thread_local_invalid_parameter_handler(previous);
    return handle == -1 && errno == EBADF;
#else
    return ::fcntl(descriptor, F_GETFD) == -1 && errno == EBADF;
#endif
}

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
    passed = passed && closed_descriptor(descriptor);
    loop.stop();
}

auto missing_file(event_loop& loop, bool& passed) -> task<void>
{
    const auto result = co_await async_openat(
        loop, AT_FDCWD, "eventloop-file-absent-8573126", O_RDONLY);
    passed = !result && result.error().value() == ENOENT;
    loop.stop();
}

auto relative_open(event_loop& loop, int directory, std::string_view name,
                   bool& passed) -> task<void>
{
    const auto opened = co_await async_openat(loop, directory, name, O_RDONLY);
    if (opened) {
        std::array<std::byte, 1> buffer {};
        const auto read = co_await async_read_at(loop, opened->get(), buffer, 0);
        passed = read && *read == 0;
    }
    loop.stop();
}

auto invalid_descriptor(event_loop& loop, bool& passed) -> task<void>
{
    std::array<std::byte, 1> buffer {};
    const auto read = co_await async_read_at(loop, -1, buffer, 0);
    const auto write = co_await async_write_at(loop, -1,
        std::span<const std::byte>(buffer), 0);
    const auto empty_read = co_await async_read_at(loop, -1,
        std::span<std::byte> {}, 0);
    const auto empty_write = co_await async_write_at(loop, -1,
        std::span<const std::byte> {}, 0);
    passed = !read && read.error().value() == EBADF &&
             !write && write.error().value() == EBADF &&
             !empty_read && empty_read.error().value() == EBADF &&
             !empty_write && empty_write.error().value() == EBADF;
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
#ifdef _WIN32
    const auto path = invalid_path ? std::string_view {} : ".";
#else
    const auto path = invalid_path ? std::string_view {} : "/dev/null";
#endif
    (void)co_await async_openat(foreign, AT_FDCWD, path, O_RDONLY);
}

#ifndef _WIN32
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
#else
auto test_wrong_loop() -> bool
{
    return child_exits_77(L"--wrong-loop-file") &&
           child_exits_77(L"--wrong-loop-invalid-path");
}
#endif

auto test_roundtrip() -> bool
{
    temporary_file file;
    if (!file.valid) return false;
    event_loop loop;
    bool passed = false;
    if (loop.spawn(roundtrip(loop, file.path, passed)) !=
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

auto test_relative_open() -> bool
{
    temporary_file file;
    if (!file.valid) return false;
#ifdef _WIN32
    const auto parent = ::CreateFileW(
        file.native_path.parent_path().c_str(),
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (parent == INVALID_HANDLE_VALUE) return false;
    const int opened = ::_open_osfhandle(reinterpret_cast<intptr_t>(parent),
                                        _O_RDONLY | _O_BINARY);
    if (opened == -1) {
        (void)::CloseHandle(parent);
        return false;
    }
#else
    const int opened = ::open(file.native_path.parent_path().c_str(),
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
#endif
#ifdef _WIN32
    unique_fd directory(opened, unique_fd::kind::file);
#else
    unique_fd directory(opened);
#endif
    if (!directory) return false;
    event_loop loop;
    bool passed = false;
    const auto name = file.native_path.filename().string();
    if (loop.spawn(relative_open(loop, static_cast<int>(directory.get()),
                                 name, passed)) != task_spawn_result::accepted) {
        return false;
    }
    return loop.run() == event_loop_result::stopped && passed &&
           loop.coroutine_statistics().live == 0;
}

auto test_invalid_descriptor() -> bool
{
    event_loop loop;
    bool passed = false;
    if (loop.spawn(invalid_descriptor(loop, passed)) !=
        task_spawn_result::accepted) return false;
    return loop.run() == event_loop_result::stopped && passed &&
           loop.coroutine_statistics().live == 0;
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
        if (loop.spawn(depth_probe(loop, file.path, completed,
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
    if (loop.spawn(cancelled_open(loop, file.path, passed)) !=
        task_spawn_result::accepted) return false;
    loop.shutdown(event_loop::clock::duration::zero());
    return loop.run() == event_loop_result::stopped && passed &&
           loop.coroutine_statistics().live == 0;
}

auto test_cancelled_read_batch() -> bool
{
    temporary_file file;
    if (!file.valid) return false;
#ifdef _WIN32
    int opened = -1;
    if (::_wsopen_s(&opened, file.native_path.c_str(),
                    _O_RDONLY | _O_BINARY, _SH_DENYNO, 0) != 0) return false;
    unique_fd descriptor(opened, unique_fd::kind::file);
#else
    unique_fd descriptor(::open(file.path.c_str(), O_RDONLY | O_CLOEXEC));
#endif
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

int main(int argc, char** argv)
{
#ifdef _WIN32
    if (argc == 2) {
        const std::string_view mode = argv[1];
        if (mode == "--wrong-loop-file" || mode == "--wrong-loop-invalid-path") {
            std::set_terminate([] { std::_Exit(77); });
            event_loop owner;
            event_loop foreign;
            (void)owner.spawn(foreign_file_awaiter(
                owner, foreign, mode == "--wrong-loop-invalid-path"));
            return 1;
        }
        return 1;
    }
#endif
    const bool passed =
                        test_wrong_loop() &&
                        test_roundtrip() && test_errors() &&
                        test_relative_open() && test_invalid_descriptor() &&
                        test_depth() && test_cancellation() &&
                        test_cancelled_read_batch();
    if (!passed) std::cerr << "file I/O coroutine test failed\n";
    return passed ? 0 : 1;
}
