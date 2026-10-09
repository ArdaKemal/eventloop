#include "http/open_file_cache.h"

#include <array>
#include <chrono>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

using namespace eventloop;
using namespace eventloop::http::detail;
using namespace std::chrono_literals;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "open file cache: " << message << '\n';
    std::exit(1);
}

auto write_file(const std::filesystem::path& path, std::string_view contents) -> void
{
    std::ofstream(path, std::ios::binary | std::ios::trunc) << contents;
}

// Replaces a file atomically, as a deployment would, with a distinct
// modification time.
auto rewrite(const std::filesystem::path& path, std::string_view contents, int seconds) -> void
{
    auto temporary = path;
    temporary += ".new";
    write_file(temporary, contents);
    const std::array<timespec, 2> times {{{seconds, 0}, {seconds, 0}}};
    check(::utimensat(AT_FDCWD, temporary.c_str(), times.data(), 0) == 0, "set modification time");
    std::filesystem::rename(temporary, path);
}

auto contents(const static_file& file, std::size_t size) -> std::string
{
    std::string result(size, '\0');
    check(read_file_at(file.get(), 0, std::as_writable_bytes(std::span {result})),
          "read cached file");
    return result;
}

} // namespace

auto main(int argc, char* argv[]) -> int
{
    if (argc == 2) {
        const std::string_view error(argv[1]);
        check(error == "ENOSYS" || error == "EPERM", "unknown syscall filter");
#ifdef SYS_openat2
        // Exercise the same traversal/cache tests with the Linux fast path
        // unavailable or denied by a sandbox, without production test hooks.
        std::array<sock_filter, 4> filter {{
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat2, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO |
                static_cast<unsigned int>(error == "ENOSYS" ? ENOSYS : EPERM)),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        }};
        sock_fprog program {static_cast<unsigned short>(filter.size()), filter.data()};
        check(::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
              ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0,
              "install openat2 filter");
#endif
    }
    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-open-file-cache-" + std::to_string(::getpid()));
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory / "www" / "assets");
    const auto www = directory / "www";
    write_file(www / "assets" / "app.js", "first");
    write_file(www / "other.txt", "other");
    write_file(www / "third.txt", "third");
    write_file(directory / "secret.txt", "secret");
    const unique_fd root(::open(www.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    check(static_cast<bool>(root), "open root");
    const auto start = std::chrono::steady_clock::now();

    {
        std::filesystem::create_directory_symlink("assets", www / "linked-assets");
        std::filesystem::create_directory_symlink(directory, www / "escape");
        std::filesystem::create_symlink("assets/app.js", www / "app-link.js");
        open_file_cache cache(4);
        for (auto* files : {static_cast<open_file_cache*>(nullptr), &cache}) {
            for (std::string_view target : {"/assets/app.js", "//assets//./app.js"}) {
                auto file = open_static(root.get(), files, target);
                check(file && contents(file->file, 5) == "first", "nested path");
                check((::fcntl(file->file.get(), F_GETFD) & FD_CLOEXEC) != 0,
                      "opened file is close-on-exec");
            }
            for (std::string_view target : {"/", "///", "/assets//"}) {
                auto folder = open_static(root.get(), files, target);
                check(folder && folder->info.kind == file_info::type::directory,
                      "root and trailing directory slashes");
            }
            for (std::string_view target : {"/linked-assets/app.js", "/app-link.js",
                    "/escape/secret.txt", "/assets/app.js/", "/assets/app.js/child",
                    "/missing", "/assets/%2e%2e/secret.txt"}) {
                check(!open_static(root.get(), files, target), "unsafe or invalid path");
            }
            // A full decode buffer cannot be NUL-terminated for openat2;
            // retain the component walk's ability to open this valid path.
            const std::string longest = "/assets/" + std::string(4083, '/') + "app.js";
            auto file = open_static(root.get(), files, longest);
            check(file && contents(file->file, 5) == "first", "maximum decoded path");
        }
    }

    {
        open_file_cache cache(4);
        // A miss opens and caches; a hit returns the same pinned descriptor.
        auto first = cache.open(root.get(), "/assets/app.js", start);
        check(first && first->file.cached() && first->info.size == 5, "miss is cached");
        auto second = cache.open(root.get(), "/assets/%61pp.js?v=1", start + 100ms);
        check(second && second->file.cached() && second->file.get() == first->file.get(),
              "decoded path hits the same entry");
        first->file.reset();
        second->file.reset();

        // Within the revalidation window a replaced file is still served as
        // before; afterwards the entry is replaced.
        rewrite(www / "assets" / "app.js", "second!", 1000000);
        auto stale = cache.open(root.get(), "/assets/app.js", start + 900ms);
        check(stale && stale->info.size == 5 && contents(stale->file, 5) == "first",
              "change is invisible within the window");
        auto fresh = cache.open(root.get(), "/assets/app.js", start + 1100ms);
        check(fresh && fresh->info.size == 7 && contents(fresh->file, 7) == "second!",
              "change is visible after the window");
        // The pinned stale descriptor stays readable after replacement.
        check(contents(stale->file, 5) == "first", "pinned descriptor survives replacement");
        stale->file.reset();
        fresh->file.reset();

        // An in-place edit keeps the old metadata within the window, while
        // the shared descriptor already reads the new bytes.
        write_file(www / "assets" / "app.js", "third!!");
        auto edited = cache.open(root.get(), "/assets/app.js", start + 1500ms);
        check(edited && edited->info.size == 7 && contents(edited->file, 7) == "third!!",
              "in-place edit within the window");
        edited->file.reset();

        // A removed file is served until the next check, then is not found.
        check(cache.open(root.get(), "/other.txt", start + 1100ms).has_value(), "cache other");
        std::filesystem::remove(www / "other.txt");
        auto removed = cache.open(root.get(), "/other.txt", start + 1500ms);
        check(removed && contents(removed->file, 5) == "other", "removed file within window");
        removed->file.reset();
        auto gone = cache.open(root.get(), "/other.txt", start + 2200ms);
        check(!gone && gone.error() == resource_error::open_failed, "removed file after window");

        // A file replaced by a symbolic link is never followed.
        check(cache.open(root.get(), "/third.txt", start + 2200ms).has_value(), "cache third");
        std::filesystem::remove(www / "third.txt");
        std::filesystem::create_symlink(directory / "secret.txt", www / "third.txt");
        auto swapped = cache.open(root.get(), "/third.txt", start + 2500ms);
        check(swapped && contents(swapped->file, 5) == "third", "old file within window");
        swapped->file.reset();
        auto link = cache.open(root.get(), "/third.txt", start + 3300ms);
        check(!link, "symbolic link is not served");

        // Directories and over-long paths bypass the cache; errors pass through.
        auto folder = cache.open(root.get(), "/assets/", start + 3300ms);
        check(folder && !folder->file.cached() &&
              folder->info.kind == file_info::type::directory, "directory is uncached");
        const std::string long_target = "/" + std::string(300, 'x');
        auto long_path = cache.open(root.get(), long_target, start + 3300ms);
        check(!long_path && long_path.error() == resource_error::open_failed,
              "long path is opened uncached");
        auto invalid = cache.open(root.get(), "/../secret.txt", start + 3300ms);
        check(!invalid && invalid.error() == resource_error::invalid_target, "invalid target");
    }

    {
        // Least recently used entries are evicted first: an evicted file is
        // reopened, so its change shows at once, while a cached one is stale.
        write_file(www / "a.txt", "aaaa");
        write_file(www / "b.txt", "bbbb");
        write_file(www / "c.txt", "cccc");
        open_file_cache cache(2);
        check(cache.open(root.get(), "/a.txt", start).has_value(), "cache a");
        check(cache.open(root.get(), "/b.txt", start).has_value(), "cache b");
        check(cache.open(root.get(), "/a.txt", start).has_value(), "use a");
        check(cache.open(root.get(), "/c.txt", start).has_value(), "cache c, evicting b");
        rewrite(www / "a.txt", "AAAAAA", 2000000);
        rewrite(www / "b.txt", "BBBBBB", 2000000);
        auto a = cache.open(root.get(), "/a.txt", start + 100ms);
        auto b = cache.open(root.get(), "/b.txt", start + 100ms);
        check(a && a->info.size == 4, "recently used entry stays cached");
        check(b && b->info.size == 6, "least recently used entry was evicted");

        a->file.reset();
        b->file.reset();

        // With every entry pinned, a further file is served uncached; once an
        // entry is released, the file takes its place.
        auto pinned_a = cache.open(root.get(), "/a.txt", start + 100ms);
        auto pinned_b = cache.open(root.get(), "/b.txt", start + 100ms);
        check(pinned_a && pinned_a->file.cached() && pinned_b && pinned_b->file.cached(),
              "both entries pinned");
        write_file(www / "d.txt", "dddd");
        auto d = cache.open(root.get(), "/d.txt", start + 100ms);
        check(d && !d->file.cached() && contents(d->file, 4) == "dddd",
              "exhausted cache serves uncached");
        d->file.reset();
        pinned_a->file.reset();
        auto again = cache.open(root.get(), "/d.txt", start + 100ms);
        check(again && again->file.cached(), "released entry is reused");
        again->file.reset();
        pinned_b->file.reset();
    }

    std::filesystem::remove_all(directory);
    return 0;
}
