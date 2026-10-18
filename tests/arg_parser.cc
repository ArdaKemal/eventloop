#include "eventloop/util/arg_parser.h"

#include <array>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

using eventloop::arg_parser;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "arg_parser: " << message << '\n';
    std::exit(1);
}

// argv storage for one parse; argv[0] carries a directory to strip.
struct arguments {
    explicit arguments(std::vector<std::string> values) : storage(std::move(values))
    {
        storage.insert(storage.begin(), "/usr/bin/tool");
        for (auto& value : storage) pointers.push_back(value.data());
        pointers.push_back(nullptr);
    }
    [[nodiscard]] auto argc() const -> int { return static_cast<int>(storage.size()); }
    [[nodiscard]] auto argv() -> char** { return pointers.data(); }
    std::vector<std::string> storage;
    std::vector<char*> pointers;
};

struct settings {
    bool verbose = false;
    int count = 1;
    std::string name = "default";
    std::vector<std::string> headers;
    std::vector<std::string> events;
    std::string url;
    int port = 80;
};

auto parse(settings& result, std::vector<std::string> values) -> void
{
    const std::array options {
        arg_parser::option {'v', "verbose", &result.verbose, false},
        arg_parser::option {'c', "count", &result.count, false},
        arg_parser::option {'\0', "name", &result.name, false},
        arg_parser::option {'H', "header", arg_parser::value_handler(
            [&result](std::string_view value) { result.headers.emplace_back(value); }), false},
        arg_parser::option {'\0', "first", arg_parser::flag_handler(
            [&result] { result.events.emplace_back("first"); }), false},
        arg_parser::option {'\0', "second", arg_parser::flag_handler(
            [&result] { result.events.emplace_back("second"); }), false},
    };
    const std::array positionals {
        arg_parser::positional {"URL", &result.url, true},
        arg_parser::positional {"PORT", &result.port, false},
    };
    arg_parser parser(options, positionals);
    parser.set_usage("usage: tool [options] URL [PORT]\n");
    arguments storage(std::move(values));
    parser.parse(storage.argc(), storage.argv());
}

struct outcome {
    int status;
    std::string out, err;
};

// Runs a parse in a child so exits can be observed.
auto run(std::vector<std::string> values) -> outcome
{
    std::array<int, 2> out_pipe {}, err_pipe {};
    check(::pipe(out_pipe.data()) == 0 && ::pipe(err_pipe.data()) == 0, "pipe");
    const auto child = ::fork();
    check(child >= 0, "fork");
    if (child == 0) {
        ::dup2(out_pipe[1], 1);
        ::dup2(err_pipe[1], 2);
        settings result;
        parse(result, std::move(values));
        std::_Exit(10);
    }
    ::close(out_pipe[1]);
    ::close(err_pipe[1]);
    const auto drain = [](int descriptor) {
        std::string text;
        std::array<char, 512> buffer {};
        for (ssize_t count; (count = ::read(descriptor, buffer.data(), buffer.size())) > 0;)
            text.append(buffer.data(), static_cast<std::size_t>(count));
        ::close(descriptor);
        return text;
    };
    outcome result {0, drain(out_pipe[0]), drain(err_pipe[0])};
    int status = 0;
    check(::waitpid(child, &status, 0) == child && WIFEXITED(status), "child exit");
    result.status = WEXITSTATUS(status);
    return result;
}

} // namespace

auto main() -> int
{
    settings parsed;
    parse(parsed, {"-v", "--count", "3", "-H", "a: 1", "--name", "x", "https://host/",
                   "--header", "b: 2", "--count", "4", "--second", "--first", "8080"});
    check(parsed.verbose && parsed.count == 4 && parsed.name == "x", "scalars keep the last value");
    check(parsed.headers == std::vector<std::string> {"a: 1", "b: 2"}, "value handler repeats");
    check(parsed.events == std::vector<std::string> {"second", "first"}, "flag handlers keep order");
    check(parsed.url == "https://host/" && parsed.port == 8080, "positionals fill in order");

    settings separated;
    parse(separated, {"--", "-dash-url"});
    check(separated.url == "-dash-url" && separated.port == 80 && separated.count == 1,
          "-- ends options; defaults remain");

    auto result = run({"--help"});
    check(result.status == 0 && result.out == "usage: tool [options] URL [PORT]\n" &&
          result.err.empty(), "--help prints usage to stdout");
    result = run({"x", "-h"});
    check(result.status == 0 && result.out.starts_with("usage:"), "-h anywhere");
    result = run({});
    check(result.status == 2 && result.err.starts_with("tool: missing URL\nusage:"),
          "missing positional");
    result = run({"x", "--bogus"});
    check(result.status == 2 && result.err.starts_with("tool: unknown option --bogus\n"),
          "unknown option");
    result = run({"x", "--count"});
    check(result.status == 2 && result.err.starts_with("tool: missing value for --count\n"),
          "missing value");
    result = run({"x", "-c", "3x"});
    check(result.status == 2 && result.err.starts_with("tool: invalid value for -c: 3x\n"),
          "invalid integer");
    result = run({"x", "1", "extra"});
    check(result.status == 2 && result.err.starts_with("tool: unexpected argument extra\n"),
          "extra positional");
    result = run({"x", "y"});
    check(result.status == 2 && result.err.starts_with("tool: invalid value for PORT: y\n"),
          "invalid positional integer");
    result = run({"x"});
    check(result.status == 10 && result.out.empty() && result.err.empty(), "valid run returns");

    std::cout << "arg_parser: ok\n";
}
