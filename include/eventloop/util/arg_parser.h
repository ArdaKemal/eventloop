#pragma once

#include <cstddef>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace eventloop {

// Command-line parser for small programs. Options are matched as "-x" or
// "--name"; a value is the next argument. Options may repeat: scalar targets
// keep the last value and handlers run for every occurrence. Other arguments
// fill positionals in order, and "--" makes every later argument positional.
//
// parse() prints the usage text to stdout and exits 0 for -h or --help. It
// prints "<program>: <message>" and the usage text to stderr and exits 2 for
// an unknown option, a missing or invalid value, a missing required option or
// positional, or an extra argument. Exceptions thrown by handlers propagate
// to the caller unchanged, so programs keep their own error reporting.
class arg_parser {
public:
    using flag_handler = std::function<void()>;
    using value_handler = std::function<void(std::string_view)>;
    using value_t = std::variant<bool*, int*, std::string*, flag_handler, value_handler>;
    using positional_value_t = std::variant<int*, std::string*, value_handler>;

    struct option {
        char short_name; // '\0' for a long name only
        std::string_view long_name; // empty for a short name only
        value_t value;
        bool required;
    };

    struct positional {
        std::string_view name; // used in error messages
        positional_value_t value;
        bool required;
    };

    // The parser copies the descriptions; their names and the usage text must
    // outlive parse().
    explicit arg_parser(std::span<const option> options,
                        std::span<const positional> positionals = {})
        : options_(options.begin(), options.end()),
          positionals_(positionals.begin(), positionals.end())
    {}

    auto parse(int argc, char* argv[]) -> void;

    auto set_usage(std::string_view usage) -> void { usage_ = usage; }

private:
    [[noreturn]] auto exit_with_usage() const -> void;
    [[noreturn]] auto fail(std::string_view message) const -> void;

    std::string_view usage_;
    std::string_view program_;
    std::vector<option> options_;
    std::vector<positional> positionals_;
};

} // namespace eventloop
