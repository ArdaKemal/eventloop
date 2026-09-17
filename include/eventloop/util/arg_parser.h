#pragma once

#include <vector>
#include <string>
#include <variant>

class arg_parser {
public:
    using value_t = std::variant<bool*, int*, std::string*>;

    struct option {
        char short_name;
        std::string_view long_name;
        value_t value;
        bool required;
    };

    arg_parser(const option *options, std::size_t count)
        : options_(options, options + count)
    {}

    auto parse(int argc, char *argv[]) -> void;

    auto set_usage(std::string_view usage)
    {
        usage_ = usage;
    }

private:
    void exit_with_usage();

    std::string_view usage_;
    std::vector<option> options_;
};
