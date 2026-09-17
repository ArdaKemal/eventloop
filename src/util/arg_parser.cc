#include "eventloop/util/arg_parser.h"

#include <charconv>
#include <algorithm>
#include <functional>

using namespace std::string_view_literals;

auto arg_parser::exit_with_usage() -> void
{
    std::puts(usage_.data());
    exit(0);
}

static auto valid_argumnet(std::string_view arg, const arg_parser::option &opt)
    -> bool
{
    if (!arg.starts_with('-')) {
        return false;
    }

    arg.remove_prefix(1);

    if (arg.starts_with('-')) {
        arg.remove_prefix(1);
        return arg == opt.long_name;
    }

    return arg.size() == 1 && arg.front() == opt.short_name;
}

auto arg_parser::parse(int argc, char *argv[]) -> void
{
    if (argc <= 1) {
        exit_with_usage();
    }

    std::vector<std::string_view> args;
    args.reserve(static_cast<std::size_t>(argc));

    std::for_each(argv + 1, argv + argc,
        [&](char *arg) { args.emplace_back(arg); });

    if (args.front() == "--help"sv || args.front() == "-h"sv) {
        exit_with_usage();
    }

    for (std::size_t i = 0; i < args.size(); i++) {
        const auto it = std::find_if(options_.begin(), options_.end(),
            std::bind_front(valid_argumnet, args[i]));

        if (it == options_.end()) {
            exit_with_usage();
        }

        if (std::holds_alternative<bool*>(it->value)) {
            *std::get<bool*>(it->value) = true;
            options_.erase(it);
            continue;
        }

        if (i + 1 >= args.size()) {
            exit_with_usage();
        }

        i++;

        if (std::holds_alternative<int*>(it->value)) {
            int n = 0;
            std::string_view arg = args[i];

            auto [_, ec] =
                std::from_chars(arg.data(), arg.data() + arg.size(), n);

            if (ec != std::errc()) {
                exit_with_usage();
            }

            *std::get<int*>(it->value) = n;
        }
        else {
            std::get<std::string*>(it->value)->assign(args[i]);
        }

        options_.erase(it);
    }

    for (const auto &opt : options_) {
        if (opt.required) {
            exit_with_usage();
        }
    }
}
