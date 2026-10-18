#include "eventloop/util/arg_parser.h"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstdlib>

namespace eventloop {

namespace {

template<class... Ts>
struct overloaded : Ts... { using Ts::operator()...; };

[[nodiscard]] auto matches(std::string_view argument, const arg_parser::option& option) -> bool
{
    if (argument.starts_with("--"))
        return !option.long_name.empty() && argument.substr(2) == option.long_name;
    return argument.size() == 2 && option.short_name != '\0' &&
           argument[1] == option.short_name;
}

auto print(std::FILE* stream, std::string_view text) -> void
{
    (void)std::fwrite(text.data(), 1, text.size(), stream);
}

} // namespace

auto arg_parser::exit_with_usage() const -> void
{
    print(stdout, usage_);
    if (!usage_.ends_with('\n')) (void)std::fputc('\n', stdout);
    std::exit(0);
}

auto arg_parser::fail(std::string_view message) const -> void
{
    print(stderr, program_);
    print(stderr, ": ");
    print(stderr, message);
    (void)std::fputc('\n', stderr);
    print(stderr, usage_);
    if (!usage_.empty() && !usage_.ends_with('\n')) (void)std::fputc('\n', stderr);
    std::exit(2);
}

auto arg_parser::parse(int argc, char* argv[]) -> void
{
    program_ = argc > 0 ? std::string_view(argv[0]) : std::string_view("program");
    if (const auto slash = program_.find_last_of("/\\"); slash != std::string_view::npos)
        program_.remove_prefix(slash + 1);

    // Stores one value, reporting a malformed integer for the named argument.
    const auto store = [this](auto& target, std::string_view value, std::string_view name) {
        std::visit(overloaded {
            [&](int* destination) {
                int number = 0;
                const auto [end, error] =
                    std::from_chars(value.data(), value.data() + value.size(), number);
                if (error != std::errc {} || end != value.data() + value.size())
                    fail("invalid value for " + std::string(name) + ": " + std::string(value));
                *destination = number;
            },
            [&](std::string* destination) { destination->assign(value); },
            [&](const value_handler& handler) { handler(value); },
            [](bool*) {},
            [](const flag_handler&) {},
        }, target);
    };

    std::vector<bool> seen(options_.size());
    std::size_t next_positional = 0;
    bool options_ended = false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument = argv[index];
        if (!options_ended && argument == "--") {
            options_ended = true;
            continue;
        }
        if (!options_ended && argument.size() > 1 && argument.front() == '-') {
            if (argument == "-h" || argument == "--help") exit_with_usage();
            const auto found = std::ranges::find_if(options_,
                [argument](const option& item) { return matches(argument, item); });
            if (found == options_.end()) fail("unknown option " + std::string(argument));
            seen[static_cast<std::size_t>(found - options_.begin())] = true;
            if (const auto* flag = std::get_if<bool*>(&found->value)) {
                **flag = true;
            } else if (const auto* handler = std::get_if<flag_handler>(&found->value)) {
                (*handler)();
            } else {
                if (++index == argc) fail("missing value for " + std::string(argument));
                store(found->value, argv[index], argument);
            }
            continue;
        }
        if (next_positional == positionals_.size())
            fail("unexpected argument " + std::string(argument));
        const auto& target = positionals_[next_positional++];
        store(target.value, argument, target.name);
    }

    for (std::size_t index = 0; index < options_.size(); ++index) {
        const auto& item = options_[index];
        if (!item.required || seen[index]) continue;
        fail("missing required option " + (item.long_name.empty()
            ? std::string {'-', item.short_name} : "--" + std::string(item.long_name)));
    }
    for (std::size_t index = next_positional; index < positionals_.size(); ++index)
        if (positionals_[index].required)
            fail("missing " + std::string(positionals_[index].name));
}

} // namespace eventloop
