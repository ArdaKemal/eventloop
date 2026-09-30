#include "quic/path_validation.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC path validation: " << message << '\n';
    std::exit(1);
}

constexpr auto token(std::byte first) -> path_challenge
{
    path_challenge result {};
    result[0] = first;
    return result;
}

auto amplification() -> void
{
    std::array<path_validation_slot, 2> slots {};
    path_validation paths(slots, path_endpoint_role::server);
    check(paths.add(0).has_value(), "zero is a valid path handle");
    check(paths.can_send(0, 0) == true && paths.can_send(0, 1) == false,
          "unvalidated path starts with zero credit");
    check(paths.record_sent(0, 1).error() ==
              path_validation_error::amplification_limited &&
              paths.bytes_sent(0) == 0,
          "rejected send is atomic");
    check(paths.record_received(0, 100).has_value(), "receive grants credit");
    check(paths.record_sent(0, 299).has_value() &&
              paths.record_sent(0, 1).has_value(),
          "exact 3x boundary accepted");
    check(paths.can_send(0, 1) == false &&
              paths.record_sent(0, 1).error() ==
                  path_validation_error::amplification_limited &&
              paths.bytes_sent(0) == 300,
          "one byte beyond 3x rejected atomically");
    check(paths.add(1).has_value() && paths.can_send(1, 1) == false,
          "credit is per path");
    check(paths.validate(0).has_value() && paths.can_send(0, 1000000) == true &&
              paths.record_sent(0, 1000000).has_value(),
          "validated path is amplification unlimited");

    std::array<path_validation_slot, 1> client_slots {};
    path_validation client(client_slots, path_endpoint_role::client);
    check(client.add(4).has_value() && client.can_send(4, 1000000) == true &&
              client.record_sent(4, 1000000).has_value(),
          "client has no amplification limit");
}

auto challenges() -> void
{
    std::array<path_validation_slot, 2> slots {};
    path_validation paths(slots, path_endpoint_role::server);
    const auto a = token(std::byte {1});
    const auto b = token(std::byte {2});
    const auto wrong = token(std::byte {3});
    const auto fresh = token(std::byte {4});
    check(paths.add(10).has_value() && paths.add(20).has_value(),
          "two paths registered");
    check(paths.issue_challenge(10, a).has_value(), "first challenge issued");
    check(paths.issue_challenge(10, b).error() ==
              path_validation_error::challenge_pending,
          "outstanding challenge cannot be replaced");
    check(paths.issue_challenge(20, a).error() ==
              path_validation_error::duplicate_challenge,
          "active tokens must be unique across paths");
    check(paths.issue_challenge(20, b).has_value(),
          "second path has independent challenge");
    check(paths.accept_response(wrong).error() ==
              path_validation_error::unmatched_response &&
              paths.is_validated(10) == false &&
              paths.is_validated(20) == false,
          "mismatched response changes no path");
    check(paths.accept_response(b) == 20 &&
              paths.is_validated(20) == true &&
              paths.is_validated(10) == false,
          "response validates matching challenge path");
    check(paths.accept_response(b).error() ==
              path_validation_error::unmatched_response,
          "duplicate response ignored");
    check(paths.accept_response(a) == 10 && paths.is_validated(10) == true,
          "first path validates independently");
    check(paths.issue_challenge(10, fresh).has_value(),
          "validated path may be probed again with fresh data");
}

auto bounds_and_capacity() -> void
{
    constexpr auto max = std::numeric_limits<std::uint64_t>::max();
    std::array<path_validation_slot, 1> slots {};
    path_validation paths(slots, path_endpoint_role::server);
    check(paths.add(1).has_value() &&
              paths.add(1).error() == path_validation_error::duplicate_path &&
              paths.add(2).error() == path_validation_error::full,
          "duplicate and capacity errors preserve slot");
    check(paths.record_received(1, max).has_value() &&
              paths.record_received(1, 1).error() ==
                  path_validation_error::counter_overflow &&
              paths.bytes_received(1) == max,
          "receive counter cannot wrap");
    check(paths.record_sent(1, max).has_value() &&
              paths.record_sent(1, 1).error() ==
                  path_validation_error::counter_overflow &&
              paths.bytes_sent(1) == max,
          "send counter cannot wrap and 3x calculation saturates");
    check(paths.remove(1).has_value() &&
              paths.record_received(1, 1).error() ==
                  path_validation_error::unknown_path &&
              paths.add(2).has_value() && paths.bytes_received(2) == 0,
          "removal frees clean slot");
    paths.reset();
    check(paths.is_validated(2).error() ==
              path_validation_error::unknown_path && paths.add(3).has_value(),
          "reset clears capacity");
}

} // namespace

auto main() -> int
{
    amplification();
    challenges();
    bounds_and_capacity();
    return 0;
}
