#include "quic/local_connection_id_registry.h"

#include <array>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {
using namespace eventloop::quic::detail;
using error = local_connection_id_error;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC local connection IDs: " << message << '\n';
    std::exit(1);
}

constexpr auto cid(unsigned value) -> std::array<std::byte, 2>
{ return {std::byte {0xa5}, static_cast<std::byte>(value)}; }

constexpr auto token(unsigned value) -> std::array<std::byte, 16>
{
    std::array<std::byte, 16> result {};
    result[0] = static_cast<std::byte>(value);
    return result;
}

auto issuance() -> void
{
    local_connection_id_registry<8> ids;
    check(ids.issue(cid(1), token(1)).error() == error::missing_initial &&
          ids.retire(0, cid(1)).error() == error::missing_initial,
          "initial state required");
    check(ids.set_active_limit(1).error() == error::invalid_limit &&
          ids.set_active_limit(max_varint_value + 1).error() == error::invalid_limit &&
          ids.active_limit() == 2, "invalid limits are atomic");
    check(ids.set_initial(cid(0), token(0)).has_value() &&
          ids.find(0)->sequence_number == 0 && ids.match(cid(0)) == ids.find(0),
          "handshake ID sequence zero");
    check(ids.set_initial(cid(9)).error() == error::already_initialized,
          "initial cannot change");
    auto preferred = ids.set_preferred_address(cid(1), token(1));
    check(preferred.has_value() && (*preferred)->sequence_number == 1 &&
          (*preferred)->preferred_address && ids.active_count() == 2,
          "preferred address is sequence one and consumes peer credit");
    check(ids.set_preferred_address(cid(2), token(2)).error() == error::invalid_preferred_address,
          "preferred address cannot be supplied twice");
    check(ids.issue(cid(2), token(2)).error() == error::connection_id_limit &&
          ids.size() == 2, "peer active limit");
    check(ids.set_active_limit(4).has_value(), "configure peer credit");
    auto next = ids.issue(cid(2), token(2));
    check(next.has_value() && (*next)->sequence_number == 2 &&
          !(*next)->preferred_address && ids.find(1) == *preferred,
          "new IDs increment sequence and pointers stay valid");
    check(ids.issue(cid(2), token(3)).error() == error::duplicate_connection_id &&
          ids.issue(cid(3), token(2)).error() == error::duplicate_reset_token &&
          ids.size() == 3, "duplicate IDs and tokens are rejected atomically");
    check(ids.set_active_limit(2).error() == error::connection_id_limit &&
          ids.active_limit() == 4, "cannot reduce limit below peer count");

    local_connection_id_registry<3> ordinary;
    check(ordinary.set_initial(cid(0)).has_value(), "token optional for handshake ID");
    auto first_new = ordinary.issue(cid(1), token(1));
    check(first_new.has_value() && (*first_new)->sequence_number == 1 &&
          !(*first_new)->preferred_address &&
          ordinary.set_preferred_address(cid(2), token(2)).error() == error::invalid_preferred_address,
          "without preferred address first NEW sequence is one");
}

auto retirement() -> void
{
    local_connection_id_registry<6> ids;
    check(ids.set_initial(cid(0), token(0)).has_value() &&
          ids.issue(cid(1), token(1)).has_value(), "retirement setup");
    check(ids.retire(2, cid(1)).error() == error::invalid_sequence &&
          ids.retire(max_varint_value + 1, cid(1)).error() == error::invalid_sequence &&
          ids.retire(0, cid(0)).error() == error::retiring_packet_destination &&
          ids.active_count() == 2, "reject unissued sequence and packet destination");
    auto retired = ids.retire(0, cid(1));
    check(retired.has_value() && *retired && !ids.match(cid(0)) &&
          ids.find(0)->retired && ids.match(cid(1)), "retired CID stops routing");
    auto duplicate = ids.retire(0, cid(1));
    check(duplicate.has_value() && !*duplicate && ids.active_count() == 1,
          "duplicate retire is idempotent");
    check(ids.retire(0, cid(0)).error() == error::retiring_packet_destination,
          "duplicate retire still validates packet destination");
    check(ids.issue(cid(0), token(2)).error() == error::duplicate_connection_id &&
          ids.issue(cid(2), token(0)).error() == error::duplicate_reset_token,
          "tombstones prevent retired CID and reset token reuse");
    auto replacement = ids.issue(cid(2), token(2));
    check(replacement.has_value() && (*replacement)->sequence_number == 2 &&
          ids.active_count() == 2, "retirement permits replacement");
}

auto retirement_requests() -> void
{
    local_connection_id_registry<6> ids;
    check(ids.set_initial(cid(0)).has_value() &&
          ids.issue(cid(1), token(1)).has_value(), "request setup");
    check(ids.issue(cid(2), token(2), 3).error() == error::invalid_retire_prior_to &&
          ids.retire_prior_to() == 0 && ids.size() == 2, "future retirement invalid");
    auto replacement = ids.issue(cid(2), token(2), 1);
    check(replacement.has_value() && (*replacement)->retire_prior_to == 1 &&
          ids.retire_prior_to() == 1 && ids.active_count() == 3 &&
          ids.peer_active_count() == 2 && ids.match(cid(0)),
          "replacement respects peer limit but routes old CID until RETIRE");
    check(ids.issue(cid(3), token(3), 2).error() == error::retirement_pending &&
          ids.issue(cid(3), token(3), 0).error() == error::invalid_retire_prior_to &&
          ids.issue(cid(3), token(3), 1).error() == error::connection_id_limit &&
          ids.size() == 3 && ids.retire_prior_to() == 1,
          "pending request and issuance failures preserve state");
    check(ids.retire(0, cid(2)).has_value(), "confirm old retirement");
    auto next = ids.issue(cid(3), token(3), 3);
    check(next.has_value() && (*next)->sequence_number == 3 &&
          ids.peer_active_count() == 1 && ids.active_count() == 3 &&
          ids.match(cid(1)) && ids.match(cid(2)), "can replace all remaining peer IDs");
}

auto bounds_and_zero_length() -> void
{
    const std::array<std::byte, 21> oversized {};
    const std::array<std::byte, 15> short_token {};
    local_connection_id_registry<3> invalid;
    check(invalid.set_initial(oversized).error() == error::invalid_connection_id &&
          invalid.set_initial(cid(0), short_token).error() == error::invalid_reset_token &&
          invalid.set_initial({}, token(0)).error() == error::invalid_reset_token &&
          invalid.size() == 0, "invalid initial sizes");
    check(invalid.set_initial(cid(0)).has_value(), "valid initial after failures");
    check(invalid.issue({}, token(1)).error() == error::invalid_connection_id &&
          invalid.issue(oversized, token(1)).error() == error::invalid_connection_id &&
          invalid.issue(cid(1), short_token).error() == error::invalid_reset_token &&
          invalid.size() == 1, "invalid new ID sizes");

    local_connection_id_registry<3> zero;
    check(zero.set_initial({}).has_value() && zero.match({}) &&
          zero.issue(cid(1), token(1)).error() == error::zero_length_connection_id &&
          zero.set_preferred_address(cid(1), token(1)).error() == error::zero_length_connection_id &&
          zero.retire(0, cid(1)).error() == error::zero_length_connection_id &&
          zero.size() == 1, "zero length excludes issuance and retirement");

    local_connection_id_registry<0> empty;
    check(empty.set_initial(cid(0)).error() == error::capacity_exhausted &&
          empty.size() == 0, "zero capacity");
    local_connection_id_registry<2> bounded;
    check(bounded.set_initial(cid(0)).has_value() &&
          bounded.issue(cid(1), token(1)).has_value(), "capacity setup");
    check(bounded.issue(cid(2), token(2), 2).error() == error::capacity_exhausted &&
          bounded.size() == 2 && bounded.retire_prior_to() == 0 &&
          bounded.active_count() == 2 && bounded.match(cid(0)),
          "capacity failure does not request retirement");
    check(bounded.retire(0, cid(1)).has_value() &&
          bounded.issue(cid(2), token(2)).error() == error::capacity_exhausted &&
          bounded.size() == 2, "retirement never recycles lifetime capacity");
}
} // namespace

auto main() -> int
{
    issuance();
    retirement();
    retirement_requests();
    bounds_and_zero_length();
    std::cout << "QUIC local connection ID registry tests passed\n";
}
