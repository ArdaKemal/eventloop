#include "quic/connection_id_registry.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC connection ID registry: " << message << '\n';
    std::exit(1);
}

[[nodiscard]] constexpr auto cid(unsigned value) -> std::array<std::byte, 2>
{ return {std::byte {0xa5}, static_cast<std::byte>(value)}; }

[[nodiscard]] constexpr auto token(unsigned value) -> std::array<std::byte, 16>
{
    std::array<std::byte, 16> result {};
    result[0] = static_cast<std::byte>(value);
    return result;
}

auto duplicates_and_limits() -> void
{
    peer_connection_id_registry<6> registry;
    check(registry.set_active_limit(1).error() == connection_id_registry_error::invalid_limit &&
          registry.active_limit() == 2, "minimum active limit");
    check(registry.set_initial(cid(0)) && registry.selected() &&
          registry.selected()->sequence_number == 0, "initial ID");
    check(registry.add(1, 0, cid(1), token(1)) &&
          registry.active_count() == 2, "second active ID");
    check(registry.add(1, 0, cid(1), token(1)) && registry.size() == 2,
          "identical retransmission");
    check(registry.add(1, 0, cid(9), token(1)).error() ==
              connection_id_registry_error::inconsistent_duplicate &&
          registry.add(1, 0, cid(1), token(9)).error() ==
              connection_id_registry_error::inconsistent_duplicate &&
          registry.add(2, 0, cid(1), token(2)).error() ==
              connection_id_registry_error::inconsistent_duplicate,
          "sequence, ID, and token consistency");
    check(registry.add(2, 0, cid(2), token(2)).error() ==
              connection_id_registry_error::connection_id_limit &&
          registry.size() == 2 && registry.retire_prior_to() == 0,
          "active limit failure is atomic");
    check(registry.select(1) && registry.selected()->sequence_number == 1,
          "select active ID");
    check(registry.select(9).error() ==
              connection_id_registry_error::unknown_connection_id &&
          registry.selected()->sequence_number == 1,
          "unknown selection preserves choice");
}

auto retirement_and_reordering() -> void
{
    peer_connection_id_registry<8> registry;
    check(registry.set_initial(cid(0)) &&
          registry.add(1, 0, cid(1), token(1)), "set up IDs");
    check(registry.add(3, 2, cid(3), token(3)) &&
          registry.retire_prior_to() == 2 && registry.active_count() == 1 &&
          registry.selected()->sequence_number == 3 &&
          registry.next_retirement() == 0,
          "retire earlier IDs before adding replacement");
    check(registry.mark_retirement_queued(0) &&
          registry.next_retirement() == 1 &&
          registry.mark_retirement_queued(1) &&
          !registry.next_retirement(), "retirement queue handoff");
    check(registry.add(2, 0, cid(2), token(2)) &&
          registry.retire_prior_to() == 2 && registry.active_count() == 2,
          "stale Retire Prior To does not decrease high water mark");
    check(registry.add(1, 0, cid(1), token(1)) &&
          !registry.next_retirement(), "retired duplicate is idempotent");
    check(registry.add(4, 4, cid(4), token(4)) &&
          registry.active_count() == 1 &&
          registry.selected()->sequence_number == 4 &&
          registry.next_retirement() == 2,
          "selected ID rotates on retirement");
    check(registry.select(3).error() ==
              connection_id_registry_error::retired_connection_id,
          "retired ID cannot be selected");
    check(registry.add(1, 0, cid(1), token(8)).error() ==
              connection_id_registry_error::inconsistent_duplicate,
          "retired tombstone retains token consistency");
    check(registry.add(0, 0, cid(0), token(0)).error() ==
              connection_id_registry_error::inconsistent_duplicate,
          "retired initial ID cannot be rebound");
}

auto late_retirement_and_atomic_exhaustion() -> void
{
    peer_connection_id_registry<3> registry;
    check(registry.set_initial(cid(0)) &&
          registry.add(3, 2, cid(3), token(3)) &&
          registry.next_retirement() == 0, "future Retire Prior To");
    check(registry.add(1, 0, cid(1), token(1)) &&
          registry.find(1)->retired && registry.next_retirement() == 0,
          "late ID below high water mark requires retirement");
    check(registry.mark_retirement_queued(0) &&
          registry.next_retirement() == 1, "late retirement queued");
    check(registry.add(4, 4, cid(4), token(4)).error() ==
              connection_id_registry_error::capacity_exhausted &&
          registry.retire_prior_to() == 2 && registry.active_count() == 1 &&
          !registry.find(0)->retirement_pending &&
          !registry.find(3)->retired && registry.selected()->sequence_number == 3,
          "lifetime capacity failure preserves all state");
    check(registry.add(2, 3, cid(2), token(2)).error() ==
              connection_id_registry_error::invalid_retire_prior_to,
          "Retire Prior To cannot exceed frame sequence");
}

auto invalid_inputs_and_zero_length() -> void
{
    peer_connection_id_registry<3> registry;
    check(registry.add(1, 0, cid(1), token(1)).error() ==
              connection_id_registry_error::missing_initial,
          "initial CID required");
    const std::array<std::byte, 21> oversized {};
    check(registry.set_initial(oversized).error() ==
              connection_id_registry_error::invalid_connection_id &&
          registry.size() == 0, "oversized initial CID rejected");
    check(registry.set_initial(cid(0)) &&
          registry.set_initial(cid(0)).error() ==
              connection_id_registry_error::already_initialized,
          "initial CID can be set once");
    check(registry.add(max_varint_value + 1, 0, cid(1), token(1)).error() ==
              connection_id_registry_error::invalid_sequence &&
          registry.add(1, 0, std::span<const std::byte> {}, token(1)).error() ==
              connection_id_registry_error::invalid_connection_id &&
          registry.add(1, 0, oversized, token(1)).error() ==
              connection_id_registry_error::invalid_connection_id &&
          registry.add(1, 0, cid(1), cid(1)).error() ==
              connection_id_registry_error::invalid_reset_token &&
          registry.size() == 1, "frame field validation");

    peer_connection_id_registry<2> zero;
    check(zero.set_initial({}) && zero.selected() && zero.selected()->id().empty(),
          "zero-length handshake CID");
    check(zero.add(1, 0, cid(1), token(1)).error() ==
              connection_id_registry_error::zero_length_connection_id &&
          zero.active_count() == 1, "NEW_CONNECTION_ID forbidden after zero CID");

    peer_connection_id_registry<0> empty;
    check(empty.set_initial(cid(0)).error() ==
              connection_id_registry_error::capacity_exhausted,
          "zero storage fails cleanly");
}

} // namespace

auto main() -> int
{
    duplicates_and_limits();
    retirement_and_reordering();
    late_retirement_and_atomic_exhaustion();
    invalid_inputs_and_zero_length();
}
