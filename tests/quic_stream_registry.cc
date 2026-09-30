#include "quic/stream_registry.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC stream registry: " << message << '\n';
    std::exit(1);
}

auto classification_and_permissions() -> void
{
    check(stream_initiator(0) == stream_role::client &&
          stream_initiator(1) == stream_role::server &&
          stream_type(2) == stream_direction::unidirectional &&
          stream_type(3) == stream_direction::unidirectional &&
          stream_ordinal(7) == 2, "ID bits and ordinal");

    stream_registry<4> client(stream_role::client);
    check(client.set_local_limit(stream_direction::bidirectional, 1) &&
          client.set_local_limit(stream_direction::unidirectional, 1) &&
          client.set_peer_limit(stream_direction::bidirectional, 1) &&
          client.set_peer_limit(stream_direction::unidirectional, 1),
          "configure client credits");
    check(client.open_local(stream_direction::bidirectional) == 0 &&
          client.open_local(stream_direction::unidirectional) == 2,
          "client local IDs");
    check(client.find(0)->can_send && client.find(0)->can_receive &&
          client.find(2)->can_send && !client.find(2)->can_receive,
          "client local permissions");
    check(client.observe_peer(1).has_value() &&
          client.observe_peer(3).has_value(), "client peer IDs");
    check(client.find(1)->can_send && client.find(1)->can_receive &&
          !client.find(3)->can_send && client.find(3)->can_receive,
          "client peer permissions");

    stream_registry<4> server(stream_role::server);
    check(server.set_local_limit(stream_direction::bidirectional, 1) &&
          server.set_local_limit(stream_direction::unidirectional, 1) &&
          server.set_peer_limit(stream_direction::bidirectional, 1) &&
          server.set_peer_limit(stream_direction::unidirectional, 1),
          "configure server credits");
    check(server.open_local(stream_direction::bidirectional) == 1 &&
          server.open_local(stream_direction::unidirectional) == 3 &&
          server.observe_peer(0).has_value() &&
          server.observe_peer(2).has_value(), "server local and peer IDs");
    check(server.find(3)->can_send && !server.find(3)->can_receive &&
          !server.find(2)->can_send && server.find(2)->can_receive,
          "server unidirectional permissions");
}

auto limits_and_implicit_streams() -> void
{
    stream_registry<6> registry(stream_role::server);
    check(registry.open_local(stream_direction::bidirectional).error() ==
          stream_registry_error::stream_limit, "zero initial peer credit");
    check(registry.set_local_limit(stream_direction::bidirectional, 3) &&
          registry.set_local_limit(stream_direction::unidirectional, 1) &&
          registry.set_peer_limit(stream_direction::bidirectional, 1),
          "set limits");
    check(registry.observe_peer(8).has_value() &&
          registry.peer_opened(stream_direction::bidirectional) == 3 &&
          registry.was_opened(0) && registry.was_opened(4) &&
          registry.was_opened(8) && registry.size() == 1,
          "higher peer ID implicitly opens lower IDs");
    check(registry.observe_peer(4).has_value() && registry.size() == 2,
          "later access to implicit stream");
    check(registry.observe_peer(12).error() ==
          stream_registry_error::stream_limit &&
          registry.observe_peer(6).error() ==
          stream_registry_error::stream_limit &&
          registry.peer_opened(stream_direction::bidirectional) == 3,
          "peer bidirectional and unidirectional limits are independent");
    check(registry.observe_peer(2).has_value() &&
          registry.peer_opened(stream_direction::unidirectional) == 1,
          "peer unidirectional credit");
    check(registry.open_local(stream_direction::bidirectional) == 1 &&
          registry.open_local(stream_direction::bidirectional).error() ==
          stream_registry_error::stream_limit, "local cumulative credit");
    check(registry.close(1) && registry.close(8) &&
          registry.open_local(stream_direction::bidirectional).error() ==
          stream_registry_error::stream_limit &&
          registry.observe_peer(12).error() ==
          stream_registry_error::stream_limit,
          "closing does not restore cumulative credits");
    check(registry.set_peer_limit(stream_direction::bidirectional, 2) &&
          registry.open_local(stream_direction::bidirectional) == 5,
          "increased peer credit permits next ID");
    check(registry.set_local_limit(stream_direction::bidirectional, 4) &&
          registry.observe_peer(12).has_value(),
          "increased local limit permits next peer ID");
}

auto tombstones_and_atomic_failure() -> void
{
    stream_registry<2> registry(stream_role::client);
    check(registry.set_local_limit(stream_direction::bidirectional, 3) &&
          registry.set_peer_limit(stream_direction::bidirectional, 3),
          "set tombstone credits");
    const auto first = registry.observe_peer(5);
    check(first && registry.observe_peer(5) == first && registry.size() == 1,
          "duplicate access shares record");
    check(registry.close(5) && registry.find(5)->closed &&
          registry.observe_peer(5).error() == stream_registry_error::closed &&
          registry.close(5).error() == stream_registry_error::closed,
          "closed stream cannot reopen");
    check(registry.open_local(stream_direction::bidirectional) == 0,
          "use second slot");
    check(registry.observe_peer(9).error() ==
          stream_registry_error::capacity_exhausted &&
          registry.peer_opened(stream_direction::bidirectional) == 2 &&
          !registry.was_opened(9), "failed observation does not advance ordinal");
    check(registry.open_local(stream_direction::bidirectional).error() ==
          stream_registry_error::capacity_exhausted &&
          registry.local_opened(stream_direction::bidirectional) == 1,
          "failed local open does not consume ID");
    check(registry.close(0) && registry.size() == 2 &&
          registry.open_local(stream_direction::bidirectional).error() ==
          stream_registry_error::capacity_exhausted,
          "closed tombstones retain fixed capacity");
    check(registry.close(1).error() ==
          stream_registry_error::unknown_stream,
          "unknown stream cannot be closed");
}

auto invalid_inputs() -> void
{
    stream_registry<2> registry(stream_role::client);
    check(registry.set_local_limit(stream_direction::bidirectional,
                                   max_stream_count) &&
          registry.set_peer_limit(stream_direction::unidirectional,
                                  max_stream_count),
          "maximum legal stream count");
    check(registry.set_local_limit(stream_direction::unidirectional,
                                   max_stream_count + 1).error() ==
          stream_registry_error::invalid_limit &&
          registry.set_peer_limit(stream_direction::bidirectional,
                                  max_stream_count + 1).error() ==
          stream_registry_error::invalid_limit,
          "reject count beyond 2^60");
    check(registry.set_local_limit(stream_direction::bidirectional, 1) &&
          registry.set_peer_limit(stream_direction::unidirectional, 1),
          "stale lower limits are ignored");
    check(registry.observe_peer(max_varint_value + 1).error() ==
          stream_registry_error::invalid_stream_id &&
          registry.observe_peer(0).error() ==
          stream_registry_error::wrong_initiator &&
          !registry.was_opened(max_varint_value + 1),
          "reject invalid ID and wrong initiator");
    check(registry.observe_peer(max_varint_value - 2).has_value() &&
          registry.peer_opened(stream_direction::bidirectional) ==
              max_stream_count,
          "maximum peer stream ID proves lower limit was ignored");
    check(registry.open_local(stream_direction::unidirectional) == 2 &&
          registry.local_opened(stream_direction::unidirectional) == 1,
          "maximum credit permits local opening");
}

} // namespace

auto main() -> int
{
    classification_and_permissions();
    limits_and_implicit_streams();
    tombstones_and_atomic_failure();
    invalid_inputs();
}
