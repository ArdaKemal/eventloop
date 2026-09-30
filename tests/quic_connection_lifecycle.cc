#include "quic/connection_lifecycle.h"

#include <cstdlib>
#include <iostream>
#include <string_view>
#include <type_traits>

namespace {
using namespace eventloop::quic::detail;
using namespace std::chrono_literals;
constexpr auto origin = lifecycle_time_point {};

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC connection lifecycle: " << message << '\n';
    std::exit(1);
}

auto idle_negotiation_and_activity() -> void
{
    connection_lifecycle connection;
    check(connection.state() == connection_state::handshake &&
          connection.can_send_data() && connection.can_send_close(), "initial state");
    check(!connection.idle_deadline(10ms), "default idle timeout disabled");
    check(connection.negotiate_idle_timeout(0ms, 100ms, origin), "sole peer timeout");
    check(connection.negotiated_idle_timeout() == 100ms, "zero local ignored");
    check(connection.negotiate_idle_timeout(80ms, 0ms, origin), "sole local timeout");
    check(connection.negotiated_idle_timeout() == 80ms, "zero peer ignored");
    check(connection.negotiate_idle_timeout(100ms, 60ms, origin), "both timeouts");
    check(connection.idle_deadline(10ms) == origin + 60ms, "minimum timeout");
    check(connection.idle_deadline(30ms) == origin + 90ms, "three PTO floor");
    check(connection.handshake_complete(origin), "handshake completes");
    check(connection.packet_sent(origin + 10ms, false), "ACK only send");
    check(connection.idle_deadline(10ms) == origin + 60ms, "ACK only does not reset");
    check(connection.packet_sent(origin + 20ms, true), "first eliciting send");
    check(connection.idle_deadline(10ms) == origin + 80ms, "first send resets");
    check(connection.packet_sent(origin + 30ms, true), "next eliciting send");
    check(connection.idle_deadline(10ms) == origin + 80ms, "next send does not reset");
    check(connection.packet_received(origin + 40ms), "successful receive");
    check(connection.idle_deadline(10ms) == origin + 100ms, "receive resets");
    check(connection.packet_sent(origin + 50ms, true), "first send after receive");
    check(connection.idle_deadline(10ms) == origin + 110ms, "receive enables send reset");
    check(connection.poll(origin + 109ms, 10ms) &&
          connection.state() == connection_state::active, "before idle deadline");
    check(connection.poll(origin + 110ms, 10ms) &&
          connection.state() == connection_state::closed, "idle closes silently");
    check(!connection.can_send_data() && !connection.can_send_close() &&
          !connection.next_deadline(10ms), "closed retires timers and output");
}

auto termination() -> void
{
    connection_lifecycle connection;
    check(connection.negotiate_idle_timeout(1ms, 1ms, origin), "short idle");
    check(connection.close_sent(origin + 1ms, 10ms), "handshake immediate close");
    check(connection.state() == connection_state::closing &&
          !connection.can_send_data() && connection.can_send_close(), "closing output policy");
    check(connection.next_deadline(1ms) == origin + 31ms &&
          !connection.idle_deadline(1ms), "closing replaces idle timer");
    check(!connection.close_sent(origin + 2ms, 100ms) &&
          connection.termination_deadline() == origin + 31ms, "close cannot extend timer");
    check(connection.enter_draining(origin + 3ms, 100ms), "closing to draining");
    check(connection.termination_deadline() == origin + 31ms, "draining preserves closing end");
    check(!connection.can_send_data() && !connection.can_send_close(), "draining forbids packets");
    check(!connection.packet_received(origin + 4ms) &&
          !connection.packet_sent(origin + 4ms, true) &&
          !connection.handshake_complete(origin + 4ms) &&
          !connection.enter_draining(origin + 4ms, 100ms), "draining immutable to traffic");
    check(connection.poll(origin + 30ms, 1ms) &&
          connection.state() == connection_state::draining, "drain persists");
    check(connection.poll(origin + 31ms, 1ms) &&
          connection.state() == connection_state::closed, "drain expiry");
    check(!connection.close_sent(origin + 32ms, 10ms) &&
          !connection.enter_draining(origin + 32ms, 10ms) &&
          !connection.poll(origin + 32ms, 10ms), "closed cannot revive");

    connection_lifecycle peer_closed;
    check(peer_closed.enter_draining(origin, 10ms) &&
          peer_closed.termination_deadline() == origin + 30ms &&
          !peer_closed.can_send_close(), "direct peer close or stateless reset");
    connection_lifecycle active_closed;
    check(active_closed.handshake_complete(origin) &&
          active_closed.close_sent(origin, 10ms), "active immediate close");
    check(active_closed.poll(origin + 30ms, 10ms) &&
          active_closed.state() == connection_state::closed, "closing expiry");
}

auto invalid_events_and_boundaries() -> void
{
    connection_lifecycle connection {origin + 10ms};
    check(!connection.negotiate_idle_timeout(-1ms, 20ms, origin + 11ms) &&
          connection.negotiated_idle_timeout() == 0ms, "negative timeout rejected");
    check(!connection.close_sent(origin + 11ms, 0ms) &&
          !connection.enter_draining(origin + 11ms, -1ms) &&
          !connection.poll(origin + 11ms, 0ms) &&
          connection.state() == connection_state::handshake &&
          !connection.termination_deadline(), "invalid PTO is failure atomic");
    check(!connection.packet_sent(origin, true) && !connection.packet_received(origin) &&
          !connection.handshake_complete(origin) &&
          !connection.close_sent(origin, 1ms) &&
          !connection.enter_draining(origin, 1ms) &&
          !connection.negotiate_idle_timeout(1ms, 1ms, origin) &&
          !connection.poll(origin, 1ms), "backwards time rejected");
    check(connection.handshake_complete(origin + 10ms), "rejected events preserve clock");
    check(!connection.handshake_complete(origin + 20ms), "duplicate handshake rejected");
    check(connection.packet_received(origin + 11ms), "duplicate does not advance clock");
    check(connection.negotiate_idle_timeout(0ms, 0ms, origin + 11ms) &&
          !connection.idle_deadline(lifecycle_duration::max()), "both disabled ignore PTO floor");
    check(lifecycle_three_pto(lifecycle_duration::max()) == lifecycle_duration::max() &&
          lifecycle_three_pto(lifecycle_duration::min()) == lifecycle_duration::zero(),
          "three PTO arithmetic saturates");
    const auto maximum = lifecycle_time_point::max();
    const auto tick = lifecycle_duration {1};
    check(lifecycle_deadline(maximum - tick, tick) == maximum &&
          lifecycle_deadline(maximum - tick, tick * 2) == maximum &&
          lifecycle_deadline(lifecycle_time_point::min(), lifecycle_duration::max()) ==
              lifecycle_time_point {-tick} &&
          lifecycle_deadline(origin, lifecycle_duration::min()) == origin,
          "deadline arithmetic handles signed boundaries");
    connection_lifecycle large {maximum - tick};
    check(large.negotiate_idle_timeout(tick, tick, maximum - tick) &&
          large.idle_deadline(lifecycle_duration::max()) == maximum, "idle saturation");
    check(large.close_sent(maximum - tick, lifecycle_duration::max()) &&
          large.termination_deadline() == maximum &&
          large.poll(maximum, tick) && large.state() == connection_state::closed,
          "closing saturation and maximum deadline expiry");
    connection_lifecycle negative {lifecycle_time_point::min()};
    check(negative.enter_draining(lifecycle_time_point::min(), tick) &&
          negative.termination_deadline() == lifecycle_time_point::min() + tick * 3,
          "negative epoch accepts positive intervals");
}
} // namespace

auto main() -> int
{
    static_assert(std::is_trivially_copyable_v<connection_lifecycle>);
    idle_negotiation_and_activity();
    termination();
    invalid_events_and_boundaries();
}
