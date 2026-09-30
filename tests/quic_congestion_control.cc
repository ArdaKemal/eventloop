#include "quic/congestion_control.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;
using namespace std::chrono_literals;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC congestion control: " << message << '\n';
    std::exit(1);
}

auto at(std::chrono::milliseconds time) -> recovery_time_point
{ return recovery_time_point {time}; }

auto packet(std::chrono::milliseconds time, std::size_t bytes,
            bool in_flight = true) -> congestion_packet
{ return {at(time), bytes, in_flight}; }

auto initial_windows() -> void
{
    newreno_congestion_controller cc;
    check(cc.congestion_window() == 12000 && cc.minimum_window() == 2400 &&
          cc.bytes_in_flight() == 0 && !cc.recovery_start(),
          "default initial state");
    check(cc.reset(1472).has_value() && cc.congestion_window() == 14720,
          "ten datagrams at 1472 bytes");
    check(cc.reset(1200).has_value() && cc.congestion_window() == 12000,
          "ten datagrams at 1200 bytes");
    check(cc.reset(2000).has_value() && cc.congestion_window() == 14720,
          "14720 byte initial cap");
    check(cc.reset(10000).has_value() && cc.congestion_window() == 20000,
          "two datagram initial cap");
    const auto prior = cc.congestion_window();
    check(cc.reset(1199).error() == congestion_error::invalid_datagram_size &&
          cc.congestion_window() == prior,
          "invalid PMTU preserves state");
    check(cc.reset(std::numeric_limits<std::size_t>::max()).error() ==
              congestion_error::invalid_datagram_size &&
          cc.congestion_window() == prior,
          "oversized PMTU cannot overflow minimum window");
}

auto flight_and_slow_start() -> void
{
    newreno_congestion_controller cc;
    check(!cc.can_send(0) && !cc.can_send(1201) && cc.can_send(1200),
          "send size bounds");
    check(cc.on_packet_sent(1200, false).has_value() &&
          cc.bytes_in_flight() == 0,
          "ACK-only packet is outside flight");
    check(cc.on_packet_sent(0, true).error() ==
              congestion_error::invalid_packet_size,
          "zero-size packet rejected");
    for (int i = 0; i < 10; ++i)
        check(cc.on_packet_sent(1200, true).has_value(), "fill initial cwnd");
    check(cc.bytes_in_flight() == 12000 && !cc.can_send(1) &&
          cc.on_packet_sent(1, true).error() ==
              congestion_error::congestion_blocked,
          "full window blocks regular send");
    check(cc.on_packet_sent(1200, true, true).has_value() &&
          cc.bytes_in_flight() == 13200,
          "PTO probe is counted beyond cwnd");
    check(cc.on_packet_acked(packet(1ms, 1200)).has_value() &&
          cc.bytes_in_flight() == 12000 && cc.congestion_window() == 13200,
          "ACK removes flight and grows slow start");
    check(cc.on_packet_acked(packet(1ms, 1200), true).has_value() &&
          cc.bytes_in_flight() == 10800 && cc.congestion_window() == 13200,
          "application limited ACK cannot grow window");
    check(cc.on_packet_discarded(packet(1ms, 1200)).has_value() &&
          cc.bytes_in_flight() == 9600 && cc.congestion_window() == 13200,
          "key discard removes flight without reducing cwnd");
    check(cc.on_packet_acked(packet(1ms, 1200, false)).has_value() &&
          cc.bytes_in_flight() == 9600 && cc.congestion_window() == 13200,
          "non-flight ACK leaves accounting unchanged");
}

auto recovery_and_avoidance() -> void
{
    newreno_congestion_controller cc;
    check(cc.on_packet_sent(1200, true).has_value(), "send before loss");
    check(cc.on_packet_sent(1200, true).has_value(), "send another old packet");
    check(cc.on_packet_lost(packet(1ms, 1200), at(5ms)).has_value() &&
          cc.congestion_window() == 6000 &&
          cc.slow_start_threshold() == 6000 &&
          cc.bytes_in_flight() == 1200 && cc.recovery_start() == at(5ms) &&
          cc.in_recovery_period(),
          "first loss enters recovery and halves cwnd");
    check(cc.on_packet_sent(1200, true).has_value(), "send in recovery");
    check(cc.on_packet_lost(packet(5ms, 1200), at(6ms)).has_value() &&
          cc.congestion_window() == 6000 && cc.recovery_start() == at(5ms),
          "same recovery epoch cannot halve twice");
    check(cc.on_ecn_ce(at(6ms), at(6ms)).has_value() &&
          cc.congestion_window() == 6000,
          "newer ECN cannot reduce during active recovery");
    check(cc.on_packet_sent(1200, true).has_value(), "send newer packet");
    check(cc.on_packet_acked(packet(6ms, 1200)).has_value() &&
          !cc.in_recovery_period() && cc.congestion_window() == 6000,
          "newer ACK exits recovery and starts avoidance credit");
    check(cc.on_packet_lost(packet(2ms, 1200), at(7ms)).has_value() &&
          cc.congestion_window() == 6000,
          "late loss from completed recovery does not halve again");
    for (int i = 0; i < 4; ++i) {
        check(cc.on_packet_sent(1200, true).has_value(), "send avoidance");
        check(cc.on_packet_acked(packet(7ms, 1200)).has_value(),
              "ACK avoidance");
    }
    check(cc.congestion_window() == 7200,
          "one cwnd of ACKed bytes adds one datagram");
    check(cc.on_packet_sent(1200, true).has_value(), "send later packet");
    check(cc.on_packet_lost(packet(7ms, 1200), at(8ms)).has_value() &&
          cc.congestion_window() == 3600,
          "later loss starts a new epoch");
    check(cc.on_ecn_ce(at(7ms), at(9ms)).has_value() &&
          cc.congestion_window() == 3600,
          "ECN from same epoch has no second reduction");
    check(cc.on_packet_acked(packet(8ms, 1200, false)).has_value() &&
          cc.congestion_window() == 3600,
          "non-flight ACK does not end recovery");
}

auto minimum_and_persistent() -> void
{
    newreno_congestion_controller cc;
    check(cc.on_ecn_ce(at(1ms), at(2ms)).has_value(), "initial ECN event");
    check(cc.on_packet_sent(1200, true).has_value() &&
          cc.on_packet_acked(packet(3ms, 1200)).has_value(),
          "ACK newer packet exits first recovery");
    check(cc.on_ecn_ce(at(3ms), at(4ms)).has_value() &&
          cc.congestion_window() == 3000,
          "next ECN epoch halves cwnd");
    check(cc.on_packet_sent(1200, true).has_value() &&
          cc.on_packet_acked(packet(5ms, 1200)).has_value(),
          "ACK newer packet exits second recovery");
    check(cc.on_ecn_ce(at(5ms), at(6ms)).has_value() &&
          cc.congestion_window() == 2400,
          "loss reduction clamps at two datagrams");
    cc.on_persistent_congestion();
    check(cc.congestion_window() == 2400 && !cc.recovery_start(),
          "persistent congestion resets to minimum window");
    check(cc.on_packet_sent(1200, true).has_value(), "send after persistent");
    check(cc.on_packet_acked(packet(7ms, 1200)).has_value() &&
          cc.congestion_window() == 3600,
          "persistent congestion resumes slow start");
}

auto boundaries() -> void
{
    newreno_congestion_controller cc;
    check(cc.on_packet_acked(packet(1ms, 1200)).error() ==
              congestion_error::flight_underflow &&
          cc.on_packet_discarded(packet(1ms, 1200)).error() ==
              congestion_error::flight_underflow,
          "retiring unsent in-flight bytes rejected");
    check(cc.on_packet_sent(1200, true).has_value(), "send for invalid time");
    check(cc.on_packet_lost(packet(2ms, 1200), at(1ms)).error() ==
              congestion_error::invalid_time &&
          cc.bytes_in_flight() == 1200 && !cc.recovery_start(),
          "future sent time leaves state unchanged");
    check(cc.on_ecn_ce(at(2ms), at(1ms)).error() ==
              congestion_error::invalid_time && !cc.recovery_start(),
          "future ECN time leaves state unchanged");
    check(cc.on_packet_acked(packet(1ms, 1201)).error() ==
              congestion_error::invalid_packet_size &&
          cc.bytes_in_flight() == 1200,
          "malformed retirement leaves state unchanged");

    const auto very_large = std::numeric_limits<std::size_t>::max() / 2;
    check(cc.reset(very_large).has_value() &&
          cc.congestion_window() == very_large * 2,
          "large legal datagram size computes capped initial cwnd");
    check(cc.on_packet_sent(very_large, true).has_value() &&
          cc.on_packet_sent(very_large, true).has_value(),
          "large flight reaches capacity without overflow");
    check(cc.on_packet_sent(2, true, true).error() ==
              congestion_error::flight_overflow &&
          cc.bytes_in_flight() == very_large * 2,
          "probe cannot overflow flight accounting");
    check(cc.on_packet_acked(packet(1ms, very_large)).has_value() &&
          cc.congestion_window() == std::numeric_limits<std::size_t>::max(),
          "slow-start growth saturates");
}

} // namespace

auto main() -> int
{
    initial_windows();
    flight_and_slow_start();
    recovery_and_avoidance();
    minimum_and_persistent();
    boundaries();
}
