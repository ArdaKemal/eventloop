#include "quic/loss_detection.h"

#include <chrono>
#include <cstdint>
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
    std::cerr << "QUIC loss detection: " << message << '\n';
    std::exit(1);
}

auto delays() -> void
{
    check(loss_delay(10ms, 20ms) == 22500us,
          "smoothed RTT selects larger value");
    check(loss_delay(20ms, 10ms) == 22500us,
          "latest RTT selects larger value");
    check(loss_delay(0us, 0us) == 1ms &&
          loss_delay(100us, 200us) == 1ms,
          "one millisecond minimum granularity");
    check(loss_delay(8ms, 0us) == 9ms &&
          loss_delay(9us, 0us) == 1ms,
          "nine-eighths multiplier and integer duration rounding");
    check(loss_delay(-1us, -2us) == 1ms,
          "negative RTTs cannot reduce granularity");
    check(loss_delay(recovery_duration::max(), 1us) ==
              recovery_duration::max(),
          "large RTT saturates without overflow");
    check(loss_delay(recovery_duration::max() / 2,
                     recovery_duration::max() / 2) ==
              saturated_add(recovery_duration::max() / 2,
                            (recovery_duration::max() / 2) / 8),
          "large finite RTT retains computed value");
}

auto thresholds() -> void
{
    check(!packet_threshold_lost(0) &&
          !packet_threshold_lost(1) &&
          !packet_threshold_lost(2) &&
          packet_threshold_lost(3) &&
          packet_threshold_lost(4),
          "packet threshold boundary");
    check(packet_threshold_lost(std::numeric_limits<std::uint64_t>::max()),
          "large transmitted-packet count");
    check(!time_threshold_lost(11249us, 10ms, 10ms) &&
          time_threshold_lost(11250us, 10ms, 10ms),
          "time threshold boundary");
    check(!time_threshold_lost(999us, 0us, 0us) &&
          time_threshold_lost(1ms, 0us, 0us),
          "minimum delay boundary");
    check(!time_threshold_lost(-1us, 0us, 0us),
          "negative elapsed time");
    check(!time_threshold_lost(recovery_duration::max() - 1us,
                               recovery_duration::max(), 0us) &&
          time_threshold_lost(recovery_duration::max(),
                              recovery_duration::max(), 0us),
          "saturated threshold boundary");
}

auto combined_predicate() -> void
{
    check(packet_is_lost(true, true, 3, 0us, 10ms, 10ms),
          "packet threshold triggers loss");
    check(packet_is_lost(true, true, 1, 11250us, 10ms, 10ms),
          "time threshold triggers loss");
    check(!packet_is_lost(true, true, 2, 11249us, 10ms, 10ms),
          "neither threshold reached");
    check(!packet_is_lost(false, true, 3, 1s, 10ms, 10ms) &&
          !packet_is_lost(true, false, 3, 1s, 10ms, 10ms),
          "acknowledged or non-flight packet excluded");
    check(!packet_is_lost(true, true, 0, 1s, 10ms, 10ms),
          "a packet needs a later acknowledged transmission");
}

} // namespace

auto main() -> int
{
    delays();
    thresholds();
    combined_predicate();
}
