#include "quic/recovery_timer.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;
using namespace std::chrono_literals;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC recovery timer: " << message << '\n';
    std::exit(1);
}

auto initial_state_and_pto() -> void
{
    const rtt_estimator estimator;
    check(!estimator.has_sample() && estimator.latest_rtt() == 0us &&
              estimator.smoothed_rtt() == 333ms &&
              estimator.rttvar() == 166500us,
          "RFC 9002 initial RTT state");
    check(estimator.pto_duration(packet_number_space::initial, false, 25ms, 0)
              == 999ms,
          "Initial PTO ignores max_ack_delay");
    check(estimator.pto_duration(packet_number_space::handshake, false, 25ms, 0)
              == 999ms,
          "Handshake PTO ignores max_ack_delay");
    check(!estimator.pto_duration(packet_number_space::application_data,
                                  false, 25ms, 0),
          "Application Data PTO unavailable before confirmation");
    check(estimator.pto_duration(packet_number_space::application_data,
                                 true, 25ms, 0) == 1024ms,
          "confirmed Application Data includes max_ack_delay");
    check(estimator.pto_duration(packet_number_space::initial, false, 25ms, 2)
              == 3996ms,
          "PTO backoff doubles across spaces");
}

auto appendix_a7_rtt_update() -> void
{
    rtt_estimator estimator;
    estimator.update(100ms, 70ms, 10ms,
                     packet_number_space::application_data, true);
    check(estimator.has_sample() && estimator.latest_rtt() == 100ms &&
              estimator.min_rtt() == 100ms &&
              estimator.smoothed_rtt() == 100ms && estimator.rttvar() == 50ms,
          "Appendix A.7 first sample ignores ACK delay");

    estimator.update(140ms, 20ms, 10ms,
                     packet_number_space::application_data, true);
    check(estimator.latest_rtt() == 140ms && estimator.min_rtt() == 100ms &&
              estimator.rttvar() == 45ms &&
              estimator.smoothed_rtt() == 103750us,
          "Appendix A.7 deviation uses previous smoothed RTT (erratum 7539)");
    check(estimator.pto_duration(packet_number_space::initial, true, 25ms, 0)
              == 283750us &&
              estimator.pto_duration(packet_number_space::application_data,
                                     true, 25ms, 2) == 1235ms,
          "space-specific PTO with RTT estimate and backoff");

    estimator.update(90ms, 80ms, 25ms,
                     packet_number_space::application_data, true);
    check(estimator.min_rtt() == 90ms && estimator.rttvar() == 37187us &&
              estimator.smoothed_rtt() == 102031us,
          "ACK delay cannot lower adjusted RTT below min_rtt");
}

auto ack_delay_policy() -> void
{
    rtt_estimator before_confirmation;
    before_confirmation.update(100ms, 0us, 10ms,
                               packet_number_space::handshake, false);
    before_confirmation.update(140ms, 20ms, 10ms,
                               packet_number_space::handshake, false);
    check(before_confirmation.smoothed_rtt() == 102500us &&
              before_confirmation.rttvar() == 42500us,
          "reported ACK delay is uncapped before confirmation");

    rtt_estimator initial_space;
    initial_space.update(100ms, 0us, 10ms,
                         packet_number_space::initial, false);
    initial_space.update(140ms, 20ms, 10ms,
                         packet_number_space::initial, false);
    check(initial_space.smoothed_rtt() == 105ms &&
              initial_space.rttvar() == 47500us,
          "Initial ACK delay ignored");

    rtt_estimator implausible_delay;
    implausible_delay.update(100ms, 0us, 25ms,
                             packet_number_space::handshake, false);
    implausible_delay.update(110ms, 50ms, 25ms,
                             packet_number_space::handshake, false);
    check(implausible_delay.smoothed_rtt() == 101250us &&
              implausible_delay.rttvar() == 40ms,
          "ACK delay that crosses min_rtt is not subtracted");
}

auto clamping_and_saturation() -> void
{
    rtt_estimator estimator {0us};
    check(estimator.pto_duration(packet_number_space::initial, false, 0us, 0,
                                 0us) == 1us,
          "PTO has positive minimum granularity");
    estimator.update(-10us, -1us, -1us,
                     packet_number_space::initial, false);
    check(estimator.latest_rtt() == 0us && estimator.min_rtt() == 0us,
          "negative sample clamped");
    estimator.reset(250ms);
    check(!estimator.has_sample() && estimator.smoothed_rtt() == 250ms &&
              estimator.rttvar() == 125ms,
          "new-path reset restores initial estimate");

    const rtt_estimator large {recovery_duration::max()};
    check(large.pto_duration(packet_number_space::initial, false, 0us, 0)
              == recovery_duration::max() &&
              large.pto_duration(packet_number_space::application_data,
                                 true, recovery_duration::max(), 1000)
              == recovery_duration::max(),
          "PTO addition, variance, and backoff saturate");
    check(saturated_add(recovery_duration::max(), 1us)
              == recovery_duration::max() &&
              saturated_multiply(recovery_duration::max(), 4)
              == recovery_duration::max(),
          "duration arithmetic saturates");
    check(weighted_average(recovery_duration::max(),
                           recovery_duration::max(), 8)
              == recovery_duration::max(),
          "weighted average does not overflow");
}

auto loss_deadline_selection() -> void
{
    using deadline = std::optional<recovery_time_point>;
    const auto origin = recovery_time_point {};
    const std::array none {deadline {}, deadline {}, deadline {}};
    check(!earliest_loss_deadline(none), "no loss deadline pending");

    const std::array mixed {
        deadline {origin + 5ms}, deadline {}, deadline {origin + 10ms},
    };
    const auto first = earliest_loss_deadline(mixed);
    check(first && first->space == packet_number_space::initial &&
              first->deadline == origin + 5ms,
          "absent Handshake deadline cannot replace earlier Initial deadline");

    const std::array zero_time {
        deadline {}, deadline {origin}, deadline {origin + 1ms},
    };
    const auto second = earliest_loss_deadline(zero_time);
    check(second && second->space == packet_number_space::handshake &&
              second->deadline == origin,
          "zero time point is a valid earliest deadline");
}

} // namespace

auto main() -> int
{
    initial_state_and_pto();
    appendix_a7_rtt_update();
    ack_delay_policy();
    clamping_and_saturation();
    loss_deadline_selection();
}
