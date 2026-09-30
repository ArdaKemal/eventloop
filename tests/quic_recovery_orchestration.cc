#include "quic/recovery_orchestration.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;
using namespace std::chrono_literals;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC recovery orchestration: " << message << '\n';
    std::exit(1);
}

auto at(std::chrono::milliseconds value) -> recovery_time_point
{ return recovery_time_point {value}; }

auto packet(std::uint64_t number, std::chrono::milliseconds time,
            bool ack_eliciting = true) -> sent_packet
{ return {number, at(time), ack_eliciting, true, 1200}; }

auto ack(std::uint64_t number) -> decoded_frame
{ return {.type = 0x02, .largest_acknowledged = number}; }

auto shared_flight_and_ack_atomicity() -> void
{
    recovery_orchestration<4> recovery;
    std::array<retired_packet, 12> output {};
    check(recovery.record(packet_number_space::initial,
                          packet(0, 0ms)).has_value() &&
          recovery.record(packet_number_space::handshake,
                          packet(0, 1ms)).has_value() &&
          recovery.congestion().bytes_in_flight() == 2400,
          "both number spaces share flight accounting");

    const auto first = ack(0);
    check(recovery.on_ack(packet_number_space::initial, first, at(100ms),
                          0us, std::span(output).first(0)).error().kind ==
              recovery_error_kind::output_full &&
          recovery.congestion().bytes_in_flight() == 2400 &&
          recovery.history(packet_number_space::initial)->size() == 1 &&
          !recovery.rtt().has_sample(),
          "small output leaves history, flight, and RTT unchanged");
    check(recovery.on_ack(packet_number_space::initial, first, at(100ms),
                          0us, output)->retired == 1 &&
          output[0].space == packet_number_space::initial &&
          output[0].reason == retirement_reason::acknowledged &&
          recovery.congestion().bytes_in_flight() == 1200 &&
          recovery.rtt().latest_rtt() == 100ms,
          "Initial ACK retires once and samples shared RTT");
    check(recovery.on_ack(packet_number_space::initial, first, at(101ms),
                          0us, output)->retired == 0 &&
          recovery.congestion().bytes_in_flight() == 1200 &&
          recovery.rtt().latest_rtt() == 100ms,
          "duplicate ACK does not retire twice");

    const auto invalid = ack(1);
    const auto failure = recovery.on_ack(packet_number_space::handshake,
                                         invalid, at(101ms), 0us, output);
    check(!failure && failure.error().kind == recovery_error_kind::history &&
          failure.error().history == sent_packet_error::invalid_ack &&
          recovery.history(packet_number_space::handshake)->size() == 1 &&
          recovery.congestion().bytes_in_flight() == 1200,
          "invalid ACK preserves shared state");
}

auto loss_alarm_and_discard() -> void
{
    recovery_orchestration<6> recovery;
    std::array<retired_packet, 18> output {};
    for (std::uint64_t number = 0; number < 4; ++number)
        check(recovery.record(packet_number_space::initial,
                              packet(number, 0ms)).has_value(),
              "record loss candidates");
    const auto result = recovery.on_ack(packet_number_space::initial, ack(3),
                                        at(1ms), 0us, output);
    check(result && result->retired == 2 &&
          output[0].packet.number == 3 &&
          output[0].reason == retirement_reason::acknowledged &&
          output[1].packet.number == 0 &&
          output[1].reason == retirement_reason::lost &&
          recovery.congestion().bytes_in_flight() == 2400,
          "packet threshold loss and ACK retire exactly once");
    const auto alarm = recovery.next_alarm();
    check(alarm && alarm->loss && alarm->space == packet_number_space::initial &&
          alarm->deadline == at(0ms) + 1125us,
          "time threshold deadline exposed");
    check(recovery.on_timeout(at(1ms), output)->retired == 0 &&
          recovery.congestion().bytes_in_flight() == 2400,
          "early timeout changes nothing");
    check(recovery.on_timeout(at(2ms), std::span(output).first(1))
              .error().kind == recovery_error_kind::output_full &&
          recovery.congestion().bytes_in_flight() == 2400,
          "loss output exhaustion is atomic");
    check(recovery.on_timeout(at(2ms), output)->retired == 2 &&
          output[0].reason == retirement_reason::lost &&
          output[1].reason == retirement_reason::lost &&
          recovery.congestion().bytes_in_flight() == 0 &&
          !recovery.next_alarm(),
          "time loss retires remaining flight");

    check(recovery.record(packet_number_space::handshake,
                          packet(0, 3ms)).has_value(),
          "record Handshake packet");
    check(recovery.discard_space(packet_number_space::handshake,
                                 std::span(output).first(0)).error().kind ==
              recovery_error_kind::output_full &&
          recovery.congestion().bytes_in_flight() == 1200,
          "discard capacity failure is atomic");
    check(recovery.discard_space(packet_number_space::handshake, output)
              ->retired == 1 &&
          output[0].reason == retirement_reason::discarded &&
          recovery.congestion().bytes_in_flight() == 0,
          "key discard retires flight without loss event");
    check(recovery.record(packet_number_space::handshake,
                          packet(1, 4ms)).error().kind ==
              recovery_error_kind::space_discarded,
          "discarded packet-number space cannot be reused");
}

auto pto_and_bounds() -> void
{
    recovery_orchestration<2> recovery;
    std::array<retired_packet, 6> output {};
    check(recovery.record(packet_number_space::application_data,
                          packet(0, 0ms)).has_value() &&
          !recovery.next_alarm(),
          "Application Data PTO waits for confirmation");
    recovery.set_handshake_confirmed(true);
    recovery.set_max_ack_delay(25ms);
    const auto first = recovery.next_alarm();
    check(first && !first->loss && first->deadline == at(1024ms),
          "confirmed Application Data PTO includes ACK delay");
    check(recovery.on_timeout(at(1024ms), output)->probe_count == 2 &&
          recovery.pto_count() == 1 &&
          recovery.congestion().bytes_in_flight() == 1200,
          "PTO requests two probes without synthesizing packets");
    check(recovery.next_alarm()->deadline == at(2048ms),
          "PTO backoff applies to next deadline");
    check(recovery.record(packet_number_space::application_data,
                          packet(1, 1025ms), true).has_value() &&
          recovery.congestion().bytes_in_flight() == 2400,
          "record transmitted probe through common flight path");
    check(recovery.on_ack(packet_number_space::application_data, ack(0),
                          at(1030ms), 0us, output)->retired == 1 &&
          recovery.pto_count() == 0,
          "acknowledged ack-eliciting packet resets PTO backoff");
    check(recovery.record(packet_number_space::application_data,
                          packet(2, 1031ms)).has_value() &&
          recovery.record(packet_number_space::application_data,
                          packet(3, 1032ms)).error().kind ==
              recovery_error_kind::history &&
          recovery.history(packet_number_space::application_data)->size() == 2,
          "fixed history capacity rejects additional packet");
    check(!recovery.record(static_cast<packet_number_space>(3),
                           packet(0, 0ms)) &&
          recovery.history(static_cast<packet_number_space>(3)) == nullptr,
          "invalid space is rejected");
}

auto lower_ack_keeps_loss_threshold() -> void
{
    recovery_orchestration<3> recovery;
    std::array<retired_packet, 9> output {};
    for (std::uint64_t number = 0; number < 3; ++number)
        check(recovery.record(packet_number_space::initial,
                              packet(number, 0ms, number != 0)).has_value(),
              "record three outstanding packets");
    check(recovery.on_ack(packet_number_space::initial, ack(2),
                          at(1ms), 0us, output)->retired == 1,
          "highest ACK leaves younger loss candidates");
    const auto result = recovery.on_ack(packet_number_space::initial,
                                        ack(0), at(2ms), 0us, output);
    check(result && result->retired == 2 &&
          output[0].packet.number == 0 &&
          output[0].reason == retirement_reason::acknowledged &&
          output[1].packet.number == 1 &&
          output[1].reason == retirement_reason::lost &&
          recovery.congestion().bytes_in_flight() == 0,
          "lower ACK uses space high-water mark for time loss");
}

auto persistent_congestion(bool cross_space_ack, bool prior_sample,
                           std::chrono::milliseconds second_send,
                           bool late_ack = false)
    -> bool
{
    recovery_orchestration<4> recovery;
    std::array<retired_packet, 12> output {};
    check(recovery.record(packet_number_space::initial,
                          packet(0, 0ms)).has_value(),
          "record RTT sample packet");
    if (!prior_sample)
        check(recovery.record(packet_number_space::initial,
                              packet(1, 1ms)).has_value(),
              "record pre-sample loss candidate");
    check(recovery.on_ack(packet_number_space::initial, ack(0), at(100ms),
                          0us, output)->retired == 1,
          "establish RTT sample");
    if (prior_sample)
        check(recovery.record(packet_number_space::initial,
                              packet(1, 101ms)).has_value(),
              "record post-sample loss candidate");
    if (cross_space_ack) {
        check(recovery.record(packet_number_space::handshake,
                              packet(0, 500ms)).has_value() &&
              recovery.on_ack(packet_number_space::handshake, ack(0),
                              at(501ms), 0us, output)->retired == 1,
              "ACK in another space separates losses");
    }
    check(recovery.record(packet_number_space::initial,
                          packet(2, second_send)).has_value() &&
          recovery.record(packet_number_space::initial,
                          packet(3, second_send + 1ms, false)).has_value(),
          "record second candidate and non-eliciting ACK target");
    const auto first = recovery.on_ack(packet_number_space::initial, ack(3),
                                       at(second_send + 2ms), 0us, output);
    check(first && first->retired == 2 && !first->persistent_congestion &&
          recovery.rtt().has_sample(),
          "first loss leaves second candidate pending");
    if (late_ack) {
        const auto acknowledged_loss = recovery.on_ack(
            packet_number_space::initial, ack(1),
            at(second_send + 3ms), 0us, output);
        check(acknowledged_loss && acknowledged_loss->retired == 0 &&
              !acknowledged_loss->persistent_congestion,
              "late ACK of a lost packet updates congestion history");
    }
    const auto second = recovery.on_timeout(at(second_send + 200ms), output);
    check(second && second->retired == 1 &&
          output[0].packet.number == 2,
          "loss alarm retires second candidate");
    return second->persistent_congestion;
}

auto persistent_congestion_edges() -> void
{
    check(persistent_congestion(false, true, 1001ms) == false,
          "duration equal to threshold is insufficient");
    check(persistent_congestion(false, true, 1002ms),
          "duration greater than threshold collapses window");
    check(!persistent_congestion(false, false, 1002ms),
          "both endpoints require a prior RTT sample");
    check(!persistent_congestion(true, true, 1300ms),
          "ACK across packet-number spaces blocks persistent congestion");
    check(!persistent_congestion(false, true, 1300ms, true),
          "late ACK of a lost packet breaks the loss period");
}

auto event_capacity_is_atomic() -> void
{
    recovery_orchestration<2> recovery;
    std::array<retired_packet, 6> output {};
    check(recovery.record(packet_number_space::initial,
                          packet(0, 0ms)).has_value() &&
          recovery.record(packet_number_space::handshake,
                          packet(0, 0ms)).has_value() &&
          recovery.on_ack(packet_number_space::handshake, ack(0),
                          at(100ms), 0us, output)->retired == 1,
          "retain a cross-space outstanding packet");
    for (std::uint64_t pair = 0; pair < 2; ++pair) {
        const auto start = std::chrono::milliseconds {101 + 1000 * pair};
        check(recovery.record(packet_number_space::handshake,
                              packet(2 * pair + 1, start)).has_value() &&
              recovery.record(packet_number_space::handshake,
                              packet(2 * pair + 2, start + 800ms, false))
                  .has_value() &&
              recovery.on_ack(packet_number_space::handshake,
                              ack(2 * pair + 2), at(start + 801ms),
                              0us, output)->retired == 2,
              "fill bounded persistent-congestion event history");
    }
    check(recovery.record(packet_number_space::handshake,
                          packet(5, 2101ms)).has_value() &&
          recovery.record(packet_number_space::handshake,
                          packet(6, 2901ms, false)).has_value(),
          "record packets at event capacity");
    const auto flight = recovery.congestion().bytes_in_flight();
    const auto failed = recovery.on_ack(packet_number_space::handshake,
                                        ack(6), at(2902ms), 0us, output);
    check(!failed &&
          failed.error().kind == recovery_error_kind::capacity_exhausted &&
          recovery.congestion().bytes_in_flight() == flight &&
          recovery.history(packet_number_space::handshake)->size() == 2 &&
          recovery.rtt().smoothed_rtt() == 100ms,
          "event overflow preserves flight, history, and RTT");
}

auto loss_precedes_ack_window_growth() -> void
{
    recovery_orchestration<4> recovery;
    std::array<retired_packet, 12> output {};
    for (std::uint64_t pn = 0; pn < 4; ++pn)
        check(recovery.record(packet_number_space::initial, packet(pn, 0ms))
                  .has_value(), "record congestion-event batch");
    check(recovery.on_ack(packet_number_space::initial, ack(3), at(1ms),
                          0us, output)->retired == 2 &&
          recovery.congestion().congestion_window() == 6000,
          "loss starts recovery before ACK growth in the same batch");
}

auto loss_timer_has_absolute_priority() -> void
{
    recovery_orchestration<3> recovery;
    recovery.set_handshake_confirmed(true);
    std::array<retired_packet, 9> output {};
    check(recovery.record(packet_number_space::initial, packet(0, 0ms)).has_value() &&
          recovery.record(packet_number_space::application_data,
                          packet(0, 1000ms)).has_value() &&
          recovery.record(packet_number_space::application_data,
                          packet(1, 1000ms)).has_value(), "record mixed timer spaces");
    check(recovery.on_ack(packet_number_space::application_data, ack(1),
                          at(1001ms), 0us, output)->retired == 1,
          "establish loss alarm alongside older PTO candidate");
    const auto alarm = recovery.next_alarm();
    check(alarm && alarm->loss &&
          alarm->space == packet_number_space::application_data &&
          alarm->deadline == at(1000ms) + 1125us,
          "loss alarm suppresses even an earlier PTO");
    recovery.set_pto_blocked(true);
    check(recovery.next_alarm()->loss &&
          recovery.on_timeout(at(1001ms), output)->probe_count == 0 &&
          recovery.pto_count() == 0,
          "amplification blocking preserves loss timer and no premature PTO");
    check(recovery.on_timeout(at(1002ms), output)->retired == 1 &&
          !recovery.next_alarm(), "loss retires while PTO is amplification blocked");
    recovery.set_pto_blocked(false);
    check(recovery.next_alarm() && !recovery.next_alarm()->loss,
          "receiving amplification credit permits PTO again");
}

auto discard_resets_backoff() -> void
{
    recovery_orchestration<2> recovery;
    std::array<retired_packet, 6> output {};
    check(recovery.record(packet_number_space::initial, packet(0, 0ms)).has_value() &&
          recovery.on_timeout(at(999ms), output)->probe_count == 2 &&
          recovery.pto_count() == 1, "arm shared PTO backoff");
    check(recovery.record(packet_number_space::handshake,
                          packet(0, 1000ms)).has_value(), "record surviving space");
    check(recovery.discard_space(packet_number_space::initial,
                                std::span(output).first(0)).error().kind ==
              recovery_error_kind::output_full && recovery.pto_count() == 1,
          "failed discard preserves backoff");
    check(recovery.discard_space(packet_number_space::initial, output)->retired == 1 &&
          recovery.pto_count() == 0 &&
          recovery.next_alarm()->space == packet_number_space::handshake &&
          recovery.next_alarm()->deadline == at(1999ms),
          "key discard resets PTO backoff for remaining space");
    check(recovery.on_ack(packet_number_space::initial, ack(0), at(1001ms),
                          0us, output).error().kind ==
              recovery_error_kind::space_discarded,
          "discarded space cannot process ACKs");
}

auto client_handshake_antideadlock() -> void
{
    recovery_orchestration<3> recovery;
    std::array<retired_packet, 9> output {};
    check(recovery.configure_client_handshake_probe(
              packet_number_space::application_data, at(0ms)).error().kind ==
              recovery_error_kind::invalid_space && !recovery.next_alarm(),
          "invalid handshake probe configuration is atomic");
    check(recovery.configure_client_handshake_probe(packet_number_space::initial,
                                                    at(0ms)).has_value() &&
          recovery.next_alarm()->deadline == at(999ms),
          "client arms Initial PTO without flight");
    check(recovery.on_timeout(at(999ms), output)->probe_space ==
              packet_number_space::initial && recovery.pto_count() == 1,
          "no-flight timeout requests an Initial probe");
    check(recovery.record(packet_number_space::initial,
                          packet(0, 1000ms), true).has_value() &&
          recovery.on_ack(packet_number_space::initial, ack(0), at(1001ms),
                          0us, output)->retired == 1 && recovery.pto_count() == 1 &&
          recovery.next_alarm(),
          "Initial ACK neither resets client backoff nor ends no-flight probing");
    check(recovery.configure_client_handshake_probe(packet_number_space::handshake,
                                                    at(1002ms)).has_value() &&
          recovery.next_alarm()->space == packet_number_space::handshake,
          "Handshake key availability changes anti-deadlock probe space");
    check(recovery.record(packet_number_space::handshake,
                          packet(0, 1002ms), true).has_value() &&
          recovery.on_ack(packet_number_space::handshake, ack(0), at(1003ms),
                          0us, output)->retired == 1 &&
          recovery.pto_count() == 0 && !recovery.next_alarm(),
          "Handshake ACK proves validation and cancels no-flight timer");
    check(recovery.configure_client_handshake_probe(packet_number_space::handshake,
                                                    at(1004ms)).has_value(),
          "rearm client probe for confirmation case");
    recovery.set_handshake_confirmed(true);
    check(!recovery.next_alarm(), "handshake confirmation cancels anti-deadlock timer");
}

auto ack_only_progress_resets_pto() -> void
{
    recovery_orchestration<2> recovery;
    std::array<retired_packet, 6> output {};
    check(recovery.record(packet_number_space::initial, packet(0, 0ms)).has_value() &&
          recovery.record(packet_number_space::initial, packet(1, 1ms, false))
              .has_value() &&
          recovery.on_timeout(at(999ms), output)->probe_count == 2,
          "backoff before ACK of non-eliciting packet");
    check(recovery.on_ack(packet_number_space::initial, ack(1), at(1000ms),
                          0us, output)->retired == 2 && recovery.pto_count() == 0,
          "validated peer ACK progress resets backoff even without eliciting ACK");
}

auto ecn_shares_the_path_controller() -> void
{
    recovery_orchestration<2> recovery;
    std::array<retired_packet, 6> output {};
    check(recovery.record(packet_number_space::initial, packet(0, 0ms)).has_value(),
          "record ECN-marked transmission");
    check(recovery.on_ecn_ce(at(1ms), at(0ms)).error().congestion ==
              congestion_error::invalid_time &&
          recovery.congestion().congestion_window() == 12000 &&
          recovery.congestion().bytes_in_flight() == 1200,
          "invalid ECN timestamp preserves congestion state");
    check(recovery.on_ecn_ce(at(0ms), at(1ms)).has_value() &&
          recovery.congestion().congestion_window() == 6000 &&
          recovery.congestion().bytes_in_flight() == 1200,
          "validated CE starts path recovery without retiring flight");
    check(recovery.on_ecn_ce(at(0ms), at(2ms)).has_value() &&
          recovery.on_ack(packet_number_space::initial, ack(0), at(2ms),
                          0us, output)->retired == 1 &&
          recovery.congestion().congestion_window() == 6000 &&
          recovery.congestion().bytes_in_flight() == 0,
          "duplicate CE and same-epoch ACK do not grow or reduce twice");
}

} // namespace

auto main() -> int
{
    shared_flight_and_ack_atomicity();
    loss_alarm_and_discard();
    pto_and_bounds();
    lower_ack_keeps_loss_threshold();
    persistent_congestion_edges();
    event_capacity_is_atomic();
    loss_precedes_ack_window_growth();
    loss_timer_has_absolute_priority();
    discard_resets_backoff();
    client_handshake_antideadlock();
    ack_only_progress_resets_pto();
    ecn_shares_the_path_controller();
}
