#include "quic/sent_packet_history.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
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
    std::cerr << "QUIC sent packet history: " << message << '\n';
    std::exit(1);
}

auto packet(std::uint64_t number) -> sent_packet
{
    return sent_packet {number, recovery_time_point {} +
                                   recovery_duration {static_cast<std::int64_t>(number)},
                        number % 2 == 0, true, 100 + static_cast<std::size_t>(number)};
}

auto send_order_and_capacity() -> void
{
    sent_packet_history<2, 2> history;
    check(!history.highest_sent() && history.size() == 0,
          "empty history");
    check(history.record(packet(1)).has_value(),
          "first packet may have a nonzero number");
    check(history.record(packet(1)).error() ==
              sent_packet_error::invalid_packet_number &&
          history.record(packet(0)).error() ==
              sent_packet_error::invalid_packet_number,
          "numbers must increase strictly");
    check(history.record(packet(3)).has_value(), "record number gap");
    check(history.record(packet(4)).error() ==
              sent_packet_error::capacity_exhausted,
          "capacity exhaustion");
    check(history.size() == 2 && history.highest_sent() == 3 &&
          history.remaining()[0].number == 1 &&
          history.remaining()[1].number == 3,
          "failed records do not mutate history");
    check(history.remove(1) && !history.remove(1), "explicit removal");
    check(history.record(packet(4)).has_value() &&
          history.highest_sent() == 4 && history.remaining()[0].number == 3 &&
          history.remaining()[1].number == 4,
          "removal frees capacity without reusing packet number");
    check(history.remove(3), "free outstanding slot");
    check(history.record(packet(6)).error() ==
              sent_packet_error::capacity_exhausted &&
          history.highest_sent() == 4 && history.size() == 1,
          "sent-range capacity exhaustion is atomic");
    history.reset();
    check(history.size() == 0 && !history.highest_sent() &&
          !history.largest_acked() &&
          history.record(packet(0)).has_value(),
          "reset restarts packet-number space");
}

auto gapped_ack_validation() -> void
{
    sent_packet_history<4> history;
    constexpr std::array<std::uint64_t, 4> numbers {0, 2, 3, 6};
    for (const auto number : numbers)
        check(history.record(packet(number)).has_value(),
              "record gapped packet numbers");
    std::array<sent_packet, 4> output {};
    decoded_frame unsent_largest {.type = 0x02, .largest_acknowledged = 5};
    check(history.acknowledge(unsent_largest, output).error() ==
              sent_packet_error::invalid_ack &&
          history.size() == 4 && !history.largest_acked(),
          "reject unsent number below high-water mark");
    decoded_frame spans_gap {.type = 0x02, .largest_acknowledged = 3,
                             .first_ack_range = 2};
    check(history.acknowledge(spans_gap, output).error() ==
              sent_packet_error::invalid_ack &&
          history.size() == 4 && !history.largest_acked(),
          "reject ACK range that includes an unsent number");
    decoded_frame valid {.type = 0x02, .largest_acknowledged = 3,
                         .first_ack_range = 1};
    check(history.acknowledge(valid, output) == 2 &&
          output[0].number == 3 && output[1].number == 2 &&
          history.largest_acked() == 3,
          "ACK valid gapped range");
    decoded_frame removed {.type = 0x02, .largest_acknowledged = 2};
    check(history.acknowledge(removed, output) == 0,
          "duplicate ACK remains valid after record removal");
    check(history.detect_lost(5, recovery_time_point {} + 1ms,
                              100ms, 100ms, output).error() ==
              sent_packet_error::invalid_ack && history.size() == 2,
          "loss scan rejects an unsent largest ACK");
}

auto ack_ranges_and_duplicates() -> void
{
    sent_packet_history<12> history;
    for (std::uint64_t number = 0; number <= 10; ++number)
        check(history.record(packet(number)).has_value(), "record packet");

    // ACKs [9,10], [5,7], [2,3] in descending packet-number order.
    constexpr std::array<std::byte, 9> bytes {
        std::byte {0x02}, std::byte {10}, std::byte {0},
        std::byte {2}, std::byte {1}, std::byte {0},
        std::byte {2}, std::byte {0}, std::byte {1}};
    const auto frame = decode_frame(bytes);
    check(frame.has_value(), "decode multiple ACK ranges");
    std::array<sent_packet, 12> output {};
    const auto count = history.acknowledge(*frame, output);
    check(count == 7 && history.largest_acked() == 10,
          "seven newly acknowledged records and largest ACK");
    constexpr std::array<std::uint64_t, 7> expected {10, 9, 7, 6, 5, 3, 2};
    for (std::size_t index = 0; index < expected.size(); ++index) {
        check(output[index].number == expected[index] &&
              output[index].bytes == 100 + expected[index] &&
              output[index].in_flight,
              "descending output and metadata");
    }
    constexpr std::array<std::uint64_t, 4> remaining {0, 1, 4, 8};
    check(history.size() == remaining.size() && history.highest_sent() == 10,
          "ACK removes only covered records");
    for (std::size_t index = 0; index < remaining.size(); ++index)
        check(history.remaining()[index].number == remaining[index],
              "remaining records stay ordered");
    check(history.acknowledge(*frame, output) == 0 && history.size() == 4 &&
          history.largest_acked() == 10,
          "duplicate ACK is harmless");
    check(history.remove(4), "remove retained record");
    constexpr std::array<std::byte, 5> removed_ack {
        std::byte {0x02}, std::byte {4}, std::byte {0},
        std::byte {0}, std::byte {0}};
    check(history.acknowledge(*decode_frame(removed_ack), output) == 0,
          "ACK of explicitly removed sent number is harmless");
}

auto atomic_failures() -> void
{
    sent_packet_history<4> history;
    for (std::uint64_t number = 0; number < 4; ++number)
        check(history.record(packet(number)).has_value(), "record for failure cases");
    std::array<sent_packet, 4> output {};
    constexpr std::array<std::byte, 5> two_bytes {
        std::byte {0x02}, std::byte {3}, std::byte {0},
        std::byte {0}, std::byte {1}};
    const auto two = decode_frame(two_bytes);
    check(two.has_value(), "decode two-packet ACK");
    check(history.acknowledge(*two, std::span(output).first(1)).error() ==
              sent_packet_error::output_full &&
          history.size() == 4 && history.remaining()[3].number == 3,
          "small output does not change ledger");

    decoded_frame unsent {.type = 0x02, .largest_acknowledged = 4};
    check(history.acknowledge(unsent, output).error() ==
              sent_packet_error::invalid_ack && history.size() == 4,
          "reject ACK above highest sent");
    constexpr std::array<std::byte, 2> bad_gap {
        std::byte {3}, std::byte {0}};
    decoded_frame malformed {.type = 0x02, .largest_acknowledged = 3,
                             .ack_range_count = 1, .ack_ranges = bad_gap};
    check(history.acknowledge(malformed, output).error() ==
              sent_packet_error::invalid_ack && history.size() == 4,
          "malformed range does not change ledger");
    constexpr std::array<std::byte, 2> trailing {
        std::byte {0}, std::byte {0}};
    decoded_frame extra {.type = 0x02, .largest_acknowledged = 3,
                         .ack_ranges = trailing};
    check(history.acknowledge(extra, output).error() ==
              sent_packet_error::invalid_ack && history.size() == 4,
          "trailing ACK bytes do not change ledger");
    check(history.acknowledge(*two, output) == 2 &&
          output[0].number == 3 && output[1].number == 2 &&
          history.size() == 2,
          "valid ACK succeeds after failures");
}

auto packet_threshold_losses() -> void
{
    sent_packet_history<6> history;
    for (std::uint64_t number = 0; number < 6; ++number)
        check(history.record(packet(number)).has_value(),
              "record packet for packet threshold");
    std::array<sent_packet, 6> output {};
    const auto result = history.detect_lost(
        5, recovery_time_point {} + 1ms, 100ms, 100ms, output);
    check(result && result->count == 3 &&
          output[0].number == 2 && output[1].number == 1 &&
          output[2].number == 0,
          "packet threshold removes three older packets descending");
    check(result->next_delay == 111503us && history.size() == 3 &&
          history.remaining()[0].number == 3 &&
          history.remaining()[1].number == 4 &&
          history.remaining()[2].number == 5,
          "next deadline and newer records remain");
    const auto repeated = history.detect_lost(
        5, recovery_time_point {} + 1ms, 100ms, 100ms, output);
    check(repeated && repeated->count == 0 &&
          repeated->next_delay == 111503us,
          "removed losses are not reported twice");
}

auto packet_threshold_with_send_gaps() -> void
{
    sent_packet_history<4> history;
    constexpr std::array<std::uint64_t, 4> numbers {0, 100, 101, 102};
    for (const auto number : numbers)
        check(history.record(packet(number)).has_value(),
              "record packets across a large number gap");
    std::array<sent_packet, 4> output {};
    const auto now = recovery_time_point {} + 1ms;
    const auto before = history.detect_lost(101, now, 100ms, 100ms, output);
    check(before && before->count == 0 && history.size() == 4 &&
          history.remaining()[0].number == 0,
          "numeric gap with two later transmissions does not trigger loss");
    check(history.remove(100), "retire a later transmitted packet");
    const auto at = history.detect_lost(102, now, 100ms, 100ms, output);
    check(at && at->count == 1 && output[0].number == 0 &&
          history.size() == 2 && history.remaining()[0].number == 101 &&
          history.remaining()[1].number == 102,
          "three later transmissions trigger loss after one is retired");
}

auto time_threshold_and_candidates() -> void
{
    sent_packet_history<3> history;
    check(history.record(sent_packet {0, recovery_time_point {},
                                      true, true, 100}).has_value(),
          "record time candidate zero");
    check(history.record(sent_packet {1, recovery_time_point {} + 1ms,
                                      true, true, 100}).has_value(),
          "record time candidate one");
    check(history.record(sent_packet {2, recovery_time_point {} + 2ms,
                                      true, true, 100}).has_value(),
          "record largest acknowledged");
    std::array<sent_packet, 3> output {};
    const auto before = history.detect_lost(
        2, recovery_time_point {} + 8ms, 8ms, 8ms, output);
    check(before && before->count == 0 && before->next_delay == 1ms &&
          history.size() == 3,
          "time threshold not reached and earliest deadline selected");
    const auto at = history.detect_lost(
        2, recovery_time_point {} + 9ms, 8ms, 8ms, output);
    check(at && at->count == 1 && output[0].number == 0 &&
          at->next_delay == 1ms && history.size() == 2,
          "time threshold exact boundary");
    const auto later = history.detect_lost(
        2, recovery_time_point {} + 10ms, 8ms, 8ms, output);
    check(later && later->count == 1 && output[0].number == 1 &&
          !later->next_delay && history.size() == 1 &&
          history.remaining()[0].number == 2,
          "later deadline and packet at largest ACK excluded");
    const auto none = history.detect_lost(
        2, recovery_time_point {} + 1s, 8ms, 8ms, output);
    check(none && none->count == 0 && !none->next_delay,
          "no earlier candidates");
}

auto loss_errors_and_nonflight() -> void
{
    sent_packet_history<5> history;
    for (std::uint64_t number = 0; number < 5; ++number) {
        auto candidate = packet(number);
        if (number == 2) candidate.in_flight = false;
        check(history.record(candidate).has_value(), "record loss candidate");
    }
    std::array<sent_packet, 5> output {};
    const auto now = recovery_time_point {} + 1ms;
    check(history.detect_lost(5, now, 100ms, 100ms, output).error() ==
              sent_packet_error::invalid_ack && history.size() == 5,
          "invalid high ACK leaves state unchanged");
    check(history.detect_lost(4, now, 100ms, 100ms,
                              std::span(output).first(1)).error() ==
              sent_packet_error::output_full && history.size() == 5 &&
          history.remaining()[0].number == 0,
          "output-full loss scan is atomic");
    const auto result = history.detect_lost(4, now, 100ms, 100ms, output);
    check(result && result->count == 2 && output[0].number == 1 &&
          output[1].number == 0 && history.size() == 3 &&
          history.remaining()[0].number == 2 &&
          history.remaining()[1].number == 3 &&
          history.remaining()[2].number == 4,
          "non-flight packet remains and packet threshold losses removed");
    check(result->next_delay == 111503us,
          "earliest remaining time threshold deadline");

    sent_packet_history<2> future;
    check(future.record(packet(0)).has_value() &&
          future.record(packet(1)).has_value(), "record future-time case");
    check(future.detect_lost(1, recovery_time_point {} - 1us,
                             1ms, 1ms, output).error() ==
              sent_packet_error::invalid_time && future.size() == 2,
          "clock before candidate send time is rejected atomically");

    sent_packet_history<2> extreme;
    check(extreme.record(sent_packet {0, recovery_time_point::min(),
                                      true, true, 1}).has_value() &&
          extreme.record(sent_packet {1, recovery_time_point::max(),
                                      true, true, 1}).has_value(),
          "record extreme clock values");
    const auto large = extreme.detect_lost(
        1, recovery_time_point::max(), recovery_duration::max(),
        recovery_duration::max(), output);
    check(large && large->count == 0 && large->next_delay &&
          *large->next_delay > recovery_duration::zero() &&
          extreme.size() == 2,
          "extreme clock difference does not overflow");
}

auto rtt_ack_sampling() -> void
{
    sent_packet_history<4> history;
    std::array<sent_packet, 4> output {};
    check(history.record(sent_packet {0, recovery_time_point {},
                                      true, true, 100}).has_value() &&
          history.record(sent_packet {1, recovery_time_point {} + 1ms,
                                      true, true, 100}).has_value(),
          "record first RTT candidates");
    rtt_estimator estimator;
    decoded_frame first {.type = 0x02, .largest_acknowledged = 0};
    check(history.acknowledge_with_rtt(
              first, recovery_time_point {} + 100ms, 80ms, 10ms,
              packet_number_space::application_data, true,
              estimator, output) == 1 &&
          estimator.has_sample() && estimator.latest_rtt() == 100ms &&
          estimator.smoothed_rtt() == 100ms &&
          history.largest_acked() == 0,
          "first RTT sample ignores ACK delay");

    decoded_frame second {.type = 0x02, .largest_acknowledged = 1};
    check(history.acknowledge_with_rtt(
              second, recovery_time_point {} + 141ms, 20ms, 10ms,
              packet_number_space::application_data, true,
              estimator, output) == 1 &&
          estimator.latest_rtt() == 140ms &&
          estimator.smoothed_rtt() == 103750us &&
          estimator.rttvar() == 45ms && history.largest_acked() == 1,
          "later RTT uses capped ACK delay and previous smoothed RTT");
    check(history.acknowledge_with_rtt(
              second, recovery_time_point {} + 1s, 20ms, 10ms,
              packet_number_space::application_data, true,
              estimator, output) == 0 &&
          estimator.latest_rtt() == 140ms && history.largest_acked() == 1,
          "duplicate ACK does not sample RTT");
}

auto rtt_ack_delay_spaces() -> void
{
    std::array<sent_packet, 2> output {};
    decoded_frame first {.type = 0x02, .largest_acknowledged = 0};
    decoded_frame second {.type = 0x02, .largest_acknowledged = 1};

    sent_packet_history<2> initial;
    rtt_estimator initial_rtt_state;
    for (std::uint64_t number = 0; number < 2; ++number)
        check(initial.record(sent_packet {number, recovery_time_point {},
                                          true, true, 100}).has_value(),
              "record Initial packets");
    check(initial.acknowledge_with_rtt(
              first, recovery_time_point {} + 100ms, 0us, 10ms,
              packet_number_space::initial, false,
              initial_rtt_state, output) == 1,
          "Initial first sample");
    check(initial.acknowledge_with_rtt(
              second, recovery_time_point {} + 140ms, 20ms, 10ms,
              packet_number_space::initial, true,
              initial_rtt_state, output) == 1 &&
          initial_rtt_state.smoothed_rtt() == 105ms &&
          initial_rtt_state.rttvar() == 47500us,
          "Initial ignores decoded ACK delay");

    sent_packet_history<2> unconfirmed;
    rtt_estimator unconfirmed_rtt;
    for (std::uint64_t number = 0; number < 2; ++number)
        check(unconfirmed.record(sent_packet {number, recovery_time_point {},
                                              true, true, 100}).has_value(),
              "record pre-confirmation packets");
    check(unconfirmed.acknowledge_with_rtt(
              first, recovery_time_point {} + 100ms, 0us, 10ms,
              packet_number_space::handshake, false,
              unconfirmed_rtt, output) == 1,
          "pre-confirmation first sample");
    check(unconfirmed.acknowledge_with_rtt(
              second, recovery_time_point {} + 140ms, 20ms, 10ms,
              packet_number_space::handshake, false,
              unconfirmed_rtt, output) == 1 &&
          unconfirmed_rtt.smoothed_rtt() == 102500us &&
          unconfirmed_rtt.rttvar() == 42500us,
          "pre-confirmation ACK delay is uncapped");
}

auto rtt_sample_selection_and_atomicity() -> void
{
    std::array<sent_packet, 3> output {};
    sent_packet_history<3> history;
    check(history.record(sent_packet {0, recovery_time_point {},
                                      true, true, 100}).has_value() &&
          history.record(sent_packet {1, recovery_time_point {} + 20ms,
                                      false, true, 100}).has_value(),
          "record mixed elicitation packets");
    rtt_estimator estimator;
    decoded_frame both {.type = 0x02, .largest_acknowledged = 1,
                        .first_ack_range = 1};
    check(history.acknowledge_with_rtt(
              both, recovery_time_point {} + 120ms, 0us, 10ms,
              packet_number_space::application_data, true,
              estimator, output) == 2 &&
          estimator.latest_rtt() == 100ms &&
          output[0].number == 1 && output[1].number == 0,
          "largest non-eliciting packet supplies send time");

    sent_packet_history<2> largest_old;
    rtt_estimator old_rtt;
    auto packet_one = packet(1);
    packet_one.ack_eliciting = true;
    check(largest_old.record(packet(0)).has_value() &&
          largest_old.record(packet_one).has_value(),
          "record largest-old case");
    decoded_frame one {.type = 0x02, .largest_acknowledged = 1};
    check(largest_old.acknowledge_with_rtt(
              one, recovery_time_point {} + 100001us, 0us, 10ms,
              packet_number_space::application_data, true,
              old_rtt, output) == 1,
          "ACK largest first");
    check(old_rtt.has_sample(), "largest-old case establishes sample");
    const auto prior_sample = old_rtt.latest_rtt();
    check(largest_old.acknowledge_with_rtt(
              both, recovery_time_point {} + 1s, 0us, 10ms,
              packet_number_space::application_data, true,
              old_rtt, output) == 1 &&
          old_rtt.latest_rtt() == prior_sample,
          "new lower ACK with old largest gives no RTT sample");

    sent_packet_history<2> atomic;
    rtt_estimator untouched;
    check(atomic.record(sent_packet {0, recovery_time_point {} + 1ms,
                                     true, true, 100}).has_value() &&
          atomic.record(sent_packet {1, recovery_time_point {} + 2ms,
                                     true, true, 100}).has_value(),
          "record atomicity candidates");
    check(atomic.acknowledge_with_rtt(
              both, recovery_time_point {} + 100ms, 0us, 10ms,
              packet_number_space::application_data, true,
              untouched, std::span(output).first(1)).error() ==
              sent_packet_error::output_full && atomic.size() == 2 &&
          !atomic.largest_acked() && !untouched.has_sample(),
          "output full preserves ledger and RTT state");
    check(atomic.acknowledge_with_rtt(
              both, recovery_time_point {} + 1ms, 0us, 10ms,
              packet_number_space::application_data, true,
              untouched, output).error() ==
              sent_packet_error::invalid_time && atomic.size() == 2 &&
          !atomic.largest_acked() && !untouched.has_sample(),
          "invalid sample time preserves ledger and RTT state");
    decoded_frame invalid {.type = 0x02, .largest_acknowledged = 2};
    check(atomic.acknowledge_with_rtt(
              invalid, recovery_time_point {} + 100ms, 0us, 10ms,
              packet_number_space::application_data, true,
              untouched, output).error() ==
              sent_packet_error::invalid_ack && atomic.size() == 2 &&
          !atomic.largest_acked() && !untouched.has_sample(),
          "invalid high ACK preserves ledger and RTT state");

    check(atomic.remove(1), "remove largest packet before ACK");
    decoded_frame removed {.type = 0x02, .largest_acknowledged = 1};
    check(atomic.acknowledge_with_rtt(
              removed, recovery_time_point {} + 100ms, 0us, 10ms,
              packet_number_space::application_data, true,
              untouched, output) == 0 && atomic.largest_acked() == 1 &&
          !untouched.has_sample(),
          "valid ACK advances largest without new retained record");
}

} // namespace

auto main() -> int
{
    send_order_and_capacity();
    gapped_ack_validation();
    ack_ranges_and_duplicates();
    atomic_failures();
    packet_threshold_losses();
    packet_threshold_with_send_gaps();
    time_threshold_and_candidates();
    loss_errors_and_nonflight();
    rtt_ack_sampling();
    rtt_ack_delay_spaces();
    rtt_sample_selection_and_atomicity();
}
