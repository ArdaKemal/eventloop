#include "quic/path_recovery_state.h"

#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;
using namespace std::chrono_literals;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC path recovery state: " << message << '\n';
    std::exit(1);
}

constexpr auto slot_bytes = std::size_t {1200};
constexpr auto initial_window = std::size_t {12000};

auto add_flight(path_recovery_slot& slot) -> void
{
    check(slot.congestion.on_packet_sent(slot_bytes, true).has_value(),
          "record in-flight bytes");
}

auto sample_rtt(path_recovery_slot& slot) -> void
{
    slot.rtt.update(50ms, 0ms, 0ms, packet_number_space::application_data,
                    true);
}

auto initial_state() -> void
{
    path_recovery_state<2> state;
    check(state.active() == nullptr && state.candidate() == nullptr &&
              !state.active_handle() && !state.candidate_handle() &&
              state.find(7) == nullptr,
          "default state has no paths");
    check(state.reset(slot_bytes).has_value(), "valid reset");
    check(!state.active_handle() && !state.candidate_handle(),
          "reset clears paths");
    check(state.reset(1199).error() ==
              path_recovery_error::invalid_datagram_size,
          "undersized datagram rejected");
    check(state.set_active(3).has_value(), "active path registered");
    check(state.active_handle() == 3 && state.active()->validated,
          "initial active path is validated");
    check(state.active()->congestion.congestion_window() == initial_window &&
              state.active()->congestion.bytes_in_flight() == 0 &&
              !state.active()->rtt.has_sample() &&
              state.active()->rtt.smoothed_rtt() == initial_rtt,
          "active path starts with initial recovery state");
    check(state.reset(1199).error() ==
              path_recovery_error::invalid_datagram_size &&
              state.active_handle() == 3,
          "rejected reset preserves paths");
}

auto unvalidated_candidate() -> void
{
    path_recovery_state<3> state;
    check(state.set_active(1).has_value(), "active path");
    add_flight(*state.active());
    sample_rtt(*state.active());
    check(state.begin_candidate(2).has_value(), "candidate registered");
    check(state.active_handle() == 1 && state.candidate_handle() == 2,
          "candidate does not replace active");
    check(!state.candidate()->validated, "candidate is unvalidated");
    check(state.active()->handle == 1 &&
              state.active()->congestion.bytes_in_flight() == slot_bytes &&
              state.active()->rtt.has_sample(),
          "candidate registration leaves active recovery state untouched");
    check(state.promote_candidate().error() ==
              path_recovery_error::not_validated,
          "unvalidated candidate cannot be promoted");
    check(state.active_handle() == 1 && state.candidate_handle() == 2,
          "failed promotion preserves both paths");
    check(state.mark_validated().has_value(), "validation recorded");
    check(state.candidate()->validated, "candidate marked validated");
}

auto promotion_resets_state() -> void
{
    path_recovery_state<3> state;
    check(state.reset(slot_bytes, 250ms).has_value(), "reset custom RTT");
    check(state.set_active(10).has_value(), "active path");
    add_flight(*state.active());
    sample_rtt(*state.active());
    check(state.begin_candidate(11).has_value(), "candidate path");
    add_flight(*state.candidate());
    sample_rtt(*state.candidate());
    check(state.mark_validated().has_value() &&
              state.promote_candidate().has_value(),
          "validated candidate promoted");
    check(state.active_handle() == 11 && !state.candidate_handle() &&
              state.candidate() == nullptr,
          "promoted candidate is active and candidate cleared");
    check(state.find(10) == nullptr, "old active slot released");
    check(!state.active()->rtt.has_sample() &&
              state.active()->rtt.smoothed_rtt() == 250ms &&
              state.active()->congestion.bytes_in_flight() == 0 &&
              state.active()->congestion.congestion_window() == initial_window,
          "promotion resets the new path to fresh recovery state");
    check(state.promote_candidate().error() ==
              path_recovery_error::no_candidate,
          "cannot promote twice");
}

auto cancellation_preserves_active() -> void
{
    path_recovery_state<3> state;
    check(state.set_active(21).has_value(), "active path");
    add_flight(*state.active());
    sample_rtt(*state.active());
    check(state.begin_candidate(22).has_value(), "candidate path");
    add_flight(*state.candidate());
    check(state.cancel_candidate().has_value(), "candidate cancelled");
    check(!state.candidate_handle() && state.candidate() == nullptr &&
              state.find(22) == nullptr,
          "cancelled candidate released");
    check(state.active_handle() == 21 &&
              state.active()->congestion.bytes_in_flight() == slot_bytes &&
              state.active()->rtt.has_sample(),
          "cancellation preserves active recovery state");
    check(state.cancel_candidate().error() ==
              path_recovery_error::no_candidate &&
              state.promote_candidate().error() ==
              path_recovery_error::no_candidate,
          "no candidate remains");
}

auto invalid_transitions() -> void
{
    path_recovery_state<2> state;
    check(state.mark_validated().error() ==
              path_recovery_error::no_candidate &&
              state.cancel_candidate().error() ==
              path_recovery_error::no_candidate &&
              state.promote_candidate().error() ==
              path_recovery_error::no_candidate,
          "candidate operations need a candidate");
    check(state.set_active(1).has_value(), "first active path");
    check(state.set_active(2).error() ==
              path_recovery_error::active_path_exists,
          "second active path rejected");
    check(state.begin_candidate(1).error() ==
              path_recovery_error::duplicate_path,
          "candidate cannot reuse active handle");
    check(state.begin_candidate(4).has_value(), "candidate added");
    check(state.begin_candidate(5).error() ==
              path_recovery_error::candidate_exists,
          "only one candidate at a time");
}

auto capacity() -> void
{
    path_recovery_state<1> state;
    check(state.reset(slot_bytes).has_value() &&
              state.set_active(31).has_value(),
          "single-slot active path");
    add_flight(*state.active());
    check(state.begin_candidate(32).error() == path_recovery_error::full,
          "candidate needs a free slot");
    check(state.active_handle() == 31 &&
              state.active()->congestion.bytes_in_flight() == slot_bytes,
          "full candidate rejection preserves active");
    check(state.reset(slot_bytes).has_value() && !state.active_handle(),
          "reset frees the slot again");
}

} // namespace

auto main() -> int
{
    initial_state();
    unvalidated_candidate();
    promotion_resets_state();
    cancellation_preserves_active();
    invalid_transitions();
    capacity();
    return 0;
}
