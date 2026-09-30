#include "quic/ecn_state.h"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {
using namespace eventloop::quic::detail;
constexpr auto app = packet_number_space::application_data;
auto check(bool value, std::string_view message) -> void
{
    if (value) return;
    std::cerr << "QUIC ECN: " << message << '\n';
    std::exit(1);
}
auto feedback_and_reordering() -> void
{
    ecn_state state;
    check(state.on_packet_sent(app, ecn_codepoint::ect0, 10).has_value(), "send ECT0");
    check(state.on_packet_sent(app, ecn_codepoint::ect1, 2).has_value(), "send ECT1");
    auto result = state.on_ack(app, 5, {2, 0, 0}, ecn_counts {3, 0, 1});
    check(result && result->newly_reported_ce == 1, "lost ACK permits excess counters and CE");
    result = state.on_ack(app, 4, {1, 0, 0}, ecn_counts {1, 0, 0});
    check(result && result->ignored_reordered && state.enabled(), "decreasing reordered feedback ignored");
    result = state.on_ack(app, 5, {1, 0, 0}, std::nullopt);
    check(result && result->ignored_reordered, "same largest with missing feedback ignored");
    result = state.on_ack(app, 9, {2, 1, 0}, ecn_counts {5, 1, 2});
    check(result && result->newly_reported_ce == 1, "latest feedback compared with accepted counters");
    check(state.on_packet_sent(packet_number_space::handshake, ecn_codepoint::ect0).has_value(), "separate space send");
    result = state.on_ack(packet_number_space::handshake, 0, {1, 0, 0}, ecn_counts {1, 0, 0});
    check(result && result->newly_reported_ce == 0, "space counters isolated");
}
auto failures() -> void
{
    ecn_state state;
    check(state.on_packet_sent(app, ecn_codepoint::ect0, 2).has_value(), "setup");
    check(state.on_ack(app, 0, {1, 0, 0}, std::nullopt).error() == ecn_error::missing_feedback &&
          !state.enabled(), "missing feedback disables ECN");
    check(state.on_packet_sent(app, ecn_codepoint::ect0).error() == ecn_error::disabled,
          "disabled rejects ECN marking");
    check(state.on_packet_sent(app, ecn_codepoint::not_ect).has_value(), "disabled permits unmarked packets");
    state.reset();
    check(state.on_packet_sent(app, ecn_codepoint::ect0, 2).has_value(), "setup decrease");
    check(state.on_ack(app, 0, {1, 0, 0}, ecn_counts {1, 0, 0}).has_value(), "first feedback");
    check(state.on_ack(app, 1, {0, 0, 0}, ecn_counts {0, 0, 0}).error() ==
          ecn_error::decreasing_feedback, "advanced decreasing counters fail");
    state.reset();
    check(state.on_packet_sent(app, ecn_codepoint::ect0, 2).has_value(), "setup remark");
    check(state.on_ack(app, 0, {1, 0, 0}, ecn_counts {0, 1, 0}).error() ==
          ecn_error::inconsistent_feedback, "wrong ECT marking fails");
    state.reset();
    check(state.on_packet_sent(app, ecn_codepoint::ect0, 2).has_value(), "setup bleaching");
    check(state.on_ack(app, 0, {2, 0, 0}, ecn_counts {1, 0, 0}).error() ==
          ecn_error::inconsistent_feedback, "underreported counts fail");
    state.reset();
    check(state.on_packet_sent(app, ecn_codepoint::ect0).has_value(), "setup excess CE");
    check(state.on_ack(app, 0, {1, 0, 0}, ecn_counts {1, 0, 1}).error() ==
          ecn_error::inconsistent_feedback, "CE exceeds total sent fails");
    state.reset();
    check(state.on_packet_sent(app, ecn_codepoint::ect0).has_value(), "mixed setup0");
    check(state.on_packet_sent(app, ecn_codepoint::ect1).has_value(), "mixed setup1");
    check(state.on_ack(app, 0, {1, 1, 0}, ecn_counts {0, 0, 1}).error() ==
          ecn_error::inconsistent_feedback, "one CE cannot account for two acknowledged packets");
}
auto boundaries() -> void
{
    ecn_state state;
    check(state.on_packet_sent(static_cast<packet_number_space>(3), ecn_codepoint::ect0).error() ==
          ecn_error::invalid_space && state.enabled(), "invalid space preserves state");
    check(state.on_packet_sent(app, ecn_codepoint::ce).error() == ecn_error::invalid_codepoint,
          "sender cannot apply CE");
    check(state.on_packet_sent(app, ecn_codepoint::ect0, max_varint_value).has_value(), "largest counter");
    check(state.on_ack(app, max_varint_value, {max_varint_value, 0, 0},
          ecn_counts {0, 0, max_varint_value}).has_value(), "largest CE accepted without overflow");
    check(state.on_packet_sent(app, ecn_codepoint::ect0).error() ==
          ecn_error::counter_overflow && !state.enabled(), "send overflow disables");
    state.reset();
    check(state.on_ack(app, 0, {}, ecn_counts {0, 0, max_varint_value + 1}).error() ==
          ecn_error::counter_overflow, "invalid wire counter rejected");
    state.reset();
    check(state.on_ack(app, 0, {1, 0, 0}, ecn_counts {1, 0, 0}).error() ==
          ecn_error::invalid_ack, "unsent acknowledgment rejected");
    state.reset();
    check(state.on_ack(app, 0, {}, std::nullopt).has_value(), "unmarked ACK needs no feedback");
}
} // namespace

int main()
{
    feedback_and_reordering();
    failures();
    boundaries();
    std::cout << "QUIC ECN tests passed\n";
}
