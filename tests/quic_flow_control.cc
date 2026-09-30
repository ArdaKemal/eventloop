#include "quic/flow_control.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC flow control: " << message << '\n';
    std::exit(1);
}

auto overlap_and_atomic_limits() -> void
{
    auto result = flow_control<2>::create(12, 12);
    check(result.has_value(), "create");
    auto& flow = *result;
    check(flow.add_stream(0, 10, 10).has_value() &&
          flow.add_stream(4, 10, 10).has_value(), "register streams");
    check(flow.send_range(0, 0, 7).has_value() &&
          flow.send_range(0, 0, 7).has_value() &&
          flow.send_range(0, 5, 5).has_value() &&
          flow.sent_total() == 10, "send retransmission and overlap");
    check(flow.send_range(4, 0, 3).error() ==
              flow_control_error::connection_limit &&
          flow.sent_total() == 10, "send aggregate limit is atomic");
    check(flow.send_range(4, 0, 2).has_value() &&
          flow.send_range(0, 9, 2).error() ==
              flow_control_error::stream_limit &&
          flow.sent_total() == 12, "send stream limit and aggregate");
    check(flow.receive_range(0, 4, 6).has_value() &&
          flow.receive_range(0, 0, 6).has_value() &&
          flow.received_total() == 10, "receive overlap");
    check(flow.receive_range(4, 0, 3).error() ==
              flow_control_error::connection_limit &&
          flow.received_total() == 10, "receive aggregate limit is atomic");
    check(flow.receive_range(4, 0, 2).has_value() &&
          flow.receive_range(0, 10, 1).error() ==
              flow_control_error::stream_limit &&
          flow.received_total() == 12, "receive stream limit");
}

auto registration_and_updates() -> void
{
    auto flow = *flow_control<1>::create(3, 3);
    check(flow.add_stream(1, 3, 3).has_value(), "first stream");
    check(flow.add_stream(1, 3, 3).error() ==
              flow_control_error::duplicate_stream && flow.size() == 1,
          "duplicate stream rejected");
    check(flow.add_stream(5, 3, 3).error() ==
              flow_control_error::capacity_exhausted && flow.size() == 1,
          "capacity exhaustion");
    check(flow.send_range(5, 0, 1).error() ==
              flow_control_error::unknown_stream, "unknown stream");
    check(flow.send_range(1, 0, 3).has_value(), "initial send credit");
    check(flow.update_send_max_data(2).has_value() &&
          flow.update_send_stream_limit(1, 2).has_value() &&
          flow.send_max_data() == 3, "stale MAX_DATA and MAX_STREAM_DATA ignored");
    check(flow.update_send_stream_limit(1, 5).has_value() &&
          flow.send_range(1, 3, 1).error() ==
              flow_control_error::connection_limit,
          "stream increase alone does not increase connection credit");
    check(flow.update_send_max_data(5).has_value() &&
          flow.send_range(1, 3, 2).has_value() && flow.sent_total() == 5,
          "increased peer credit");
}

auto consumption_and_replenishment() -> void
{
    auto flow = *flow_control<2>::create(0, 5);
    check(flow.add_stream(0, 0, 5).has_value() &&
          flow.add_stream(4, 0, 5).has_value(), "receive streams");
    check(flow.receive_range(0, 0, 4).has_value() &&
          flow.consume(0, 3).has_value(), "consume received bytes");
    check(flow.consume(0, 2).error() == flow_control_error::over_consumed &&
          flow.consumed_total() == 3, "overconsumption is atomic");
    check(flow.replenish_receive_stream_limit(0, 5) == 8 &&
          flow.replenish_receive_max_data(5) == 8,
          "window replenishment tracks consumed bytes");
    check(flow.replenish_receive_stream_limit(0, 1) == 8 &&
          flow.replenish_receive_max_data(1) == 8,
          "advertised limits never decrease");
    check(flow.receive_range(0, 4, 4).has_value() &&
          flow.receive_range(4, 0, 1).error() ==
              flow_control_error::connection_limit,
          "stream credit cannot bypass aggregate credit");
    check(flow.consume(0, 5).has_value() &&
          flow.replenish_receive_max_data(5) == 13 &&
          flow.receive_range(4, 0, 1).has_value(),
          "consumption restores connection window");
}

auto final_size_contract() -> void
{
    auto flow = *flow_control<2>::create(10, 10);
    check(flow.add_stream(0, 10, 10).has_value() &&
          flow.add_stream(4, 10, 10).has_value(), "final-size streams");
    check(flow.send_stream_range(0, 0, 4, true).has_value() &&
          flow.send_stream_range(0, 0, 4, true).has_value() &&
          flow.set_send_final_size(0, 4).has_value() &&
          flow.sent_total() == 4, "exact FIN and RESET retransmissions");
    check(flow.send_stream_range(0, 0, 3, true).error() ==
              flow_control_error::final_size &&
          flow.set_send_final_size(0, 5).error() ==
              flow_control_error::final_size &&
          flow.send_range(0, 4, 1).error() ==
              flow_control_error::final_size && flow.sent_total() == 4,
          "conflicting send final size and data beyond final size");
    check(flow.send_range(4, 0, 5).has_value() &&
          flow.set_send_final_size(4, 4).error() ==
              flow_control_error::final_size &&
          flow.set_send_final_size(4, 5).has_value() &&
          flow.sent_total() == 9,
          "send final size below high offset rejected atomically");

    check(flow.receive_range(0, 0, 3).has_value() &&
          flow.receive_stream_range(0, 0, 2, true).error() ==
              flow_control_error::final_size && flow.received_total() == 3,
          "receive FIN below high offset rejected");
    check(flow.receive_stream_range(0, 4, 2, true).has_value() &&
          flow.receive_stream_range(0, 4, 2, true).has_value() &&
          flow.set_receive_final_size(0, 6).has_value() &&
          flow.received_total() == 6,
          "FIN above data offset charges highest offset once");
    check(flow.receive_stream_range(0, 4, 1, true).error() ==
              flow_control_error::final_size &&
          flow.set_receive_final_size(0, 7).error() ==
              flow_control_error::final_size &&
          flow.receive_range(0, 6, 1).error() ==
              flow_control_error::final_size && flow.received_total() == 6,
          "conflicting receive final size and data beyond final size");
}

auto reset_credit_atomicity() -> void
{
    auto flow = *flow_control<2>::create(5, 5);
    check(flow.add_stream(0, 4, 4).has_value() &&
          flow.add_stream(4, 4, 4).has_value(), "reset streams");
    check(flow.set_send_final_size(0, 5).error() ==
              flow_control_error::stream_limit &&
          flow.set_receive_final_size(0, 5).error() ==
              flow_control_error::stream_limit &&
          flow.sent_total() == 0 && flow.received_total() == 0,
          "reset final size respects stream credit atomically");
    check(flow.set_send_final_size(0, 4).has_value() &&
          flow.set_receive_final_size(0, 4).has_value() &&
          flow.sent_total() == 4 && flow.received_total() == 4,
          "reset final size charges connection credit");
    check(flow.set_send_final_size(4, 2).error() ==
              flow_control_error::connection_limit &&
          flow.set_receive_final_size(4, 2).error() ==
              flow_control_error::connection_limit &&
          flow.sent_total() == 4 && flow.received_total() == 4,
          "reset aggregate failure leaves state unchanged");
    check(flow.set_send_final_size(4, 1).has_value() &&
          flow.set_receive_final_size(4, 1).has_value() &&
          flow.set_send_final_size(4, 1).has_value() &&
          flow.set_receive_final_size(4, 1).has_value() &&
          flow.sent_total() == 5 && flow.received_total() == 5,
          "reset final size exact retransmission and recovered credit");
}

auto boundaries() -> void
{
    constexpr auto max = max_varint_value;
    check(flow_control<1>::create(max + 1, 0).error() ==
              flow_control_error::invalid_value, "invalid initial limit");
    auto flow = *flow_control<1>::create(max, max);
    check(flow.add_stream(max + 1, 1, 1).error() ==
              flow_control_error::invalid_value && flow.size() == 0,
          "invalid stream ID");
    check(flow.add_stream(0, max, max).has_value(), "maximum limits");
    check(flow.send_range(0, max, 1).error() ==
              flow_control_error::invalid_value &&
          flow.receive_range(0, max + 1, 0).error() ==
              flow_control_error::invalid_value,
          "offset plus length checked before mutation");
    check(flow.send_range(0, max, 0).has_value() &&
          flow.receive_range(0, max, 0).has_value() &&
          flow.sent_total() == max && flow.received_total() == max,
          "maximum final offset");
    check(flow.consume(0, max).has_value() &&
          flow.replenish_receive_max_data(1).error() ==
              flow_control_error::invalid_value &&
          flow.replenish_receive_stream_limit(0, 1).error() ==
              flow_control_error::invalid_value &&
          flow.receive_max_data() == max,
          "window overflow checked");
    check(flow.update_send_max_data(max + 1).error() ==
              flow_control_error::invalid_value &&
          flow.update_send_stream_limit(0, max + 1).error() ==
              flow_control_error::invalid_value,
          "peer credit bounds");
}

} // namespace

auto main() -> int
{
    overlap_and_atomic_limits();
    registration_and_updates();
    consumption_and_replenishment();
    final_size_contract();
    reset_credit_atomicity();
    boundaries();
}
