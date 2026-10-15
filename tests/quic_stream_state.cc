#include "quic/stream_state.h"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {
using namespace eventloop::quic::detail;
void check(bool ok, std::string_view message)
{
    if (ok) return;
    std::cerr << "QUIC stream state: " << message << '\n';
    std::exit(1);
}
void ok(stream_state::result r, std::string_view message) { check(r.has_value(), message); }
void error(stream_state::result r, stream_state_error e, std::string_view message)
{ check(!r && r.error() == e, message); }
auto make(std::uint64_t id, stream_role role = stream_role::client) -> stream_state
{ auto r = stream_state::create(id, role); check(r.has_value(), "create"); return *r; }

void directions()
{
    for (const auto role : {stream_role::client, stream_role::server}) {
        for (std::uint64_t id = 0; id != 8; ++id) {
            auto s = make(id, role);
            const bool local = stream_initiator(id) == role;
            const bool bidi = stream_type(id) == stream_direction::bidirectional;
            check((s.sending() != stream_send_state::absent) == (local || bidi), "send permissions");
            check((s.receiving() != stream_receive_state::absent) == (!local || bidi), "receive permissions");
            if (!local && !bidi) {
                error(s.send_stream(0, 1), stream_state_error::stream_state, "uni send");
                error(s.send_reset(0), stream_state_error::stream_state, "uni reset send");
                error(s.receive_stop_sending(0), stream_state_error::stream_state, "uni stop receive");
                error(s.receive_max_stream_data(), stream_state_error::stream_state, "uni max receive");
                error(s.send_data_blocked(), stream_state_error::stream_state, "uni blocked send");
            }
            if (local && !bidi) {
                error(s.receive_stream(0, 1), stream_state_error::stream_state, "uni receive");
                error(s.receive_reset(0), stream_state_error::stream_state, "uni reset receive");
                error(s.send_stop_sending(), stream_state_error::stream_state, "uni stop send");
                error(s.send_max_stream_data(), stream_state_error::stream_state, "uni max send");
                error(s.receive_data_blocked(), stream_state_error::stream_state, "uni blocked receive");
            }
        }
    }
    check(!stream_state::create(max_varint_value + 1, stream_role::client), "invalid ID");
}

void fin_and_gaps()
{
    auto s = make(0);
    ok(s.send_data_blocked(), "blocked opens sender");
    ok(s.send_stream(0, 10), "send data");
    error(s.send_stream(0, 5, true), stream_state_error::final_size, "FIN below sent high water");
    check(s.sending() == stream_send_state::send && !s.send_final_size(), "rejected FIN unchanged");
    ok(s.send_stream(10, 0, true), "FIN");
    ok(s.send_stream(2, 3), "retransmit");
    ok(s.send_stream(10, 0, true), "retransmit FIN");
    error(s.send_stream(10, 1), stream_state_error::final_size, "send past FIN");
    error(s.send_stream(9, 0, true), stream_state_error::final_size, "change FIN");
    error(s.send_data_blocked(), stream_state_error::invalid_transition, "blocked after FIN");
    ok(s.all_data_acked(), "ACK data and FIN");
    ok(s.all_data_acked(), "duplicate ACK");
    error(s.send_stream(0, 1), stream_state_error::invalid_transition, "terminal send");
    error(s.send_reset(10), stream_state_error::invalid_transition, "terminal reset send");
    ok(s.receive_max_stream_data(), "late MAX_STREAM_DATA");
    ok(s.receive_stop_sending(123), "late stop");
    check(!s.reset_required(), "late stop does not reset");
    check(!s.closed(), "one half remains open");

    ok(s.receive_stream(5, 5, true), "FIN arrives with gap");
    check(s.receiving() == stream_receive_state::size_known, "gap blocks completion");
    error(s.receive_stream(10, 1), stream_state_error::final_size, "receive past FIN");
    error(s.receive_reset(11), stream_state_error::final_size, "reset disagrees with FIN");
    check(s.receive_final_size() == 10 && s.receiving() == stream_receive_state::size_known,
          "rejected receive events unchanged");
    ok(s.receive_contiguous(0), "zero contiguous watermark");
    ok(s.receive_stream(0, 5), "gap data");
    ok(s.receive_contiguous(10), "reassembly closes gap");
    check(s.receiving() == stream_receive_state::data_received, "complete data");
    ok(s.receive_contiguous(5), "stale watermark");
    ok(s.receive_reset(10), "suppress late reset after complete data");
    check(s.receiving() == stream_receive_state::data_received, "late reset retains complete data");
    ok(s.read_all_data(), "application reads");
    ok(s.read_all_data(), "duplicate completion");
    check(s.closed(), "both halves terminal");
    ok(s.receive_stream(5, 5, true), "delayed STREAM after terminal");
    error(s.receive_stream(0, 9, true), stream_state_error::final_size, "late conflicting FIN");
    ok(s.receive_data_blocked(), "delayed blocked frame");
    error(s.read_reset(), stream_state_error::invalid_transition, "read nonexistent reset");
}

void reliable_resets()
{
    // RESET_STREAM_AT keeps receiving until the reader has consumed the reliable prefix.
    auto r = make(0, stream_role::server);
    ok(r.receive_stream(0, 10), "prefix data");
    ok(r.receive_contiguous(10), "prefix contiguous");
    ok(r.receive_reset(20, 6), "reliable reset");
    check(r.receiving() == stream_receive_state::receive && r.reliable_size() == 6 &&
          r.receive_final_size() == 20, "reset waits for the reliable prefix");
    r.receive_reset_progress(5);
    check(r.receiving() == stream_receive_state::receive, "partial prefix keeps waiting");
    r.receive_reset_progress(6);
    check(r.receiving() == stream_receive_state::reset_received, "prefix read surfaces the reset");

    // The smallest reliable size wins, and a larger one is ignored.
    auto m = make(0, stream_role::server);
    ok(m.receive_reset(20, 6), "first reliable reset");
    ok(m.receive_reset(20, 9), "later larger reliable size");
    check(m.reliable_size() == 6, "reliable size only decreases");
    ok(m.receive_reset(20, 2), "later smaller reliable size");
    m.receive_reset_progress(2);
    check(m.receiving() == stream_receive_state::reset_received, "smaller size surfaces sooner");

    // A reliable size above the final size is malformed; the final size is fixed.
    auto bad = make(0, stream_role::server);
    error(bad.receive_reset(10, 11), stream_state_error::frame_encoding, "reliable above final");
    ok(bad.receive_reset(10, 4), "valid reliable reset after rejection");
    error(bad.receive_reset(11, 4), stream_state_error::final_size, "final size cannot change");

    // Fully received data stays readable until the reliable prefix. A zero reliable size
    // keeps RESET_STREAM's suppression of a reset after complete data.
    auto d = make(0, stream_role::server);
    ok(d.receive_stream(0, 10, true), "FIN");
    ok(d.receive_contiguous(10), "all data");
    ok(d.receive_reset(10, 4), "reset after complete data");
    check(d.receiving() == stream_receive_state::data_received, "prefix keeps data readable");
    d.receive_reset_progress(4);
    check(d.receiving() == stream_receive_state::reset_received, "complete prefix surfaces reset");
    auto e = make(0, stream_role::server);
    ok(e.receive_stream(0, 10, true), "FIN for plain reset");
    ok(e.receive_contiguous(10), "all data for plain reset");
    ok(e.receive_reset(10), "plain reset after complete data");
    e.receive_reset_progress(0);
    check(e.receiving() == stream_receive_state::data_received, "plain reset is suppressed");

    // Send side: the reliable reset commits the final size and keeps Data Sent until
    // the data and the reset are acknowledged.
    auto t = make(0);
    ok(t.send_stream(0, 8), "reliable data");
    ok(t.send_reset_at(8), "commit final size");
    check(t.sending() == stream_send_state::data_sent, "reliable reset keeps data sent");
    error(t.send_reset_at(7), stream_state_error::final_size, "final size below data");
    error(t.send_reset_at(9), stream_state_error::final_size, "final size changed");
    ok(t.all_data_acked(), "reliable data acknowledged");
    check(t.sending() == stream_send_state::data_received, "terminal after acknowledgement");
    error(t.send_reset_at(8), stream_state_error::invalid_transition, "no reset after completion");
}

void resets_and_stop()
{
    for (int phase = 0; phase != 3; ++phase) {
        auto s = make(2);
        if (phase >= 1) ok(s.send_stream(0, 4), "send before stop");
        if (phase == 2) ok(s.send_stream(4, 0, true), "FIN before stop");
        ok(s.receive_stop_sending(42), "stop requests reset");
        ok(s.receive_stop_sending(99), "duplicate stop");
        check(s.reset_required() && s.stop_error() == 42, "stop preserves first error");
        ok(s.send_reset(phase == 0 ? 0 : 4), "respond with reset");
        check(!s.reset_required(), "reset work retired");
        ok(s.send_reset(phase == 0 ? 0 : 4), "reset retransmission");
        error(s.send_stream(0, 0), stream_state_error::invalid_transition, "STREAM after reset");
        ok(s.all_data_acked(), "late data ACK ignored");
        check(!s.closed(), "reset waits for ACK");
        ok(s.reset_acked(), "reset ACK");
        ok(s.reset_acked(), "duplicate reset ACK");
        check(s.closed(), "send-only stream terminal");
        error(s.send_reset(phase == 0 ? 0 : 4), stream_state_error::invalid_transition, "terminal reset");
    }

    auto r = make(3);
    ok(r.send_stop_sending(), "abort reading");
    ok(r.send_stop_sending(), "retransmit stop");
    check(r.stop_sending_pending(), "stop work pending");
    ok(r.receive_stream(5, 5), "data after stop still accounted");
    error(r.receive_reset(9), stream_state_error::final_size, "reset below high water");
    check(r.stop_sending_pending() && !r.receive_final_size(), "rejected reset unchanged");
    ok(r.receive_reset(10), "reset received");
    check(!r.stop_sending_pending(), "reset stops stop retransmission");
    ok(r.receive_reset(10), "duplicate reset");
    error(r.receive_reset(11), stream_state_error::final_size, "conflicting reset");
    ok(r.receive_stream(0, 10, true), "delayed data after reset");
    ok(r.receive_contiguous(10), "complete data after reset retains reset policy");
    check(r.receiving() == stream_receive_state::reset_received, "reset policy stable");
    error(r.send_stop_sending(), stream_state_error::invalid_transition, "no stop after reset");
    error(r.read_all_data(), stream_state_error::invalid_transition, "reset is not data");
    ok(r.read_reset(), "application reset");
    ok(r.read_reset(), "duplicate application reset");
    check(r.closed(), "receive-only stream terminal");
    ok(r.receive_reset(10), "late reset after terminal");
}

void limits_and_empty()
{
    check(stream_state_transport_error(stream_state_error::stream_state) == 0x05 &&
          stream_state_transport_error(stream_state_error::final_size) == 0x06 &&
          stream_state_transport_error(stream_state_error::frame_encoding) == 0x07 &&
          !stream_state_transport_error(stream_state_error::invalid_transition) &&
          !stream_state_transport_error(stream_state_error::invalid_value), "wire error classifications");
    auto s = make(0);
    error(s.all_data_acked(), stream_state_error::invalid_transition, "ACK before FIN");
    error(s.reset_acked(), stream_state_error::invalid_transition, "ACK before reset");
    error(s.receive_contiguous(1), stream_state_error::invalid_transition, "unreceived watermark");
    error(s.send_stream(max_varint_value, 1), stream_state_error::invalid_value, "send offset overflow");
    error(s.receive_stream(max_varint_value, 1), stream_state_error::frame_encoding, "wire offset overflow");
    error(s.receive_stop_sending(max_varint_value + 1), stream_state_error::frame_encoding, "error code bound");
    check(!s.stop_error() && !s.reset_required(), "invalid stop unchanged");
    ok(s.send_max_stream_data(), "credit in receive state");
    ok(s.receive_stream(0, 0, true), "empty stream FIN");
    check(s.receiving() == stream_receive_state::data_received, "empty stream complete");
    error(s.send_max_stream_data(), stream_state_error::invalid_transition, "no credit after FIN");
    ok(s.send_stop_sending(), "stop allowed after all data");
    check(!s.stop_sending_pending(), "completed data has no retransmit work");
    ok(s.read_all_data(), "empty EOF consumed");
    ok(s.send_stream(0, 0, true), "empty send FIN");
    ok(s.all_data_acked(), "empty FIN ACK");
    check(s.closed(), "empty bidi complete");

    auto top = make(3);
    ok(top.receive_stream(max_varint_value, 0, true), "maximum final size");
    error(top.receive_stream(max_varint_value + 1, 0), stream_state_error::frame_encoding, "invalid offset");
    check(top.receiving() == stream_receive_state::size_known, "max offset retains gap");
}
} // namespace

int main()
{
    directions();
    fin_and_gaps();
    resets_and_stop();
    reliable_resets();
    limits_and_empty();
    std::cout << "QUIC stream state tests passed\n";
}
