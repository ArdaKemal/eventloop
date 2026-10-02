#include "quic/stream_send_buffer.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC stream send: " << message << '\n';
    std::exit(1);
}

auto input(std::string_view value) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(value.data(), value.size()));
}

auto equals(stream_send_chunk chunk, std::uint64_t offset,
            std::string_view text, bool fin = false) -> bool
{
    if (chunk.offset != offset || chunk.data.size() != text.size() ||
        chunk.fin != fin) return false;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (std::to_integer<unsigned char>(chunk.data[i]) !=
            static_cast<unsigned char>(text[i])) return false;
    }
    return true;
}

auto flow_credit_and_fin() -> void
{
    stream_send_buffer<8> stream(3);
    check(stream.append(input("abcdef")) == std::uint64_t {0},
          "application data queued beyond current flow credit");
    check(stream.next_offset() == 6 && stream.writable_bytes() == 2,
          "monotonic offsets and bounded capacity");
    check(equals(stream.next_pending(8), 0, "abc"),
          "send selection clipped at flow credit");
    check(stream.mark_sent(0, 4).error() == stream_send_error::flow_blocked &&
              equals(stream.next_pending(8), 0, "abc"),
          "flow-blocked transmission changes no state");
    check(stream.mark_sent(0, 3).has_value(), "credited prefix sent");
    check(stream.next_pending(8).data.empty(), "remaining data flow blocked");
    check(stream.close() == std::uint64_t {6} && stream.final_size() == 6,
          "close commits final size");
    check(stream.writable_bytes() == 0 &&
              stream.append(input("x")).error() == stream_send_error::closed &&
              stream.close().error() == stream_send_error::closed,
          "closed stream rejects appends and repeated close");
    check(!stream.next_pending(8).fin, "FIN waits for final-size credit");
    check(stream.extend_flow_limit(6).has_value(), "flow credit extended");
    check(equals(stream.next_pending(8), 3, "def", true),
          "FIN attached to final data chunk");
    check(stream.mark_sent(3, 3, true).has_value(), "final frame sent");
    check(stream.acknowledge(0, 3).has_value() && !stream.complete(),
          "partial ACK retires prefix");
    check(stream.acknowledge(3, 3, true).has_value() && stream.complete(),
          "all data and FIN ACKed");
    check(stream.base_offset() == 6 && stream.buffered_size() == 0 &&
              stream.next_pending(8).data.empty() &&
              !stream.next_pending(8).fin,
          "ACKed bytes and FIN never retransmitted");
}

auto partial_ack_loss_and_fin_only() -> void
{
    stream_send_buffer<12> stream(12);
    check(stream.append(input("abcdefgh")) == std::uint64_t {0},
          "initial data queued");
    check(equals(stream.next_pending(3), 0, "abc"),
          "packet-size cap applied");
    check(stream.mark_sent(0, 8).has_value(), "bytes sent");
    check(stream.close() == std::uint64_t {8}, "close after data sent");
    check(equals(stream.next_pending(0), 8, "", true),
          "empty FIN available independently of data budget");
    check(stream.mark_sent(8, 0, true).has_value(), "empty FIN sent");
    check(stream.acknowledge(0, 2).has_value(), "prefix ACKed");
    check(stream.mark_lost(2, 4).has_value() &&
              equals(stream.next_pending(8), 2, "cdef"),
          "partial loss schedules retransmission");
    check(stream.acknowledge(4, 2).has_value() &&
              equals(stream.next_pending(8), 2, "cd"),
          "ACK removes bytes from pending loss");
    check(stream.mark_lost(0, 8).has_value() &&
              equals(stream.next_pending(8), 2, "cd"),
          "overlapping late loss does not restore ACKed bytes");
    check(stream.mark_sent(2, 2).has_value() &&
              stream.acknowledge(2, 2).has_value() &&
              stream.base_offset() == 6,
          "out-of-order ACKed range retires with prefix");
    check(equals(stream.next_pending(8), 6, "gh"),
          "remaining lost suffix selected");
    check(stream.mark_lost(8, 0, true).has_value(), "FIN loss recorded");
    check(stream.mark_sent(6, 2).has_value() &&
              stream.acknowledge(6, 2).has_value(),
          "remaining data ACKed");
    check(equals(stream.next_pending(8), 8, "", true),
          "lost FIN retransmitted alone");
    check(stream.mark_sent(8, 0, true).has_value() &&
              stream.acknowledge(8, 0, true).has_value() && stream.complete(),
          "FIN retransmission ACK completes stream");
    check(stream.mark_lost(8, 0, true).has_value() &&
              !stream.next_pending(8).fin,
          "late FIN loss cannot resurrect ACKed FIN");
}

auto ring_wrap_and_capacity() -> void
{
    stream_send_buffer<4> stream(16);
    check(stream.writable_bytes() == 4 &&
              stream.append(input("abcd")) == std::uint64_t {0},
          "capacity filled");
    check(stream.append(input("e")).error() ==
              stream_send_error::capacity_exceeded &&
              stream.next_offset() == 4 &&
              equals(stream.next_pending(4), 0, "abcd"),
          "capacity rejection is atomic");
    check(stream.mark_sent(0, 4).has_value() &&
              stream.acknowledge(0, 4).has_value(),
          "initial window retired");
    check(stream.append(input("ef")) == std::uint64_t {4} &&
              stream.mark_sent(4, 2).has_value() &&
              stream.acknowledge(4, 2).has_value() &&
              stream.append(input("ghij")) == std::uint64_t {6},
          "ring slots reused with increasing offsets");
    check(equals(stream.next_pending(4), 6, "gh"),
          "first contiguous physical span");
    check(stream.mark_sent(6, 2).has_value() &&
              equals(stream.next_pending(4), 8, "ij"),
          "selection resumes after wrap");
    check(stream.mark_sent(8, 2).has_value() &&
              stream.acknowledge(6, 4).has_value() &&
              stream.base_offset() == 10,
          "wrapped data retired");
}

auto invalid_reports_and_empty_stream() -> void
{
    stream_send_buffer<4> stream(4);
    check(stream.append(input("abcd")) == std::uint64_t {0},
          "data queued");
    check(stream.acknowledge(0, 1).error() ==
              stream_send_error::unsent_data &&
              stream.mark_lost(0, 1).error() ==
                  stream_send_error::unsent_data,
          "unsent ACK and loss rejected");
    check(stream.mark_sent(0, 2).has_value(), "prefix sent");
    check(stream.acknowledge(0, 3).error() ==
              stream_send_error::unsent_data && stream.base_offset() == 0,
          "mixed sent and unsent ACK rejected atomically");
    check(stream.mark_lost(0, 3).error() ==
              stream_send_error::unsent_data &&
              equals(stream.next_pending(4), 2, "cd"),
          "mixed sent and unsent loss rejected atomically");
    check(stream.mark_sent(3, 2).error() ==
              stream_send_error::invalid_range &&
              stream.acknowledge(5, 0).error() ==
                  stream_send_error::invalid_range,
          "out-of-range reports rejected");
    check(stream.mark_sent(0, 2, true).error() ==
              stream_send_error::invalid_fin,
          "FIN cannot be sent before close");
    check(stream.close() == std::uint64_t {4}, "final size committed");
    check(stream.acknowledge(0, 2, true).error() ==
              stream_send_error::invalid_fin && stream.base_offset() == 0,
          "misplaced FIN ACK rejects bytes atomically");
    check(stream.mark_sent(2, 2, true).has_value() &&
              stream.acknowledge(0, 4, true).has_value() && stream.complete(),
          "valid FIN and byte ACK complete stream");
    check(stream.mark_sent(4, 0, true).error() ==
              stream_send_error::invalid_fin,
          "ACKed FIN cannot be retransmitted");

    stream_send_buffer<1> empty(0);
    check(empty.close() == std::uint64_t {0} &&
              equals(empty.next_pending(0), 0, "", true),
          "zero-length stream has an empty FIN");
    check(empty.mark_sent(0, 0, true).has_value() &&
              empty.acknowledge(0, 0, true).has_value() && empty.complete(),
          "zero-length stream completion");

    stream_send_buffer<1> invalid(max_varint_value + 1);
    check(!invalid.valid() &&
              invalid.append(input("x")).error() ==
                  stream_send_error::invalid_flow_limit &&
              invalid.close().error() == stream_send_error::invalid_flow_limit,
          "invalid initial flow limit rejected");
    check(stream.extend_flow_limit(3).error() ==
              stream_send_error::invalid_flow_limit &&
              stream.extend_flow_limit(max_varint_value + 1).error() ==
                  stream_send_error::invalid_flow_limit,
          "flow limit cannot decrease or exceed QUIC range");
}

auto fin_report_ordering() -> void
{
    stream_send_buffer<4> stream(2);
    check(stream.append(input("abcd")) == std::uint64_t {0} &&
              stream.close() == std::uint64_t {4},
          "final size may exceed current flow credit");
    check(stream.acknowledge(4, 0, true).error() ==
              stream_send_error::invalid_fin &&
              stream.mark_lost(4, 0, true).error() ==
                  stream_send_error::invalid_fin,
          "FIN reports require a transmitted FIN");
    check(equals(stream.next_pending(4), 0, "ab") &&
              stream.mark_sent(2, 2, true).error() ==
                  stream_send_error::flow_blocked,
          "final frame cannot exceed stream credit");
    check(stream.mark_sent(0, 2).has_value() &&
              stream.extend_flow_limit(4).has_value() &&
              equals(stream.next_pending(4), 2, "cd", true) &&
              stream.mark_sent(2, 2, true).has_value(),
          "FIN attaches at the final offset after credit extension");
    check(stream.mark_lost(2, 2, true).has_value() &&
              stream.acknowledge(2, 2, true).has_value() &&
              stream.acknowledge(0, 2).has_value() &&
              stream.complete(),
          "late ACK wins over a reported FIN and data loss");
    check(stream.mark_lost(2, 2, true).has_value() &&
              !stream.next_pending(4).fin &&
              stream.next_pending(4).data.empty(),
          "later duplicate loss cannot restore completed stream");
}

auto fin_only_after_data_ack() -> void
{
    stream_send_buffer<2> stream(2);
    check(stream.append(input("ab")) == std::uint64_t {0} &&
              stream.mark_sent(0, 2).has_value() &&
              stream.acknowledge(0, 2).has_value() &&
              stream.close() == std::uint64_t {2} &&
              equals(stream.next_pending(0), 2, "", true),
          "ACKed data can be followed by a FIN-only frame");
    check(stream.mark_sent(2, 0, true).has_value() &&
              stream.mark_lost(2, 0, true).has_value() &&
              equals(stream.next_pending(0), 2, "", true) &&
              stream.acknowledge(2, 0, true).has_value() &&
              stream.complete(),
          "FIN-only retransmission retires on ACK");
}

auto send_preflight_preserves_pending_bytes_and_fin() -> void
{
    stream_send_buffer<8> stream(8);
    check(stream.append(input("abcd")).has_value() && stream.close().has_value(),
          "prepare pending data and FIN");
    check(stream.preflight_mark_sent(0, 4, true).has_value() &&
          equals(stream.next_pending(8), 0, "abcd", true),
          "successful preflight preserves pending bytes and FIN");
    check(stream.preflight_mark_sent(0, 3, true).error() == stream_send_error::invalid_fin &&
          stream.mark_sent(0, 3, true).error() == stream_send_error::invalid_fin &&
          equals(stream.next_pending(8), 0, "abcd", true),
          "failed preflight and commit leave data and FIN pending");
    check(stream.mark_sent(0, 4, true).has_value() &&
          stream.acknowledge(2, 1).has_value() &&
          stream.preflight_mark_sent(1, 3, true).error() == stream_send_error::invalid_range &&
          stream.mark_lost(0, 4, true).has_value() &&
          equals(stream.next_pending(8), 0, "ab", false),
          "preflight rejects selectively ACKed bytes without consuming retransmissions");
}

} // namespace

auto main() -> int
{
    send_preflight_preserves_pending_bytes_and_fin();
    flow_credit_and_fin();
    partial_ack_loss_and_fin_only();
    ring_wrap_and_capacity();
    invalid_reports_and_empty_stream();
    fin_report_ordering();
    fin_only_after_data_ack();
}
