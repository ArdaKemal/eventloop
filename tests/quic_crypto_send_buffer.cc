#include "quic/crypto_send_buffer.h"

#include <array>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC CRYPTO send buffer: " << message << '\n';
    std::exit(1);
}

auto input(std::string_view value) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(value.data(), value.size()));
}

auto equals(crypto_send_chunk chunk, std::uint64_t offset,
            std::string_view text) -> bool
{
    if (chunk.offset != offset || chunk.data.size() != text.size()) return false;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (std::to_integer<unsigned char>(chunk.data[i]) !=
            static_cast<unsigned char>(text[i])) return false;
    }
    return true;
}

auto partial_ack_and_loss() -> void
{
    crypto_send_buffer<16> buffer;
    check(buffer.append(input("abcdefgh")) == 0, "append initial handshake");
    check(equals(buffer.next_pending(3), 0, "abc"), "packet sized selection");
    check(buffer.mark_sent(0, 8).has_value(), "record sent bytes");
    check(buffer.next_pending(8).data.empty(), "sent bytes not pending");
    check(buffer.acknowledge(0, 3).has_value(), "partial ACK");
    check(buffer.base_offset() == 3 && buffer.buffered_size() == 5,
          "ACKed prefix released");
    check(buffer.mark_lost(3, 3).has_value(), "partial loss");
    check(equals(buffer.next_pending(8), 3, "def"),
          "only lost bytes retransmittable");
    check(buffer.mark_sent(3, 3).has_value(), "retransmission recorded");
    check(buffer.acknowledge(6, 2).has_value(), "out of order ACK");
    check(buffer.base_offset() == 3, "gap retains later ACKed data");
    check(buffer.mark_lost(3, 5).has_value(), "overlapping loss accepted");
    check(equals(buffer.next_pending(8), 3, "def"),
          "ACK wins over overlapping loss");
    check(buffer.acknowledge(3, 3).has_value() &&
          buffer.base_offset() == 8 && buffer.buffered_size() == 0,
          "all ACKed bytes retired");
    check(buffer.mark_lost(0, 8).has_value() &&
          buffer.acknowledge(0, 8).has_value() &&
          buffer.next_pending(8).data.empty(),
          "late duplicate reports do not resurrect retired data");
}

auto overlapping_transmissions_and_wrap() -> void
{
    crypto_send_buffer<8> buffer;
    check(buffer.append(input("abcdef")) == 0, "append first data");
    check(buffer.mark_sent(0, 6).has_value() &&
          buffer.mark_sent(2, 4).has_value(), "overlapping probe recorded");
    check(buffer.mark_lost(0, 4).has_value() &&
          equals(buffer.next_pending(8), 0, "abcd"),
          "lost overlap becomes pending");
    check(buffer.acknowledge(2, 4).has_value(), "probe ACK accepted");
    check(equals(buffer.next_pending(8), 0, "ab"),
          "probe ACK removes retransmission of overlap");
    check(buffer.mark_sent(0, 2).has_value() &&
          buffer.acknowledge(0, 2).has_value(), "retire prefix");
    check(buffer.append(input("ghijkl")) == 6, "reuse ring slots");
    check(equals(buffer.next_pending(8), 6, "gh"),
          "selection stops at physical wrap");
    check(buffer.mark_sent(6, 2).has_value() &&
          equals(buffer.next_pending(8), 8, "ijkl"),
          "selection resumes after wrap");
    check(buffer.mark_sent(8, 4).has_value() &&
          buffer.acknowledge(6, 6).has_value(), "complete wrapped range");
    check(buffer.base_offset() == 12 && buffer.buffered_size() == 0,
          "wrapped ACK retires all bytes");
}

auto bounds_and_failure_atomicity() -> void
{
    crypto_send_buffer<4> buffer;
    check(buffer.append(input("abcd")) == 0, "fill capacity");
    check(buffer.append(input("e")).error() ==
              crypto_send_error::capacity_exceeded &&
          buffer.next_offset() == 4 &&
          equals(buffer.next_pending(4), 0, "abcd"),
          "failed append leaves data intact");
    check(buffer.acknowledge(0, 1).error() ==
              crypto_send_error::unsent_data &&
          buffer.base_offset() == 0, "unsent ACK rejected");
    check(buffer.mark_lost(0, 1).error() ==
              crypto_send_error::unsent_data, "unsent loss rejected");
    check(buffer.mark_sent(0, 2).has_value(), "partial send");
    check(buffer.acknowledge(0, 3).error() ==
              crypto_send_error::unsent_data &&
          buffer.base_offset() == 0,
          "mixed sent and unsent ACK rejects atomically");
    check(buffer.mark_lost(0, 3).error() ==
              crypto_send_error::unsent_data &&
          equals(buffer.next_pending(4), 2, "cd"),
          "mixed sent and unsent loss rejects atomically");
    check(buffer.mark_sent(3, 2).error() ==
              crypto_send_error::invalid_range &&
          buffer.acknowledge(4, 1).error() ==
              crypto_send_error::invalid_range &&
          buffer.mark_lost(5, 0).error() ==
              crypto_send_error::invalid_range,
          "out of bounds reports rejected");
    check(buffer.mark_sent(2, 2).has_value() &&
          buffer.acknowledge(0, 4).has_value(), "retire full window");
    check(buffer.mark_sent(0, 1).error() ==
              crypto_send_error::invalid_range,
          "retired bytes cannot be marked sent again");
    check(buffer.append({}) == 4 && buffer.next_offset() == 4,
          "empty append does not advance offset");
    buffer.reset();
    check(buffer.base_offset() == 0 && buffer.next_offset() == 0 &&
          buffer.append(input("xy")) == 0 &&
          equals(buffer.next_pending(4), 0, "xy"),
          "reset starts a new level stream");
}

auto delayed_reports_after_ring_reuse() -> void
{
    crypto_send_buffer<4> buffer;
    check(buffer.append(input("abcd")) == 0 &&
              buffer.mark_sent(0, 4).has_value() &&
              buffer.acknowledge(1, 3).has_value(),
          "out-of-order ACK retains the unacknowledged prefix");
    check(buffer.base_offset() == 0 &&
              buffer.append(input("e")).error() ==
                  crypto_send_error::capacity_exceeded,
          "out-of-order ACK does not release ring capacity");
    check(buffer.mark_lost(0, 4).has_value() &&
              equals(buffer.next_pending(4), 0, "a"),
          "loss does not resurrect ACKed suffix");
    check(buffer.mark_sent(0, 1).has_value() &&
              buffer.acknowledge(0, 1).has_value() &&
              buffer.append(input("efgh")) == 4,
          "retiring prefix releases wrapped slots");
    check(buffer.acknowledge(0, 4).has_value() &&
              buffer.mark_lost(0, 4).has_value() &&
              equals(buffer.next_pending(4), 4, "efgh"),
          "delayed reports cannot affect reused slots");
    check(buffer.mark_sent(4, 4).has_value() &&
              buffer.mark_sent(4, 1).has_value() &&
              buffer.acknowledge(4, 1).has_value() &&
              buffer.mark_sent(4, 2).error() ==
                  crypto_send_error::invalid_range &&
              buffer.mark_lost(5, 3).has_value() &&
              equals(buffer.next_pending(4), 5, "fgh"),
          "failed overlapping send does not clear pending bytes");
}

} // namespace

auto main() -> int
{
    partial_ack_and_loss();
    overlapping_transmissions_and_wrap();
    bounds_and_failure_atomicity();
    delayed_reports_after_ring_reuse();
}
