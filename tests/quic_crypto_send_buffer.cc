#include "quic/crypto_send_buffer.h"

#include <array>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;

static_assert([] {
    crypto_send_buffer<17> buffer;
    std::array<std::byte,17> data {};
    if (!buffer.append(data) || !buffer.mark_sent(0,16)) return false;
    if (buffer.acknowledge(0,17) || !buffer.acknowledge(0,16)) return false;
    const auto pending=buffer.next_pending(17);
    return buffer.base_offset()==16 && pending.offset==16 && pending.data.size()==1;
}(), "flag validation remains usable during constant evaluation");

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

auto successive_probes_carry_different_bytes() -> void
{
    crypto_send_buffer<16> buffer;
    check(buffer.append(input("abcdefghij")) == 0 && buffer.mark_sent(0, 10).has_value() &&
          buffer.acknowledge(3, 2).has_value(), "outstanding flight with a gap");
    check(equals(buffer.next_unacknowledged(3), 0, "abc"), "first probe takes the oldest bytes");
    check(equals(buffer.next_unacknowledged(3, 3), 5, "fgh"), "next probe skips past it and ACKed bytes");
    check(equals(buffer.next_unacknowledged(3, 8), 8, "ij"), "probe reaches the end of the flight");
    check(buffer.next_unacknowledged(3, 10).data.empty(), "nothing follows the last probe");
}

auto split_loss_keeps_later_losses() -> void
{
    crypto_send_buffer<64> buffer;
    std::string bytes(64, 'x');
    for (std::size_t i = 20; i < 30; ++i) bytes[i] = 'a' + static_cast<char>(i - 20);
    check(buffer.append(input(bytes)) == 0 && buffer.mark_sent(0, 64).has_value() &&
          buffer.mark_lost(0, 10).has_value() && buffer.mark_lost(20, 10).has_value(),
          "two lost ranges");
    check(buffer.acknowledge(4, 2).has_value(), "ACK splits the first lost range");
    check(buffer.mark_sent(0, 4).has_value() && buffer.mark_sent(6, 4).has_value(),
          "split halves retransmitted");
    check(equals(buffer.next_pending(16), 20, "abcdefghij"), "later lost range still pending");
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

auto pending_selection_after_out_of_order_send() -> void
{
    crypto_send_buffer<8> buffer;
    check(buffer.append(input("abcdefgh")) == 0, "append full ring");
    check(buffer.preflight_mark_sent(0, 8).has_value() &&
              equals(buffer.next_pending(8), 0, "abcdefgh"),
          "send preflight does not advance pending selection");
    check(buffer.mark_sent(4, 4).has_value() &&
              equals(buffer.next_pending(8), 0, "abcd"),
          "sending a later interval preserves the earlier pending interval");
    check(buffer.mark_sent(0, 2).has_value() &&
              equals(buffer.next_pending(8), 2, "cd") &&
              buffer.mark_sent(2, 2).has_value() &&
              buffer.next_pending(8).data.empty(),
          "selection skips transmitted suffix when the pending prefix is sent");
    check(buffer.mark_lost(4, 4).has_value() &&
              buffer.mark_lost(0, 2).has_value() &&
              equals(buffer.next_pending(8), 0, "ab"),
          "earlier loss rewinds selection ahead of later pending data");
    check(buffer.acknowledge(0, 2).has_value() &&
              equals(buffer.next_pending(8), 4, "efgh"),
          "ACK of pending loss skips the transmitted gap");
    check(buffer.mark_sent(4, 2).has_value() &&
              buffer.acknowledge(6, 2).has_value() &&
              buffer.next_pending(8).data.empty(),
          "ACK of pending suffix leaves no pending bytes");
    check(buffer.mark_lost(2, 6).has_value() &&
              equals(buffer.next_pending(8), 2, "cdef"),
          "overlapping loss restores unacknowledged data only");
    check(buffer.mark_sent(2, 4).has_value() &&
              buffer.acknowledge(2, 4).has_value() &&
              buffer.append(input("ijklmnop")) == 8 &&
              equals(buffer.next_pending(8), 8, "ijklmnop"),
          "append after retirement restarts selection at reused storage");
    buffer.reset();
    check(buffer.append(input("xy")) == 0 && buffer.mark_sent(0, 2).has_value() &&
              buffer.retransmit_initial() && equals(buffer.next_pending(8), 0, "xy"),
          "Retry restores initial pending selection after reset");
}

auto bulk_flags_prefix_and_wrap() -> void
{
    crypto_send_buffer<8> buffer;
    check(buffer.append(input("abcdefgh")) == 0 &&
              buffer.mark_sent(0, 8).has_value() &&
              buffer.acknowledge(4, 4).has_value() &&
              buffer.mark_lost(0, 8).has_value() &&
              buffer.mark_sent(0, 4).has_value() &&
              buffer.acknowledge(0, 2).has_value(),
          "ACKed suffix waits for retransmitted prefix");
    check(buffer.append(input("ij")) == 8 && buffer.mark_sent(8, 2).has_value() &&
              buffer.mark_lost(2, 8).has_value() && buffer.acknowledge(2, 2).has_value(),
          "prefix retirement traverses earlier ACKed suffix");
    check(buffer.base_offset() == 8 && equals(buffer.next_pending(8), 8, "ij"),
          "retiring suffix preserves live data in reused ring slots");
    check(buffer.append(input("klmnop")) == 10 && buffer.mark_sent(8, 8).has_value() &&
              buffer.acknowledge(9, 3).has_value() && buffer.acknowledge(8, 4).has_value() &&
              buffer.base_offset() == 12,
          "overlapping ACK retires exactly the covered prefix");
    check(buffer.append(input("qrst")) == 16 && buffer.mark_sent(12, 8).has_value() &&
              buffer.acknowledge(14, 6).has_value() && buffer.mark_lost(12, 8).has_value(),
          "sent and ACKed flag ranges cross the physical ring boundary");
    check(buffer.mark_sent(12, 8).error() == crypto_send_error::invalid_range &&
              equals(buffer.next_pending(8), 12, "mn"),
          "failed wrapped send cannot clear its pending prefix");
    check(buffer.acknowledge(12, 2).has_value() && buffer.base_offset() == 20 &&
              buffer.buffered_size() == 0 && buffer.next_pending(8).data.empty(),
          "prefix ACK retires previously ACKed suffix across wrap");
    check(buffer.acknowledge(8, 12).has_value() && buffer.mark_lost(8, 12).has_value() &&
              buffer.append(input("uv")) == 20 &&
              equals(buffer.next_pending(8), 20, "uv"),
          "late reports do not rewrite newly reused slots");
}

auto flag_validation_word_boundaries() -> void
{
    const std::array<std::byte,31> data {};
    for (std::size_t unsent=0;unsent<data.size();++unsent) {
        crypto_send_buffer<31> buffer;
        check(buffer.append(data)==0 && buffer.mark_sent(0,unsent).has_value() &&
                  buffer.mark_sent(unsent+1,data.size()-unsent-1).has_value(),
              "leave one unsent byte at each validation position");
        check(buffer.acknowledge(0,data.size()).error()==crypto_send_error::unsent_data &&
                  buffer.mark_lost(0,data.size()).error()==crypto_send_error::unsent_data &&
                  buffer.base_offset()==0 && buffer.next_pending(31).offset==unsent,
              "word and remainder checks reject unsent bytes without mutation");
        check(buffer.mark_sent(unsent,1).has_value() &&
                  buffer.acknowledge(0,17).has_value() &&
                  buffer.append(std::span(data).first(17))==31 &&
                  buffer.mark_sent(31,17).has_value(),
              "reuse the ring with an unaligned validation start");
        const auto acked=18+unsent%30;
        check(buffer.acknowledge(acked,1).has_value() &&
                  buffer.preflight_mark_sent(17,31).error()==crypto_send_error::invalid_range,
              "word checks reject ACKed bytes in either wrapped segment");
        check(buffer.mark_lost(17,31).has_value() &&
                  buffer.mark_sent(17,31).error()==crypto_send_error::invalid_range,
              "failed wrapped send retains retransmission state");
        const auto pending=buffer.next_pending(31);
        check(pending.offset==17 && pending.data.size()==std::min<std::size_t>(acked-17,14),
              "validation failure preserves the pending prefix");
        check(buffer.acknowledge(17,31).has_value() && buffer.base_offset()==48 &&
                  buffer.next_pending(31).data.empty(),
              "validated wrapped ACK retires the full live window");
    }
}

auto acked_suffix_word_boundaries() -> void
{
    const std::array<std::byte,31> data {};
    for (std::size_t gap=1;gap<31;++gap) {
        crypto_send_buffer<31> buffer;
        check(buffer.append(data)==0 && buffer.mark_sent(0,31).has_value() &&
                  buffer.acknowledge(0,17).has_value() &&
                  buffer.append(std::span(data).first(17))==31 &&
                  buffer.mark_sent(31,17).has_value(),
              "prepare a full wrapped sent window");
        check(buffer.acknowledge(18,gap-1).has_value() &&
                  buffer.acknowledge(18+gap,30-gap).has_value() &&
                  buffer.acknowledge(17,1).has_value() &&
                  buffer.base_offset()==17+gap && buffer.buffered_size()==31-gap,
              "ACK suffix scan stops at each unacknowledged byte position");
        check(buffer.mark_lost(17+gap,1).has_value() &&
                  buffer.next_pending(31).offset==17+gap &&
                  buffer.next_pending(31).data.size()==1 &&
                  buffer.mark_sent(17+gap,1).has_value() &&
                  buffer.acknowledge(17+gap,1).has_value() &&
                  buffer.base_offset()==48 && buffer.buffered_size()==0,
              "filling the gap retires the wrapped ACKed suffix exactly");
        check(buffer.append(data)==48 && buffer.next_pending(31).offset==48,
              "retired word segments can be reused");
    }
}

auto pending_run_word_boundaries() -> void
{
    const std::array<std::byte,31> data {};
    for (std::size_t stop=1;stop<31;++stop) {
        crypto_send_buffer<31> buffer;
        check(buffer.append(data)==0 && buffer.mark_sent(stop,1).has_value(),
              "place a sent byte at every pending-run position");
        for (std::size_t maximum=0;maximum<=32;++maximum) {
            const auto chunk=buffer.next_pending(maximum);
            check(chunk.offset==0 && chunk.data.size()==std::min(maximum,stop),
                  "word scan clips at packet limit or first nonpending byte");
        }
        check(buffer.mark_sent(0,stop).has_value() &&
                  (stop==30 || buffer.next_pending(31).offset==stop+1) &&
                  buffer.next_pending(31).data.size()==30-stop,
              "pending cursor advances across the sent byte");
    }
    crypto_send_buffer<31> buffer;
    check(buffer.append(data)==0 && buffer.mark_sent(0,31).has_value() &&
              buffer.acknowledge(0,17).has_value() &&
              buffer.append(std::span(data).first(17))==31 &&
              buffer.mark_lost(17,14).has_value(),
          "prepare pending runs on both physical ring segments");
    check(buffer.next_pending(31).offset==17 && buffer.next_pending(31).data.size()==14 &&
              buffer.mark_sent(17,14).has_value() &&
              buffer.next_pending(31).offset==31 && buffer.next_pending(31).data.size()==17,
          "word scan stops at physical wrap and resumes in the next segment");
    check(buffer.mark_sent(31,17).has_value() && buffer.next_pending(31).data.empty(),
          "fully transmitted wrapped ring returns no pending span");
}

} // namespace

auto main() -> int
{
    partial_ack_and_loss();
    successive_probes_carry_different_bytes();
    split_loss_keeps_later_losses();
    overlapping_transmissions_and_wrap();
    bounds_and_failure_atomicity();
    delayed_reports_after_ring_reuse();
    pending_selection_after_out_of_order_send();
    bulk_flags_prefix_and_wrap();
    flag_validation_word_boundaries();
    acked_suffix_word_boundaries();
    pending_run_word_boundaries();
}
