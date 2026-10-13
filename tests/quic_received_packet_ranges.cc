#include "quic/received_packet_ranges.h"

#include <algorithm>
#include <array>
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
    std::cerr << "QUIC received packet ranges: " << message << '\n';
    std::exit(1);
}

template <std::size_t Capacity>
auto expect_ranges(const received_packet_ranges<Capacity>& received,
                   std::span<const ack_range> expected) -> void
{
    const auto actual = received.ranges();
    check(actual.size() == expected.size(), "range count");
    for (std::size_t index = 0; index < actual.size(); ++index)
        check(actual[index].smallest == expected[index].smallest &&
              actual[index].largest == expected[index].largest,
              "range content/order");
}

auto insertion_and_capacity() -> void
{
    received_packet_ranges<3> received;
    check(received.size() == 0, "initially empty");
    for (const auto number : std::array<std::uint64_t, 3> {10, 7, 3})
        check(received.insert(number) == true, "insert disjoint packet");
    constexpr std::array initial {ack_range {10, 10}, ack_range {7, 7},
                                  ack_range {3, 3}};
    expect_ranges(received, initial);
    check(received.insert(5) == true && received.minimum_acceptable() == 4,
          "fourth disjoint range evicts the oldest");
    constexpr std::array evicted {ack_range {10, 10}, ack_range {7, 7},
                                  ack_range {5, 5}};
    expect_ranges(received, evicted);
    check(received.insert(3).error() == received_packet_error::retired_packet_number,
          "evicted packets count as retired");
    check(received.insert(7) == false, "duplicate at capacity");
    check(received.insert(8) == true && received.insert(9) == true,
          "adjacent packets merge higher ranges at capacity");
    constexpr std::array merged {ack_range {7, 10}, ack_range {5, 5}};
    expect_ranges(received, merged);
    check(received.insert(4) == true && received.insert(6) == true,
          "join below and bridge ranges");
    constexpr std::array bridged {ack_range {4, 10}};
    expect_ranges(received, bridged);
    check(received.insert(5) == false, "interior duplicate");
    check(received.insert(max_varint_value + 1).error() ==
              received_packet_error::invalid_packet_number,
          "reject out-of-range packet number");
    expect_ranges(received, bridged);
    received.reset();
    check(received.size() == 0 && !received.largest_received() &&
          received.minimum_acceptable() == 0 && received.insert(0) == true,
          "reset allows packet zero");
    constexpr std::array zero {ack_range {0, 0}};
    expect_ranges(received, zero);
}

auto ack_encoding() -> void
{
    received_packet_ranges<4> received;
    for (const auto number : std::array<std::uint64_t, 7> {10, 9, 7, 6,
                                                            5, 3, 2})
        check(received.insert(number) == true, "insert ACK packet");
    std::array<std::byte, 8> storage {};
    const auto ack = received.make_ack(3, storage);
    check(ack && ack->type == 0x02 && ack->largest_acknowledged == 10 &&
          ack->ack_delay == 3 && ack->ack_range_count == 2 &&
          ack->first_ack_range == 1 && ack->ack_ranges.size() == 4,
          "ACK frame fields");
    constexpr std::array pairs {std::byte {0}, std::byte {2},
                                std::byte {0}, std::byte {1}};
    check(std::equal(ack->ack_ranges.begin(), ack->ack_ranges.end(),
                     pairs.begin()), "canonical gap/range bytes");

    auto cursor = ack_range_cursor::from_frame(*ack);
    check(cursor.has_value(), "generated ACK cursor");
    for (const auto expected : {ack_range {9, 10}, ack_range {5, 7},
                                ack_range {2, 3}}) {
        const auto next = cursor->next();
        check(next && next->has_value() &&
              next->value().smallest == expected.smallest &&
              next->value().largest == expected.largest,
              "generated range round trip");
    }
    const auto end = cursor->next();
    check(end && !end->has_value(), "generated ACK cursor end");

    std::array<std::byte, 16> wire {};
    const auto encoded = encode_frame(*ack, wire);
    constexpr std::array expected_wire {
        std::byte {2}, std::byte {10}, std::byte {3}, std::byte {2},
        std::byte {1}, std::byte {0}, std::byte {2}, std::byte {0},
        std::byte {1}};
    check(encoded == expected_wire.size() &&
          std::equal(wire.begin(), wire.begin() + *encoded,
                     expected_wire.begin()), "full ACK encoding");
    const auto decoded = decode_frame(std::span(wire).first(*encoded));
    check(decoded && decoded->largest_acknowledged == 10 &&
          decoded->ack_range_count == 2, "full ACK decode");

    std::array<std::byte, 2> short_storage {};
    const auto newest = received.make_ack(3, short_storage);
    check(newest && newest->ack_range_count == 1 &&
          newest->ack_ranges.size() == 2 &&
          short_storage[0] == std::byte {0} &&
          short_storage[1] == std::byte {2},
          "small storage keeps newest additional range");
}

auto ack_storage_limits() -> void
{
    received_packet_ranges<3> received;
    std::array<std::byte, 4> storage {};
    storage.fill(std::byte {0xa5});
    const auto untouched = storage;
    check(received.make_ack(0, storage).error() == received_packet_error::empty,
          "empty tracker cannot make ACK");
    check(received.insert(100) == true && received.insert(0) == true,
          "large-gap setup");
    check(received.make_ack(max_varint_value + 1, storage).error() ==
              received_packet_error::invalid_ack_delay,
          "ACK delay bounds");
    check(storage == untouched, "failed ACK generation leaves storage intact");
    const auto base = received.make_ack(0, std::span(storage).first(1));
    check(base && base->ack_range_count == 0 && base->ack_ranges.empty() &&
          base->largest_acknowledged == 100 && storage == untouched,
          "small storage emits newest range only");
    const auto ack = received.make_ack(0, storage);
    check(ack && ack->ack_ranges.size() == 3 &&
          ack->ack_ranges[0] == std::byte {0x40} &&
          ack->ack_ranges[1] == std::byte {98} &&
          ack->ack_ranges[2] == std::byte {0},
          "multi-byte gap uses canonical varint");

    received_packet_ranges<2> edge;
    check(edge.insert(max_varint_value) == true && edge.insert(0) == true,
          "packet-number boundaries");
    std::array<std::byte, 16> edge_storage {};
    const auto edge_ack = edge.make_ack(0, edge_storage);
    check(edge_ack && edge_ack->largest_acknowledged == max_varint_value,
          "maximum packet number encoded");
    auto edge_cursor = ack_range_cursor::from_frame(*edge_ack);
    check(edge_cursor.has_value(), "maximum packet ACK validates");
    const auto high = edge_cursor->next();
    const auto low = edge_cursor->next();
    check(high && high->has_value() &&
          high->value().smallest == max_varint_value &&
          low && low->has_value() && low->value().smallest == 0,
          "maximum packet ACK range round trip");
    check(edge.retire_through(max_varint_value) == true &&
          edge.minimum_acceptable() == max_varint_value + 1 &&
          edge.size() == 0 && edge.largest_received() == max_varint_value,
          "maximum packet retirement preserves high-water mark");
    check(edge.insert(max_varint_value).error() ==
              received_packet_error::retired_packet_number,
          "retired maximum packet cannot be accepted again");
}

auto retirement_and_floor() -> void
{
    received_packet_ranges<2> received;
    for (std::uint64_t number = 3; number <= 10; ++number)
        check(received.insert(number) == true, "retirement setup");
    check(received.largest_received() == 10 &&
          received.minimum_acceptable() == 0, "initial lifetime state");
    check(received.retire_through(11).error() ==
              received_packet_error::invalid_retirement &&
          received.retire_through(max_varint_value + 1).error() ==
              received_packet_error::invalid_retirement,
          "retirement validates packet-number bounds");
    check(received.minimum_acceptable() == 0 && received.size() == 1,
          "failed retirement is atomic");
    check(received.retire_through(6) == true,
          "retire acknowledged lower portion");
    constexpr std::array partial {ack_range {7, 10}};
    expect_ranges(received, partial);
    check(received.minimum_acceptable() == 7 &&
          received.largest_received() == 10, "partial range trim");
    check(received.insert(6).error() ==
              received_packet_error::retired_packet_number &&
          received.insert(3).error() ==
              received_packet_error::retired_packet_number,
          "forgotten packets cannot be accepted again");
    check(received.retire_through(6) == false,
          "stale retirement is a no-op");
    check(received.retire_through(10) == true && received.size() == 0 &&
          received.minimum_acceptable() == 11 &&
          received.largest_received() == 10,
          "retirement can empty ranges without losing largest received");
    std::array<std::byte, 1> storage {};
    check(received.make_ack(0, storage).error() == received_packet_error::empty,
          "fully retired tracker has no ACK range");
    check(received.insert(10).error() ==
              received_packet_error::retired_packet_number &&
          received.insert(11) == true,
          "only newer packets accepted after full retirement");

    received_packet_ranges<2> gapped;
    check(gapped.insert(10) == true && gapped.insert(5) == true,
          "gapped retirement setup");
    check(gapped.retire_through(8).error() ==
              received_packet_error::invalid_retirement &&
          gapped.minimum_acceptable() == 0,
          "retirement rejects a number never received");
    check(gapped.retire_through(5) == true && gapped.size() == 1,
          "retire older disjoint range");
    constexpr std::array remaining {ack_range {10, 10}};
    expect_ranges(gapped, remaining);
    check(gapped.insert(20) == true && gapped.largest_received() == 20,
          "new highest can use capacity freed by retirement");
}

auto range_width_boundaries() -> void
{
    received_packet_ranges<2> one_byte_gap;
    check(one_byte_gap.insert(130) == true &&
          one_byte_gap.insert(65) == true, "one-byte gap setup");
    std::array<std::byte, 2> pair {};
    const auto one_byte = one_byte_gap.make_ack(0, pair);
    check(one_byte && one_byte->ack_range_count == 1 &&
          pair[0] == std::byte {63} && pair[1] == std::byte {0},
          "gap 63 fits two bytes");

    received_packet_ranges<2> two_byte_gap;
    check(two_byte_gap.insert(130) == true &&
          two_byte_gap.insert(64) == true, "two-byte gap setup");
    const auto omitted = two_byte_gap.make_ack(0, pair);
    check(omitted && omitted->ack_range_count == 0 &&
          omitted->ack_ranges.empty(), "gap 64 needs three bytes");
    std::array<std::byte, 3> wider {};
    const auto included = two_byte_gap.make_ack(0, wider);
    check(included && included->ack_range_count == 1 &&
          wider[0] == std::byte {0x40} && wider[1] == std::byte {64} &&
          wider[2] == std::byte {0}, "gap 64 encodes in two-byte varint");

    received_packet_ranges<2> range_length;
    check(range_length.insert(66) == true, "range-width setup");
    for (std::uint64_t number = 0; number <= 63; ++number)
        check(range_length.insert(number) == true, "grow lower range");
    const auto short_range = range_length.make_ack(0, pair);
    check(short_range && short_range->ack_range_count == 1 &&
          pair[1] == std::byte {63}, "range length 63 fits two bytes");
    check(range_length.insert(64) == true, "cross range-width boundary");
    const auto wide_range = range_length.make_ack(0, pair);
    check(wide_range && wide_range->ack_range_count == 0,
          "range length 64 does not fit two bytes");
}

auto highest_at_capacity() -> void
{
    received_packet_ranges<2> received;
    check(received.insert(10) == true && received.insert(7) == true,
          "full capacity setup");
    check(received.insert(20) == true && received.largest_received() == 20 &&
          received.minimum_acceptable() == 8,
          "new highest packet evicts the oldest range");
    check(received.insert(15) == true && received.minimum_acceptable() == 11,
          "each new disjoint range evicts the next oldest");
    check(received.insert(12).error() == received_packet_error::retired_packet_number &&
          received.largest_received() == 20,
          "a packet older than every range is refused at capacity");
    check(received.retire_through(10) == false,
          "retiring an evicted range is a stale no-op");
    check(received.insert(21) == true && received.largest_received() == 21,
          "adjacent highest packet succeeds at full capacity");
}

} // namespace

auto main() -> int
{
    insertion_and_capacity();
    ack_encoding();
    ack_storage_limits();
    retirement_and_floor();
    range_width_boundaries();
    highest_at_capacity();
}
