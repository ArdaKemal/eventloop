#include "quic/stream_receive_buffer.h"

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
    std::cerr << "QUIC stream receive: " << message << '\n';
    std::exit(1);
}

auto input(std::string_view value) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(value.data(), value.size()));
}

auto equals(std::span<const std::byte> value, std::string_view text) -> bool
{
    if (value.size() != text.size()) return false;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (std::to_integer<unsigned char>(value[i]) !=
            static_cast<unsigned char>(text[i])) return false;
    }
    return true;
}

auto ordered_delivery_and_fin() -> void
{
    std::array<std::byte, 8> storage {};
    std::array<std::byte, 1> coverage {};
    stream_receive_buffer stream(storage, coverage, 12);
    check(stream.valid(), "valid caller storage");
    check(stream.insert(4, input("ef"), true) == std::size_t {2},
          "out of order FIN data stored");
    check(stream.highest_received_offset() == 6 && stream.final_size() == 6,
          "FIN establishes final size");
    check(stream.readable().empty() && !stream.complete(),
          "gap blocks completion");
    check(stream.insert(0, input("ab")) == std::size_t {2} &&
              equals(stream.readable(), "ab"),
          "prefix delivered");
    check(stream.consume(2).has_value(), "prefix consumed");
    check(stream.insert(2, input("cd")) == std::size_t {2} &&
              equals(stream.readable(), "cdef"),
          "gap fill delivers ordered tail");
    check(stream.consume(4).has_value() && stream.complete(),
          "completion follows consumption through final size");
    check(stream.next_offset() == 6 && stream.readable().empty(),
          "all bytes consumed");
    check(stream.insert(4, input("ef"), true) == std::size_t {0},
          "duplicate FIN accepted");
}

auto overlap_and_atomicity() -> void
{
    std::array<std::byte, 8> storage {};
    std::array<std::byte, 1> coverage {};
    stream_receive_buffer stream(storage, coverage, 16);
    check(stream.insert(2, input("cdef")) == std::size_t {4}, "first range stored");
    check(stream.insert(4, input("efgh")) == std::size_t {2},
          "matching overlap accepted");
    check(stream.insert(2, input("cdef")) == std::size_t {0},
          "duplicate range adds no bytes");
    check(stream.insert(1, input("bcdX")).error() ==
              stream_receive_error::conflicting_data,
          "conflicting buffered overlap rejected");
    check(stream.highest_received_offset() == 8 && !stream.final_size(),
          "conflict leaves metadata unchanged");
    check(stream.insert(0, input("ab")) == std::size_t {2} &&
              equals(stream.readable(), "abcdefgh"),
          "conflict did not insert prefix");
    check(stream.consume(5).has_value(), "partial consume");
    check(equals(stream.readable(), "fgh"), "remaining ordered bytes");
    check(stream.insert(3, input("defgh")) == std::size_t {0},
          "consumed prefix ignored on retransmission");
    check(stream.insert(8, input("ij")) == std::size_t {2},
          "new bytes fit after consumption");
    check(equals(stream.readable(), "fgh"), "first wrapped span");
    check(stream.consume(3).has_value() &&
              equals(stream.readable(), "ij"),
          "second wrapped span");
}

auto final_size_rules() -> void
{
    std::array<std::byte, 8> storage {};
    std::array<std::byte, 1> coverage {};
    stream_receive_buffer stream(storage, coverage, 16);
    check(stream.insert(4, input("ef")) == std::size_t {2}, "tail received");
    check(stream.insert(0, input("abcd"), true).error() ==
              stream_receive_error::final_size_error,
          "FIN below highest received offset rejected");
    check(!stream.final_size() && stream.readable().empty(),
          "rejected FIN leaves state intact");
    check(stream.insert(0, input("abcdef"), true) == std::size_t {4},
          "FIN at highest offset accepted");
    check(stream.final_size() == 6, "final size recorded");
    check(stream.insert(0, input("abcde"), true).error() ==
              stream_receive_error::final_size_error,
          "changed final size rejected");
    check(stream.insert(6, input("x")).error() ==
              stream_receive_error::final_size_error,
          "data beyond final size rejected");
    check(stream.insert(7, {}, false).error() ==
              stream_receive_error::final_size_error,
          "empty frame beyond final size rejected");
    check(equals(stream.readable(), "abcdef"),
          "final-size errors do not change buffered bytes");

    std::array<std::byte, 1> empty_storage {};
    std::array<std::byte, 1> empty_coverage {};
    stream_receive_buffer empty(empty_storage, empty_coverage, 0);
    check(empty.insert(0, {}, true) == std::size_t {0} && empty.complete(),
          "empty FIN completes zero-length stream");
    check(empty.insert(0, {}, true) == std::size_t {0},
          "duplicate empty FIN accepted");
}

auto limits_and_invalid_input() -> void
{
    std::array<std::byte, 4> storage {};
    std::array<std::byte, 1> coverage {};
    stream_receive_buffer stream(storage, coverage, 5);
    check(stream.insert(4, {}, false) == std::size_t {0} &&
              stream.highest_received_offset() == 4,
          "empty frame records highest offset");
    check(stream.insert(4, input("xy")).error() ==
              stream_receive_error::flow_limit_exceeded,
          "per-stream flow limit enforced");
    check(stream.insert(5, {}, true).error() ==
              stream_receive_error::capacity_exceeded,
          "distant FIN exceeds reassembly capacity");
    check(!stream.final_size(), "capacity error leaves FIN unset");
    check(stream.extend_flow_limit(8).has_value() &&
              stream.flow_limit() == 8,
          "flow credit can increase");
    check(stream.extend_flow_limit(7).error() ==
              stream_receive_error::invalid_flow_limit,
          "flow credit cannot decrease");
    check(stream.insert(0, input("abcde")).error() ==
              stream_receive_error::capacity_exceeded,
          "data beyond ring capacity rejected");
    check(stream.insert(0, input("abcd")) == std::size_t {4},
          "data within ring capacity accepted");
    check(stream.consume(5).error() == stream_receive_error::invalid_consume,
          "unread bytes cannot be consumed");
    check(stream.consume(4).has_value(), "full prefix consumed");
    check(stream.insert(5, {}, true) == std::size_t {0} && !stream.complete(),
          "FIN accepted after receive window advances");
    check(stream.insert(4, input("e")) == std::size_t {1} &&
              equals(stream.readable(), "e"),
          "missing byte delivered");
    check(stream.consume(1).has_value() && stream.complete(),
          "stream completes after final byte consumed");

    check(stream.insert(max_varint_value + 1, {}).error() ==
              stream_receive_error::invalid_offset,
          "offset above varint limit rejected");
    check(stream.insert(max_varint_value, input("x")).error() ==
              stream_receive_error::invalid_offset,
          "offset plus data above varint limit rejected");
    check(stream.extend_flow_limit(max_varint_value + 1).error() ==
              stream_receive_error::invalid_flow_limit,
          "flow limit above varint range rejected");

    std::array<std::byte, 0> absent {};
    stream_receive_buffer no_storage(absent, coverage, 1);
    check(!no_storage.valid() &&
              no_storage.insert(0, input("x")).error() ==
                  stream_receive_error::invalid_storage,
          "zero storage rejected");
    stream_receive_buffer no_coverage(storage, absent, 1);
    check(!no_coverage.valid() &&
              no_coverage.consume(0).error() ==
                  stream_receive_error::invalid_storage,
          "undersized bitmap rejected");
    stream_receive_buffer bad_limit(storage, coverage, max_varint_value + 1);
    check(!bad_limit.valid() &&
              bad_limit.insert(0, {}).error() ==
                  stream_receive_error::invalid_flow_limit,
          "invalid initial flow limit rejected");
}

} // namespace

auto main() -> int
{
    ordered_delivery_and_fin();
    overlap_and_atomicity();
    final_size_rules();
    limits_and_invalid_input();
}
