#include "quic/crypto_buffer.h"

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
    std::cerr << "QUIC CRYPTO buffer: " << message << '\n';
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

auto reordered_and_gapped() -> void
{
    std::array<std::byte, 8> storage {};
    std::array<std::byte, 1> coverage {};
    crypto_receive_buffer buffer(storage, coverage);
    check(buffer.valid(), "valid caller storage");
    check(buffer.insert(4, input("ef")) == 2, "out of order bytes stored");
    check(buffer.readable().empty(), "gap blocks delivery");
    check(buffer.insert(0, input("ab")) == 2, "prefix stored");
    check(equals(buffer.readable(), "ab"), "only prefix readable");
    check(buffer.insert(2, input("cd")) == 2, "gap filled");
    check(equals(buffer.readable(), "abcdef"), "ordered contiguous bytes");
    check(buffer.consume(3).has_value() && buffer.next_offset() == 3,
          "partial consume advances offset");
    check(equals(buffer.readable(), "def"), "remaining bytes readable");
    check(buffer.insert(6, input("gh")) == 2, "append to buffered tail");
    check(equals(buffer.readable(), "defgh"), "tail becomes contiguous");
    check(buffer.consume(5).has_value() && buffer.readable().empty(),
          "consume all buffered bytes");
}

auto overlap_and_duplicates() -> void
{
    std::array<std::byte, 8> storage {};
    std::array<std::byte, 1> coverage {};
    crypto_receive_buffer buffer(storage, coverage);
    check(buffer.insert(2, input("cdef")) == 4, "initial range");
    check(buffer.insert(2, input("cdef")) == 0, "identical duplicate");
    check(buffer.insert(4, input("efgh")) == 2, "identical overlap");
    check(buffer.insert(1, input("bcdX")).error() ==
              crypto_buffer_error::conflicting_data,
          "conflicting overlap rejected");
    check(buffer.insert(0, input("a")) == 1 && buffer.readable().size() == 1,
          "conflict did not partially insert new prefix");
    check(buffer.insert(1, input("b")) == 1 &&
              equals(buffer.readable(), "abcdefgh"),
          "valid overlap remains intact");
    check(buffer.consume(8).has_value(), "consume assembled range");
    check(buffer.insert(0, input("abcdefgh")) == 0,
          "old retransmission ignored");
}

auto wrap_and_reset() -> void
{
    std::array<std::byte, 8> storage {};
    std::array<std::byte, 1> coverage {};
    crypto_receive_buffer buffer(storage, coverage);
    check(buffer.insert(0, input("abcdef")) == 6, "initial ring data");
    check(buffer.consume(6).has_value(), "advance to ring tail");
    check(buffer.insert(6, input("ghij")) == 4, "ring wraps");
    check(equals(buffer.readable(), "gh"), "first physical span");
    check(buffer.consume(2).has_value(), "consume first physical span");
    check(equals(buffer.readable(), "ij"), "second physical span");
    buffer.reset();
    check(buffer.next_offset() == 0 && buffer.readable().empty(),
          "reset clears offsets and coverage");
    check(buffer.insert(0, input("xy")) == 2 &&
              equals(buffer.readable(), "xy"),
          "storage reusable after reset");
}

auto bounds_and_empty_data() -> void
{
    std::array<std::byte, 4> storage {};
    std::array<std::byte, 1> coverage {};
    crypto_receive_buffer buffer(storage, coverage);
    check(buffer.insert(0, {}).value() == 0, "empty input accepted");
    check(buffer.insert(max_varint_value, {}).value() == 0,
          "empty input at maximum offset accepted");
    check(buffer.next_offset() == 0, "empty input does not advance offset");
    check(buffer.insert(max_varint_value + 1, {}).error() ==
              crypto_buffer_error::invalid_offset,
          "offset beyond QUIC range rejected");
    check(buffer.insert(max_varint_value, input("x")).error() ==
              crypto_buffer_error::invalid_offset,
          "offset plus length overflow rejected");
    check(buffer.insert(4, input("x")).error() ==
              crypto_buffer_error::capacity_exceeded,
          "future byte outside capacity rejected");
    check(buffer.insert(0, input("abcde")).error() ==
              crypto_buffer_error::capacity_exceeded,
          "oversized range rejected");
    check(buffer.consume(1).error() == crypto_buffer_error::invalid_consume,
          "unread bytes cannot be consumed");
    check(buffer.insert(0, input("abc")) == 3, "short range accepted");
    check(buffer.consume(3).has_value(), "consume short range");
    check(buffer.insert(1, input("bcde")) == 2 &&
              equals(buffer.readable(), "d"),
          "consumed prefix trimmed from retransmission");
    check(buffer.consume(1).has_value() && equals(buffer.readable(), "e"),
          "trimmed range wraps correctly");

    std::array<std::byte, 0> missing {};
    crypto_receive_buffer no_storage(missing, coverage);
    check(!no_storage.valid() &&
              no_storage.insert(0, input("x")).error() ==
                  crypto_buffer_error::invalid_storage,
          "zero capacity rejected");
    std::array<std::byte, 0> no_coverage {};
    crypto_receive_buffer no_bitmap(storage, no_coverage);
    check(!no_bitmap.valid() &&
              no_bitmap.consume(0).error() ==
                  crypto_buffer_error::invalid_storage,
          "undersized bitmap rejected");
}

} // namespace

auto main() -> int
{
    reordered_and_gapped();
    overlap_and_duplicates();
    wrap_and_reset();
    bounds_and_empty_data();
}
