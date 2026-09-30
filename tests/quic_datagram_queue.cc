#include "quic/datagram_queue.h"
#include "quic/frames.h"

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
    std::cerr << "QUIC datagram queue: " << message << '\n';
    std::exit(1);
}

auto bytes(std::string_view text) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(text.data(), text.size()));
}

auto matches(std::span<const std::byte> data, std::string_view text) -> bool
{
    if (data.size() != text.size()) return false;
    for (std::size_t i = 0; i < data.size(); ++i)
        if (std::to_integer<char>(data[i]) != text[i]) return false;
    return true;
}

auto negotiation_and_frame_sizes() -> void
{
    std::array<std::byte, 64> storage {};
    std::array<datagram_slot, 1> slots {{{storage}}};
    datagram_queue queue(slots);
    check(queue.push(bytes("a")).error() ==
              datagram_queue_error::not_negotiated && queue.empty(),
          "disabled direction rejects send");

    queue.reset(5); // 0x31 + one-byte length + three payload bytes.
    check(queue.push(bytes("abc")).has_value(),
          "exact negotiated frame size accepted");
    const auto first = queue.front();
    check(first && first->length_present && matches(first->data, "abc"),
          "front preserves exact payload");
    std::array<std::byte, 8> frame_storage {};
    decoded_frame frame;
    frame.type = first->length_present ? 0x31 : 0x30;
    frame.data = first->data;
    const auto encoded = encode_frame(frame, frame_storage);
    check(encoded && *encoded == 5, "queued payload encodes at negotiated size");
    check(queue.pop().has_value(), "pop consumes one datagram");
    check(queue.push(bytes("abcd")).error() ==
              datagram_queue_error::frame_too_large && queue.empty(),
          "oversized complete frame rejected atomically");

    check(queue.push(bytes("abcd"), false).has_value(),
          "lengthless frame uses one byte less overhead");
    check(queue.front() && !queue.front()->length_present,
          "lengthless frame shape retained");
    check(queue.pop().has_value(), "lengthless datagram consumed");

    queue.reset(1);
    check(queue.push({}, false).has_value(),
          "empty lengthless datagram allowed");
    check(queue.pop().has_value(), "empty lengthless datagram consumed");
    check(queue.push({}).error() == datagram_queue_error::frame_too_large,
          "empty length-bearing frame still needs two bytes");
    queue.reset(2);
    check(queue.push({}).has_value() && queue.front() &&
              queue.front()->data.empty(),
          "empty length-bearing datagram allowed");
    std::array<std::byte, 0> empty_output {};
    check(queue.consume(empty_output) == std::size_t {0} && queue.empty(),
          "empty datagram consumes exactly one queue slot");

    queue.reset(66);
    check(queue.push(std::span<const std::byte>(storage.data(), 64)).error() ==
              datagram_queue_error::frame_too_large,
          "varint length growth counts toward negotiated frame size");
    queue.reset(67);
    check(queue.push(std::span<const std::byte>(storage.data(), 64)).has_value(),
          "varint length boundary accepted at exact total size");
}

auto boundaries_capacity_and_reset() -> void
{
    std::array<std::byte, 3> first_storage {};
    std::array<std::byte, 3> second_storage {};
    std::array<datagram_slot, 2> slots {{{first_storage}, {second_storage}}};
    datagram_queue queue(slots, 8);
    check(queue.push(bytes("one")).has_value() &&
              queue.push(bytes("two")).has_value() && queue.size() == 2,
          "two datagrams queued separately");
    check(queue.push(bytes("x")).error() == datagram_queue_error::full &&
              matches(queue.front()->data, "one"),
          "full queue rejects without replacing oldest");

    std::array<std::byte, 2> short_output {std::byte {0x7f}, std::byte {0x7f}};
    check(queue.consume(short_output).error() ==
              datagram_queue_error::output_too_small &&
              queue.size() == 2 && matches(queue.front()->data, "one") &&
              short_output[0] == std::byte {0x7f},
          "short receive does not truncate or consume");
    std::array<std::byte, 3> output {};
    check(queue.consume(output) == std::size_t {3} &&
              matches(output, "one") && queue.size() == 1 &&
              matches(queue.front()->data, "two"),
          "consume returns one whole datagram");
    check(queue.push(bytes("new")).has_value() && queue.size() == 2,
          "released slot reused across ring wrap");
    check(queue.consume(output) == std::size_t {3} &&
              matches(output, "two") &&
              queue.consume(output) == std::size_t {3} &&
              matches(output, "new") && queue.empty(),
          "FIFO boundaries survive wrap");
    check(queue.consume(output).error() == datagram_queue_error::empty &&
              queue.pop().error() == datagram_queue_error::empty,
          "empty queue reports empty");

    check(queue.push(bytes("one")).has_value(), "queue refilled");
    queue.reset(0);
    check(queue.empty() && queue.size() == 0 &&
              queue.push(bytes("x")).error() ==
                  datagram_queue_error::not_negotiated,
          "reset drops contents and disables direction");
    queue.reset(8);
    check(queue.push(bytes("toolong")).error() ==
              datagram_queue_error::frame_too_large && queue.empty(),
          "caller storage capacity enforced");

    datagram_queue no_slots({}, 8);
    check(no_slots.push({}).error() == datagram_queue_error::full,
          "zero slot capacity reports full");
}

} // namespace

auto main() -> int
{
    negotiation_and_frame_sizes();
    boundaries_capacity_and_reset();
}
