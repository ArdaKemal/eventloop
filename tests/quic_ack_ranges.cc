#include "quic/ack_ranges.h"

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
    std::cerr << "QUIC ACK ranges: " << message << '\n';
    std::exit(1);
}

auto expect_range(ack_range_cursor& cursor, std::uint64_t smallest,
                  std::uint64_t largest) -> void
{
    const auto result = cursor.next();
    check(result && result->has_value() && result->value().smallest == smallest &&
          result->value().largest == largest, "unexpected range");
}

auto expect_end(ack_range_cursor& cursor) -> void
{
    const auto result = cursor.next();
    check(result && !result->has_value(), "expected end of ranges");
}

auto expect_error(const decoded_frame& frame, frame_error error) -> void
{
    auto cursor = ack_range_cursor::from_frame(frame);
    if (!cursor) {
        check(cursor.error() == error, "wrong header error");
        return;
    }
    for (;;) {
        const auto result = cursor->next();
        if (!result) {
            check(result.error() == error, "wrong range error");
            const auto repeated = cursor->next();
            check(!repeated && repeated.error() == error,
                  "error must remain terminal");
            return;
        }
        check(result->has_value(), "malformed ranges accepted");
    }
}

auto valid_ranges() -> void
{
    constexpr std::array<std::byte, 5> one {
        std::byte {0x02}, std::byte {10}, std::byte {0},
        std::byte {0}, std::byte {1}};
    const auto frame = decode_frame(one);
    check(frame.has_value(), "one-range ACK decode");
    auto cursor = ack_range_cursor::from_frame(*frame);
    check(cursor.has_value(), "one-range cursor");
    expect_range(*cursor, 9, 10);
    expect_end(*cursor);
    expect_end(*cursor);

    constexpr std::array<std::byte, 9> many {
        std::byte {0x02}, std::byte {10}, std::byte {0},
        std::byte {2}, std::byte {1}, std::byte {0},
        std::byte {2}, std::byte {0}, std::byte {1}};
    const auto many_frame = decode_frame(many);
    check(many_frame.has_value(), "multiple-range ACK decode");
    auto many_cursor = ack_range_cursor::from_frame(*many_frame);
    check(many_cursor.has_value(), "multiple-range cursor");
    expect_range(*many_cursor, 9, 10);
    expect_range(*many_cursor, 5, 7);
    expect_range(*many_cursor, 2, 3);
    expect_end(*many_cursor);

    constexpr std::array<std::byte, 2> boundary {
        std::byte {0}, std::byte {0}};
    decoded_frame edge {.type = 0x02, .largest_acknowledged = 2,
                        .ack_range_count = 1, .ack_ranges = boundary};
    auto edge_cursor = ack_range_cursor::from_frame(edge);
    check(edge_cursor.has_value(), "gap boundary cursor");
    expect_range(*edge_cursor, 2, 2);
    expect_range(*edge_cursor, 0, 0);
    expect_end(*edge_cursor);

    decoded_frame zero {.type = 0x02};
    auto zero_cursor = ack_range_cursor::from_frame(zero);
    check(zero_cursor.has_value(), "zero packet number cursor");
    expect_range(*zero_cursor, 0, 0);
    expect_end(*zero_cursor);
}

auto malformed_ranges() -> void
{
    constexpr std::array<std::byte, 2> zero_pair {
        std::byte {0}, std::byte {0}};
    constexpr std::array<std::byte, 2> big_gap {
        std::byte {1}, std::byte {0}};
    constexpr std::array<std::byte, 2> big_range {
        std::byte {0}, std::byte {1}};
    constexpr std::array<std::byte, 2> partial_varint {
        std::byte {0x40}, std::byte {0}};
    constexpr std::array<std::byte, 1> lone_gap {std::byte {0}};

    expect_error(decoded_frame {.type = 0x01}, frame_error::invalid_frame);
    expect_error(decoded_frame {.type = 0x02, .largest_acknowledged = 1,
                                .first_ack_range = 2},
                 frame_error::invalid_ack_range);
    expect_error(decoded_frame {.type = 0x02, .largest_acknowledged = 1,
                                .ack_range_count = 1, .ack_ranges = zero_pair},
                 frame_error::invalid_ack_range);
    expect_error(decoded_frame {.type = 0x02, .largest_acknowledged = 2,
                                .ack_range_count = 1, .ack_ranges = big_gap},
                 frame_error::invalid_ack_range);
    expect_error(decoded_frame {.type = 0x02, .largest_acknowledged = 2,
                                .ack_range_count = 1, .ack_ranges = big_range},
                 frame_error::invalid_ack_range);
    expect_error(decoded_frame {.type = 0x02, .largest_acknowledged = 10,
                                .ack_range_count = 1,
                                .ack_ranges = partial_varint},
                 frame_error::truncated);
    expect_error(decoded_frame {.type = 0x02, .largest_acknowledged = 10,
                                .ack_range_count = 1, .ack_ranges = lone_gap},
                 frame_error::truncated);
    expect_error(decoded_frame {.type = 0x02, .largest_acknowledged = 10,
                                .ack_range_count = 2, .ack_ranges = zero_pair},
                 frame_error::truncated);
    expect_error(decoded_frame {.type = 0x02, .largest_acknowledged = 10,
                                .ack_ranges = zero_pair},
                 frame_error::invalid_ack_range);
    expect_error(decoded_frame {.type = 0x02, .largest_acknowledged = 10,
                                .ack_range_count = 1,
                                .ack_ranges = std::span(zero_pair).first(1)},
                 frame_error::truncated);
    expect_error(decoded_frame {.type = 0x02,
                                .largest_acknowledged = max_varint_value + 1},
                 frame_error::invalid_value);
}

} // namespace

auto main() -> int
{
    valid_ranges();
    malformed_ranges();
}
