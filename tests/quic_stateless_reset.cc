#include "quic/stateless_reset.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>

namespace {

using namespace eventloop::quic::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC stateless reset: " << message << '\n';
    std::exit(1);
}

constexpr auto token(unsigned seed) -> stateless_reset_token
{
    stateless_reset_token result {};
    for (unsigned i = 0; i < result.size(); ++i)
        result[i] = static_cast<std::byte>(seed + i);
    return result;
}

auto encoding() -> void
{
    constexpr auto reset_token = token(0x80);
    std::array<std::byte, 27> random;
    for (unsigned i = 0; i < random.size(); ++i)
        random[i] = static_cast<std::byte>(0xe0 + i);
    std::array<std::byte, 48> output;
    output.fill(std::byte {0xa5});
    const auto minimum = encode_stateless_reset(
        std::span(random).first(5), reset_token, 22, false, output);
    check(minimum == 21 && output[0] == std::byte {0x60},
          "minimum packet and fixed short-header bits");
    check(std::equal(random.begin() + 1, random.begin() + 5,
                     output.begin() + 1) &&
          std::equal(reset_token.begin(), reset_token.end(), output.begin() + 5) &&
          output[21] == std::byte {0xa5},
          "prefix, trailing token, and untouched output tail");
    const auto larger = encode_stateless_reset(random, reset_token, 44,
                                               false, output);
    check(larger == 43 &&
          std::equal(reset_token.begin(), reset_token.end(), output.begin() + 27),
          "variable response size strictly below trigger");
    check(encode_stateless_reset(random, reset_token,
              std::numeric_limits<std::size_t>::max(), false, output) == 43,
          "maximum trigger size does not overflow");

    for (unsigned first = 0; first < 256; ++first) {
        random[0] = static_cast<std::byte>(first);
        check(encode_stateless_reset(random, reset_token, 44, false, output) == 43 &&
              output[0] == static_cast<std::byte>((first & 0x3f) | 0x40),
              "all random first bytes retain six unpredictable bits");
    }
    // Both sources alias output, including a token overwritten by the prefix.
    std::copy(random.begin(), random.end(), output.begin());
    std::copy(reset_token.begin(), reset_token.end(), output.begin() + 27);
    check(encode_stateless_reset(std::span(output).first(27),
              std::span(output).subspan(27, 16), 44, false, output) == 43 &&
          std::equal(reset_token.begin(), reset_token.end(), output.begin() + 27),
          "in-place encoding");
    std::copy(reset_token.begin(), reset_token.end(), output.begin());
    const auto saved_prefix = output;
    check(encode_stateless_reset(std::span(output).subspan(1, 27),
              std::span(output).first(16), 44, false, output) == 43 &&
          std::equal(reset_token.begin(), reset_token.end(), output.begin() + 27) &&
          std::equal(saved_prefix.begin() + 2, saved_prefix.begin() + 28,
                     output.begin() + 1),
          "overlap preserves token before moving prefix");
}

auto failures_are_atomic() -> void
{
    constexpr auto reset_token = token(0x80);
    constexpr std::array<std::byte, 6> random {};
    std::array<std::byte, 32> output;
    output.fill(std::byte {0xa5});
    const auto unchanged = [&] {
        return std::all_of(output.begin(), output.end(),
                          [](auto b) { return b == std::byte {0xa5}; });
    };
    check(encode_stateless_reset(random, reset_token, 23, true, output).error() ==
              stateless_reset_error::connection_may_be_active && unchanged(),
          "reset oracle guard");
    check(encode_stateless_reset(random, std::span(reset_token).first(15),
              23, false, output).error() == stateless_reset_error::invalid_token &&
          unchanged(), "short token rejected atomically");
    std::array<std::byte, 17> long_token {};
    check(encode_stateless_reset(random, long_token, 23, false, output).error() ==
              stateless_reset_error::invalid_token && unchanged(),
          "long token rejected atomically");
    check(encode_stateless_reset(std::span(random).first(4), reset_token,
              23, false, output).error() ==
              stateless_reset_error::insufficient_unpredictable_bytes && unchanged(),
          "38 unpredictable bits required");
    for (std::size_t size = 0; size <= 22; ++size)
        check(encode_stateless_reset(random, reset_token, size, false,
                  output).error() == stateless_reset_error::response_not_smaller &&
              unchanged(), "tiny, equal, or larger response rejected atomically");
    check(encode_stateless_reset(random, reset_token, 23, false,
              std::span(output).first(21)).error() ==
              stateless_reset_error::output_too_small && unchanged(),
          "short output rejected atomically");
}

auto detection() -> void
{
    constexpr std::array<stateless_reset_token, 3> active {
        token(0x10), token(0x40), token(0x80)};
    constexpr std::array<std::byte, 5> random {};
    std::array<std::byte, 21> packet {};
    for (const auto& candidate : active) {
        check(encode_stateless_reset(random, candidate, 22, false, packet) == 21 &&
              detect_stateless_reset(packet, active) == true,
              "first, middle, and last tokens match");
    }
    const auto original = packet;
    for (unsigned i = 5; i < packet.size(); ++i) {
        packet = original;
        packet[i] ^= std::byte {1};
        check(detect_stateless_reset(packet, active) == false,
              "every token byte is compared");
    }
    packet = original;
    packet[0] = std::byte {0xc0};
    check(detect_stateless_reset(packet, active) == true,
          "valid suffix recognized with long-header form");
    packet[0] = std::byte {0};
    check(detect_stateless_reset(packet, active) == true,
          "valid suffix recognized independently of fixed bit");
    check(detect_stateless_reset(packet,
              std::span<const stateless_reset_token> {}) == false &&
          detect_stateless_reset(packet, std::span(active).first(2)) == false,
          "empty set and caller-filtered retired token do not match");
    for (std::size_t size = 0; size < 21; ++size)
        check(detect_stateless_reset(std::span(packet).first(size), active).error() ==
                  stateless_reset_error::invalid_datagram,
              "undersized datagram rejected");
    std::array<std::byte, 64> coalesced {};
    std::copy(packet.begin(), packet.end(), coalesced.end() - packet.size());
    check(detect_stateless_reset(coalesced, active) == true,
          "suffix uses entire datagram");
    std::copy(active.back().begin(), active.back().end(), coalesced.begin());
    coalesced.back() ^= std::byte {1};
    check(detect_stateless_reset(coalesced, active) == false,
          "token elsewhere in datagram does not match");
}

} // namespace

auto main() -> int
{
    encoding();
    failures_are_atomic();
    detection();
}
