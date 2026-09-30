#include "quic/retry_token.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <limits>

using namespace eventloop::quic::detail;
namespace {
void check(bool ok) { if (!ok) std::abort(); }
}
int main()
{
    retry_token_protector protector;
    std::array<std::uint8_t, 16> key {};
    std::array<std::uint8_t, 12> nonce {};
    std::array<std::uint8_t, 6> address {127,0,0,1,1,187};
    std::array<std::uint8_t, 8> dcid {1,2,3,4,5,6,7,8};
    std::array<std::uint8_t, max_retry_token_size> token {};
    auto size = protector.seal(key, nonce, 100, address, dcid, token);
    check(size.has_value());
    const auto encoded = std::span<const std::uint8_t>(token).first(*size);
    auto decoded = protector.open(key, encoded, address, 110, 10, dcid);
    check(decoded.has_value() && decoded->issued_at == 100 && std::ranges::equal(decoded->dcid(), dcid));
    check(protector.open(key, encoded, address, 110, 10).has_value());
    check(protector.open(key, encoded, address, 111, 10).error() == retry_token_error::expired);
    check(protector.open(key, encoded, address, 99, 10).error() == retry_token_error::future_issue_time);
    auto other_address = address;
    other_address.back() ^= 1;
    check(protector.open(key, encoded, other_address, 100, 0).error() == retry_token_error::address_mismatch);
    auto other_dcid = dcid;
    other_dcid[0] ^= 1;
    check(protector.open(key, encoded, address, 100, 0, other_dcid).error() == retry_token_error::dcid_mismatch);
    auto other_key = key;
    other_key[0] = 1;
    check(protector.open(other_key, encoded, address, 100, 0).error() == retry_token_error::authentication_failed);
    for (std::size_t i = 1; i < *size; ++i) {
        auto damaged = token;
        damaged[i] ^= 1;
        check(!protector.open(key, std::span<const std::uint8_t>(damaged).first(*size), address, 100, 0));
    }
    auto version = token;
    version[0] = 2;
    check(protector.open(key, std::span<const std::uint8_t>(version).first(*size), address, 100, 0).error() == retry_token_error::unsupported_version);
    for (std::size_t i = 0; i < *size; ++i)
        check(!protector.open(key, encoded.first(i), address, 100, 0));
    auto trailing = token;
    check(!protector.open(key, std::span<const std::uint8_t>(trailing).first(*size + 1), address, 100, 0));

    std::array<std::uint8_t, max_retry_token_size> output;
    output.fill(0xa5);
    const auto unchanged = output;
    check(protector.seal(key, nonce, 0, address, dcid, std::span<std::uint8_t>(output).first(*size - 1)).error() == retry_token_error::output_too_small);
    check(output == unchanged);
    std::array<std::uint8_t, 65> oversized_address {};
    std::array<std::uint8_t, 21> oversized_dcid {};
    check(protector.seal(key, nonce, 0, oversized_address, dcid, output).error() == retry_token_error::invalid_input);
    check(protector.seal(key, nonce, 0, address, oversized_dcid, output).error() == retry_token_error::invalid_input);
    check(protector.seal(key, nonce, 0, {}, dcid, output).error() == retry_token_error::invalid_input);
    check(output == unchanged);
    check(protector.open(key, encoded, oversized_address, 100, 0).error() == retry_token_error::invalid_input);
    check(protector.open(key, encoded, address, 100, 0, oversized_dcid).error() == retry_token_error::invalid_input);

    std::array<std::uint8_t, max_retry_address_size> maximal_address {};
    std::array<std::uint8_t, 20> maximal_dcid {};
    nonce[0] = 1;
    size = protector.seal(key, nonce, std::numeric_limits<std::uint64_t>::max(), maximal_address, maximal_dcid, token);
    check(size && *size == max_retry_token_size);
    check(protector.open(key, token, maximal_address, std::numeric_limits<std::uint64_t>::max(), 0, maximal_dcid).has_value());
    nonce[0] = 2;
    size = protector.seal(key, nonce, 0, address, {}, token);
    check(size.has_value());
    check(protector.open(key, std::span<const std::uint8_t>(token).first(*size), address, std::numeric_limits<std::uint64_t>::max(), std::numeric_limits<std::uint64_t>::max(), std::span<const std::uint8_t>{}).has_value());
    std::cout << "QUIC Retry token tests passed\n";
}
