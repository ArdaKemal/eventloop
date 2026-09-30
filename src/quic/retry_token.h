#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

namespace eventloop::quic::detail {

inline constexpr std::size_t max_retry_address_size = 64;
inline constexpr std::size_t max_retry_token_size = 123;

enum class retry_token_error {
    invalid_input, output_too_small, malformed, unsupported_version,
    authentication_failed, address_mismatch, dcid_mismatch,
    expired, future_issue_time, provider_failure,
};

struct retry_token_contents {
    std::uint64_t issued_at {};
    std::array<std::uint8_t, 20> original_dcid {};
    std::uint8_t original_dcid_size {};
    [[nodiscard]] auto dcid() const -> std::span<const std::uint8_t>
    { return {original_dcid.data(), original_dcid_size}; }
};

// Opaque Retry tokens only; do not use these as NEW_TOKEN tokens. The caller
// supplies canonical address bytes (including port if binding to it), a secret
// server key, and a nonce that is unique under that key. Times use one caller
// defined unsigned time unit. Replay prevention/key rotation remain caller work.
// One loop-affine instance owns a reusable EVP context; construction and OpenSSL
// provider initialization can allocate. Operations use fixed local scratch and
// never publish partial ciphertext or unauthenticated plaintext.
class retry_token_protector {
public:
    retry_token_protector();
    ~retry_token_protector();
    retry_token_protector(const retry_token_protector&) = delete;
    auto operator=(const retry_token_protector&) -> retry_token_protector& = delete;

    [[nodiscard]] auto seal(
        std::span<const std::uint8_t, 16> key,
        std::span<const std::uint8_t, 12> nonce, std::uint64_t issued_at,
        std::span<const std::uint8_t> peer_address,
        std::span<const std::uint8_t> original_dcid,
        std::span<std::uint8_t> output)
        -> std::expected<std::size_t, retry_token_error>;

    // Recovery of original_dcid supports stateless Retry. When an original ID
    // is already known, expected_dcid also checks that binding.
    [[nodiscard]] auto open(
        std::span<const std::uint8_t, 16> key,
        std::span<const std::uint8_t> token,
        std::span<const std::uint8_t> peer_address,
        std::uint64_t now, std::uint64_t maximum_age,
        std::optional<std::span<const std::uint8_t>> expected_dcid = std::nullopt)
        -> std::expected<retry_token_contents, retry_token_error>;

private:
    EVP_CIPHER_CTX* context_ {};
};

} // namespace eventloop::quic::detail
