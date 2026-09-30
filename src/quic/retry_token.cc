#include "quic/retry_token.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>

namespace eventloop::quic::detail {
namespace {
constexpr std::uint8_t token_version = 1;
constexpr std::size_t prefix_size = 13;
constexpr std::size_t tag_size = 16;
constexpr std::size_t maximum_plaintext = 94;
constexpr std::array<std::uint8_t, 21> domain {
    'e','v','e','n','t','l','o','o','p',' ','Q','U','I','C',' ','R','e','t','r','y',1
};
auto valid_address(std::span<const std::uint8_t> address) -> bool
{ return !address.empty() && address.size() <= max_retry_address_size; }
}

retry_token_protector::retry_token_protector() : context_(EVP_CIPHER_CTX_new()) {}
retry_token_protector::~retry_token_protector() { EVP_CIPHER_CTX_free(context_); }

auto retry_token_protector::seal(
    std::span<const std::uint8_t, 16> key,
    std::span<const std::uint8_t, 12> nonce, std::uint64_t issued_at,
    std::span<const std::uint8_t> peer_address,
    std::span<const std::uint8_t> original_dcid,
    std::span<std::uint8_t> output)
    -> std::expected<std::size_t, retry_token_error>
{
    if (!valid_address(peer_address) || original_dcid.size() > 20)
        return std::unexpected(retry_token_error::invalid_input);
    const auto plaintext_size = 10 + peer_address.size() + original_dcid.size();
    const auto token_size = prefix_size + plaintext_size + tag_size;
    if (output.size() < token_size)
        return std::unexpected(retry_token_error::output_too_small);
    if (!context_) return std::unexpected(retry_token_error::provider_failure);
    std::array<std::uint8_t, maximum_plaintext> plaintext {};
    std::array<std::uint8_t, max_retry_token_size> result {};
    for (unsigned i = 0; i < 8; ++i)
        plaintext[i] = static_cast<std::uint8_t>(issued_at >> (56 - 8 * i));
    plaintext[8] = static_cast<std::uint8_t>(peer_address.size());
    std::ranges::copy(peer_address, plaintext.begin() + 9);
    const auto cid_offset = 9 + peer_address.size();
    plaintext[cid_offset] = static_cast<std::uint8_t>(original_dcid.size());
    std::ranges::copy(original_dcid, plaintext.begin() + cid_offset + 1);
    result[0] = token_version;
    std::ranges::copy(nonce, result.begin() + 1);
    int written = 0;
    int final_written = 0;
    const bool succeeded =
        EVP_EncryptInit_ex(context_, EVP_aes_128_gcm(), nullptr, key.data(), nonce.data()) == 1 &&
        EVP_EncryptUpdate(context_, nullptr, &written, domain.data(), static_cast<int>(domain.size())) == 1 &&
        EVP_EncryptUpdate(context_, nullptr, &written, result.data(), static_cast<int>(prefix_size)) == 1 &&
        EVP_EncryptUpdate(context_, result.data() + prefix_size, &written, plaintext.data(), static_cast<int>(plaintext_size)) == 1 &&
        written == static_cast<int>(plaintext_size) &&
        EVP_EncryptFinal_ex(context_, result.data() + prefix_size + plaintext_size, &final_written) == 1 &&
        final_written == 0 &&
        EVP_CIPHER_CTX_ctrl(context_, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag_size), result.data() + prefix_size + plaintext_size) == 1;
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    if (!succeeded) return std::unexpected(retry_token_error::provider_failure);
    std::copy_n(result.begin(), token_size, output.begin());
    return token_size;
}

auto retry_token_protector::open(
    std::span<const std::uint8_t, 16> key,
    std::span<const std::uint8_t> token,
    std::span<const std::uint8_t> peer_address,
    std::uint64_t now, std::uint64_t maximum_age,
    std::optional<std::span<const std::uint8_t>> expected_dcid)
    -> std::expected<retry_token_contents, retry_token_error>
{
    if (!valid_address(peer_address) || (expected_dcid && expected_dcid->size() > 20))
        return std::unexpected(retry_token_error::invalid_input);
    if (token.size() < prefix_size + 11 + tag_size || token.size() > max_retry_token_size)
        return std::unexpected(retry_token_error::malformed);
    if (token[0] != token_version)
        return std::unexpected(retry_token_error::unsupported_version);
    if (!context_) return std::unexpected(retry_token_error::provider_failure);
    const auto plaintext_size = token.size() - prefix_size - tag_size;
    std::array<std::uint8_t, maximum_plaintext> plaintext {};
    struct cleanse_guard {
        std::span<std::uint8_t> bytes;
        ~cleanse_guard() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
    } guard {plaintext};
    std::array<std::uint8_t, tag_size> tag {};
    std::copy_n(token.end() - tag_size, tag_size, tag.begin());
    int written = 0;
    int final_written = 0;
    if (EVP_DecryptInit_ex(context_, EVP_aes_128_gcm(), nullptr, key.data(), token.data() + 1) != 1 ||
        EVP_DecryptUpdate(context_, nullptr, &written, domain.data(), static_cast<int>(domain.size())) != 1 ||
        EVP_DecryptUpdate(context_, nullptr, &written, token.data(), static_cast<int>(prefix_size)) != 1 ||
        EVP_DecryptUpdate(context_, plaintext.data(), &written, token.data() + prefix_size, static_cast<int>(plaintext_size)) != 1 ||
        written != static_cast<int>(plaintext_size) ||
        EVP_CIPHER_CTX_ctrl(context_, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_size), tag.data()) != 1)
        return std::unexpected(retry_token_error::provider_failure);
    if (EVP_DecryptFinal_ex(context_, plaintext.data() + plaintext_size, &final_written) != 1)
        return std::unexpected(retry_token_error::authentication_failed);
    if (final_written != 0) return std::unexpected(retry_token_error::provider_failure);
    const std::size_t address_size = plaintext[8];
    if (address_size == 0 || address_size > max_retry_address_size || 10 + address_size > plaintext_size)
        return std::unexpected(retry_token_error::malformed);
    const auto cid_offset = 9 + address_size;
    const std::size_t cid_size = plaintext[cid_offset];
    if (cid_size > 20 || cid_offset + 1 + cid_size != plaintext_size)
        return std::unexpected(retry_token_error::malformed);
    if (address_size != peer_address.size() || CRYPTO_memcmp(plaintext.data() + 9, peer_address.data(), address_size) != 0)
        return std::unexpected(retry_token_error::address_mismatch);
    if (expected_dcid && (expected_dcid->size() != cid_size ||
        (cid_size && CRYPTO_memcmp(plaintext.data() + cid_offset + 1, expected_dcid->data(), cid_size) != 0)))
        return std::unexpected(retry_token_error::dcid_mismatch);
    retry_token_contents result;
    for (unsigned i = 0; i < 8; ++i) result.issued_at = (result.issued_at << 8) | plaintext[i];
    if (result.issued_at > now) return std::unexpected(retry_token_error::future_issue_time);
    if (now - result.issued_at > maximum_age) return std::unexpected(retry_token_error::expired);
    result.original_dcid_size = static_cast<std::uint8_t>(cid_size);
    std::copy_n(plaintext.begin() + cid_offset + 1, cid_size, result.original_dcid.begin());
    return result;
}
} // namespace eventloop::quic::detail
