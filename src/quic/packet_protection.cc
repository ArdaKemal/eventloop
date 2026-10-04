#include "quic/packet_protection.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <algorithm>
#include <array>
#include <memory>
#include <string_view>

namespace eventloop::quic::detail {
namespace {

constexpr std::array<std::uint8_t, 20> v1_initial_salt {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};
constexpr std::array<std::uint8_t, 20> v2_initial_salt {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};
constexpr std::array<std::uint8_t, 16> v1_retry_key {
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
constexpr std::array<std::uint8_t, 12> v1_retry_nonce {
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
    0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};
constexpr std::array<std::uint8_t, 16> v2_retry_key {
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
    0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
};
constexpr std::array<std::uint8_t, 12> v2_retry_nonce {
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c,
    0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
};

auto valid_retry_prefix(std::uint32_t version,
                        std::span<const std::uint8_t> packet) -> bool
{
    if (packet.size() < 7 || packet.size() > 65527 ||
        (packet[0] & 0xc0) != 0xc0 ||
        ((packet[0] >> 4) & 3) !=
            long_header_type_bits(version, long_packet_type::retry)) {
        return false;
    }
    const auto encoded_version =
        (std::uint32_t{packet[1]} << 24) |
        (std::uint32_t{packet[2]} << 16) |
        (std::uint32_t{packet[3]} << 8) | packet[4];
    if (encoded_version != version || packet[5] > 20) {
        return false;
    }
    const auto source_length_offset = std::size_t{6} + packet[5];
    if (source_length_offset >= packet.size() ||
        packet[source_length_offset] > 20) {
        return false;
    }
    return std::size_t{packet[source_length_offset]} <=
           packet.size() - source_length_offset - 1;
}

using cipher_context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

// HMAC-SHA256 with the algorithm and digest fetched once per thread. Each
// call only re-keys the context, which avoids OpenSSL's per-derivation KDF
// context, digest fetch and HMAC context allocations.
class hmac_sha256 {
public:
    hmac_sha256() noexcept
    {
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        if (mac == nullptr) return;
        context_ = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
        char digest[] = "SHA256";
        const std::array params {
            OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
            OSSL_PARAM_construct_end(),
        };
        if (context_ != nullptr && EVP_MAC_CTX_set_params(context_, params.data()) <= 0) {
            EVP_MAC_CTX_free(context_);
            context_ = nullptr;
        }
    }
    ~hmac_sha256() { EVP_MAC_CTX_free(context_); }
    hmac_sha256(const hmac_sha256&) = delete;
    auto operator=(const hmac_sha256&) -> hmac_sha256& = delete;

    // HMAC(key, first || second) into output.
    [[nodiscard]] auto compute(std::span<const std::uint8_t> key,
                               std::span<const std::uint8_t> first,
                               std::span<const std::uint8_t> second,
                               std::array<std::uint8_t, 32>& output) noexcept -> bool
    {
        std::size_t written = 0;
        return context_ != nullptr && !key.empty() &&
               EVP_MAC_init(context_, key.data(), key.size(), nullptr) > 0 &&
               EVP_MAC_update(context_, first.data(), first.size()) > 0 &&
               EVP_MAC_update(context_, second.data(), second.size()) > 0 &&
               EVP_MAC_final(context_, output.data(), &written, output.size()) > 0 &&
               written == output.size();
    }

private:
    EVP_MAC_CTX* context_ {nullptr};
};

// HKDF (RFC 5869) with SHA-256. Extract takes the input keying material as
// key; expand produces at most one 32-byte block, which covers every QUIC
// secret, key, IV and header-protection key.
auto hkdf(std::span<const std::uint8_t> key,
          std::span<const std::uint8_t> salt,
          std::span<const std::uint8_t> info,
          int mode, std::span<std::uint8_t> output) -> bool
{
    thread_local hmac_sha256 hmac;
    std::array<std::uint8_t, 32> block {};
    if (mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY) {
        if (output.size() != block.size() || !hmac.compute(salt, key, {}, block)) return false;
    } else {
        constexpr std::array<std::uint8_t, 1> counter {1};
        if (output.size() > block.size() || !hmac.compute(key, info, counter, block)) return false;
    }
    std::copy_n(block.begin(), output.size(), output.begin());
    std::fill(block.begin(), block.end(), std::uint8_t {0});
    return true;
}

auto cipher() -> cipher_context
{
    return {EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
}

auto retry_associated_data(EVP_CIPHER_CTX* ctx,
                           std::span<const std::uint8_t> original_dcid,
                           std::span<const std::uint8_t> retry_without_tag,
                           bool encrypting) -> bool
{
    int written = 0;
    const auto update = encrypting ? EVP_EncryptUpdate : EVP_DecryptUpdate;
    const auto length = static_cast<std::uint8_t>(original_dcid.size());
    return update(ctx, nullptr, &written, &length, 1) > 0 &&
           update(ctx, nullptr, &written, original_dcid.data(),
                  static_cast<int>(original_dcid.size())) > 0 &&
           update(ctx, nullptr, &written, retry_without_tag.data(),
                  static_cast<int>(retry_without_tag.size())) > 0;
}

template<std::size_t N>
auto expand_label(std::span<const std::uint8_t> secret,
                  std::string_view label,
                  std::array<std::uint8_t, N>& result) -> bool
{
    // TLS 1.3 HKDF-Expand-Label with an empty context.
    std::array<std::uint8_t, 2 + 1 + 6 + 255 + 1> info {};
    const auto label_length = 6 + label.size();
    info[0] = static_cast<std::uint8_t>(N >> 8);
    info[1] = static_cast<std::uint8_t>(N);
    info[2] = static_cast<std::uint8_t>(label_length);
    constexpr std::string_view prefix = "tls13 ";
    std::copy(prefix.begin(), prefix.end(), info.begin() + 3);
    std::copy(label.begin(), label.end(), info.begin() + 3 + prefix.size());
    info[3 + label_length] = 0;
    return hkdf(secret, {}, std::span(info.data(), 4 + label_length),
                EVP_KDF_HKDF_MODE_EXPAND_ONLY, result);
}

auto overlaps(std::span<const std::uint8_t> a,
              std::span<const std::uint8_t> b) noexcept -> bool
{
    if (a.empty() || b.empty()) return false;
    const auto x = reinterpret_cast<std::uintptr_t>(a.data());
    const auto y = reinterpret_cast<std::uintptr_t>(b.data());
    return x <= y ? y - x < a.size() : x - y < b.size();
}

auto nonce_for(const aes_128_gcm_keys& keys, std::uint64_t packet_number)
    -> std::array<std::uint8_t, 12>
{
    auto nonce = keys.iv;
    for (std::size_t i = 0; i < 8; ++i) {
        nonce[11 - i] ^= static_cast<std::uint8_t>(packet_number >> (i * 8));
    }
    return nonce;
}

} // namespace

auto derive_initial_secrets(
    std::uint32_t version, std::span<const std::uint8_t> client_initial_dcid)
    -> std::expected<initial_secrets, protection_error>
{
    if (!is_supported_version(version)) {
        return std::unexpected(protection_error::unsupported_version);
    }
    if (client_initial_dcid.size() > 20) {
        return std::unexpected(protection_error::invalid_input);
    }
    std::array<std::uint8_t, 32> initial_secret {};
    const auto salt = version == version_1
        ? std::span<const std::uint8_t>(v1_initial_salt)
        : std::span<const std::uint8_t>(v2_initial_salt);
    initial_secrets result;
    if (!hkdf(client_initial_dcid, salt, {}, EVP_KDF_HKDF_MODE_EXTRACT_ONLY,
              initial_secret) ||
        !expand_label(initial_secret, "client in", result.client) ||
        !expand_label(initial_secret, "server in", result.server)) {
        return std::unexpected(protection_error::provider_failure);
    }
    return result;
}

auto derive_aes_128_gcm_keys(
    std::uint32_t version, std::span<const std::uint8_t> traffic_secret)
    -> std::expected<aes_128_gcm_keys, protection_error>
{
    if (!is_supported_version(version)) {
        return std::unexpected(protection_error::unsupported_version);
    }
    // TLS_AES_128_GCM_SHA256 always supplies a 32-byte traffic secret.
    if (traffic_secret.size() != 32) {
        return std::unexpected(protection_error::invalid_input);
    }
    const auto v2 = version == version_2;
    aes_128_gcm_keys result;
    if (!expand_label(traffic_secret, v2 ? "quicv2 key" : "quic key", result.key) ||
        !expand_label(traffic_secret, v2 ? "quicv2 iv" : "quic iv", result.iv) ||
        !expand_label(traffic_secret, v2 ? "quicv2 hp" : "quic hp", result.hp)) {
        return std::unexpected(protection_error::provider_failure);
    }
    return result;
}

auto derive_next_traffic_secret(
    std::uint32_t version, std::span<const std::uint8_t> traffic_secret)
    -> std::expected<std::array<std::uint8_t, 32>, protection_error>
{
    if (!is_supported_version(version))
        return std::unexpected(protection_error::unsupported_version);
    if (traffic_secret.size() != 32)
        return std::unexpected(protection_error::invalid_input);
    std::array<std::uint8_t, 32> result {};
    if (!expand_label(traffic_secret,
                      version == version_2 ? "quicv2 ku" : "quic ku", result))
        return std::unexpected(protection_error::provider_failure);
    return result;
}

packet_protection_context::packet_protection_context() noexcept
    : seal_(EVP_CIPHER_CTX_new()), open_(EVP_CIPHER_CTX_new()),
      hp_(EVP_CIPHER_CTX_new()), owner_(std::this_thread::get_id())
{
    const aes_128_gcm_keys zero {};
    initialized_ = seal_ && open_ && hp_ &&
        EVP_EncryptInit_ex(static_cast<EVP_CIPHER_CTX*>(seal_), EVP_aes_128_gcm(),
                          nullptr, zero.key.data(), zero.iv.data()) > 0 &&
        EVP_DecryptInit_ex(static_cast<EVP_CIPHER_CTX*>(open_), EVP_aes_128_gcm(),
                          nullptr, zero.key.data(), zero.iv.data()) > 0 &&
        EVP_EncryptInit_ex(static_cast<EVP_CIPHER_CTX*>(hp_), EVP_aes_128_ecb(),
                          nullptr, zero.hp.data(), nullptr) > 0;
}
packet_protection_context::~packet_protection_context()
{
    EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(seal_));
    EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(open_));
    EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(hp_));
}
auto packet_protection_context::ready() const noexcept -> bool
{
    return initialized_ && owner_ == std::this_thread::get_id();
}

auto packet_protection_context::seal(const aes_128_gcm_keys& keys, std::uint64_t packet_number,
                  std::span<const std::uint8_t> header,
                  std::span<const std::uint8_t> plaintext,
                  std::span<std::uint8_t> output)
    -> std::expected<std::size_t, protection_error>
{
    if (packet_number > max_packet_number || plaintext.size() > 65511 ||
        header.size() > 65527) {
        return std::unexpected(protection_error::invalid_input);
    }
    if (output.size() < plaintext.size() + 16) {
        return std::unexpected(protection_error::output_too_small);
    }
    if (overlaps(output.first(plaintext.size() + 16), header) ||
        overlaps(output.first(plaintext.size() + 16), plaintext))
        return std::unexpected(protection_error::invalid_input);
    auto* ctx = static_cast<EVP_CIPHER_CTX*>(seal_);
    const auto nonce = nonce_for(keys, packet_number);
    int written = 0;
    int final_written = 0;
    if (!ready())
        return std::unexpected(protection_error::provider_failure);
    // Re-key only on a key change; the nonce alone selects the packet.
    const auto reuse_key = seal_key_set_ && seal_key_ == keys.key;
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                           reuse_key ? nullptr : keys.key.data(), nonce.data()) <= 0)
        return std::unexpected(protection_error::provider_failure);
    seal_key_ = keys.key;
    seal_key_set_ = true;
    if (EVP_EncryptUpdate(ctx, nullptr, &written, header.data(),
                          static_cast<int>(header.size())) <= 0 ||
        EVP_EncryptUpdate(ctx, output.data(), &written, plaintext.data(),
                          static_cast<int>(plaintext.size())) <= 0 ||
        EVP_EncryptFinal_ex(ctx, output.data() + written,
                            &final_written) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                            output.data() + plaintext.size()) <= 0) {
        return std::unexpected(protection_error::provider_failure);
    }
    return plaintext.size() + 16;
}

auto packet_protection_context::open(const aes_128_gcm_keys& keys, std::uint64_t packet_number,
                  std::span<const std::uint8_t> header,
                  std::span<const std::uint8_t> ciphertext_and_tag,
                  std::span<std::uint8_t> output, std::span<std::uint8_t> scratch)
    -> std::expected<std::size_t, protection_error>
{
    if (packet_number > max_packet_number || header.size() > 65527 ||
        ciphertext_and_tag.size() < 16 ||
        ciphertext_and_tag.size() > 65527) {
        return std::unexpected(protection_error::invalid_input);
    }
    if (output.size() < ciphertext_and_tag.size() - 16) {
        return std::unexpected(protection_error::output_too_small);
    }
    auto* ctx = static_cast<EVP_CIPHER_CTX*>(open_);
    const auto nonce = nonce_for(keys, packet_number);
    const auto length = ciphertext_and_tag.size() - 16;
    // GCM exposes plaintext before authenticating it. Keep that plaintext
    // away from caller storage until the tag has been checked.
    if (scratch.size() < length) return std::unexpected(protection_error::output_too_small);
    scratch = scratch.first(length);
    if (overlaps(scratch, output) || overlaps(scratch, header) ||
        overlaps(scratch, ciphertext_and_tag))
        return std::unexpected(protection_error::invalid_input);
    std::uint8_t empty {};
    auto* destination = scratch.empty() ? &empty : scratch.data();
    struct clear_scratch {
        std::span<std::uint8_t> bytes;
        ~clear_scratch() { if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size()); }
    } clear {scratch};
    int written = 0;
    int final_written = 0;
    if (!ready())
        return std::unexpected(protection_error::provider_failure);
    // Re-key only on a key change; the nonce alone selects the packet.
    const auto reuse_key = open_key_set_ && open_key_ == keys.key;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           reuse_key ? nullptr : keys.key.data(), nonce.data()) <= 0 ||
        EVP_DecryptUpdate(ctx, nullptr, &written, header.data(),
                          static_cast<int>(header.size())) <= 0 ||
        EVP_DecryptUpdate(ctx, destination, &written,
                          ciphertext_and_tag.data(), static_cast<int>(length)) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<std::uint8_t*>(ciphertext_and_tag.data() + length)) <= 0) {
        return std::unexpected(protection_error::provider_failure);
    }
    open_key_ = keys.key;
    open_key_set_ = true;
    if (EVP_DecryptFinal_ex(ctx, destination + written,
                            &final_written) <= 0) {
        return std::unexpected(protection_error::authentication_failed);
    }
    std::copy_n(scratch.begin(), length, output.begin());
    return length;
}

auto packet_protection_context::protect_header(
    const aes_128_gcm_keys& keys, std::span<std::uint8_t> packet,
    std::size_t packet_number_offset, bool removing)
    -> std::expected<std::size_t, protection_error>
{
    if (packet_number_offset == 0 || packet_number_offset > packet.size() ||
        packet.size() - packet_number_offset < 20) {
        return std::unexpected(protection_error::invalid_input);
    }
    auto* ctx = static_cast<EVP_CIPHER_CTX*>(hp_);
    std::array<std::uint8_t, 16> mask {};
    int written = 0;
    if (!ready())
        return std::unexpected(protection_error::provider_failure);
    const auto reuse_key = hp_key_set_ && hp_key_ == keys.hp;
    if (!reuse_key) {
        hp_key_set_ = false;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, keys.hp.data(), nullptr) <= 0 ||
            EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0)
            return std::unexpected(protection_error::provider_failure);
        hp_key_ = keys.hp;
        hp_key_set_ = true;
    }
    // ECB has no chaining state. Each complete sample leaves no buffered bytes
    // with padding disabled, so consecutive samples need no reset or final call.
    if (EVP_EncryptUpdate(ctx, mask.data(), &written,
                          packet.data() + packet_number_offset + 4, 16) <= 0 ||
        written != 16) {
        hp_key_set_ = false;
        return std::unexpected(protection_error::provider_failure);
    }
    const auto first_mask = (packet[0] & 0x80) != 0 ? 0x0f : 0x1f;
    const auto length = removing
        ? static_cast<std::size_t>(((packet[0] ^ (mask[0] & first_mask)) & 3) + 1)
        : static_cast<std::size_t>((packet[0] & 3) + 1);
    packet[0] ^= static_cast<std::uint8_t>(mask[0] & first_mask);
    for (std::size_t i = 0; i < length; ++i) {
        packet[packet_number_offset + i] ^= mask[i + 1];
    }
    return length;
}

auto seal_payload(packet_protection_context& context, const aes_128_gcm_keys& keys,
    std::uint64_t number, std::span<const std::uint8_t> header,
    std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> output)
    -> std::expected<std::size_t, protection_error>
{ return context.seal(keys, number, header, plaintext, output); }
auto open_payload(packet_protection_context& context, const aes_128_gcm_keys& keys,
    std::uint64_t number, std::span<const std::uint8_t> header,
    std::span<const std::uint8_t> ciphertext, std::span<std::uint8_t> output,
    std::span<std::uint8_t> scratch) -> std::expected<std::size_t, protection_error>
{ return context.open(keys, number, header, ciphertext, output, scratch); }
auto apply_aes_header_protection(packet_protection_context& context,
    const aes_128_gcm_keys& keys, std::span<std::uint8_t> packet,
    std::size_t offset, bool removing) -> std::expected<std::size_t, protection_error>
{ return context.protect_header(keys, packet, offset, removing); }
auto seal_payload(const aes_128_gcm_keys& keys, std::uint64_t number,
    std::span<const std::uint8_t> header, std::span<const std::uint8_t> plaintext,
    std::span<std::uint8_t> output) -> std::expected<std::size_t, protection_error>
{ packet_protection_context context; return context.seal(keys, number, header, plaintext, output); }
auto open_payload(const aes_128_gcm_keys& keys, std::uint64_t number,
    std::span<const std::uint8_t> header, std::span<const std::uint8_t> ciphertext,
    std::span<std::uint8_t> output) -> std::expected<std::size_t, protection_error>
{
    packet_protection_context context;
    std::array<std::uint8_t, 65511> scratch;
    return context.open(keys, number, header, ciphertext, output, scratch);
}
auto apply_aes_header_protection(const aes_128_gcm_keys& keys,
    std::span<std::uint8_t> packet, std::size_t offset, bool removing)
    -> std::expected<std::size_t, protection_error>
{ packet_protection_context context; return context.protect_header(keys, packet, offset, removing); }

auto reconstruct_packet_number(std::uint32_t truncated,
                               std::size_t encoded_length,
                               std::optional<std::uint64_t> largest_received)
    -> std::expected<std::uint64_t, protection_error>
{
    if (encoded_length < 1 || encoded_length > 4 ||
        (largest_received && *largest_received > max_packet_number)) {
        return std::unexpected(protection_error::invalid_input);
    }
    const auto window = std::uint64_t{1} << (encoded_length * 8);
    if (truncated >= window) {
        return std::unexpected(protection_error::invalid_input);
    }
    if (!largest_received) {
        return truncated;
    }
    const auto expected = *largest_received + 1;
    const auto half_window = window / 2;
    auto candidate = (expected & ~(window - 1)) | truncated;
    if (candidate + half_window <= expected &&
        candidate <= max_packet_number - window) {
        candidate += window;
    } else if (candidate > expected + half_window && candidate >= window) {
        candidate -= window;
    }
    if (candidate > max_packet_number) {
        return std::unexpected(protection_error::invalid_input);
    }
    return candidate;
}

auto generate_retry_integrity_tag(
    std::uint32_t version, std::span<const std::uint8_t> original_dcid,
    std::span<const std::uint8_t> retry_without_tag)
    -> std::expected<std::array<std::uint8_t, 16>, protection_error>
{
    if (!is_supported_version(version)) {
        return std::unexpected(protection_error::unsupported_version);
    }
    if (original_dcid.size() > 20 ||
        !valid_retry_prefix(version, retry_without_tag) ||
        retry_without_tag.size() > 65527 - 16) {
        return std::unexpected(protection_error::invalid_input);
    }
    auto ctx = cipher();
    const auto& key = version == version_1 ? v1_retry_key : v2_retry_key;
    const auto& nonce = version == version_1 ? v1_retry_nonce : v2_retry_nonce;
    std::array<std::uint8_t, 16> result {};
    int written = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr,
                                   key.data(), nonce.data()) <= 0 ||
        !retry_associated_data(ctx.get(), original_dcid, retry_without_tag, true) ||
        EVP_EncryptFinal_ex(ctx.get(), result.data(), &written) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16,
                            result.data()) <= 0) {
        return std::unexpected(protection_error::provider_failure);
    }
    return result;
}

auto validate_retry_integrity_tag(
    std::uint32_t version, std::span<const std::uint8_t> original_dcid,
    std::span<const std::uint8_t> retry_with_tag)
    -> std::expected<void, protection_error>
{
    if (!is_supported_version(version)) {
        return std::unexpected(protection_error::unsupported_version);
    }
    if (original_dcid.size() > 20 || retry_with_tag.size() < 16 ||
        retry_with_tag.size() > 65527 ||
        !valid_retry_prefix(version, retry_with_tag.first(retry_with_tag.size() - 16))) {
        return std::unexpected(protection_error::invalid_input);
    }
    auto ctx = cipher();
    const auto& key = version == version_1 ? v1_retry_key : v2_retry_key;
    const auto& nonce = version == version_1 ? v1_retry_nonce : v2_retry_nonce;
    int written = 0;
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr,
                                   key.data(), nonce.data()) <= 0 ||
        !retry_associated_data(ctx.get(), original_dcid,
                               retry_with_tag.first(retry_with_tag.size() - 16),
                               false) ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<std::uint8_t*>(retry_with_tag.data() +
                                                      retry_with_tag.size() - 16)) <= 0) {
        return std::unexpected(protection_error::provider_failure);
    }
    std::array<std::uint8_t, 1> empty {};
    if (EVP_DecryptFinal_ex(ctx.get(), empty.data(), &written) <= 0) {
        return std::unexpected(protection_error::authentication_failed);
    }
    return {};
}

} // namespace eventloop::quic::detail
