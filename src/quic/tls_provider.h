#pragma once

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include "quic/crypto_buffer.h"

#include <openssl/ssl.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>

#if !OPENSSL_VERSION_PREREQ(3, 5)
#error "QUIC TLS requires OpenSSL 3.5 or newer"
#endif

namespace eventloop::quic::detail {

enum class tls_level : std::uint8_t { initial, handshake, application };
enum class tls_direction : std::uint8_t { read, write };
enum class tls_progress { waiting, complete };
enum class tls_error {
    invalid_configuration,
    provider_failure,
    capacity_exceeded,
    invalid_crypto_data,
    unsupported_secret,
    missing_transport_parameters,
    missing_alpn,
};

// Callbacks run synchronously on the caller's loop. They must copy data they
// retain, must not throw or reenter the adapter, and return false on exhaustion.
// send_crypto appends the entire span to the level's bounded CRYPTO send buffer.
struct tls_callbacks {
    void* argument {};
    bool (*send_crypto)(void*, tls_level, std::span<const std::byte>) noexcept {};
    bool (*install_secret)(void*, tls_level, tls_direction, std::uint16_t,
                           std::span<const std::uint8_t>) noexcept {};
};

struct tls_options {
    bool server {false};
    std::string_view server_name {};
    // One application protocol, without the ALPN length prefix.
    std::span<const std::uint8_t> alpn {};
    // RFC 9287 grease_quic_bit is appended unless already supplied empty.
    std::span<const std::uint8_t> transport_parameters {};
};

// SSL_CTX uses TLS_method()/TLS_client_method()/TLS_server_method(), with trust,
// certificates and keys configured by the owner. Server contexts must first
// call configure_server_context(), before sharing the context between loops.
// Input buffers and callback argument outlive this nonmovable adapter. The TLS
// engine allocates during handshake; QUIC input/output storage remains bounded.
class tls_provider {
public:
    static constexpr std::size_t max_transport_parameters = 4096;

    tls_provider(std::array<crypto_receive_buffer*, 3> input,
                 tls_callbacks callbacks) noexcept
        : input_(input), callbacks_(callbacks) {}
    ~tls_provider();
    tls_provider(const tls_provider&) = delete;
    auto operator=(const tls_provider&) -> tls_provider& = delete;

    static auto configure_server_context(SSL_CTX* context) noexcept -> void;
    [[nodiscard]] auto initialize(SSL_CTX* context, const tls_options& options)
        -> std::expected<void, tls_error>;
    [[nodiscard]] auto provide_crypto(tls_level level, std::uint64_t offset,
                                     std::span<const std::byte> data) noexcept
        -> std::expected<void, tls_error>;
    // Also processes application-level post-handshake CRYPTO after completion.
    [[nodiscard]] auto advance() -> std::expected<tls_progress, tls_error>;
    [[nodiscard]] auto peer_transport_parameters() const noexcept
        -> std::span<const std::uint8_t>;
    [[nodiscard]] auto negotiated_alpn() const noexcept
        -> std::span<const std::uint8_t>;
    [[nodiscard]] auto alert() const noexcept -> std::optional<std::uint8_t>
    { return alert_; }

private:
    static auto send(SSL*, const unsigned char*, std::size_t, std::size_t*, void*)
        noexcept -> int;
    static auto receive(SSL*, const unsigned char**, std::size_t*, void*)
        noexcept -> int;
    static auto release(SSL*, std::size_t, void*) noexcept -> int;
    static auto secret(SSL*, std::uint32_t, int, const unsigned char*,
                       std::size_t, void*) noexcept -> int;
    static auto parameters(SSL*, const unsigned char*, std::size_t, void*)
        noexcept -> int;
    static auto send_alert(SSL*, unsigned char, void*) noexcept -> int;
    static auto select_alpn(SSL*, const unsigned char**, unsigned char*,
                            const unsigned char*, unsigned int, void*)
        noexcept -> int;
    auto fail(tls_error error) noexcept -> int;

    SSL* ssl_ {};
    std::array<crypto_receive_buffer*, 3> input_;
    tls_callbacks callbacks_;
    std::array<std::uint8_t, max_transport_parameters> local_parameters_ {};
    std::array<std::uint8_t, max_transport_parameters> peer_parameters_ {};
    std::array<std::uint8_t, 255> alpn_ {};
    std::size_t peer_parameters_size_ {0};
    std::size_t alpn_size_ {0};
    crypto_receive_buffer* loan_buffer_ {};
    std::size_t loan_size_ {0};
    tls_level read_level_ {tls_level::initial};
    tls_level write_level_ {tls_level::initial};
    std::optional<tls_error> failure_ {};
    std::optional<std::uint8_t> alert_ {};
    bool got_parameters_ {false};
    bool complete_ {false};
};

} // namespace eventloop::quic::detail
