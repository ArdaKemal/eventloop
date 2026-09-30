#include "quic/tls_provider.h"
#include "quic/varint.h"

#include <openssl/core_dispatch.h>
#include <openssl/err.h>

#include <algorithm>

namespace eventloop::quic::detail {

tls_provider::~tls_provider() { SSL_free(ssl_); }

auto tls_provider::configure_server_context(SSL_CTX* context) noexcept -> void
{
    SSL_CTX_set_alpn_select_cb(context, select_alpn, nullptr);
}

auto tls_provider::initialize(SSL_CTX* context, const tls_options& options)
    -> std::expected<void, tls_error>
{
    if (ssl_ || failure_ || !context || !callbacks_.send_crypto ||
        !callbacks_.install_secret || options.alpn.empty() ||
        options.alpn.size() > alpn_.size() ||
        options.transport_parameters.size() > local_parameters_.size() ||
        (!options.server && (options.server_name.empty() ||
                            options.server_name.size() > 253 ||
                            options.server_name.find('\0') != std::string_view::npos)))
        return std::unexpected(tls_error::invalid_configuration);
    for (auto* buffer : input_)
        if (!buffer || !buffer->valid())
            return std::unexpected(tls_error::invalid_configuration);

    // Validate the advertisement before allocating SSL or changing adapter
    // state, so malformed/oversized local parameters permit a corrected retry.
    bool grease = false;
    auto encoded_parameters = std::as_bytes(options.transport_parameters);
    while (!encoded_parameters.empty()) {
        const auto id = decode_varint(encoded_parameters);
        if (!id) return std::unexpected(tls_error::invalid_configuration);
        encoded_parameters = encoded_parameters.subspan(id->encoded_size);
        const auto length = decode_varint(encoded_parameters);
        if (!length) return std::unexpected(tls_error::invalid_configuration);
        encoded_parameters = encoded_parameters.subspan(length->encoded_size);
        if (length->value > encoded_parameters.size())
            return std::unexpected(tls_error::invalid_configuration);
        if (id->value == 0x2ab2) {
            if (grease || length->value != 0)
                return std::unexpected(tls_error::invalid_configuration);
            grease = true;
        }
        encoded_parameters = encoded_parameters.subspan(static_cast<std::size_t>(length->value));
    }
    constexpr std::array<std::uint8_t, 3> advertisement {0x6a, 0xb2, 0};
    if (!grease && options.transport_parameters.size() > local_parameters_.size() - advertisement.size())
        return std::unexpected(tls_error::capacity_exceeded);
    const auto local_size = options.transport_parameters.size() + (grease ? 0 : advertisement.size());

    ssl_ = SSL_new(context);
    if (!ssl_) return std::unexpected(tls_error::provider_failure);
    SSL_set_app_data(ssl_, this);
    static const OSSL_DISPATCH callbacks[] = {
        {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, reinterpret_cast<void (*)(void)>(send)},
        {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, reinterpret_cast<void (*)(void)>(receive)},
        {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, reinterpret_cast<void (*)(void)>(release)},
        {OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, reinterpret_cast<void (*)(void)>(secret)},
        {OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, reinterpret_cast<void (*)(void)>(parameters)},
        {OSSL_FUNC_SSL_QUIC_TLS_ALERT, reinterpret_cast<void (*)(void)>(send_alert)},
        {0, nullptr},
    };
    std::copy(options.transport_parameters.begin(), options.transport_parameters.end(),
              local_parameters_.begin());
    if (!grease) std::copy(advertisement.begin(), advertisement.end(),
                           local_parameters_.begin() + options.transport_parameters.size());
    std::copy(options.alpn.begin(), options.alpn.end(), alpn_.begin());
    alpn_size_ = options.alpn.size();
    if (SSL_set_quic_tls_cbs(ssl_, callbacks, this) != 1 ||
        SSL_set_max_proto_version(ssl_, TLS1_3_VERSION) != 1 ||
        SSL_set_ciphersuites(ssl_, "TLS_AES_128_GCM_SHA256") != 1 ||
        SSL_set_quic_tls_transport_params(ssl_, local_parameters_.data(),
                                          local_size) != 1 ||
        SSL_set_quic_tls_early_data_enabled(ssl_, 0) != 1)
        return std::unexpected((fail(tls_error::provider_failure), *failure_));
    // The current packet protection provider supports AES-128-GCM/SHA-256.
    // Disable tickets and early data until resumption is implemented by QUIC.
    SSL_set_options(ssl_, SSL_OP_NO_TICKET);
    if (options.server) {
        if (SSL_set_num_tickets(ssl_, 0) != 1)
            return std::unexpected((fail(tls_error::provider_failure), *failure_));
        SSL_set_accept_state(ssl_);
    } else {
        std::array<char, 254> hostname {};
        std::copy(options.server_name.begin(), options.server_name.end(), hostname.begin());
        std::array<std::uint8_t, 256> wire_alpn {};
        wire_alpn[0] = static_cast<std::uint8_t>(alpn_size_);
        std::copy_n(alpn_.begin(), alpn_size_, wire_alpn.begin() + 1);
        SSL_set_verify(ssl_, SSL_VERIFY_PEER, nullptr);
        if (SSL_set1_host(ssl_, hostname.data()) != 1 ||
            SSL_set_tlsext_host_name(ssl_, hostname.data()) != 1 ||
            SSL_set_alpn_protos(ssl_, wire_alpn.data(),
                               static_cast<unsigned int>(alpn_size_ + 1)) != 0)
            return std::unexpected((fail(tls_error::provider_failure), *failure_));
        SSL_set_connect_state(ssl_);
    }
    return {};
}

auto tls_provider::provide_crypto(tls_level level, std::uint64_t offset,
                                  std::span<const std::byte> data) noexcept
    -> std::expected<void, tls_error>
{
    if (failure_) return std::unexpected(*failure_);
    const auto index = static_cast<std::size_t>(level);
    if (!ssl_ || index >= input_.size())
        return std::unexpected(tls_error::invalid_configuration);
    // Retransmissions of consumed bytes are harmless. Additional data at a
    // discarded encryption level cannot be passed to the TLS engine.
    if (index < static_cast<std::size_t>(read_level_) &&
        (offset > input_[index]->next_offset() ||
         data.size() > input_[index]->next_offset() - offset)) {
        fail(tls_error::invalid_crypto_data);
        return std::unexpected(*failure_);
    }
    const auto result = input_[index]->insert(offset, data);
    if (!result) {
        const auto error = result.error() == crypto_buffer_error::capacity_exceeded
            ? tls_error::capacity_exceeded : tls_error::invalid_crypto_data;
        fail(error);
        return std::unexpected(error);
    }
    return {};
}

auto tls_provider::advance() -> std::expected<tls_progress, tls_error>
{
    if (failure_) return std::unexpected(*failure_);
    if (!ssl_) return std::unexpected(tls_error::invalid_configuration);
    ERR_clear_error();
    int result;
    if (complete_) {
        unsigned char byte {};
        std::size_t read {0};
        result = SSL_read_ex(ssl_, &byte, 0, &read);
    } else {
        result = SSL_do_handshake(ssl_);
    }
    const auto error = result == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl_, result);
    if (failure_) return std::unexpected(*failure_);
    if (error != SSL_ERROR_NONE && error != SSL_ERROR_WANT_READ &&
        error != SSL_ERROR_WANT_WRITE) {
        fail(tls_error::provider_failure);
        return std::unexpected(*failure_);
    }
    if (SSL_is_init_finished(ssl_)) {
        if (!got_parameters_) fail(tls_error::missing_transport_parameters);
        if (negotiated_alpn().empty()) fail(tls_error::missing_alpn);
        if (failure_) return std::unexpected(*failure_);
        complete_ = true;
    }
    return complete_ ? tls_progress::complete : tls_progress::waiting;
}

auto tls_provider::peer_transport_parameters() const noexcept
    -> std::span<const std::uint8_t>
{ return {peer_parameters_.data(), peer_parameters_size_}; }

auto tls_provider::negotiated_alpn() const noexcept -> std::span<const std::uint8_t>
{
    if (!ssl_) return {};
    const unsigned char* data {};
    unsigned int size {0};
    SSL_get0_alpn_selected(ssl_, &data, &size);
    return {data, size};
}

auto tls_provider::fail(tls_error error) noexcept -> int
{
    if (!failure_) failure_ = error;
    return 0;
}

auto tls_provider::send(SSL*, const unsigned char* data, std::size_t size,
                        std::size_t* consumed, void* argument) noexcept -> int
{
    auto& self = *static_cast<tls_provider*>(argument);
    *consumed = 0;
    if (!self.callbacks_.send_crypto(self.callbacks_.argument, self.write_level_,
        {reinterpret_cast<const std::byte*>(data), size}))
        return self.fail(tls_error::capacity_exceeded);
    *consumed = size;
    return 1;
}

auto tls_provider::receive(SSL*, const unsigned char** data, std::size_t* size,
                           void* argument) noexcept -> int
{
    auto& self = *static_cast<tls_provider*>(argument);
    if (self.loan_buffer_) return self.fail(tls_error::invalid_crypto_data);
    auto* buffer = self.input_[static_cast<std::size_t>(self.read_level_)];
    const auto readable = buffer->readable();
    *data = reinterpret_cast<const unsigned char*>(readable.data());
    *size = readable.size();
    if (!readable.empty()) {
        self.loan_buffer_ = buffer;
        self.loan_size_ = readable.size();
    }
    return 1;
}

auto tls_provider::release(SSL*, std::size_t size, void* argument) noexcept -> int
{
    auto& self = *static_cast<tls_provider*>(argument);
    if (!self.loan_buffer_ || size != self.loan_size_ ||
        !self.loan_buffer_->consume(size))
        return self.fail(tls_error::invalid_crypto_data);
    self.loan_buffer_ = nullptr;
    self.loan_size_ = 0;
    return 1;
}

auto tls_provider::secret(SSL* ssl, std::uint32_t level, int direction,
                          const unsigned char* data, std::size_t size,
                          void* argument) noexcept -> int
{
    auto& self = *static_cast<tls_provider*>(argument);
    tls_level mapped;
    if (level == OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE) mapped = tls_level::handshake;
    else if (level == OSSL_RECORD_PROTECTION_LEVEL_APPLICATION) mapped = tls_level::application;
    else return self.fail(tls_error::unsupported_secret);
    const auto* cipher = SSL_get_current_cipher(ssl);
    if ((direction != 0 && direction != 1) || size != 32 || !cipher ||
        SSL_CIPHER_get_protocol_id(cipher) != 0x1301)
        return self.fail(tls_error::unsupported_secret);
    if (direction == 0 &&
        !self.input_[static_cast<std::size_t>(self.read_level_)]->readable().empty() &&
        !self.loan_buffer_)
        return self.fail(tls_error::invalid_crypto_data);
    if (!self.callbacks_.install_secret(self.callbacks_.argument, mapped,
        direction == 0 ? tls_direction::read : tls_direction::write,
        SSL_CIPHER_get_protocol_id(cipher), {data, size}))
        return self.fail(tls_error::capacity_exceeded);
    (direction == 0 ? self.read_level_ : self.write_level_) = mapped;
    return 1;
}

auto tls_provider::parameters(SSL*, const unsigned char* data, std::size_t size,
                              void* argument) noexcept -> int
{
    auto& self = *static_cast<tls_provider*>(argument);
    if (self.got_parameters_) return self.fail(tls_error::invalid_crypto_data);
    if (size > self.peer_parameters_.size()) return self.fail(tls_error::capacity_exceeded);
    std::copy_n(data, size, self.peer_parameters_.begin());
    self.peer_parameters_size_ = size;
    self.got_parameters_ = true;
    return 1;
}

auto tls_provider::send_alert(SSL*, unsigned char code, void* argument) noexcept -> int
{
    auto& self = *static_cast<tls_provider*>(argument);
    self.alert_ = code;
    return self.fail(tls_error::provider_failure);
}

auto tls_provider::select_alpn(SSL* ssl, const unsigned char** output,
                               unsigned char* output_size,
                               const unsigned char* input, unsigned int size,
                               void*) noexcept -> int
{
    auto* self = static_cast<tls_provider*>(SSL_get_app_data(ssl));
    if (!self) return SSL_TLSEXT_ERR_ALERT_FATAL;
    std::size_t position = 0;
    while (position < size) {
        const auto length = input[position++];
        if (length == 0 || length > size - position) return SSL_TLSEXT_ERR_ALERT_FATAL;
        if (length == self->alpn_size_ &&
            std::equal(self->alpn_.begin(), self->alpn_.begin() + length, input + position)) {
            *output = self->alpn_.data();
            *output_size = length;
            return SSL_TLSEXT_ERR_OK;
        }
        position += length;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

} // namespace eventloop::quic::detail
