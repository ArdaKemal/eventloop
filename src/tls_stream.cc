#include "eventloop/tls_stream.h"

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <utility>

#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/certstor_system.h>
#include <botan/credentials_manager.h>
#include <botan/data_src.h>
#include <botan/exceptn.h>
#include <botan/pkcs8.h>
#include <botan/tls_alert.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session_manager_memory.h>
#include <botan/x509cert.h>

namespace {

enum class context_role { client, server };

class client_credentials final : public Botan::Credentials_Manager {
public:
    client_credentials()
        : store_(std::make_unique<Botan::System_Certificate_Store>())
    {
    }

    explicit client_credentials(const std::filesystem::path& trusted_ca)
    {
        auto store = std::make_unique<Botan::Certificate_Store_In_Memory>();
        Botan::DataSource_Stream source(trusted_ca.string());
        while (!source.end_of_data()) {
            try {
                store->add_certificate(Botan::X509_Certificate(source));
            } catch (const Botan::Exception&) {
                break;
            }
        }
        if (store->all_subjects().empty()) {
            throw std::invalid_argument("trusted CA file contains no certificates");
        }
        store_ = std::move(store);
    }

    auto trusted_certificate_authorities(const std::string&, const std::string&)
        -> std::vector<Botan::Certificate_Store*> override
    {
        return {store_.get()};
    }

private:
    std::unique_ptr<Botan::Certificate_Store> store_;
};

class server_credentials final : public Botan::Credentials_Manager {
public:
    server_credentials(const std::filesystem::path& certificate_chain,
                       const std::filesystem::path& private_key,
                       std::string_view password)
    {
        Botan::DataSource_Stream certificates(certificate_chain.string());
        while (!certificates.end_of_data()) {
            try {
                certificate_chain_.emplace_back(certificates);
            } catch (const Botan::Exception&) {
                break;
            }
        }
        if (certificate_chain_.empty()) {
            throw std::invalid_argument("certificate chain file contains no certificates");
        }

        Botan::DataSource_Stream key_source(private_key.string());
        if (password.empty()) {
            private_key_ = Botan::PKCS8::load_key(key_source);
        } else {
            private_key_ = Botan::PKCS8::load_key(key_source, password);
        }

        const auto certificate_key = certificate_chain_.front().subject_public_key();
        if (certificate_key->public_key_bits() != private_key_->public_key_bits()) {
            throw std::invalid_argument("certificate and private key do not match");
        }
    }

    auto trusted_certificate_authorities(const std::string&, const std::string&)
        -> std::vector<Botan::Certificate_Store*> override
    {
        return {};
    }

    auto find_cert_chain(
        const std::vector<std::string>& key_types,
        const std::vector<Botan::AlgorithmIdentifier>&,
        const std::vector<Botan::X509_DN>&,
        const std::string&, const std::string&)
        -> std::vector<Botan::X509_Certificate> override
    {
        const auto algorithm = certificate_chain_.front().subject_public_key()->algo_name();
        if (key_types.empty() ||
            std::ranges::find(key_types, algorithm) != key_types.end()) {
            return certificate_chain_;
        }
        return {};
    }

    auto private_key_for(const Botan::X509_Certificate&, const std::string&,
                         const std::string&) -> std::shared_ptr<Botan::Private_Key> override
    {
        return private_key_;
    }

private:
    std::vector<Botan::X509_Certificate> certificate_chain_;
    std::shared_ptr<Botan::Private_Key> private_key_;
};

class tls_category final : public std::error_category {
public:
    [[nodiscard]] auto name() const noexcept -> const char* override
    {
        return "tls";
    }

    [[nodiscard]] auto message(int value) const -> std::string override
    {
        if (value >= 0 && value < 256) {
            return Botan::TLS::Alert(static_cast<Botan::TLS::AlertType>(value)).type_string();
        }
        switch (static_cast<tls_errc>(value)) {
        case tls_errc::truncated:
            return "TLS connection closed without close_notify";
        case tls_errc::handshake_failed:
            return "TLS handshake failed";
        case tls_errc::protocol_error:
            return "TLS protocol error";
        }
        return "unknown TLS error";
    }
};

} // namespace

class tls_context::implementation {
public:
    implementation(context_role role,
                   std::shared_ptr<Botan::Credentials_Manager> credentials)
        : role(role), rng(std::make_shared<Botan::AutoSeeded_RNG>()),
          sessions(std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng)),
          credentials(std::move(credentials)),
          policy(std::make_shared<Botan::TLS::Policy>())
    {
    }

    context_role role;
    std::shared_ptr<Botan::RandomNumberGenerator> rng;
    std::shared_ptr<Botan::TLS::Session_Manager> sessions;
    std::shared_ptr<Botan::Credentials_Manager> credentials;
    std::shared_ptr<const Botan::TLS::Policy> policy;
};

tls_context::tls_context(std::unique_ptr<implementation> implementation)
    : implementation_(std::move(implementation))
{
}

tls_context::~tls_context() = default;

auto tls_context::make_system_client() -> std::shared_ptr<tls_context>
{
    return std::shared_ptr<tls_context>(new tls_context(std::make_unique<implementation>(
        context_role::client, std::make_shared<client_credentials>())));
}

auto tls_context::make_client(const std::filesystem::path& trusted_ca)
    -> std::shared_ptr<tls_context>
{
    return std::shared_ptr<tls_context>(new tls_context(std::make_unique<implementation>(
        context_role::client, std::make_shared<client_credentials>(trusted_ca))));
}

auto tls_context::make_server(const std::filesystem::path& certificate_chain,
                              const std::filesystem::path& private_key,
                              std::string_view password) -> std::shared_ptr<tls_context>
{
    return std::shared_ptr<tls_context>(new tls_context(std::make_unique<implementation>(
        context_role::server,
        std::make_shared<server_credentials>(certificate_chain, private_key, password))));
}

auto tls_error_category() noexcept -> const std::error_category&
{
    static const tls_category category;
    return category;
}

auto make_error_code(tls_errc error) noexcept -> std::error_code
{
    return {static_cast<int>(error), tls_error_category()};
}

class tls_stream::implementation final : public Botan::TLS::Callbacks {
public:
    implementation(tls_stream& owner, std::shared_ptr<tls_context> context,
                   tls_client_options options)
        : owner_(owner), context_(std::move(context)),
          callback_(this, [](Botan::TLS::Callbacks*) {})
    {
        if (!context_ || context_->implementation_->role != context_role::client) {
            throw std::invalid_argument("a client TLS context is required");
        }
        if (options.hostname.empty()) {
            throw std::invalid_argument("TLS client hostname cannot be empty");
        }
        const auto& config = *context_->implementation_;
        channel_ = std::make_unique<Botan::TLS::Client>(
            callback_, config.sessions, config.credentials, config.policy, config.rng,
            Botan::TLS::Server_Information(options.hostname),
            Botan::TLS::Protocol_Version::latest_tls_version(),
            options.application_protocols);
    }

    implementation(tls_stream& owner, std::shared_ptr<tls_context> context,
                   tls_server_options options)
        : owner_(owner), context_(std::move(context)),
          server_protocols_(std::move(options.application_protocols)),
          callback_(this, [](Botan::TLS::Callbacks*) {})
    {
        if (!context_ || context_->implementation_->role != context_role::server) {
            throw std::invalid_argument("a server TLS context is required");
        }
        const auto& config = *context_->implementation_;
        channel_ = std::make_unique<Botan::TLS::Server>(
            callback_, config.sessions, config.credentials, config.policy, config.rng);
    }

    auto tls_emit_data(std::span<const std::uint8_t> data) -> void override
    {
        owner_.tcp_stream::write(std::as_bytes(data));
    }

    auto tls_record_received(std::uint64_t, std::span<const std::uint8_t> data)
        -> void override
    {
        owner_.emit_data(std::as_bytes(data));
    }

    auto tls_alert(Botan::TLS::Alert alert) -> void override
    {
        if (alert.is_fatal()) {
            fatal_error_ = std::error_code(
                static_cast<int>(alert.type()), tls_error_category());
        }
    }

    auto tls_session_activated() -> void override
    {
        owner_.emit_ready();
    }

    auto tls_peer_closed_connection() -> bool override
    {
        peer_closed_ = true;
        return true;
    }

    auto tls_server_choose_app_protocol(const std::vector<std::string>& client_protocols)
        -> std::string override
    {
        if (server_protocols_.empty()) {
            return {};
        }
        for (const auto& protocol : server_protocols_) {
            if (std::ranges::find(client_protocols, protocol) != client_protocols.end()) {
                return protocol;
            }
        }
        throw Botan::TLS::TLS_Exception(Botan::TLS::AlertType::NoApplicationProtocol);
    }

    tls_stream& owner_;
    std::shared_ptr<tls_context> context_;
    std::vector<std::string> server_protocols_;
    std::shared_ptr<Botan::TLS::Callbacks> callback_;
    std::unique_ptr<Botan::TLS::Channel> channel_;
    std::error_code fatal_error_;
    bool peer_closed_ {false};
};

tls_stream::tls_stream(event_loop& loop, int descriptor,
                       std::shared_ptr<tls_context> context,
                       tls_client_options options)
    : tls_stream(loop, unique_fd(descriptor), std::move(context),
                 std::move(options))
{
}

tls_stream::tls_stream(event_loop& loop, unique_fd descriptor,
                       std::shared_ptr<tls_context> context,
                       tls_client_options options)
    : tcp_stream(loop, std::move(descriptor)),
      implementation_(std::make_unique<implementation>(
          *this, std::move(context), std::move(options)))
{
}

tls_stream::tls_stream(event_loop& loop, int descriptor,
                       std::shared_ptr<tls_context> context,
                       tls_server_options options)
    : tls_stream(loop, unique_fd(descriptor), std::move(context),
                 std::move(options))
{
}

tls_stream::tls_stream(event_loop& loop, unique_fd descriptor,
                       std::shared_ptr<tls_context> context,
                       tls_server_options options)
    : tcp_stream(loop, std::move(descriptor)),
      implementation_(std::make_unique<implementation>(
          *this, std::move(context), std::move(options)))
{
}

tls_stream::~tls_stream() = default;

auto tls_stream::write(std::span<const std::byte> data) -> void
{
    if (!ready()) {
        throw std::logic_error("cannot write before the TLS handshake completes");
    }
    try {
        implementation_->channel_->send({
            reinterpret_cast<const std::uint8_t*>(data.data()), data.size()});
    } catch (const Botan::TLS::TLS_Exception& error) {
        emit_error({static_cast<int>(error.type()), tls_error_category()});
        abort();
    } catch (const Botan::Exception&) {
        emit_error(make_error_code(tls_errc::protocol_error));
        abort();
    }
}

auto tls_stream::close() -> void
{
    if (closing_) {
        return;
    }
    closing_ = true;
    try {
        if (!implementation_->channel_->is_closed_for_writing()) {
            implementation_->channel_->close();
        }
        tcp_stream::close();
    } catch (const Botan::Exception&) {
        emit_error(make_error_code(tls_errc::protocol_error));
        abort();
    }
}

auto tls_stream::ready() const noexcept -> bool
{
    return implementation_ && implementation_->channel_->is_active() &&
           !closing_ && tcp_stream::ready();
}

auto tls_stream::application_protocol() const -> std::string
{
    if (!implementation_ || !implementation_->channel_->is_active()) {
        return {};
    }
    return implementation_->channel_->application_protocol();
}

auto tls_stream::on_transport_data(std::span<const std::byte> data) -> void
{
    try {
        implementation_->channel_->received_data({
            reinterpret_cast<const std::uint8_t*>(data.data()), data.size()});
    } catch (const Botan::TLS::TLS_Exception& error) {
        emit_error({static_cast<int>(error.type()), tls_error_category()});
        abort();
        return;
    } catch (const Botan::Exception&) {
        emit_error(make_error_code(ready() ? tls_errc::protocol_error
                                           : tls_errc::handshake_failed));
        abort();
        return;
    }

    if (implementation_->fatal_error_) {
        emit_error(implementation_->fatal_error_);
        abort();
        return;
    }
    if (implementation_->peer_closed_) {
        if (!close_emitted_) {
            close_emitted_ = true;
            emit_close();
        }
        close();
    }
}

auto tls_stream::on_transport_close() -> void
{
    if (implementation_->peer_closed_ ||
        implementation_->channel_->is_closed_for_reading()) {
        if (!close_emitted_) {
            close_emitted_ = true;
            emit_close();
        }
        tcp_stream::close();
        return;
    }
    emit_error(make_error_code(tls_errc::truncated));
    abort();
}

auto tls_stream::on_transport_error(std::error_code error) -> void
{
    emit_error(error);
    abort();
}
