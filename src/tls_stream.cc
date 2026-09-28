#include "eventloop/tls_stream.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
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
#include <botan/x509_crl.h>

#include <sys/socket.h>

namespace eventloop {

namespace {

[[nodiscard]] auto system_code(int value) noexcept -> std::error_code
{
    return {value, std::generic_category()};
}

[[nodiscard]] auto task_code(task_result result) noexcept -> std::error_code
{
    return system_code(result == task_result::frame_allocation_failure
                           ? ENOMEM : ECANCELED);
}

struct active_operation_guard {
    bool& active;
    ~active_operation_guard() { active = false; }
};

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
        if (std::filesystem::is_directory(trusted_ca)) {
            for (const auto& entry : std::filesystem::directory_iterator(trusted_ca)) {
                if (!entry.is_regular_file()) continue;
                try {
                    store->add_certificate(Botan::X509_Certificate(
                        entry.path().string()));
                } catch (const Botan::Exception&) {
                }
                try {
                    store->add_crl(Botan::X509_CRL(entry.path().string()));
                } catch (const Botan::Exception&) {
                }
            }
            if (store->all_subjects().empty()) {
                throw std::invalid_argument("trusted CA directory contains no certificates");
            }
            store_ = std::move(store);
            return;
        }
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
    static constexpr std::size_t encrypted_capacity = 64 * 1024;
    // Raw TCP reads are at most 4 KiB, so one read cannot deliver more
    // plaintext than this before the caller consumes the queued bytes.
    static constexpr std::size_t plaintext_capacity = 4096;

    implementation(std::shared_ptr<tls_context> context,
                   tls_client_options options)
        : context_(std::move(context)),
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

    implementation(std::shared_ptr<tls_context> context,
                   tls_server_options options)
        : context_(std::move(context)),
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
        if (data.size() > encrypted_capacity - encrypted_size_) {
            throw std::length_error("TLS encrypted output capacity exceeded");
        }
        std::memcpy(encrypted_.data() + encrypted_size_, data.data(), data.size());
        encrypted_size_ += data.size();
    }

    auto tls_record_received(std::uint64_t, std::span<const std::uint8_t> data)
        -> void override
    {
        if (data.size() > plaintext_capacity - plaintext_size_) {
            throw std::length_error("TLS plaintext input capacity exceeded");
        }
        std::memcpy(plaintext_.data() + plaintext_size_, data.data(), data.size());
        plaintext_size_ += data.size();
    }

    auto tls_alert(Botan::TLS::Alert alert) -> void override
    {
        if (alert.is_fatal()) {
            fatal_error_ = std::error_code(
                static_cast<int>(alert.type()), tls_error_category());
        }
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

    std::shared_ptr<tls_context> context_;
    std::vector<std::string> server_protocols_;
    std::shared_ptr<Botan::TLS::Callbacks> callback_;
    std::unique_ptr<Botan::TLS::Channel> channel_;
    std::error_code fatal_error_;
    bool peer_closed_ {false};
    std::array<std::byte, encrypted_capacity> encrypted_ {};
    std::size_t encrypted_size_ {0};
    std::array<std::byte, plaintext_capacity> plaintext_ {};
    std::size_t plaintext_size_ {0};
    std::array<std::byte, 4096> input_ {};
};

tls_stream::tls_stream(event_loop& loop, unique_fd descriptor,
                       std::shared_ptr<tls_context> context,
                       tls_client_options options)
    : tcp_stream(loop, std::move(descriptor)),
      implementation_(std::make_unique<implementation>(
          std::move(context), std::move(options)))
{
}

tls_stream::tls_stream(event_loop& loop, ip_endpoint endpoint,
                       std::shared_ptr<tls_context> context,
                       tls_client_options options)
    : tcp_stream(loop, endpoint),
      implementation_(std::make_unique<implementation>(
          std::move(context), std::move(options)))
{
}

tls_stream::tls_stream(event_loop& loop, unique_fd descriptor,
                       std::shared_ptr<tls_context> context,
                       tls_server_options options)
    : tcp_stream(loop, std::move(descriptor)),
      implementation_(std::make_unique<implementation>(
          std::move(context), std::move(options)))
{
}

tls_stream::~tls_stream()
{
    if (exclusive_operation_active_ || read_operation_active_ ||
        write_operation_active_ || flush_active_ || flush_waiter_) {
        std::terminate();
    }
}

auto tls_stream::close() -> void
{
    if (closing_) return;
    closing_ = true;
    tcp_stream::close();
}

auto tls_stream::application_protocol() const -> std::string
{
    if (!implementation_ || !implementation_->channel_->is_active()) {
        return {};
    }
    return implementation_->channel_->application_protocol();
}

auto tls_stream::async_handshake()
    -> task<std::expected<void, std::error_code>>
{
    return handshake_task(owner_loop(), *this);
}

auto tls_stream::async_read_some(std::span<std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
    return read_task(owner_loop(), *this, buffer);
}

auto tls_stream::async_write_some(std::span<const std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
    return write_task(owner_loop(), *this, buffer);
}

auto tls_stream::async_close()
    -> task<std::expected<void, std::error_code>>
{
    return close_task(owner_loop(), *this);
}

auto tls_stream::activate_async_tls() noexcept
    -> std::expected<void, std::error_code>
{
    if (async_tls_mode_) return {};
    if (closing_) return std::unexpected(system_code(ECANCELED));
    auto result = activate_async_transport();
    if (!result) return result;
    async_tls_mode_ = true;
    return {};
}

auto tls_stream::receive_encrypted(std::span<const std::byte> data) noexcept
    -> std::error_code
{
    try {
        implementation_->channel_->received_data({
            reinterpret_cast<const std::uint8_t*>(data.data()), data.size()});
    } catch (const Botan::TLS::TLS_Exception& error) {
        return {static_cast<int>(error.type()), tls_error_category()};
    } catch (const Botan::Exception&) {
        return make_error_code(implementation_->channel_->is_active()
                                   ? tls_errc::protocol_error
                                   : tls_errc::handshake_failed);
    } catch (const std::length_error&) {
        return system_code(ENOBUFS);
    } catch (...) {
        return make_error_code(tls_errc::protocol_error);
    }
    return implementation_->fatal_error_;
}

auto tls_stream::take_plaintext(std::span<std::byte> buffer) noexcept
    -> std::size_t
{
    auto& state = *implementation_;
    const auto size = std::min(buffer.size(), state.plaintext_size_);
    if (size != 0) {
        std::memcpy(buffer.data(), state.plaintext_.data(), size);
        state.plaintext_size_ -= size;
        std::memmove(state.plaintext_.data(), state.plaintext_.data() + size,
                     state.plaintext_size_);
    }
    return size;
}

class tls_stream::flush_waiter {
public:
    friend class tls_stream;
    explicit flush_waiter(tls_stream& owner) noexcept : owner_(owner)
    {
        cancellation_.operation = this;
        cancellation_.cancel = &cancel;
    }

    ~flush_waiter()
    {
        if (owner_.flush_waiter_ == this) std::terminate();
    }

    [[nodiscard]] auto await_ready() noexcept -> bool
    {
        if (owner_.flush_active_) return false;
        owner_.flush_active_ = true;
        return true;
    }

    template<typename Promise>
    [[nodiscard]] auto await_suspend(std::coroutine_handle<Promise> handle)
        noexcept -> bool
    {
        auto& state = *handle.promise().cancellation_state();
        if (state.requested ||
            !detail::coroutine_frame_access::attach_cancellation(
                state, cancellation_)) {
            error_ = system_code(ECANCELED);
            return false;
        }
        if (owner_.flush_waiter_ != nullptr) std::terminate();
        continuation_ = handle;
        owner_.flush_waiter_ = this;
        return true;
    }

    [[nodiscard]] auto await_resume() const noexcept
        -> std::expected<void, std::error_code>
    {
        if (error_) return std::unexpected(error_);
        return {};
    }

    auto finish(std::error_code error) noexcept -> void
    {
        error_ = error;
        continuation_.resume();
    }

private:
    static auto cancel(detail::coroutine_cancellation_node& node)
        noexcept -> void
    {
        auto& self = *static_cast<flush_waiter*>(node.operation);
        self.owner_.flush_waiter_ = nullptr;
        detail::coroutine_frame_access::detach_cancellation(
            self.cancellation_);
        self.finish(system_code(ECANCELED));
    }

    tls_stream& owner_;
    std::coroutine_handle<> continuation_ {};
    detail::coroutine_cancellation_node cancellation_;
    std::error_code error_;
};

auto tls_stream::release_flush() noexcept -> void
{
    auto* waiter = std::exchange(flush_waiter_, nullptr);
    if (waiter == nullptr) {
        flush_active_ = false;
        return;
    }
    detail::coroutine_frame_access::detach_cancellation(
        waiter->cancellation_);
    // Ownership passes directly to the resumed coroutine. No other flusher
    // can enter between the current write and its continuation.
    waiter->finish({});
}

auto tls_stream::flush_task(event_loop& loop, tls_stream& self)
    -> task<std::expected<void, std::error_code>>
{
    (void)loop;
    auto acquired = co_await flush_waiter {self};
    if (!acquired) co_return std::unexpected(acquired.error());
    struct flush_guard {
        tls_stream& owner;
        ~flush_guard() { owner.release_flush(); }
    } guard {self};
    auto& state = *self.implementation_;
    while (state.encrypted_size_ != 0) {
        const auto result = co_await self.tcp_stream::async_write_some(
            std::span<const std::byte>(state.encrypted_.data(),
                                       state.encrypted_size_));
        if (!result) co_return std::unexpected(result.error());
        if (*result == 0) co_return std::unexpected(system_code(EPIPE));
        state.encrypted_size_ -= *result;
        std::memmove(state.encrypted_.data(), state.encrypted_.data() + *result,
                     state.encrypted_size_);
    }
    co_return std::expected<void, std::error_code> {};
}

auto tls_stream::handshake_task(event_loop& loop, tls_stream& self)
    -> task<std::expected<void, std::error_code>>
{
    if (self.exclusive_operation_active_ || self.read_operation_active_ ||
        self.write_operation_active_) {
        co_return std::unexpected(system_code(EBUSY));
    }
    self.exclusive_operation_active_ = true;
    active_operation_guard guard {self.exclusive_operation_active_};
    if (co_await cancellation_requested()) {
        co_return std::unexpected(system_code(ECANCELED));
    }
    // Outbound TCP streams activate their transport before they connect.
    // Check the actual peer before sending the client's TLS handshake.
    sockaddr_storage peer {};
    socklen_t peer_size = sizeof(peer);
    if (::getpeername(self.descriptor(), reinterpret_cast<sockaddr*>(&peer),
                      &peer_size) == -1) {
        co_return std::unexpected(system_code(errno));
    }
    if (auto activated = self.activate_async_tls(); !activated) {
        co_return std::unexpected(activated.error());
    }
    auto& encrypted = self.implementation_->input_;
    while (!self.implementation_->channel_->is_active()) {
        auto flushed = co_await flush_task(loop, self);
        if (!flushed) co_return std::unexpected(task_code(flushed.error()));
        if (!*flushed) co_return std::unexpected(flushed->error());
        auto received = co_await self.tcp_stream::async_read_some(encrypted);
        if (!received) co_return std::unexpected(received.error());
        if (*received == 0) {
            co_return std::unexpected(make_error_code(tls_errc::truncated));
        }
        if (auto error = self.receive_encrypted(
                std::span(encrypted).first(*received)); error) {
            co_return std::unexpected(error);
        }
    }
    auto flushed = co_await flush_task(loop, self);
    if (!flushed) co_return std::unexpected(task_code(flushed.error()));
    if (!*flushed) co_return std::unexpected(flushed->error());
    co_return std::expected<void, std::error_code> {};
}

auto tls_stream::read_task(event_loop& loop, tls_stream& self,
                           std::span<std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
    if (self.exclusive_operation_active_ || self.read_operation_active_) {
        co_return std::unexpected(system_code(EBUSY));
    }
    self.read_operation_active_ = true;
    active_operation_guard guard {self.read_operation_active_};
    if (co_await cancellation_requested()) {
        co_return std::unexpected(system_code(ECANCELED));
    }
    if (!self.async_tls_mode_) {
        co_return std::unexpected(system_code(ENOTCONN));
    }
    if (buffer.empty()) co_return std::size_t {0};
    if (auto size = self.take_plaintext(buffer); size != 0) co_return size;
    if (self.implementation_->peer_closed_) co_return std::size_t {0};
    if (!self.implementation_->channel_->is_active()) {
        co_return std::unexpected(system_code(ENOTCONN));
    }
    auto& encrypted = self.implementation_->input_;
    for (;;) {
        if (self.implementation_->peer_closed_) co_return std::size_t {0};
        auto received = co_await self.tcp_stream::async_read_some(encrypted);
        if (!received) co_return std::unexpected(received.error());
        if (*received == 0) {
            if (self.implementation_->peer_closed_) co_return std::size_t {0};
            co_return std::unexpected(make_error_code(tls_errc::truncated));
        }
        if (auto error = self.receive_encrypted(
                std::span(encrypted).first(*received)); error) {
            co_return std::unexpected(error);
        }
        auto flushed = co_await flush_task(loop, self);
        if (!flushed) co_return std::unexpected(task_code(flushed.error()));
        if (!*flushed) co_return std::unexpected(flushed->error());
        if (auto size = self.take_plaintext(buffer); size != 0) co_return size;
    }
}

auto tls_stream::write_task(event_loop& loop, tls_stream& self,
                            std::span<const std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
    if (self.exclusive_operation_active_ || self.write_operation_active_) {
        co_return std::unexpected(system_code(EBUSY));
    }
    self.write_operation_active_ = true;
    active_operation_guard guard {self.write_operation_active_};
    if (co_await cancellation_requested()) {
        co_return std::unexpected(system_code(ECANCELED));
    }
    if (!self.async_tls_mode_ || !self.implementation_->channel_->is_active() ||
        self.transport_closed() ||
        self.implementation_->channel_->is_closed_for_writing()) {
        co_return std::unexpected(system_code(ENOTCONN));
    }
    if (buffer.empty()) co_return std::size_t {0};
    const auto size = std::min<std::size_t>(buffer.size(), 4096);
    try {
        self.implementation_->channel_->send({
            reinterpret_cast<const std::uint8_t*>(buffer.data()), size});
    } catch (const Botan::TLS::TLS_Exception& error) {
        co_return std::unexpected(std::error_code(
            static_cast<int>(error.type()), tls_error_category()));
    } catch (const Botan::Exception&) {
        co_return std::unexpected(make_error_code(tls_errc::protocol_error));
    } catch (const std::length_error&) {
        co_return std::unexpected(system_code(ENOBUFS));
    }
    auto flushed = co_await flush_task(loop, self);
    if (!flushed) co_return std::unexpected(task_code(flushed.error()));
    if (!*flushed) co_return std::unexpected(flushed->error());
    co_return size;
}

auto tls_stream::close_task(event_loop& loop, tls_stream& self)
    -> task<std::expected<void, std::error_code>>
{
    if (self.exclusive_operation_active_ || self.read_operation_active_ ||
        self.write_operation_active_) {
        co_return std::unexpected(system_code(EBUSY));
    }
    self.exclusive_operation_active_ = true;
    active_operation_guard guard {self.exclusive_operation_active_};
    if (co_await cancellation_requested()) {
        co_return std::unexpected(system_code(ECANCELED));
    }
    if (!self.async_tls_mode_) {
        co_return std::unexpected(system_code(ENOTCONN));
    }
    try {
        if (!self.implementation_->channel_->is_closed_for_writing()) {
            self.implementation_->channel_->close();
        }
    } catch (const Botan::Exception&) {
        co_return std::unexpected(make_error_code(tls_errc::protocol_error));
    } catch (const std::length_error&) {
        co_return std::unexpected(system_code(ENOBUFS));
    } catch (...) {
        co_return std::unexpected(make_error_code(tls_errc::protocol_error));
    }
    auto flushed = co_await flush_task(loop, self);
    if (!flushed) co_return std::unexpected(task_code(flushed.error()));
    co_return *flushed;
}

} // namespace eventloop
