#include "eventloop/tls_stream.h"
#include "socket_operations.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#ifdef _WIN32
#include <wincrypt.h>
#endif

namespace eventloop {
namespace {
[[nodiscard]] auto system_code(int value) noexcept -> std::error_code
{
    return {value, std::generic_category()};
}
#ifndef __linux__
[[nodiscard]] auto task_code(task_result result) noexcept -> std::error_code
{
    return system_code(result == task_result::frame_allocation_failure ? ENOMEM : ECANCELED);
}
#endif
struct active_operation_guard {
    bool& active;
    ~active_operation_guard() { active = false; }
};
// SSL_get_error() requires an empty queue before its matching I/O call.
// Clearing an already empty queue still scans all OpenSSL error slots; the
// normal established-I/O path only needs to check whether there is an error.
auto clear_io_errors() noexcept -> void
{
    if (ERR_peek_error() != 0) ERR_clear_error();
}
enum class context_role { client, server };
struct tls_callbacks {
    std::vector<std::string> server_protocols_;
    std::error_code fatal_error_;
};
int select_alpn(SSL* ssl, const unsigned char** out, unsigned char* length,
                const unsigned char* input, unsigned int size, void*)
{
    auto& state = *static_cast<tls_callbacks*>(SSL_get_app_data(ssl));
    if (state.server_protocols_.empty()) return SSL_TLSEXT_ERR_NOACK;
    for (const auto& protocol : state.server_protocols_) {
        for (unsigned int offset = 0; offset < size;) {
            const auto n = input[offset++];
            if (n == 0 || n > size - offset) return SSL_TLSEXT_ERR_ALERT_FATAL;
            if (n == protocol.size() && std::memcmp(input + offset, protocol.data(), n) == 0) {
                *out = input + offset; *length = n;
                return SSL_TLSEXT_ERR_OK;
            }
            offset += n;
        }
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}
template<class T, auto Free> using ssl_ptr = std::unique_ptr<T, decltype(Free)>;
auto require_ssl(long result, const char* message) -> void
{
    if (result != 1) { ERR_clear_error(); throw std::invalid_argument(message); }
}
// Missing CRLs are allowed, as in the previous trust-store implementation.
// A supplied CRL must still pass signature/time checks and revoked leaves fail.
auto verify_certificate(int ok, X509_STORE_CTX* store) -> int
{
    if (!ok && X509_STORE_CTX_get_error(store) == X509_V_ERR_UNABLE_TO_GET_CRL) {
        X509_STORE_CTX_set_error(store, X509_V_OK);
        return 1;
    }
    return ok;
}
auto load_trust_file(X509_STORE* store, const std::filesystem::path& path,
                     bool& has_crl) -> std::size_t
{
    ssl_ptr<BIO, BIO_free> input(BIO_new_file(path.string().c_str(), "rb"), BIO_free);
    if (!input) { ERR_clear_error(); return 0; }
    STACK_OF(X509_INFO)* entries = PEM_X509_INFO_read_bio(input.get(), nullptr, nullptr, nullptr);
    if (!entries || sk_X509_INFO_num(entries) == 0) {
        sk_X509_INFO_pop_free(entries, X509_INFO_free);
        ERR_clear_error();
        (void)BIO_reset(input.get());
        ssl_ptr<X509, X509_free> cert(d2i_X509_bio(input.get(), nullptr), X509_free);
        if (cert) {
            require_ssl(X509_STORE_add_cert(store, cert.get()), "cannot add trusted certificate");
            return 1;
        }
        ERR_clear_error();
        (void)BIO_reset(input.get());
        ssl_ptr<X509_CRL, X509_CRL_free> crl(d2i_X509_CRL_bio(input.get(), nullptr), X509_CRL_free);
        if (crl) {
            require_ssl(X509_STORE_add_crl(store, crl.get()), "cannot add trusted CRL");
            has_crl = true;
        }
        ERR_clear_error();
        return 0;
    }
    struct entries_guard {
        STACK_OF(X509_INFO)* entries;
        ~entries_guard() { sk_X509_INFO_pop_free(entries, X509_INFO_free); }
    } guard {entries};
    std::size_t count = 0;
    for (int i = 0; i < sk_X509_INFO_num(entries); ++i) {
        auto* entry = sk_X509_INFO_value(entries, i);
        if (entry->x509) {
            require_ssl(X509_STORE_add_cert(store, entry->x509), "cannot add trusted certificate");
            ++count;
        }
        if (entry->crl) {
            require_ssl(X509_STORE_add_crl(store, entry->crl), "cannot add trusted CRL");
            has_crl = true;
        }
    }
    ERR_clear_error();
    return count;
}
class tls_category final : public std::error_category {
public:
    auto name() const noexcept -> const char* override { return "tls"; }
    auto message(int value) const -> std::string override
    {
        if (value >= 0 && value < 256) return SSL_alert_desc_string_long(value);
        switch (static_cast<tls_errc>(value)) {
        case tls_errc::truncated: return "TLS connection closed without close_notify";
        case tls_errc::handshake_failed: return "TLS handshake failed";
        case tls_errc::protocol_error: return "TLS protocol error";
        }
        return "unknown TLS error";
    }
};
} // namespace

class tls_context::implementation {
public:
    explicit implementation(context_role role)
        : role(role), context(SSL_CTX_new(TLS_method()), SSL_CTX_free)
    {
        if (!context) throw std::bad_alloc();
        require_ssl(SSL_CTX_set_min_proto_version(context.get(), TLS1_2_VERSION), "TLS minimum version");
        SSL_CTX_set_options(context.get(), SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
#ifdef __linux__
        SSL_CTX_set_options(context.get(), SSL_OP_ENABLE_KTLS);
#endif
        // Keep record buffers for the connection, avoiding release/reallocate on each read.
        SSL_CTX_clear_mode(context.get(), SSL_MODE_RELEASE_BUFFERS);
        SSL_CTX_set_mode(context.get(), SSL_MODE_AUTO_RETRY);
        require_ssl(SSL_CTX_set_max_send_fragment(context.get(), 16 * 1024), "TLS send fragment limit");
        SSL_CTX_set_session_cache_mode(context.get(), SSL_SESS_CACHE_OFF);
        SSL_CTX_set_num_tickets(context.get(), 0);
        if (role == context_role::client)
            SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, verify_certificate);
    }
    context_role role;
    ssl_ptr<SSL_CTX, SSL_CTX_free> context;
};
tls_context::tls_context(std::unique_ptr<implementation> implementation)
    : implementation_(std::move(implementation)) {}
tls_context::~tls_context() = default;
auto tls_context::make_system_client() -> std::shared_ptr<tls_context>
{
    auto config = std::make_unique<implementation>(context_role::client);
#ifdef _WIN32
    auto* roots = CertOpenSystemStoreA(0, "ROOT");
    if (!roots) throw std::invalid_argument("cannot open system certificate store");
    struct root_guard { HCERTSTORE store; ~root_guard() { CertCloseStore(store, 0); } } guard {roots};
    PCCERT_CONTEXT entry = nullptr;
    while ((entry = CertEnumCertificatesInStore(roots, entry)) != nullptr) {
        const unsigned char* bytes = entry->pbCertEncoded;
        ssl_ptr<X509, X509_free> cert(d2i_X509(nullptr, &bytes, entry->cbCertEncoded), X509_free);
        if (cert) (void)X509_STORE_add_cert(SSL_CTX_get_cert_store(config->context.get()), cert.get());
        ERR_clear_error();
    }
#else
    require_ssl(SSL_CTX_set_default_verify_paths(config->context.get()), "cannot load system trust store");
#endif
    return std::shared_ptr<tls_context>(new tls_context(std::move(config)));
}
auto tls_context::make_client(const std::filesystem::path& trusted_ca) -> std::shared_ptr<tls_context>
{
    auto config = std::make_unique<implementation>(context_role::client);
    auto* store = SSL_CTX_get_cert_store(config->context.get());
    bool has_crl = false;
    std::size_t count = 0;
    if (std::filesystem::is_directory(trusted_ca)) {
        for (const auto& entry : std::filesystem::directory_iterator(trusted_ca))
            if (entry.is_regular_file()) count += load_trust_file(store, entry.path(), has_crl);
    } else count = load_trust_file(store, trusted_ca, has_crl);
    if (count == 0) throw std::invalid_argument("trusted CA path contains no certificates");
    if (has_crl) require_ssl(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL), "CRL checks");
    return std::shared_ptr<tls_context>(new tls_context(std::move(config)));
}
auto tls_context::make_server(const std::filesystem::path& certificate_chain,
                              const std::filesystem::path& private_key,
                              std::string_view password) -> std::shared_ptr<tls_context>
{
    auto config = std::make_unique<implementation>(context_role::server);
    auto* ctx = config->context.get();
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, nullptr);
    require_ssl(SSL_CTX_use_certificate_chain_file(ctx, certificate_chain.string().c_str()), "cannot load certificate chain");
    SSL_CTX_set_default_passwd_cb(ctx, [](char* out, int size, int, void* arg) -> int {
        auto pass = *static_cast<std::string_view*>(arg);
        if (size <= 0 || pass.size() >= static_cast<std::size_t>(size)) return 0;
        if (!pass.empty()) std::memcpy(out, pass.data(), pass.size());
        return static_cast<int>(pass.size());
    });
    SSL_CTX_set_default_passwd_cb_userdata(ctx, &password);
    const auto loaded = SSL_CTX_use_PrivateKey_file(ctx, private_key.string().c_str(), SSL_FILETYPE_PEM);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, nullptr);
    SSL_CTX_set_default_passwd_cb(ctx, nullptr);
    require_ssl(loaded, "cannot load private key");
    require_ssl(SSL_CTX_check_private_key(ctx), "certificate and private key do not match");
    return std::shared_ptr<tls_context>(new tls_context(std::move(config)));
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

class tls_stream::implementation : public tls_callbacks {
public:
    static constexpr std::size_t encrypted_capacity = 64 * 1024;
    static constexpr std::size_t input_capacity = 4096;
    implementation(std::shared_ptr<tls_context> context, tls_client_options options)
        : context_(std::move(context)), ssl_(nullptr, SSL_free)
    {
        initialize(context_role::client);
        if (options.hostname.empty() || options.hostname.size() > 255 || options.hostname.find('\0') != std::string::npos)
            throw std::invalid_argument("TLS client hostname is invalid");
        auto* param = SSL_get0_param(ssl_.get());
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        // Numeric IPs use iPAddress SANs; DNS names use hostname verification and SNI.
        if (X509_VERIFY_PARAM_set1_ip_asc(param, options.hostname.c_str()) != 1) {
            ERR_clear_error();
            require_ssl(SSL_set1_host(ssl_.get(), options.hostname.c_str()), "TLS hostname");
            require_ssl(SSL_set_tlsext_host_name(ssl_.get(), options.hostname.c_str()), "TLS SNI");
        }
        // ALPN's on-wire length is bounded by the TLS extension length.
        auto* protocols = reinterpret_cast<unsigned char*>(encrypted_.data());
        constexpr std::size_t protocol_capacity = 65535;
        std::size_t size = 0;
        for (const auto& protocol : options.application_protocols) {
            if (protocol.empty() || protocol.size() > 255 || protocol.size() + 1 > protocol_capacity - size)
                throw std::invalid_argument("TLS ALPN list exceeds wire limits");
            protocols[size++] = static_cast<unsigned char>(protocol.size());
            std::memcpy(protocols + size, protocol.data(), protocol.size());
            size += protocol.size();
        }
        if (size != 0 && SSL_set_alpn_protos(ssl_.get(), protocols, static_cast<unsigned int>(size)) != 0)
            throw std::bad_alloc();
    }
    implementation(std::shared_ptr<tls_context> context, tls_server_options options)
        : tls_callbacks {std::move(options.application_protocols), {}}, context_(std::move(context)), ssl_(nullptr, SSL_free)
    {
        initialize(context_role::server);
        for (const auto& protocol : server_protocols_)
            if (protocol.empty() || protocol.size() > 255) throw std::invalid_argument("invalid TLS ALPN protocol");
    }
    auto initialize(context_role role) -> void
    {
        if (!context_ || context_->implementation_->role != role)
            throw std::invalid_argument("TLS context role mismatch");
        ssl_.reset(SSL_new(context_->implementation_->context.get()));
        if (!ssl_) throw std::bad_alloc();
        auto* bio = BIO_new(bio_method());
        if (!bio) throw std::bad_alloc();
        BIO_set_data(bio, this);
        BIO_set_init(bio, 1);
        SSL_set_bio(ssl_.get(), bio, bio);
        SSL_set_app_data(ssl_.get(), static_cast<tls_callbacks*>(this));
        SSL_set_info_callback(ssl_.get(), [](const SSL* ssl, int where, int value) {
            if ((where & SSL_CB_ALERT) && (value >> 8) == SSL3_AL_FATAL) {
                auto* state = static_cast<tls_callbacks*>(SSL_get_app_data(ssl));
                state->fatal_error_ = {value & 255, tls_error_category()};
            }
        });
        if (role == context_role::client) SSL_set_connect_state(ssl_.get());
        else SSL_set_accept_state(ssl_.get());
        // Setting the connection role resets the record layer; preallocate after it.
        if (SSL_alloc_buffers(ssl_.get()) != 1) {
            ERR_clear_error();
            throw std::bad_alloc();
        }
    }
    static auto bio_method() -> const BIO_METHOD*
    {
        static ssl_ptr<BIO_METHOD, BIO_meth_free> methods([] {
            auto* method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "eventloop fixed TLS buffers");
            if (!method) throw std::bad_alloc();
            if (BIO_meth_set_read(method, [](BIO* bio, char* out, int count) -> int {
                BIO_clear_retry_flags(bio);
                auto& state = *static_cast<implementation*>(BIO_get_data(bio));
                if (count <= 0) return 0;
                if (state.input_size_ == 0) { BIO_set_retry_read(bio); return -1; }
                const auto size = std::min(static_cast<std::size_t>(count), state.input_size_);
                std::memcpy(out, state.input_.data() + state.input_offset_, size);
                state.input_offset_ += size; state.input_size_ -= size;
                return static_cast<int>(size);
            }) != 1 || BIO_meth_set_write(method, [](BIO* bio, const char* input, int count) -> int {
                BIO_clear_retry_flags(bio);
                auto& state = *static_cast<implementation*>(BIO_get_data(bio));
                if (count <= 0) return 0;
                const auto size = static_cast<std::size_t>(count);
                if (size > state.encrypted_.size()) {
                    state.fatal_error_ = system_code(ENOBUFS);
                    return -1;
                }
                if (size > state.encrypted_.size() - state.encrypted_size_) {
                    BIO_set_retry_write(bio); return -1;
                }
                std::memcpy(state.encrypted_.data() + state.encrypted_size_, input, size);
                state.encrypted_size_ += size;
                return count;
            }) != 1 || BIO_meth_set_ctrl(method, [](BIO* bio, int command, long, void*) -> long {
                auto& state = *static_cast<implementation*>(BIO_get_data(bio));
                if (command == BIO_CTRL_FLUSH) return 1;
                if (command == BIO_CTRL_PENDING) return static_cast<long>(state.input_size_);
                if (command == BIO_CTRL_WPENDING) return static_cast<long>(state.encrypted_size_);
                return 0;
            }) != 1) { BIO_meth_free(method); throw std::bad_alloc(); }
            return method;
        }(), BIO_meth_free);
        return methods.get();
    }
    auto active() const noexcept -> bool { return SSL_is_init_finished(ssl_.get()) == 1; }
    auto error(int result) noexcept -> int
    {
        const int value = SSL_get_error(ssl_.get(), result);
#ifdef __linux__
        if (value == SSL_ERROR_SYSCALL && errno != 0)
            fatal_error_ = system_code(errno);
#endif
        return value;
    }
    auto failure() noexcept -> std::error_code
    {
        const auto code = ERR_peek_last_error();
        const bool exhausted = code && ERR_GET_REASON(code) == ERR_R_MALLOC_FAILURE;
        const bool truncated = code && ERR_GET_LIB(code) == ERR_LIB_SSL &&
            ERR_GET_REASON(code) == SSL_R_UNEXPECTED_EOF_WHILE_READING;
        ERR_clear_error();
        if (exhausted) return system_code(ENOMEM);
        if (truncated) return make_error_code(tls_errc::truncated);
        if (fatal_error_) return fatal_error_;
        return make_error_code(active() ? tls_errc::protocol_error : tls_errc::handshake_failed);
    }
    std::shared_ptr<tls_context> context_;
    ssl_ptr<SSL, SSL_free> ssl_;
    bool peer_closed_ {false};
    std::array<std::byte, encrypted_capacity> encrypted_ {};
    std::size_t encrypted_size_ {0};
    std::array<std::byte, input_capacity> input_ {};
    std::size_t input_offset_ {0};
    std::size_t input_size_ {0};
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
    if (!implementation_ || !implementation_->active()) return {};
    const unsigned char* protocol = nullptr;
    unsigned int size = 0;
    SSL_get0_alpn_selected(implementation_->ssl_.get(), &protocol, &size);
    if (size == 0) return {};
    return {reinterpret_cast<const char*>(protocol), size};
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

auto tls_stream::kernel_sendfile_available() const noexcept -> bool
{
#ifdef __linux__
    return async_tls_mode_ && implementation_->active() && !transport_closed() &&
        !(SSL_get_shutdown(implementation_->ssl_.get()) & SSL_SENT_SHUTDOWN) &&
        BIO_get_ktls_send(SSL_get_wbio(implementation_->ssl_.get())) != 0;
#else
    return false;
#endif
}

auto tls_stream::async_send_file(unique_fd file, std::uint64_t offset,
                                 std::size_t size)
    -> task<std::expected<void, std::error_code>>
{
    const auto descriptor = file.get();
    return send_file_task(owner_loop(), *this, std::move(file), descriptor, offset, size, {});
}

auto tls_stream::async_send_file(native_socket file, std::uint64_t offset,
                                 std::size_t size, std::span<const std::byte> prefix)
    -> task<std::expected<void, std::error_code>>
{
    return send_file_task(owner_loop(), *this, {}, file, offset, size, prefix);
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
#ifdef __linux__
    if (SSL_set_fd(implementation_->ssl_.get(), descriptor()) != 1) {
        ERR_clear_error();
        return std::unexpected(system_code(ENOMEM));
    }
#endif
    async_tls_mode_ = true;
    return {};
}

auto tls_stream::receive_encrypted(std::span<const std::byte> data) noexcept
    -> std::error_code
{
    auto& state = *implementation_;
    if (state.input_size_ != 0 || data.size() > state.input_.size()) return system_code(ENOBUFS);
    if (data.data() != state.input_.data()) std::memcpy(state.input_.data(), data.data(), data.size());
    state.input_offset_ = 0;
    state.input_size_ = data.size();
    return {};
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
#ifdef __linux__
    (void)self;
    co_return std::expected<void, std::error_code> {};
#else
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
#endif
}

auto tls_stream::handshake_task(event_loop& loop, tls_stream& self)
    -> task<std::expected<void, std::error_code>>
{
#ifdef __linux__
    (void)loop;
#endif
    if (self.exclusive_operation_active_ || self.read_operation_active_ || self.write_operation_active_)
        co_return std::unexpected(system_code(EBUSY));
    self.exclusive_operation_active_ = true;
    active_operation_guard guard {self.exclusive_operation_active_};
    if (co_await cancellation_requested()) co_return std::unexpected(system_code(ECANCELED));
    if (auto peer = detail::socket_operations::peer_endpoint(self.descriptor()); !peer)
        co_return std::unexpected(peer.error());
    if (auto activated = self.activate_async_tls(); !activated) co_return std::unexpected(activated.error());
    bool completed = false;
    struct failure_guard { tls_stream& stream; bool& completed; ~failure_guard() { if (!completed) stream.close(); } } failure {self, completed};
    auto& state = *self.implementation_;
    for (;;) {
        ERR_clear_error();
#ifdef __linux__
        errno = 0;
#endif
        const int result = SSL_do_handshake(state.ssl_.get());
        const int error = result == 1 ? SSL_ERROR_NONE : state.error(result);
        if (error != SSL_ERROR_NONE && error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
            co_return std::unexpected(state.failure());
#ifdef __linux__
        if (result == 1) { completed = true; co_return std::expected<void, std::error_code> {}; }
        auto ready = error == SSL_ERROR_WANT_READ
            ? co_await self.await_readable() : co_await self.await_writable();
        if (!ready) co_return std::unexpected(ready.error());
        if (self.transport_closed()) co_return std::unexpected(system_code(ECANCELED));
        if (co_await cancellation_requested()) co_return std::unexpected(system_code(ECANCELED));
#else
        auto flushed = co_await flush_task(loop, self);
        if (!flushed) co_return std::unexpected(task_code(flushed.error()));
        if (!*flushed) co_return std::unexpected(flushed->error());
        if (result == 1) { completed = true; co_return std::expected<void, std::error_code> {}; }
        if (error == SSL_ERROR_WANT_WRITE || state.input_size_ != 0) continue;
        auto received = co_await self.tcp_stream::async_read_some(state.input_);
        if (!received) co_return std::unexpected(received.error());
        if (*received == 0) co_return std::unexpected(make_error_code(tls_errc::truncated));
        if (auto input_error = self.receive_encrypted(std::span(state.input_).first(*received)); input_error)
            co_return std::unexpected(input_error);
#endif
    }
}

auto tls_stream::read_task(event_loop& loop, tls_stream& self, std::span<std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
#ifdef __linux__
    (void)loop;
#endif
    if (self.exclusive_operation_active_ || self.read_operation_active_)
        co_return std::unexpected(system_code(EBUSY));
    self.read_operation_active_ = true;
    active_operation_guard guard {self.read_operation_active_};
    if (co_await cancellation_requested()) co_return std::unexpected(system_code(ECANCELED));
    if (!self.async_tls_mode_) co_return std::unexpected(system_code(ENOTCONN));
    if (buffer.empty()) co_return std::size_t {0};
    auto& state = *self.implementation_;
    if (state.peer_closed_) co_return std::size_t {0};
    if (!state.active()) co_return std::unexpected(system_code(ENOTCONN));
    bool completed = false;
    struct failure_guard { tls_stream& stream; bool& completed; ~failure_guard() { if (!completed) stream.close(); } } failure {self, completed};
    for (;;) {
        std::size_t size = 0;
        clear_io_errors();
#ifdef __linux__
        errno = 0;
#endif
        const int result = SSL_read_ex(state.ssl_.get(), buffer.data(), buffer.size(), &size);
        const int error = result == 1 ? SSL_ERROR_NONE : state.error(result);
        if (error == SSL_ERROR_ZERO_RETURN) {
            state.peer_closed_ = true;
            completed = true;
            co_return std::size_t {0};
        }
        if (error != SSL_ERROR_NONE && error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
            co_return std::unexpected(state.failure());
#ifdef __linux__
        if (result == 1) { completed = true; co_return size; }
        auto ready = error == SSL_ERROR_WANT_READ
            ? co_await self.await_readable() : co_await self.await_writable();
        if (!ready) co_return std::unexpected(ready.error());
        if (self.transport_closed()) co_return std::unexpected(system_code(ECANCELED));
        if (co_await cancellation_requested()) co_return std::unexpected(system_code(ECANCELED));
#else
        auto flushed = co_await flush_task(loop, self);
        if (!flushed) co_return std::unexpected(task_code(flushed.error()));
        if (!*flushed) co_return std::unexpected(flushed->error());
        if (result == 1) { completed = true; co_return size; }
        if (error == SSL_ERROR_WANT_WRITE || state.input_size_ != 0) continue;
        auto received = co_await self.tcp_stream::async_read_some(state.input_);
        if (!received) co_return std::unexpected(received.error());
        if (*received == 0) co_return std::unexpected(make_error_code(tls_errc::truncated));
        if (auto input_error = self.receive_encrypted(std::span(state.input_).first(*received)); input_error)
            co_return std::unexpected(input_error);
#endif
    }
}

auto tls_stream::write_task(event_loop& loop, tls_stream& self, std::span<const std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
#ifdef __linux__
    (void)loop;
#endif
    if (self.exclusive_operation_active_ || self.write_operation_active_)
        co_return std::unexpected(system_code(EBUSY));
    self.write_operation_active_ = true;
    active_operation_guard guard {self.write_operation_active_};
    if (co_await cancellation_requested()) co_return std::unexpected(system_code(ECANCELED));
    auto& state = *self.implementation_;
    if (!self.async_tls_mode_ || !state.active() || self.transport_closed() ||
        (SSL_get_shutdown(state.ssl_.get()) & SSL_SENT_SHUTDOWN))
        co_return std::unexpected(system_code(ENOTCONN));
    if (buffer.empty()) co_return std::size_t {0};
    bool completed = false;
    struct failure_guard { tls_stream& stream; bool& completed; ~failure_guard() { if (!completed) stream.close(); } } failure {self, completed};
    const auto size = std::min<std::size_t>(buffer.size(), 4096);
#ifndef __linux__
    // Flush before writing, so this record always has bounded output space.
    auto flushed = co_await flush_task(loop, self);
    if (!flushed) co_return std::unexpected(task_code(flushed.error()));
    if (!*flushed) co_return std::unexpected(flushed->error());
#endif
    for (;;) {
        std::size_t written = 0;
        clear_io_errors();
#ifdef __linux__
        errno = 0;
#endif
        const int result = SSL_write_ex(state.ssl_.get(), buffer.data(), size, &written);
        const int error = result == 1 ? SSL_ERROR_NONE : state.error(result);
        // Renegotiation is disabled; established writes do not need a second
        // transport reader. Preserve the caller's buffer across output retries.
        if (error != SSL_ERROR_NONE && error != SSL_ERROR_WANT_WRITE
#ifdef __linux__
            && error != SSL_ERROR_WANT_READ
#endif
            )
            co_return std::unexpected(state.failure());
#ifdef __linux__
        if (result == 1) { completed = true; co_return written; }
        auto ready = error == SSL_ERROR_WANT_READ
            ? co_await self.await_readable() : co_await self.await_writable();
        if (!ready) co_return std::unexpected(ready.error());
        if (self.transport_closed()) co_return std::unexpected(system_code(ECANCELED));
        if (co_await cancellation_requested()) co_return std::unexpected(system_code(ECANCELED));
#else
        auto sent = co_await flush_task(loop, self);
        if (!sent) co_return std::unexpected(task_code(sent.error()));
        if (!*sent) co_return std::unexpected(sent->error());
        if (result == 1) { completed = true; co_return written; }
#endif
    }
}

auto tls_stream::close_task(event_loop& loop, tls_stream& self)
    -> task<std::expected<void, std::error_code>>
{
#ifdef __linux__
    (void)loop;
#endif
    if (self.exclusive_operation_active_ || self.read_operation_active_ || self.write_operation_active_)
        co_return std::unexpected(system_code(EBUSY));
    self.exclusive_operation_active_ = true;
    active_operation_guard guard {self.exclusive_operation_active_};
    if (co_await cancellation_requested()) co_return std::unexpected(system_code(ECANCELED));
    if (!self.async_tls_mode_) co_return std::unexpected(system_code(ENOTCONN));
    bool completed = false;
    struct failure_guard { tls_stream& stream; bool& completed; ~failure_guard() { if (!completed) stream.close(); } } failure {self, completed};
    auto& state = *self.implementation_;
    for (;;) {
        ERR_clear_error();
#ifdef __linux__
        errno = 0;
#endif
        const int result = SSL_shutdown(state.ssl_.get());
        const int error = result < 0 ? state.error(result) : SSL_ERROR_NONE;
        if (error != SSL_ERROR_NONE && error != SSL_ERROR_WANT_WRITE && error != SSL_ERROR_WANT_READ)
            co_return std::unexpected(state.failure());
#ifdef __linux__
        if (SSL_get_shutdown(state.ssl_.get()) & SSL_SENT_SHUTDOWN) {
            completed = true;
            co_return std::expected<void, std::error_code> {};
        }
        if (error != SSL_ERROR_WANT_WRITE && error != SSL_ERROR_WANT_READ)
            co_return std::unexpected(state.failure());
        auto ready = error == SSL_ERROR_WANT_READ
            ? co_await self.await_readable() : co_await self.await_writable();
        if (!ready) co_return std::unexpected(ready.error());
        if (self.transport_closed()) co_return std::unexpected(system_code(ECANCELED));
        if (co_await cancellation_requested()) co_return std::unexpected(system_code(ECANCELED));
#else
        auto flushed = co_await flush_task(loop, self);
        if (!flushed) co_return std::unexpected(task_code(flushed.error()));
        if (!*flushed) co_return std::unexpected(flushed->error());
        // API sends close_notify without waiting for the peer's reply.
        if (SSL_get_shutdown(state.ssl_.get()) & SSL_SENT_SHUTDOWN) {
            completed = true;
            co_return std::expected<void, std::error_code> {};
        }
        if (error != SSL_ERROR_WANT_WRITE) co_return std::unexpected(state.failure());
#endif
    }
}

auto tls_stream::send_file_task(event_loop& loop, tls_stream& self,
    unique_fd owned_file, native_socket file, std::uint64_t offset, std::size_t size,
    std::span<const std::byte> prefix)
    -> task<std::expected<void, std::error_code>>
{
    (void)loop;
    (void)owned_file; // Retained in this frame for the owning overload.
#ifdef __linux__
    if (self.exclusive_operation_active_ || self.write_operation_active_)
        co_return std::unexpected(system_code(EBUSY));
    self.write_operation_active_ = true;
    active_operation_guard guard {self.write_operation_active_};
    if (co_await cancellation_requested())
        co_return std::unexpected(system_code(ECANCELED));
    if (file == static_cast<native_socket>(-1)) co_return std::unexpected(system_code(EBADF));
    if (!self.kernel_sendfile_available())
        co_return std::unexpected(system_code(EOPNOTSUPP));
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) ||
        size > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) - offset)
        co_return std::unexpected(system_code(EOVERFLOW));
    bool completed = false;
    struct failure_guard {
        tls_stream& stream;
        bool& completed;
        ~failure_guard() { if (!completed) stream.close(); }
    } failure {self, completed};
    auto& state = *self.implementation_;
    // Keep the H2 DATA header and file payload under one write guard and task.
    // The prefix is borrowed from the caller's bounded queue; it is never copied
    // into frame storage, and SSL retries keep the same pointer and length.
    while (!prefix.empty()) {
        const auto amount = std::min<std::size_t>(prefix.size(), 16 * 1024);
        std::size_t written = 0;
        clear_io_errors();
        errno = 0;
        const int result = SSL_write_ex(state.ssl_.get(), prefix.data(), amount, &written);
        if (result == 1) {
            if (written == 0) co_return std::unexpected(system_code(EIO));
            prefix = prefix.subspan(written);
            continue;
        }
        const int error = state.error(result);
        if (error != SSL_ERROR_WANT_WRITE && error != SSL_ERROR_WANT_READ)
            co_return std::unexpected(state.failure());
        auto ready = error == SSL_ERROR_WANT_READ
            ? co_await self.await_readable() : co_await self.await_writable();
        if (!ready) co_return std::unexpected(ready.error());
        if (self.transport_closed()) co_return std::unexpected(system_code(ECANCELED));
        if (co_await cancellation_requested()) co_return std::unexpected(system_code(ECANCELED));
    }
    while (size != 0) {
        const auto amount = std::min(size,
            static_cast<std::size_t>(std::numeric_limits<ossl_ssize_t>::max()));
        clear_io_errors();
        errno = 0;
        const auto result = SSL_sendfile(state.ssl_.get(), file,
            static_cast<off_t>(offset), amount, 0);
        if (result > 0) {
            offset += static_cast<std::uint64_t>(result);
            size -= static_cast<std::size_t>(result);
            continue;
        }
        const auto error = state.error(static_cast<int>(result));
        if (error != SSL_ERROR_WANT_WRITE && error != SSL_ERROR_WANT_READ) {
            if (error == SSL_ERROR_SYSCALL && errno != 0)
                co_return std::unexpected(system_code(errno));
            co_return std::unexpected(state.failure());
        }
        auto ready = error == SSL_ERROR_WANT_READ
            ? co_await self.await_readable() : co_await self.await_writable();
        if (!ready) co_return std::unexpected(ready.error());
        if (self.transport_closed()) co_return std::unexpected(system_code(ECANCELED));
        if (co_await cancellation_requested()) co_return std::unexpected(system_code(ECANCELED));
    }
    completed = true;
    co_return std::expected<void, std::error_code> {};
#else
    (void)self; (void)file; (void)offset; (void)size; (void)prefix;
    co_return std::unexpected(system_code(EOPNOTSUPP));
#endif
}
} // namespace eventloop
