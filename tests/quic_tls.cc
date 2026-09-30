#include "quic/tls_provider.h"

#include <openssl/evp.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <memory>

using namespace eventloop::quic::detail;

static auto check(bool value) -> void
{
    if (!value) { std::fputs("QUIC TLS check failed\n", stderr); std::abort(); }
}

struct endpoint {
    static constexpr std::size_t capacity = 16384;
    std::array<std::array<std::byte, capacity>, 3> storage {};
    std::array<std::array<std::byte, capacity / 8>, 3> coverage {};
    crypto_receive_buffer initial {storage[0], coverage[0]};
    crypto_receive_buffer handshake {storage[1], coverage[1]};
    crypto_receive_buffer application {storage[2], coverage[2]};
    std::array<std::uint64_t, 3> offsets {};
    std::array<std::array<std::array<std::uint8_t, 32>, 2>, 2> secrets {};
    std::size_t secret_count {0};
    endpoint* peer {};
    bool reject_output {false};
    tls_provider tls {{&initial, &handshake, &application}, {this, send, secret}};

    static auto send(void* arg, tls_level level, std::span<const std::byte> data)
        noexcept -> bool
    {
        auto& self = *static_cast<endpoint*>(arg);
        if (self.reject_output) return false;
        auto& offset = self.offsets[static_cast<std::size_t>(level)];
        // Deliver each TLS message in reverse fragment order to exercise the
        // bounded CRYPTO reassembler without exposing records to the adapter.
        auto remaining = data.size();
        while (remaining) {
            const auto start = remaining > 7 ? remaining - 7 : 0;
            if (!self.peer->tls.provide_crypto(level, offset + start,
                                               data.subspan(start, remaining - start)))
                return false;
            remaining = start;
        }
        offset += data.size();
        return true;
    }

    static auto secret(void* arg, tls_level level, tls_direction direction,
                        std::uint16_t cipher, std::span<const std::uint8_t> data)
        noexcept -> bool
    {
        auto& self = *static_cast<endpoint*>(arg);
        if (cipher != 0x1301 || data.size() != 32 || level == tls_level::initial)
            return false;
        std::copy(data.begin(), data.end(),
                  self.secrets[static_cast<std::size_t>(level) - 1]
                              [static_cast<std::size_t>(direction)].begin());
        ++self.secret_count;
        return true;
    }
};

struct contexts {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client {SSL_CTX_new(TLS_method()), SSL_CTX_free};
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> server {SSL_CTX_new(TLS_method()), SSL_CTX_free};

    contexts()
    {
        check(client && server);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key {
            EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1"), EVP_PKEY_free};
        std::unique_ptr<X509, decltype(&X509_free)> certificate {X509_new(), X509_free};
        check(key && certificate);
        check(X509_set_version(certificate.get(), 2) == 1);
        check(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) == 1);
        check(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) != nullptr);
        check(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600) != nullptr);
        check(X509_set_pubkey(certificate.get(), key.get()) == 1);
        auto* name = X509_get_subject_name(certificate.get());
        check(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
              reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) == 1);
        check(X509_set_issuer_name(certificate.get(), name) == 1);
        std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> san {
            X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                               const_cast<char*>("DNS:localhost")), X509_EXTENSION_free};
        check(san && X509_add_ext(certificate.get(), san.get(), -1) == 1);
        check(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0);
        check(SSL_CTX_use_certificate(server.get(), certificate.get()) == 1);
        check(SSL_CTX_use_PrivateKey(server.get(), key.get()) == 1);
        check(X509_STORE_add_cert(SSL_CTX_get_cert_store(client.get()), certificate.get()) == 1);
        tls_provider::configure_server_context(server.get());
    }
};

static constexpr std::array<std::uint8_t, 4> protocol {'t', 'e', 's', 't'};
static constexpr std::array<std::uint8_t, 4> other_protocol {'f', 'a', 'i', 'l'};
static constexpr std::array<std::uint8_t, 3> client_parameters {1, 1, 0};
static constexpr std::array<std::uint8_t, 3> server_parameters {3, 1, 0};
static constexpr std::array<std::uint8_t, 6> advertised_client_parameters {1,1,0,0x6a,0xb2,0};
static constexpr std::array<std::uint8_t, 6> advertised_server_parameters {3,1,0,0x6a,0xb2,0};

static auto initialize(endpoint& client, endpoint& server, contexts& context,
                        std::string_view hostname = "localhost",
                        std::span<const std::uint8_t> server_alpn = protocol) -> void
{
    client.peer = &server;
    server.peer = &client;
    check(client.tls.initialize(context.client.get(),
          {false, hostname, protocol, client_parameters}).has_value());
    check(server.tls.initialize(context.server.get(),
          {true, {}, server_alpn, server_parameters}).has_value());
}

int main()
{
    contexts context;
    {
        endpoint client, server;
        initialize(client, server, context);
        bool client_complete = false, server_complete = false;
        for (int step = 0; step < 20 && (!client_complete || !server_complete); ++step) {
            const auto c = client.tls.advance();
            const auto s = server.tls.advance();
            check(c.has_value() && s.has_value());
            client_complete = *c == tls_progress::complete;
            server_complete = *s == tls_progress::complete;
        }
        check(client_complete && server_complete);
        check(client.secret_count == 4 && server.secret_count == 4);
        for (std::size_t level = 0; level < 2; ++level) {
            check(client.secrets[level][0] == server.secrets[level][1]);
            check(client.secrets[level][1] == server.secrets[level][0]);
        }
        check(std::ranges::equal(client.tls.negotiated_alpn(), protocol));
        check(std::ranges::equal(server.tls.negotiated_alpn(), protocol));
        check(std::ranges::equal(client.tls.peer_transport_parameters(), advertised_server_parameters));
        check(std::ranges::equal(server.tls.peer_transport_parameters(), advertised_client_parameters));
        check(client.tls.advance().has_value() && server.tls.advance().has_value());
    }
    {
        auto client_storage=std::make_unique<endpoint>(), server_storage=std::make_unique<endpoint>();
        auto& client=*client_storage;
        auto& server=*server_storage;
        client.peer=&server; server.peer=&client;
        const std::array<std::uint8_t,4> invalid{0x6a,0xb2,1,0};
        const auto rejected=client.tls.initialize(context.client.get(),{false,"localhost",protocol,invalid});
        check(!rejected && rejected.error()==tls_error::invalid_configuration);
        const std::array<std::uint8_t,6> duplicate{0x6a,0xb2,0,0x6a,0xb2,0};
        const auto duplicated=client.tls.initialize(context.client.get(),{false,"localhost",protocol,duplicate});
        check(!duplicated && duplicated.error()==tls_error::invalid_configuration);
        check(client.tls.initialize(context.client.get(),{false,"localhost",protocol,advertised_client_parameters}).has_value());
        check(server.tls.initialize(context.server.get(),{true,{},protocol,advertised_server_parameters}).has_value());
        bool complete=false;
        for(int step=0;step<20 && !complete;++step) {
            const auto c=client.tls.advance(), s=server.tls.advance();
            check(c.has_value() && s.has_value());
            complete=*c==tls_progress::complete && *s==tls_progress::complete;
        }
        check(complete);
        // Caller advertisements are preserved exactly, without duplication.
        check(std::ranges::equal(client.tls.peer_transport_parameters(),advertised_server_parameters));
        check(std::ranges::equal(server.tls.peer_transport_parameters(),advertised_client_parameters));
    }
    {
        auto client_storage=std::make_unique<endpoint>();
        auto& client=*client_storage;
        std::array<std::uint8_t,4094> too_large{};
        too_large[0]=0x21; too_large[1]=0x4f; too_large[2]=0xfb; // unknown parameter, 4091 bytes
        const auto rejected=client.tls.initialize(context.client.get(),{false,"localhost",protocol,too_large});
        check(!rejected && rejected.error()==tls_error::capacity_exceeded);
        std::array<std::uint8_t,4093> boundary{};
        boundary[0]=0x21; boundary[1]=0x4f; boundary[2]=0xfa; // 4090 + header + grease = 4096
        check(client.tls.initialize(context.client.get(),{false,"localhost",protocol,boundary}).has_value());
        auto full_storage=std::make_unique<endpoint>();
        std::array<std::uint8_t,4096> already_advertised{};
        std::copy(boundary.begin(),boundary.end(),already_advertised.begin());
        already_advertised[4093]=0x6a; already_advertised[4094]=0xb2;
        check(full_storage->tls.initialize(context.client.get(),{false,"localhost",protocol,already_advertised}).has_value());
    }
    {
        endpoint client, server;
        initialize(client, server, context, "wrong.example");
        check(client.tls.advance().has_value());
        check(server.tls.advance().has_value());
        check(!client.tls.advance());
        check(client.tls.alert().has_value());
    }
    {
        contexts untrusted;
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> empty_trust {
            SSL_CTX_new(TLS_method()), SSL_CTX_free};
        check(empty_trust != nullptr);
        untrusted.client = std::move(empty_trust);
        endpoint client, server;
        initialize(client, server, untrusted);
        check(client.tls.advance().has_value());
        check(server.tls.advance().has_value());
        check(!client.tls.advance());
        check(client.tls.alert().has_value());
    }
    {
        endpoint client, server;
        initialize(client, server, context, "localhost", other_protocol);
        check(client.tls.advance().has_value());
        check(!server.tls.advance());
        check(server.tls.alert() == SSL_AD_NO_APPLICATION_PROTOCOL);
    }
    {
        endpoint client, server;
        initialize(client, server, context);
        client.reject_output = true;
        const auto result = client.tls.advance();
        check(!result && result.error() == tls_error::capacity_exceeded);
        check(!client.tls.advance());
    }
    {
        endpoint client, server;
        initialize(client, server, context);
        const std::array<std::byte, 1> data {};
        const auto result = client.tls.provide_crypto(tls_level::initial, endpoint::capacity, data);
        check(!result && result.error() == tls_error::capacity_exceeded);
    }
    {
        endpoint client, server;
        initialize(client, server, context);
        const std::array<std::byte, 1> first {std::byte {1}};
        const std::array<std::byte, 1> conflicting {std::byte {2}};
        check(client.tls.provide_crypto(tls_level::initial, 1, first).has_value());
        const auto result = client.tls.provide_crypto(tls_level::initial, 1, conflicting);
        check(!result && result.error() == tls_error::invalid_crypto_data);
        check(!client.tls.advance());
    }
    std::puts("QUIC TLS tests passed");
}
