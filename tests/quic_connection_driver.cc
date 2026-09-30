#include "quic/connection_driver.h"
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <cstdio>
#include <cstdlib>
#include <memory>
using namespace eventloop::quic::detail;
static auto checked(bool value, int line) -> void
{ if (!value) { std::fprintf(stderr, "connection core check failed at line %d\n", line); std::abort(); } }
#define check(value) checked((value), __LINE__)
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


static constexpr std::array<std::uint8_t, 4> protocol {'t','e','s','t'};
static constexpr std::array<std::uint8_t, 29> parameters {15,1,42,4,2,0x60,0,5,2,0x50,0,6,2,0x50,0,7,2,0x50,0,8,1,32,9,1,32,0x20,2,0x44,0xb0};
static constexpr std::array<std::uint8_t, 8> dcid {1,2,3,4,5,6,7,8};
static bool valid_parameters(void*, std::span<const std::uint8_t> value) noexcept
{
    // The TLS adapter appends the empty RFC 9287 grease_quic_bit parameter
    // (0x2ab2) to the configured transport parameters.
    constexpr std::array<std::uint8_t, 3> grease {0x6a, 0xb2, 0};
    return value.size() == parameters.size() + grease.size() &&
        std::ranges::equal(value.first(parameters.size()), parameters) &&
        std::ranges::equal(value.subspan(parameters.size()), grease);
}
static bool on_frame(void* argument, tls_level, const decoded_frame&) noexcept
{ ++*static_cast<int*>(argument); return true; }
struct buffers {
    std::array<std::uint8_t, 2048> encoded {}, frame {}, build_scratch {},
        packet_scratch {}, plaintext {}, auth_scratch {};
};

using namespace eventloop;
using namespace std::chrono_literals;
static auto receiver(event_loop&,udp_endpoint& endpoint) -> task<void>
{ (void)co_await endpoint.run(); }
static auto drive(event_loop&,connection_driver& driver,bool& clean) -> task<void>
{ const auto result=co_await driver.run(); clean=result && result->has_value(); if (!clean) std::fprintf(stderr,"driver failure %d\n", result ? static_cast<int>(result->error()) : -1); }
static auto observe(event_loop& loop,bounded_connection& client,bounded_connection& server,
    connection_driver& client_driver,connection_driver& server_driver,bool& delivered) -> task<void>
{
    std::optional<std::uint64_t> id;
    constexpr std::array<std::byte,3> data{std::byte{1},std::byte{2},std::byte{3}};
    for (int i=0;i<4000;++i) {
        if (!id && client.core().state()==connection_state::active && server.core().state()==connection_state::active) {
            id=client.open_stream(stream_direction::bidirectional).value();
            check(client.stream(*id)->send.append(data).has_value());
            check(client.stream(*id)->send.close().has_value());
        }
        if (id && client.stream(*id)->send.complete()) {
            const auto* stream=server.stream(*id);
            delivered=stream && stream->receive && std::ranges::equal(stream->receive->readable(),data);
            break;
        }
        if (co_await sleep_for(loop,1ms)!=timer_wait_result::expired) co_return;
    }
    client_driver.stop(); server_driver.stop();
    // Drivers must retire their pending sends before endpoint shutdown.
    (void)co_await sleep_for(loop,10ms);
    loop.shutdown(event_loop::clock::duration::zero());
}
int main()
{
#ifdef _WIN32
    WSADATA data{}; check(WSAStartup(MAKEWORD(2,2),&data)==0);
#endif
    contexts context;
    for (auto version : {version_1,version_2}) {
        event_loop loop;
        udp_endpoint client_endpoint(loop,ip_endpoint::loopback_v4(),path_endpoint_role::client);
        udp_endpoint server_endpoint(loop,ip_endpoint::loopback_v4(),path_endpoint_role::server);
        connection_callbacks callbacks{nullptr,valid_parameters,nullptr};
        const auto now=lifecycle_time_point::clock::now();
        auto client=std::make_unique<bounded_connection>(endpoint_role::client,callbacks,now);
        auto server=std::make_unique<bounded_connection>(endpoint_role::server,callbacks,now);
        check(client->initialize(context.client.get(),{false,"localhost",protocol,parameters},version,dcid).has_value());
        check(server->initialize(context.server.get(),{true,{},protocol,parameters},version,dcid).has_value());
        auto client_driver=std::make_unique<connection_driver>(loop,client_endpoint,*client,dcid,dcid,server_endpoint.local_endpoint(),true);
        auto server_driver=std::make_unique<connection_driver>(loop,server_endpoint,*server,dcid,dcid,client_endpoint.local_endpoint());
        bool delivered=false,client_clean=false,server_clean=false;
        check(loop.spawn(receiver(loop,client_endpoint))==task_spawn_result::accepted);
        check(loop.spawn(receiver(loop,server_endpoint))==task_spawn_result::accepted);
        check(loop.spawn(drive(loop,*client_driver,client_clean))==task_spawn_result::accepted);
        check(loop.spawn(drive(loop,*server_driver,server_clean))==task_spawn_result::accepted);
        check(loop.spawn(observe(loop,*client,*server,*client_driver,*server_driver,delivered))==task_spawn_result::accepted);
        (void)loop.run();
        if (!delivered) std::fprintf(stderr,"delivery failure state %d/%d dropped %zu/%zu\n",static_cast<int>(client->core().state()),static_cast<int>(server->core().state()),client_driver->dropped_packets(),server_driver->dropped_packets()); check(delivered && client_clean && server_clean);
        check(loop.coroutine_statistics().live==0);
    }
#ifdef _WIN32
    (void)WSACleanup();
#endif
    std::puts("QUIC UDP TLS driver passed");
}
