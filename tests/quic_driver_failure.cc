// Driver failure must wake a pending public accept operation and preserve
// its error. Mismatched ALPN deterministically fails the server TLS driver.
#include "eventloop/quic.h"
#include "eventloop/event_loop.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace {

using namespace eventloop;
using namespace std::chrono_literals;

struct file_closer {
    auto operator()(FILE* file) const noexcept -> void
    { if (file != nullptr) (void)std::fclose(file); }
};

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::fprintf(stderr, "QUIC driver failure: %.*s\n",
                 static_cast<int>(message.size()), message.data());
    std::abort();
}

auto write_pem(const std::filesystem::path& path, X509* certificate,
               EVP_PKEY* key) -> bool
{
    // Use a memory BIO so the test does not pass a C-runtime FILE* across the
    // OpenSSL DLL boundary (which needs OPENSSL_Applink on Windows).
    std::unique_ptr<BIO, decltype(&BIO_free)> bio {BIO_new(BIO_s_mem()), BIO_free};
    if (!bio) return false;
    const int written = certificate != nullptr
        ? PEM_write_bio_X509(bio.get(), certificate)
        : PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr);
    if (written != 1) return false;
    char* data = nullptr;
    const auto size = BIO_get_mem_data(bio.get(), &data);
    if (size <= 0) return false;
    std::unique_ptr<FILE, file_closer> file {std::fopen(path.string().c_str(), "wb")};
    if (!file) return false;
    return std::fwrite(data, 1, static_cast<std::size_t>(size), file.get()) ==
        static_cast<std::size_t>(size);
}

auto make_certificate(const std::filesystem::path& directory) -> bool
{
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key {
        EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1"), EVP_PKEY_free};
    std::unique_ptr<X509, decltype(&X509_free)> certificate {X509_new(), X509_free};
    if (!key || !certificate) return false;
    if (X509_set_version(certificate.get(), 2) != 1) return false;
    if (ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) != 1) return false;
    if (X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) == nullptr) return false;
    if (X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600) == nullptr) return false;
    if (X509_set_pubkey(certificate.get(), key.get()) != 1) return false;
    auto* name = X509_get_subject_name(certificate.get());
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) != 1)
        return false;
    if (X509_set_issuer_name(certificate.get(), name) != 1) return false;
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> san {
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                            const_cast<char*>("DNS:localhost")), X509_EXTENSION_free};
    if (!san || X509_add_ext(certificate.get(), san.get(), -1) != 1) return false;
    if (X509_sign(certificate.get(), key.get(), EVP_sha256()) <= 0) return false;
    return write_pem(directory / "cert.pem", certificate.get(), nullptr) &&
        write_pem(directory / "key.pem", nullptr, key.get());
}

constexpr std::array<std::uint8_t, 4> server_protocol {'t', 'e', 's', 't'};
constexpr std::array<std::uint8_t, 4> client_protocol {'n', 'o', 'p', 'e'};

struct outcome {
    bool accepted_finished {false};
    bool connected_finished {false};
    bool timed_out {false};
    std::error_code error {};
};

auto accept_failure(event_loop&, quic_endpoint& server, outcome& result) -> task<void>
{
    auto accepted = flatten_result(co_await server.async_accept());
    if (!accepted) result.error = accepted.error();
    result.accepted_finished = true;
}

auto connect_peer(event_loop&, quic_endpoint& client, ip_endpoint address,
                  outcome& result) -> task<void>
{
    (void)flatten_result(co_await client.async_connect(address, "localhost"));
    result.connected_finished = true;
}

auto watch(event_loop& loop, quic_endpoint& server, quic_endpoint& client,
           outcome& result) -> task<void>
{
    for (int i = 0; i < 400 && !result.accepted_finished; ++i)
        (void)co_await sleep_for(loop, 5ms);
    result.timed_out = !result.accepted_finished;
    co_await server.async_close();
    co_await client.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

auto scenario(quic_version version, const std::filesystem::path& certificate) -> void
{
    event_loop loop;
    quic_server_options server_options;
    server_options.certificate_chain = certificate / "cert.pem";
    server_options.private_key = certificate / "key.pem";
    server_options.alpn = server_protocol;
    quic_client_options client_options;
    client_options.alpn = client_protocol;
    client_options.trusted_ca = certificate / "cert.pem";
    client_options.version = version;
    quic_endpoint server(loop, ip_endpoint::loopback_v4(0), std::move(server_options));
    quic_endpoint client(loop, ip_endpoint::loopback_v4(0), std::move(client_options));
    outcome result;
    check(loop.spawn(accept_failure(loop, server, result)) == task_spawn_result::accepted,
          "spawn pending accept");
    check(loop.spawn(connect_peer(loop, client, server.local_endpoint(), result)) ==
          task_spawn_result::accepted, "spawn mismatched peer");
    check(loop.spawn(watch(loop, server, client, result)) == task_spawn_result::accepted,
          "spawn watchdog");
    (void)loop.run();
    check(!result.timed_out, "driver failure wakes pending accept before watchdog");
    check(result.accepted_finished, "accept completed");
    check(result.connected_finished, "endpoint shutdown wakes pending connect");
    check(std::string_view(result.error.category().name()) == "eventloop.quic.driver",
          "accept reports the driver error category");
    check(result.error.message() == "TLS failure", "accept preserves TLS failure");
}

} // namespace

auto main() -> int
{
#ifdef _WIN32
    WSADATA data {};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
#endif
    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-quic-driver-failure-" + std::to_string(
            static_cast<unsigned long long>(std::rand())));
    std::filesystem::create_directories(directory);
    check(make_certificate(directory), "generate certificate");
    scenario(quic_version::v1, directory);
    scenario(quic_version::v2, directory);
    std::filesystem::remove_all(directory);
#ifdef _WIN32
    (void)WSACleanup();
#endif
    std::puts("QUIC driver failure tests passed (v1 and v2)");
}
