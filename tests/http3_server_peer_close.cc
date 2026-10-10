// A client that closes its connection before http3_server accepts it fails
// only that connection: the server keeps accepting. Browsers do this when a
// viewer seeks away from a video while the handshake is finishing.
#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/quic.h"
#include "eventloop/task.h"
#include "eventloop/task_composition.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>

namespace {

using namespace eventloop;
using namespace std::chrono_literals;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::fprintf(stderr, "HTTP/3 server peer close: %.*s\n",
                 static_cast<int>(message.size()), message.data());
    std::abort();
}

auto make_certificate(const std::filesystem::path& directory) -> bool
{
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key {
        EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1"), EVP_PKEY_free};
    std::unique_ptr<X509, decltype(&X509_free)> certificate {X509_new(), X509_free};
    if (!key || !certificate) return false;
    X509_set_version(certificate.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60);
    X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600);
    X509_set_pubkey(certificate.get(), key.get());
    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name {
        X509_NAME_new(), X509_NAME_free};
    if (!name) return false;
    if (X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) != 1)
        return false;
    if (X509_set_subject_name(certificate.get(), name.get()) != 1) return false;
    if (X509_set_issuer_name(certificate.get(), name.get()) != 1) return false;
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> san {
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                            const_cast<char*>("DNS:localhost")), X509_EXTENSION_free};
    if (!san || X509_add_ext(certificate.get(), san.get(), -1) != 1) return false;
    if (X509_sign(certificate.get(), key.get(), EVP_sha256()) <= 0) return false;
    // OpenSSL file BIOs, not FILE*: a FILE* crossing into OpenSSL needs applink on Windows.
    std::unique_ptr<BIO, decltype(&BIO_free)> cert {
        BIO_new_file((directory / "cert.pem").string().c_str(), "wb"), BIO_free};
    std::unique_ptr<BIO, decltype(&BIO_free)> pkey {
        BIO_new_file((directory / "key.pem").string().c_str(), "wb"), BIO_free};
    return cert && pkey && PEM_write_bio_X509(cert.get(), certificate.get()) == 1 &&
        PEM_write_bio_PrivateKey(pkey.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1;
}

constexpr std::array<std::uint8_t, 2> alpn {'h', '3'};

struct outcome {
    bool first_connected {false};
    bool second_connected {false};
    bool serving_after_second {false};
};

// A refused handshake would otherwise wait out the client's idle timeout.
auto connect(event_loop& loop, quic_endpoint& client, ip_endpoint address)
    -> task<std::expected<quic_connection, std::error_code>>
{
    auto attempt = co_await with_timeout(loop, client.async_connect(address, "localhost"), 3s);
    if (attempt && attempt->result) co_return flatten_result(std::move(*attempt->result));
    co_return std::unexpected(std::make_error_code(std::errc::timed_out));
}

auto scenario(event_loop& loop, http::http3_server& server, quic_endpoint& client,
              task_handle<void>& serving, outcome& result) -> task<void>
{
    const auto address = server.local_endpoint();
    // The endpoint completes this handshake before run() accepts anything.
    auto first = flatten_result(co_await connect(loop, client, address));
    result.first_connected = first.has_value();
    if (first) first->close();
    (void)co_await sleep_for(loop, 50ms);

    if (loop.spawn(server.run(), serving) == task_spawn_result::accepted) {
        (void)co_await sleep_for(loop, 50ms);
        auto second = flatten_result(co_await connect(loop, client, address));
        result.second_connected = second.has_value();
        (void)co_await sleep_for(loop, 50ms);
        result.serving_after_second = !serving.done();
        if (second) second->close();
    }
    co_await server.async_close();
    co_await client.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

} // namespace

auto main() -> int
{
    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-http3-peer-close-" + std::to_string(
            static_cast<unsigned long long>(std::rand())));
    std::filesystem::create_directories(directory / "www");
    check(make_certificate(directory), "certificate generation");
    std::ofstream(directory / "www" / "index.html") << "hello";

    outcome result;
    {
        event_loop loop;
        http::http3_server server(loop, ip_endpoint::loopback_v4(0),
            directory / "cert.pem", directory / "key.pem",
            http::server_options {.document_root = directory / "www"});
        quic_client_options options;
        options.alpn = alpn;
        options.trusted_ca = directory / "cert.pem";
        quic_endpoint client(loop, ip_endpoint::loopback_v4(0), std::move(options));
        task_handle<void> serving;
        check(loop.spawn(scenario(loop, server, client, serving, result)) ==
                  task_spawn_result::accepted, "spawn scenario");
        (void)loop.run();
    }
    std::filesystem::remove_all(directory);
    check(result.first_connected, "handshake completes before run()");
    check(result.second_connected, "a later client still connects");
    check(result.serving_after_second, "run() keeps accepting after a peer close");
    std::puts("HTTP/3 server peer close tests passed");
}
