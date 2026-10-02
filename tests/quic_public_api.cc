// Public QUIC API end-to-end test: in-house client and server over loopback
// for QUIC v1 and v2, exercising the handshake, bidirectional stream I/O, and
// the RFC 9221 DATAGRAM extension. The certificate is generated in-process.
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

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::fprintf(stderr, "QUIC public API: %.*s\n",
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
    std::unique_ptr<FILE, decltype(&std::fclose)> file {
        std::fopen(path.string().c_str(), "wb"), std::fclose};
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

constexpr std::array<std::uint8_t, 4> protocol {'t', 'e', 's', 't'};
// Larger than reserved receive storage. Delay the reader so ACKs alone cannot
// let the sender overrun it; subsequent reads must replenish stream credit.
const auto bulk_request = [] {
    std::array<std::byte, 12 * 1024> bytes {};
    for (std::size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<std::byte>(i % 251);
    return bytes;
}();
const std::array<std::byte, 4> reply {std::byte {'p'}, std::byte {'o'},
                                      std::byte {'n'}, std::byte {'g'}};
const std::array<std::byte, 5> datagram_in {std::byte {'d'}, std::byte {'g'},
                                            std::byte {'1'}, std::byte {'2'},
                                            std::byte {'3'}};
const std::array<std::byte, 4> datagram_out {std::byte {'d'}, std::byte {'g'},
                                             std::byte {'o'}, std::byte {'k'}};
const std::array<std::byte, 4> server_uni_data {std::byte {'u'}, std::byte {'n'},
                                                std::byte {'i'}, std::byte {'!'}};

struct outcome {
    bool server_ok {false};
    bool client_ok {false};
};

auto accept_sparse_streams(event_loop&, quic_connection& connection) -> task<bool>
{
    std::array<std::byte, 8> buffer {};
    // Higher IDs implicitly open the lower IDs. Accept the higher ID first,
    // then wait for the missing lower streams, across two rounds of slot reuse.
    for (std::uint64_t round = 0; round < 2; ++round) {
        for (const std::uint64_t ordinal : {3u, 1u, 2u}) {
            const auto id = flatten_result(co_await connection.async_accept_stream());
            if (!id || *id != (round * 3 + ordinal) * 4) co_return false;
            const auto count = flatten_result(co_await connection.async_read(*id, buffer));
            if (!count || *count != reply.size() ||
                !std::equal(reply.begin(), reply.end(), buffer.begin())) co_return false;
            const auto eof = flatten_result(co_await connection.async_read(*id, buffer));
            if (!eof || *eof != 0) co_return false;
            const auto sent = flatten_result(co_await connection.async_write(*id, reply, true));
            if (!sent || *sent != reply.size()) co_return false;
        }
    }
    co_return true;
}

auto send_sparse_streams(event_loop&, quic_connection& connection) -> task<bool>
{
    std::array<std::byte, 8> buffer {};
    for (unsigned round = 0; round < 2; ++round) {
        std::array<std::uint64_t, 3> streams {};
        for (auto& id : streams) {
            const auto opened = flatten_result(co_await connection.async_open_stream(
                quic_stream_direction::bidirectional));
            if (!opened) co_return false;
            id = *opened;
        }
        for (const std::size_t position : {2u, 0u, 1u}) {
            const auto id = streams[position];
            const auto sent = flatten_result(co_await connection.async_write(id, reply, true));
            if (!sent || *sent != reply.size()) co_return false;
            const auto count = flatten_result(co_await connection.async_read(id, buffer));
            if (!count || *count != reply.size() ||
                !std::equal(reply.begin(), reply.end(), buffer.begin())) co_return false;
            const auto eof = flatten_result(co_await connection.async_read(id, buffer));
            if (!eof || *eof != 0) co_return false;
        }
    }
    co_return true;
}

auto server_serve(event_loop& loop, quic_endpoint& server, outcome& result) -> task<void>
{
    auto accepted = flatten_result(co_await server.async_accept());
    if (!accepted) co_return;
    auto connection = std::move(*accepted);
    auto stream = flatten_result(co_await connection.async_accept_stream());
    if (!stream) { connection.close(); co_return; }
    (void)co_await sleep_for(loop, 50ms);
    std::array<std::byte, 64> buffer {};
    std::size_t offset = 0;
    bool stream_ok = true;
    while (offset < bulk_request.size()) {
        const auto count = flatten_result(co_await connection.async_read(*stream, buffer));
        if (!count || *count == 0 || *count > bulk_request.size() - offset ||
            !std::equal(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*count),
                        bulk_request.begin() + static_cast<std::ptrdiff_t>(offset))) {
            stream_ok = false;
            break;
        }
        offset += *count;
    }
    if (stream_ok)
        (void)flatten_result(co_await connection.async_write(*stream, reply, false));
    auto uni = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::unidirectional));
    bool uni_ok = false;
    if (uni) {
        const auto sent = flatten_result(co_await connection.async_write(
            *uni, server_uni_data, true));
        uni_ok = sent && *sent == server_uni_data.size();
    }
    auto received = flatten_result(co_await connection.async_receive_datagram(buffer));
    const bool datagram_ok = received && *received == datagram_in.size() &&
        std::equal(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*received),
                   datagram_in.begin());
    if (datagram_ok)
        (void)flatten_result(co_await connection.async_send_datagram(datagram_out));
    const auto sparse_ok = co_await accept_sparse_streams(loop, connection);
    result.server_ok = stream_ok && uni_ok && datagram_ok && sparse_ok && *sparse_ok;
}

auto client_run(event_loop& loop, quic_endpoint& client, ip_endpoint server,
                outcome& result) -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(server, "localhost"));
    if (!connected) co_return;
    auto connection = std::move(*connected);
    auto stream = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!stream) { connection.close(); co_return; }
    std::size_t offset = 0;
    while (offset < bulk_request.size()) {
        const auto sent = flatten_result(co_await connection.async_write(*stream,
            std::span(bulk_request).subspan(offset), false));
        if (!sent || *sent == 0) { connection.close(); co_return; }
        offset += *sent;
    }
    std::array<std::byte, 64> buffer {};
    auto count = flatten_result(co_await connection.async_read(*stream, buffer));
    const bool stream_ok = count && *count == reply.size() &&
        std::equal(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*count),
                   reply.begin());
    const auto uni = flatten_result(co_await connection.async_accept_stream());
    bool uni_ok = uni && ((*uni & 3u) == 3u);
    if (uni_ok) {
        const auto uni_count = flatten_result(co_await connection.async_read(*uni, buffer));
        uni_ok = uni_count && *uni_count == server_uni_data.size() &&
            std::equal(buffer.begin(),
                buffer.begin() + static_cast<std::ptrdiff_t>(*uni_count),
                server_uni_data.begin());
    }
    (void)flatten_result(co_await connection.async_send_datagram(datagram_in));
    auto received = flatten_result(co_await connection.async_receive_datagram(buffer));
    const bool datagram_ok = received && *received == datagram_out.size() &&
        std::equal(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*received),
                   datagram_out.begin());
    const auto sparse_ok = co_await send_sparse_streams(loop, connection);
    (void)flatten_result(co_await connection.async_write(*stream, {}, true));
    result.client_ok = stream_ok && uni_ok && datagram_ok && sparse_ok && *sparse_ok;
}

auto watch(event_loop& loop, quic_endpoint& server, quic_endpoint& client,
           outcome& result) -> task<void>
{
    for (int i = 0; i < 2000 && !(result.server_ok && result.client_ok); ++i)
        (void)co_await sleep_for(loop, 5ms);
    co_await server.async_close();
    co_await client.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

auto scenario(quic_version version, const std::filesystem::path& certificate,
              bool small_windows = false) -> bool
{
    event_loop loop;
    quic_server_options server_options;
    server_options.certificate_chain = certificate / "cert.pem";
    server_options.private_key = certificate / "key.pem";
    server_options.alpn = protocol;
    server_options.limits.max_datagram_frame_size = 1200;

    quic_client_options client_options;
    client_options.alpn = protocol;
    client_options.trusted_ca = certificate / "cert.pem";
    client_options.limits.max_datagram_frame_size = 1200;
    client_options.version = version;
    if (small_windows) {
        server_options.limits.max_data = client_options.limits.max_data = 1024;
        server_options.limits.max_stream_data = client_options.limits.max_stream_data = 512;
        // Oversized requested counts must be capped before serialization and
        // accepted by the bounded connection on both sides of the handshake.
        server_options.limits.max_streams_bidi = client_options.limits.max_streams_bidi = UINT64_MAX;
        server_options.limits.max_streams_uni = client_options.limits.max_streams_uni = UINT64_MAX;
    }

    quic_endpoint server(loop, ip_endpoint::loopback_v4(0),
                         std::move(server_options));
    quic_endpoint client(loop, ip_endpoint::loopback_v4(0),
                         std::move(client_options));
    const auto server_address = server.local_endpoint();
    outcome result;
    check(loop.spawn(server_serve(loop, server, result)) == task_spawn_result::accepted,
          "spawn server");
    check(loop.spawn(client_run(loop, client, server_address, result)) ==
              task_spawn_result::accepted,
          "spawn client");
    check(loop.spawn(watch(loop, server, client, result)) == task_spawn_result::accepted,
          "spawn watch");
    (void)loop.run();
    return result.server_ok && result.client_ok;
}

} // namespace

auto main() -> int
{
#ifdef _WIN32
    WSADATA data {};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
#endif
    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-quic-public-" + std::to_string(
            static_cast<unsigned long long>(std::rand())));
    std::filesystem::create_directories(directory);
    if (!make_certificate(directory)) {
        std::fprintf(stderr, "certificate generation failed\n");
        return 1;
    }
    const bool v1 = scenario(quic_version::v1, directory);
    const bool v2 = scenario(quic_version::v2, directory);
    const bool small_v1 = scenario(quic_version::v1, directory, true);
    const bool small_v2 = scenario(quic_version::v2, directory, true);
    std::filesystem::remove_all(directory);
#ifdef _WIN32
    (void)WSACleanup();
#endif
    check(v1, "QUIC v1 public API scenario");
    check(v2, "QUIC v2 public API scenario");
    check(small_v1, "QUIC v1 small receive windows");
    check(small_v2, "QUIC v2 small receive windows");
    std::puts("QUIC public API tests passed (v1 and v2)");
    return 0;
}
