// Skirmish: a multiplayer first-person arena shooter. The page is served over
// HTTPS (TCP) and the game runs over WebTransport on HTTP/3 (UDP) on the same
// port. Browsers pin the generated certificate with the hash from /cert-hash.

#include "server.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/task.h"
#include "eventloop/tls_context.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace eventloop;
using namespace skirmish;
namespace fs = std::filesystem;

namespace {

struct options {
    std::string bind = "127.0.0.1";
    std::uint16_t port = 4443;
    std::size_t max_players = 16;
    fs::path web = SKIRMISH_WEB_ROOT;
    double killcam_speed = 1.25;
};

auto usage() -> void
{
    std::cout <<
        "Skirmish: arena shooter over WebTransport (HTTP/3) and HTTPS\n"
        "usage: skirmish [options]\n"
        "  --bind ADDRESS       numeric IPv4/IPv6 address (default 127.0.0.1)\n"
        "  --port PORT          HTTPS port, also UDP for WebTransport (default 4443)\n"
        "  --max-players N      players per server, 1..64 (default 16)\n"
        "  --web DIR            browser client files (default: the source tree's web/)\n"
        "  --killcam-speed X    killcam playback rate: 0 (unpaced) or 0.25..16 (default 1.25; 1 makes respawn reset every replay)\n";
}

auto parse(int argc, char** argv) -> options
{
    options result;
    for (int i = 1; i < argc; ++i) {
        const std::string_view option = argv[i];
        if (option == "--help") {
            usage();
            std::exit(0);
        }
        if (i + 1 >= argc) throw std::invalid_argument("missing value for " + std::string(option));
        const std::string_view value = argv[++i];
        if (option == "--bind") {
            result.bind = value;
        } else if (option == "--web") {
            result.web = value;
        } else if (option == "--port") {
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result.port);
            if (parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size() || result.port == 0)
                throw std::invalid_argument("invalid --port");
        } else if (option == "--killcam-speed") {
            const std::string text(value);
            char* end = nullptr;
            result.killcam_speed = std::strtod(text.c_str(), &end);
            if (text.empty() || end != text.c_str() + text.size() ||
                !(result.killcam_speed == 0 || (result.killcam_speed >= 0.25 && result.killcam_speed <= 16)))
                throw std::invalid_argument("--killcam-speed must be 0 or 0.25..16");
        } else if (option == "--max-players") {
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result.max_players);
            if (parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size() ||
                result.max_players < 1 || result.max_players > kMaxPlayers)
                throw std::invalid_argument("--max-players must be 1..64");
        } else {
            throw std::invalid_argument("unknown option " + std::string(option));
        }
    }
    return result;
}

// Writes a fresh P-256 certificate for localhost valid for 13 days and returns
// the base64 SHA-256 of its DER encoding, the value /cert-hash serves.
auto generate_certificate(const fs::path& certificate, const fs::path& private_key) -> std::string
{
    using key_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using cert_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    key_ptr key(EVP_EC_gen("P-256"), EVP_PKEY_free);
    cert_ptr cert(X509_new(), X509_free);
    if (!key || !cert) throw std::runtime_error("cannot generate a key");
    X509_set_version(cert.get(), X509_VERSION_3);
    ASN1_INTEGER_set_int64(X509_get_serialNumber(cert.get()),
        std::chrono::system_clock::now().time_since_epoch().count() & 0x7fffffffffff);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 13L * 24 * 3600);
    X509_set_pubkey(cert.get(), key.get());
    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name(X509_NAME_new(), X509_NAME_free);
    if (!name || !X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
                                             reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) ||
        !X509_set_subject_name(cert.get(), name.get()) || !X509_set_issuer_name(cert.get(), name.get()))
        throw std::runtime_error("cannot name the certificate");
    X509V3_CTX context;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, cert.get(), cert.get(), nullptr, nullptr, 0);
    for (const auto& [nid, value] : {
             std::pair {NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1,IP:::1"},
             std::pair {NID_basic_constraints, "critical,CA:FALSE"},
             std::pair {NID_ext_key_usage, "serverAuth"}}) {
        auto* extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value);
        if (!extension || !X509_add_ext(cert.get(), extension, -1))
            throw std::runtime_error("cannot build the certificate");
        X509_EXTENSION_free(extension);
    }
    if (!X509_sign(cert.get(), key.get(), EVP_sha256())) throw std::runtime_error("cannot sign the certificate");

    unsigned char* der_raw = nullptr;
    const int der_length = i2d_X509(cert.get(), &der_raw);
    if (der_length <= 0 || der_raw == nullptr) throw std::runtime_error("cannot encode the certificate");
    std::unique_ptr<unsigned char, void (*)(void*)> der(der_raw, [](void* p) { OPENSSL_free(p); });
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int digest_length = 0;
    if (!EVP_Digest(der.get(), static_cast<std::size_t>(der_length), digest.data(), &digest_length,
                    EVP_sha256(), nullptr))
        throw std::runtime_error("cannot hash the certificate");
    std::array<char, 64> encoded {};
    const int encoded_length = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded.data()),
                                               digest.data(), static_cast<int>(digest_length));
    if (encoded_length <= 0) throw std::runtime_error("cannot encode the hash");

    const int key_fd = ::open(private_key.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    auto* key_file = key_fd < 0 ? nullptr : ::fdopen(key_fd, "w");
    auto* cert_file = std::fopen(certificate.c_str(), "w");
    const bool written = key_file && cert_file &&
        PEM_write_PrivateKey(key_file, key.get(), nullptr, nullptr, 0, nullptr, nullptr) &&
        PEM_write_X509(cert_file, cert.get());
    if (key_file) std::fclose(key_file);
    if (cert_file) std::fclose(cert_file);
    if (!written) throw std::runtime_error("cannot write the certificate");
    return std::string(encoded.data(), static_cast<std::size_t>(encoded_length));
}

// Removes the temporary certificate directory when main returns.
struct directory_cleanup {
    fs::path path;
    ~directory_cleanup()
    {
        std::error_code ignored;
        fs::remove_all(path, ignored);
    }
};

auto stop_after(event_loop& loop, std::chrono::milliseconds delay) -> task<void>
{
    (void)co_await sleep_for(loop, delay);
    loop.stop();
}

} // namespace

auto main(int argc, char** argv) -> int
{
    try {
        const auto settings = parse(argc, argv);
        if (!fs::exists(settings.web / "index.html")) {
            std::fprintf(stderr, "warning: %s has no index.html\n", settings.web.c_str());
        }
        const auto directory = fs::temp_directory_path() / ("skirmish-" + std::to_string(::getpid()));
        fs::create_directories(directory);
        const directory_cleanup cleanup {directory};
        const auto certificate = directory / "certificate.pem";
        const auto private_key = directory / "private-key.pem";
        const auto hash = generate_certificate(certificate, private_key);

        event_loop_options loop_options;
        loop_options.coroutine_frame_capacities = {4096, 4096, 10240, 10240, 2048, 256};
        event_loop loop(loop_options);
        auto game = std::make_unique<game_server>(settings.max_players, "{\"sha256\":\"" + hash + "\"}",
                                                         settings.killcam_speed);

        auto routes = std::make_shared<http::router>();
        if (!routes->add(http::method_type::connect, "/arena", arena_session, game.get()).has_value() ||
            !routes->add(http::method_type::get, "/cert-hash", cert_hash, game.get()).has_value()) {
            throw std::runtime_error("cannot register routes");
        }
        http::server_options server_options;
        server_options.routes = routes;
        server_options.document_root = settings.web;
        server_options.open_file_cache_capacity = 64;
        server_options.connection_capacity = settings.max_players + 4;
        server_options.webtransport.enabled = true;

        const auto endpoint = ip_endpoint::parse(settings.bind, settings.port);
        auto tls = std::make_unique<http::https_server>(loop, endpoint,
            tls_context::make_server(certificate, private_key), server_options);
        auto* listener = tls.get();
        loop.add(std::move(tls));
        auto quic = std::make_unique<http::http3_server>(loop, endpoint, certificate, private_key, server_options);

        if (loop.spawn(listener->run()) != task_spawn_result::accepted ||
            loop.spawn(tick_loop(loop, *game)) != task_spawn_result::accepted ||
            loop.spawn(stats_loop(loop, *game)) != task_spawn_result::accepted ||
            loop.spawn(quic->run()) != task_spawn_result::accepted) {
            throw std::runtime_error("cannot start the server");
        }

        std::printf("Skirmish on https://%s:%u/ (WebTransport /arena on UDP %u, %zu players per server)\n",
                    settings.bind.c_str(), static_cast<unsigned>(settings.port),
                    static_cast<unsigned>(settings.port), settings.max_players);
        std::fflush(stdout);

        // Ctrl-C: close every session with code 4 and give the handlers a
        // moment to send their close frames before the transport goes down.
        if (loop.run() == event_loop_result::interrupted) {
            game->begin_shutdown();
            (void)loop.spawn(stop_after(loop, std::chrono::milliseconds {500}));
            (void)loop.run();
        }
        // run() returns stopped once every root (including HTTP/3) has finished.
        quic->close();
        loop.shutdown(std::chrono::seconds {2});
        while (loop.run() == event_loop_result::interrupted) {}
    } catch (const std::exception& error) {
        std::cerr << "skirmish: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
