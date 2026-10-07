// Lantern: a YouTube-style video site on eventloop.
//
// Serves the browser client from web/ over TLS HTTP/1.1 and HTTP/2 (and
// optionally HTTP/3 and cleartext HTTP/1.1), resumable chunked uploads, and
// video playback with byte ranges for seeking.

#include "api.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/server.h"
#include "eventloop/task.h"
#include "eventloop/tls_context.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <charconv>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace eventloop;
namespace fs = std::filesystem;

namespace {

struct options {
    std::string bind = "127.0.0.1";
    std::uint16_t port = 8443;
    std::uint16_t http_port = 0;
    fs::path data = "lantern-data";
    fs::path web = LANTERN_WEB_ROOT;
    fs::path certificate;
    fs::path private_key;
    std::uint64_t max_video_mib = 4096;
    bool http3 = false;
};

auto usage() -> void
{
    std::cout <<
        "Lantern: a video site over HTTP/1.1, HTTP/2, and HTTP/3\n"
        "usage: lantern [options]\n"
        "  --bind ADDRESS       numeric IPv4/IPv6 address (default 127.0.0.1)\n"
        "  --port PORT          HTTPS port, also UDP for HTTP/3 (default 8443)\n"
        "  --http-port PORT     also serve cleartext HTTP/1.1 on this port\n"
        "  --data DIR           journal, videos, and generated certificate (default lantern-data)\n"
        "  --web DIR            browser client files (default: the source tree's web/)\n"
        "  --certificate FILE   PEM certificate chain (default: generated self-signed)\n"
        "  --private-key FILE   PEM private key\n"
        "  --max-video MIB      largest accepted video (default 4096)\n"
        "  --http3              also serve HTTP/3 on the UDP port and advertise it\n";
}

template<typename T>
auto parse_number(std::string_view value, std::string_view option) -> T
{
    T result {};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size() || result == 0)
        throw std::invalid_argument("invalid " + std::string(option));
    return result;
}

auto parse(int argc, char** argv) -> options
{
    options result;
    for (int i = 1; i < argc; ++i) {
        const std::string_view option = argv[i];
        if (option == "--help") { usage(); std::exit(0); }
        if (option == "--http3") { result.http3 = true; continue; }
        if (i + 1 >= argc) throw std::invalid_argument("missing value for " + std::string(option));
        const std::string_view value = argv[++i];
        if (option == "--bind") result.bind = value;
        else if (option == "--data") result.data = value;
        else if (option == "--web") result.web = value;
        else if (option == "--certificate") result.certificate = value;
        else if (option == "--private-key") result.private_key = value;
        else if (option == "--port") result.port = parse_number<std::uint16_t>(value, option);
        else if (option == "--http-port") result.http_port = parse_number<std::uint16_t>(value, option);
        else if (option == "--max-video") result.max_video_mib = parse_number<std::uint64_t>(value, option);
        else throw std::invalid_argument("unknown option " + std::string(option));
    }
    if (result.certificate.empty() != result.private_key.empty())
        throw std::invalid_argument("--certificate and --private-key go together");
    return result;
}

// A P-256 certificate for localhost, 127.0.0.1, and ::1, valid for a year.
auto generate_certificate(const fs::path& certificate, const fs::path& private_key) -> void
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
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 365L * 24 * 3600);
    X509_set_pubkey(cert.get(), key.get());
    auto* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);
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

    const int key_fd = ::open(private_key.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    auto* key_file = key_fd < 0 ? nullptr : ::fdopen(key_fd, "w");
    auto* cert_file = std::fopen(certificate.c_str(), "w");
    const bool written = key_file && cert_file &&
        PEM_write_PrivateKey(key_file, key.get(), nullptr, nullptr, 0, nullptr, nullptr) &&
        PEM_write_X509(cert_file, cert.get());
    if (key_file) std::fclose(key_file);
    if (cert_file) std::fclose(cert_file);
    if (!written) throw std::runtime_error("cannot write the certificate");
}

auto open_directory(const fs::path& path) -> unique_fd
{
    fs::create_directories(path);
    unique_fd directory(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (directory.get() < 0) throw std::runtime_error("cannot open " + path.string());
    return directory;
}

} // namespace

auto main(int argc, char** argv) -> int
{
    try {
        const auto settings = parse(argc, argv);
        if (!fs::exists(settings.web / "index.html"))
            throw std::invalid_argument("--web directory has no index.html");
        auto certificate = settings.certificate;
        auto private_key = settings.private_key;
        fs::create_directories(settings.data);
        if (certificate.empty()) {
            certificate = settings.data / "certificate.pem";
            private_key = settings.data / "private-key.pem";
            if (!fs::exists(certificate) || !fs::exists(private_key)) {
                generate_certificate(certificate, private_key);
                std::cout << "Generated a self-signed certificate in " << settings.data << '\n';
            }
        }

        // Rebuild the catalog, then resume each upload from the bytes on disk.
        const auto journal_path = settings.data / "journal.tsv";
        lantern::catalog library;
        {
            std::ifstream journal(journal_path, std::ios::binary);
            library.replay(std::string(std::istreambuf_iterator<char>(journal), {}));
        }
        auto uploads = open_directory(settings.data / "uploads");
        std::vector<std::string> missing;
        for (auto& [id, pending] : library.uploads()) {
            struct stat status {};
            if (::fstatat(uploads.get(), id.c_str(), &status, 0) != 0) missing.push_back(id);
            else pending.received = std::min<std::uint64_t>(status.st_size, pending.details.size);
        }
        for (const auto& id : missing) library.uploads().erase(id);
        unique_fd journal(::open(journal_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600));
        if (journal.get() < 0) throw std::runtime_error("cannot open the journal");
        const auto journal_end = static_cast<std::uint64_t>(fs::file_size(journal_path));

        event_loop_options loop_options;
        loop_options.post_capacity = 4096;
        // Each playing video holds a handler frame for its range request.
        loop_options.coroutine_frame_capacities = {8192, 8192, 8192, 10240, 2048, 256};
        event_loop loop(loop_options);
        lantern::app application {
            .loop = loop, .library = library, .uploads = std::move(uploads),
            .videos = open_directory(settings.data / "videos"),
            .thumbnails = open_directory(settings.data / "thumbnails"),
            .journal = std::move(journal), .journal_end = journal_end,
            .max_video_bytes = settings.max_video_mib * 1024 * 1024,
            .alt_svc = settings.http3 ? "h3=\":" + std::to_string(settings.port) + "\"; ma=86400" : "",
        };

        http::server_options server_options {
            .routes = lantern::make_routes(application),
            .document_root = settings.web,
            .open_file_cache_capacity = 64,
            .max_request_body = lantern::chunk_bytes,
            .connection_capacity = 64,
        };
        auto tls = std::make_unique<http::https_server>(loop, ip_endpoint::parse(settings.bind, settings.port),
            tls_context::make_server(certificate, private_key), server_options);
        auto* secure = tls.get();
        loop.add(std::move(tls));
        http::server* plain = nullptr;
        if (settings.http_port != 0) {
            auto cleartext = std::make_unique<http::server>(loop,
                ip_endpoint::parse(settings.bind, settings.http_port), server_options);
            plain = cleartext.get();
            loop.add(std::move(cleartext));
        }
        std::unique_ptr<http::http3_server> quic;
        if (settings.http3)
            quic = std::make_unique<http::http3_server>(loop, ip_endpoint::parse(settings.bind, settings.port),
                                                        certificate, private_key, server_options);

        task_handle<void> serving_quic;
        if (loop.spawn(secure->run()) != task_spawn_result::accepted ||
            (plain && loop.spawn(plain->run()) != task_spawn_result::accepted) ||
            (quic && loop.spawn(quic->run(), serving_quic) != task_spawn_result::accepted))
            throw std::runtime_error("cannot start the server");

        const auto host = settings.bind == "127.0.0.1" ? std::string("localhost") : settings.bind;
        std::cout << "Lantern on https://" << host << ':' << settings.port << "/ (HTTP/1.1, HTTP/2"
                  << (settings.http3 ? ", HTTP/3" : "") << ")";
        if (plain) std::cout << " and http://" << host << ':' << settings.http_port << "/";
        std::cout << '\n' << std::flush;
        // Shutdown cancels every handler; interrupted uploads resume from disk.
        // HTTP/3 does not stop with the loop: close it, and its run() task
        // retires the endpoint.
        while (loop.run() == event_loop_result::interrupted) {
            if (quic) quic->close();
            loop.shutdown(std::chrono::seconds {2});
        }
        while (quic && !serving_quic.done()) (void)loop.run();
    } catch (const std::exception& error) {
        std::cerr << "lantern: " << error.what() << '\n';
        return 1;
    }
}
