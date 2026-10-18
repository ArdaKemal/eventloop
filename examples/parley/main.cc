// Parley: a WhatsApp-style chat server on eventloop.
//
// Serves the browser client from web/ over TLS HTTP/2 (and optionally
// HTTP/3), a JSON API, uploaded media, and realtime events over WebSockets
// (RFC 8441/9220) or server-sent events.

#include "api.h"

#include "eventloop/event_loop.h"
#include "eventloop/file_io.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/server.h"
#include "eventloop/task.h"
#include "eventloop/tls_context.h"
#include "eventloop/util/arg_parser.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <charconv>
#include <span>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace eventloop;
namespace fs = std::filesystem;

namespace {

struct options {
    std::string bind = "127.0.0.1";
    std::uint16_t port = 8443;
    fs::path data = "parley-data";
    fs::path web = PARLEY_WEB_ROOT;
    fs::path certificate;
    fs::path private_key;
    bool http3 = false;
};

constexpr std::string_view usage =
    "Parley: WhatsApp-style chat over HTTP/2, HTTP/3, and WebSockets\n"
    "usage: parley [options]\n"
    "  --bind ADDRESS       numeric IPv4/IPv6 address (default 127.0.0.1)\n"
    "  --port PORT          HTTPS port, also UDP for HTTP/3 (default 8443)\n"
    "  --data DIR           journal, media, and generated certificate (default parley-data)\n"
    "  --web DIR            browser client files (default: the source tree's web/)\n"
    "  --certificate FILE   PEM certificate chain (default: generated self-signed)\n"
    "  --private-key FILE   PEM private key\n"
    "  --http3              also serve HTTP/3 on the UDP port and advertise it\n";

auto parse(int argc, char** argv) -> options
{
    options result;
    const auto path = [](fs::path& target) {
        return arg_parser::value_handler([&target](std::string_view value) { target = value; });
    };
    const auto port = [&result](std::string_view value) {
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result.port);
        if (parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size() || result.port == 0)
            throw std::invalid_argument("invalid --port");
    };
    const std::array arguments {
        arg_parser::option {'\0', "bind", &result.bind, false},
        arg_parser::option {'\0', "port", arg_parser::value_handler(port), false},
        arg_parser::option {'\0', "data", path(result.data), false},
        arg_parser::option {'\0', "web", path(result.web), false},
        arg_parser::option {'\0', "certificate", path(result.certificate), false},
        arg_parser::option {'\0', "private-key", path(result.private_key), false},
        arg_parser::option {'\0', "http3", &result.http3, false},
    };
    arg_parser parser(arguments);
    parser.set_usage(usage);
    parser.parse(argc, argv);
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

// Appends journal lines in order with positional writes. A line written
// twice (after a cancelled write) lands on the same bytes.
auto journal_writer(event_loop& loop, parley::app& application, int descriptor,
                    std::uint64_t& offset) -> task<void>
{
    auto& backlog = application.data.journal_backlog();
    std::string writing;
    for (;;) {
        if (backlog.empty()) {
            if (!co_await application.journal_ready.async_wait()) co_return;
            continue;
        }
        writing.swap(backlog);
        std::size_t done = 0;
        while (done < writing.size()) {
            const auto wrote = co_await async_write_at(loop, descriptor,
                std::as_bytes(std::span(writing)).subspan(done), static_cast<std::int64_t>(offset + done));
            if (!wrote || *wrote == 0) break;
            done += *wrote;
        }
        offset += done;
        if (done < writing.size()) {
            // Cancelled or failed: keep the rest for the final flush in main().
            backlog.insert(0, writing, done);
            co_return;
        }
        writing.clear();
    }
}

auto ticker(event_loop& loop, parley::app& application) -> task<void>
{
    for (;;) {
        if (co_await sleep_for(loop, std::chrono::seconds {15}) == timer_wait_result::cancelled) break;
        application.clients.heartbeat();
    }
}

} // namespace

auto main(int argc, char** argv) -> int
{
    try {
        const auto settings = parse(argc, argv);
        fs::create_directories(settings.data / "media");
        auto certificate = settings.certificate;
        auto private_key = settings.private_key;
        if (certificate.empty()) {
            certificate = settings.data / "certificate.pem";
            private_key = settings.data / "private-key.pem";
            if (!fs::exists(certificate) || !fs::exists(private_key)) {
                generate_certificate(certificate, private_key);
                std::cout << "Generated a self-signed certificate in " << settings.data << '\n';
            }
        }
        if (!fs::exists(settings.web / "index.html"))
            throw std::invalid_argument("--web directory has no index.html");

        const auto journal_path = settings.data / "journal.jsonl";
        parley::store data(journal_path);
        unique_fd journal(::open(journal_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600));
        unique_fd media(::open((settings.data / "media").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if (journal.get() < 0 || media.get() < 0) throw std::runtime_error("cannot open the data directory");
        std::uint64_t journal_offset = data.journal_size();

        event_loop_options loop_options;
        loop_options.worker_count = 2; // password hashing
        loop_options.post_capacity = 4096;
        // Every live WebSocket or event stream keeps a handler frame, and
        // HTTP/3 request frames use the 2 KiB class.
        loop_options.coroutine_frame_capacities = {8192, 8192, 8192, 10240, 2048, 64};
        event_loop loop(loop_options);
        parley::hub clients(data);
        parley::app application {
            .loop = loop, .data = data, .clients = clients, .media_directory = std::move(media),
            .alt_svc = settings.http3 ? "h3=\":" + std::to_string(settings.port) + "\"; ma=86400" : "",
            .journal_ready = eventloop::wakeup(loop),
        };
        data.set_journal_wakeup(&application.journal_ready);

        const auto endpoint = ip_endpoint::parse(settings.bind, settings.port);
        http::server_options server_options {
            .routes = parley::make_routes(application),
            .document_root = settings.web,
            .open_file_cache_capacity = 64,
            .max_request_body = parley::max_upload_bytes,
            .connection_capacity = 64,
        };
        auto tls = std::make_unique<http::https_server>(loop, endpoint,
            tls_context::make_server(certificate, private_key), server_options);
        auto* listener = tls.get();
        loop.add(std::move(tls));
        std::unique_ptr<http::http3_server> quic;
        if (settings.http3)
            quic = std::make_unique<http::http3_server>(loop, endpoint, certificate, private_key, server_options);

        task_handle<void> serving_quic;
        if (loop.spawn(listener->run()) != task_spawn_result::accepted ||
            loop.spawn(journal_writer(loop, application, journal.get(), journal_offset)) !=
                task_spawn_result::accepted ||
            loop.spawn(ticker(loop, application)) != task_spawn_result::accepted ||
            (quic && loop.spawn(quic->run(), serving_quic) != task_spawn_result::accepted))
            throw std::runtime_error("cannot start the server");

        std::cout << "Parley on https://" << (settings.bind == "127.0.0.1" ? "localhost" : settings.bind)
                  << ':' << settings.port << "/ (HTTP/2" << (settings.http3 ? ", HTTP/3" : "")
                  << ")\n" << std::flush;
        // Shutdown cancels every handler, the journal writer, and the ticker.
        // HTTP/3 does not stop with the loop: close it, and its run() task
        // retires the endpoint.
        while (loop.run() == event_loop_result::interrupted) {
            if (quic) quic->close();
            loop.shutdown(std::chrono::seconds {2});
        }
        while (quic && !serving_quic.done()) (void)loop.run();

        // Lines the cancelled writer did not reach.
        const auto& rest = data.journal_backlog();
        for (std::size_t done = 0; done < rest.size();) {
            const auto wrote = ::pwrite(journal.get(), rest.data() + done, rest.size() - done,
                                        static_cast<off_t>(journal_offset + done));
            if (wrote <= 0) throw std::runtime_error("cannot write the journal");
            done += static_cast<std::size_t>(wrote);
        }
    } catch (const std::exception& error) {
        std::cerr << "parley: " << error.what() << '\n';
        return 1;
    }
}
