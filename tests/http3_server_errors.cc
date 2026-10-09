// HTTP/3 server error scoping over loopback: a public quic_endpoint client
// sends raw HTTP/3 frames to a public http3_server. Malformed requests and
// exhausted request storage fail only their stream, request-body violations
// after a complete response stop the body, and frame-sequence violations close
// the connection with CONNECTION_CLOSE. QPACK and frame encoding come from the
// private codecs; the certificate is generated in-process.
#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/quic.h"
#include "http3/frames.h"
#include "http3/qpack.h"

#include <openssl/bio.h>
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
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace eventloop;
using namespace std::chrono_literals;
namespace h3 = eventloop::http3::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::fprintf(stderr, "HTTP/3 server errors: %.*s\n",
                 static_cast<int>(message.size()), message.data());
    std::abort();
}

auto write_pem(const std::filesystem::path& path, X509* certificate,
               EVP_PKEY* key) -> bool
{
    std::unique_ptr<BIO, decltype(&BIO_free)> bio {BIO_new(BIO_s_mem()), BIO_free};
    if (!bio) return false;
    const int written = certificate != nullptr
        ? PEM_write_bio_X509(bio.get(), certificate)
        : PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr);
    if (written != 1) return false;
    char* data = nullptr;
    const auto size = BIO_get_mem_data(bio.get(), &data);
    if (size <= 0) return false;
    struct closer { auto operator()(FILE* f) const noexcept -> void { std::fclose(f); } };
    std::unique_ptr<FILE, closer> file {std::fopen(path.string().c_str(), "wb")};
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
    return write_pem(directory / "cert.pem", certificate.get(), nullptr) &&
        write_pem(directory / "key.pem", nullptr, key.get());
}

constexpr std::array<std::uint8_t, 2> alpn {'h', '3'};
const auto reset_error = make_error_code(quic_errc::stream_reset);

// One encoded frame: HEADERS from fields, or any type with a raw payload.
auto headers(std::vector<h3::field> fields) -> std::vector<std::byte>
{
    std::vector<std::byte> block(4096);
    const auto size = h3::qpack_encode(fields, block);
    check(size.has_value(), "encode field section");
    block.resize(*size);
    std::vector<std::byte> frame(block.size() + 16);
    const auto framed = h3::encode_frame(h3::headers_frame, block, frame);
    check(framed.has_value(), "frame HEADERS");
    frame.resize(*framed);
    return frame;
}
auto frame(std::uint64_t type, std::string_view payload) -> std::vector<std::byte>
{
    std::vector<std::byte> output(payload.size() + 16);
    const auto framed = h3::encode_frame(type,
        std::as_bytes(std::span(payload.data(), payload.size())), output);
    check(framed.has_value(), "frame payload");
    output.resize(*framed);
    return output;
}
auto get(std::string_view path, std::vector<h3::field> extra = {}) -> std::vector<std::byte>
{
    std::vector<h3::field> fields {{":method", "GET"}, {":scheme", "https"},
                                   {":authority", "localhost"}, {":path", path}};
    fields.insert(fields.end(), extra.begin(), extra.end());
    return headers(fields);
}

struct outcome {
    bool malformed_reset {false};
    bool rejected {false};
    bool content_length_stopped {false};
    bool trailers_stopped {false};
    bool valid_trailers {false};
    bool survived {false};
    bool connection_closed {false};
    bool cancel_push_closed {false};
    bool done {false};
};

auto send(event_loop&, quic_connection& connection, std::uint64_t id, std::span<const std::byte> bytes,
          bool fin) -> task<bool>
{
    while (!bytes.empty()) {
        const auto sent = flatten_result(co_await connection.async_write(id, bytes, false));
        if (!sent || *sent == 0) co_return false;
        bytes = bytes.subspan(*sent);
    }
    if (fin && !flatten_result(co_await connection.async_write(id, {}, true))) co_return false;
    co_return true;
}

// Reads a whole response; returns its :status, or 0 on a stream error.
auto response_status(event_loop&, quic_connection& connection, std::uint64_t id, std::error_code& error)
    -> task<unsigned>
{
    std::vector<std::byte> bytes;
    std::array<std::byte, 1024> buffer {};
    for (;;) {
        const auto got = flatten_result(co_await connection.async_read(id, buffer));
        if (!got) { error = got.error(); co_return 0u; }
        if (*got == 0) break;
        bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*got));
    }
    const auto first = h3::decode_frame(bytes, bytes.size());
    if (!first || first->type != h3::headers_frame) co_return 0u;
    std::array<h3::field, 16> fields {};
    std::array<char, 1024> strings {};
    const auto count = h3::qpack_decode(first->payload, fields, strings);
    if (!count || *count == 0 || fields[0].name != ":status") co_return 0u;
    co_return static_cast<unsigned>(std::stoul(std::string(fields[0].value)));
}

// After a complete response, the server stops reading a bad request body.
// Keep writing padding until STOP_SENDING turns writes into stream_reset.
auto stopped_after(event_loop& loop, quic_connection& connection, std::uint64_t id) -> task<bool>
{
    const auto padding = frame(0x21, "padding");
    for (int attempt = 0; attempt < 400; ++attempt) {
        const auto sent = flatten_result(co_await connection.async_write(id, padding, false));
        // Once the response was read, answering STOP_SENDING finishes both
        // halves, so the stream may already be retired (invalid_argument).
        if (!sent) co_return sent.error() == reset_error ||
            sent.error() == make_error_code(quic_errc::invalid_argument);
        (void)co_await sleep_for(loop, 5ms);
    }
    co_return false;
}

auto open_request(event_loop&, quic_connection& connection) -> task<std::uint64_t>
{
    const auto id = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    check(id.has_value(), "open request stream");
    co_return *id;
}

auto client(event_loop& loop, quic_endpoint& endpoint, ip_endpoint server, outcome& result)
    -> task<void>
{
    auto connected = flatten_result(co_await endpoint.async_connect(server, "localhost"));
    if (!connected) { result.done = true; co_return; }
    auto connection = std::move(*connected);
    const auto control = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::unidirectional));
    const std::array<std::byte, 3> settings {std::byte {0}, std::byte {4}, std::byte {0}};
    if (!control || !(co_await send(loop, connection, *control, settings, false)).value_or(false)) {
        result.done = true;
        co_return;
    }
    std::error_code error;

    // 1. Uppercase field names make a request malformed: H3_MESSAGE_ERROR on
    // this stream only.
    auto id = (co_await open_request(loop, connection)).value_or(0);
    (void)co_await send(loop, connection, id, get("/hello.txt", {{"X-Upper", "1"}}), true);
    auto status = (co_await response_status(loop, connection, id, error)).value_or(0);
    result.malformed_reset = status == 0 && error == reset_error;

    // 2. With one request slot, a request held open after its response keeps
    // the slot; the next request is rejected (H3_REQUEST_REJECTED).
    const auto held = (co_await open_request(loop, connection)).value_or(0);
    (void)co_await send(loop, connection, held, get("/hello.txt"), false);
    status = (co_await response_status(loop, connection, held, error)).value_or(0);
    id = (co_await open_request(loop, connection)).value_or(0);
    (void)co_await send(loop, connection, id, get("/hello.txt"), true);
    error = {};
    const auto rejected = (co_await response_status(loop, connection, id, error)).value_or(0);
    result.rejected = status == 200 && rejected == 0 && error == reset_error;
    (void)co_await send(loop, connection, held, {}, true);
    (void)co_await sleep_for(loop, 20ms);

    // 3. DATA beyond Content-Length, received after the response.
    id = (co_await open_request(loop, connection)).value_or(0);
    (void)co_await send(loop, connection, id, get("/hello.txt", {{"content-length", "1"}}), false);
    status = (co_await response_status(loop, connection, id, error)).value_or(0);
    (void)co_await send(loop, connection, id, frame(h3::data_frame, "ab"), false);
    result.content_length_stopped = status == 200 &&
        (co_await stopped_after(loop, connection, id)).value_or(false);

    // 4. A pseudo-header in trailers.
    id = (co_await open_request(loop, connection)).value_or(0);
    (void)co_await send(loop, connection, id, get("/hello.txt"), false);
    status = (co_await response_status(loop, connection, id, error)).value_or(0);
    (void)co_await send(loop, connection, id, headers({{":path", "/"}}), false);
    result.trailers_stopped = status == 200 &&
        (co_await stopped_after(loop, connection, id)).value_or(false);

    // 5. A body matching Content-Length and valid trailers complete cleanly.
    id = (co_await open_request(loop, connection)).value_or(0);
    auto request = get("/hello.txt", {{"content-length", "2"}});
    for (auto part : {frame(h3::data_frame, "ok"), headers({{"x-checksum", "1"}})})
        request.insert(request.end(), part.begin(), part.end());
    (void)co_await send(loop, connection, id, request, true);
    status = (co_await response_status(loop, connection, id, error)).value_or(0);
    result.valid_trailers = status == 200;

    // 6. Earlier stream errors left the connection usable.
    id = (co_await open_request(loop, connection)).value_or(0);
    (void)co_await send(loop, connection, id, get("/hello.txt"), true);
    result.survived = (co_await response_status(loop, connection, id, error)).value_or(0) == 200;

    // 7. DATA before HEADERS is H3_FRAME_UNEXPECTED: the server closes the
    // connection with CONNECTION_CLOSE instead of leaving an idle timeout.
    id = (co_await open_request(loop, connection)).value_or(0);
    (void)co_await send(loop, connection, id, frame(h3::data_frame, "x"), true);
    const auto started = event_loop::clock::now();
    error = {};
    status = (co_await response_status(loop, connection, id, error)).value_or(0);
    result.connection_closed = status == 0 && error && error != reset_error &&
        event_loop::clock::now() - started < 2s;

    // 8. CANCEL_PUSH names an ID the server never promised: H3_ID_ERROR closes
    // this second connection, even though the ID is within MAX_PUSH_ID.
    auto push_connected = flatten_result(co_await endpoint.async_connect(server, "localhost"));
    if (!push_connected) { result.done = true; co_return; }
    auto push_connection = std::move(*push_connected);
    const auto push_control = flatten_result(co_await push_connection.async_open_stream(
        quic_stream_direction::unidirectional));
    if (!push_control) { result.done = true; co_return; }
    if (!(co_await send(loop, push_connection, *push_control, settings, false)).value_or(false)) {
        result.done = true;
        co_return;
    }
    auto push_frames = frame(0x0d, "\x05"); // MAX_PUSH_ID 5
    const auto cancel = frame(0x03, "\x05"); // CANCEL_PUSH 5
    push_frames.insert(push_frames.end(), cancel.begin(), cancel.end());
    const auto probe = (co_await open_request(loop, push_connection)).value_or(0);
    const auto control_sent =
        (co_await send(loop, push_connection, *push_control, push_frames, false)).value_or(false);
    error = {};
    (void)co_await send(loop, push_connection, probe, get("/hello.txt"), true);
    status = (co_await response_status(loop, push_connection, probe, error)).value_or(0);
    result.cancel_push_closed = control_sent && status == 0 && error && error != reset_error;
    result.done = true;
}

auto watch(event_loop& loop, http::http3_server& server, quic_endpoint& endpoint,
           outcome& result) -> task<void>
{
    for (int i = 0; i < 2000 && !result.done; ++i) (void)co_await sleep_for(loop, 5ms);
    co_await server.async_close();
    co_await endpoint.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

} // namespace

auto main() -> int
{
    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-http3-errors-" + std::to_string(
            static_cast<unsigned long long>(std::rand())));
    std::filesystem::create_directories(directory / "www");
    check(make_certificate(directory), "certificate generation");
    std::ofstream(directory / "www" / "hello.txt") << "hello";

    outcome result;
    {
        event_loop loop;
        http::http3_server server(loop, ip_endpoint::loopback_v4(0),
            directory / "cert.pem", directory / "key.pem",
            http::server_options {.document_root = directory / "www",
                                  .connection_capacity = 2, .request_capacity = 1});
        quic_client_options options;
        options.alpn = alpn;
        options.trusted_ca = directory / "cert.pem";
        quic_endpoint endpoint(loop, ip_endpoint::loopback_v4(0), std::move(options));
        task_handle<void> serving;
        check(loop.spawn(server.run(), serving) == task_spawn_result::accepted, "spawn server");
        check(loop.spawn(client(loop, endpoint, server.local_endpoint(), result)) ==
                  task_spawn_result::accepted, "spawn client");
        check(loop.spawn(watch(loop, server, endpoint, result)) ==
                  task_spawn_result::accepted, "spawn watch");
        (void)loop.run();
    }
    std::filesystem::remove_all(directory);
    check(result.malformed_reset, "malformed request resets only its stream");
    check(result.rejected, "exhausted request storage rejects the stream");
    check(result.content_length_stopped, "DATA beyond Content-Length stops the body");
    check(result.trailers_stopped, "pseudo-header trailers stop the body");
    check(result.valid_trailers, "valid body and trailers");
    check(result.survived, "connection survives stream errors");
    check(result.connection_closed, "frame-sequence error closes the connection");
    check(result.cancel_push_closed, "unpromised CANCEL_PUSH closes the connection");
    std::puts("HTTP/3 server error scoping tests passed");
}
