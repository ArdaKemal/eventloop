// Public QUIC API end-to-end test: in-house client and server over loopback
// for QUIC v1 and v2, exercising the handshake, bidirectional stream I/O, and
// the RFC 9221 DATAGRAM extension, and application stream resets,
// STOP_SENDING, and CONNECTION_CLOSE, and SO_REUSEPORT servers on separate
// loops, worker-indexed connection IDs from QUIC and HTTP/3 servers, and
// connections that survive client rebinding across shared-port workers. The certificate is generated
// in-process.
#include "eventloop/quic.h"
#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/task_composition.h"
#include "eventloop/udp_socket.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

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

// More rounds than the server's 32 concurrent bidirectional streams, so every
// abandoned stream must retire and return its stream credit.
constexpr std::size_t control_rounds = 40;
constexpr std::uint64_t stream_error = 0x10c;

struct control_outcome {
    std::size_t server_rounds {0};
    std::size_t client_rounds {0};
    bool server_closed {false};
    bool client_saw_close {false};
    event_loop::clock::time_point closed_at {};
    event_loop::clock::time_point observed_at {};
};

auto control_server(event_loop& loop, quic_endpoint& server, control_outcome& result)
    -> task<void>
{
    auto accepted = flatten_result(co_await server.async_accept());
    if (!accepted) co_return;
    auto connection = std::move(*accepted);
    std::array<std::byte, 8> buffer {};
    for (std::size_t round = 0; round < control_rounds; ++round) {
        const auto id = flatten_result(co_await connection.async_accept_stream());
        if (!id) break;
        if (!connection.stop_sending(*id, stream_error) ||
            !connection.reset_stream(*id, stream_error)) break;
        // Both operations are idempotent once applied.
        if (!connection.stop_sending(*id, stream_error) ||
            !connection.reset_stream(*id, stream_error)) break;
        const auto read = flatten_result(co_await connection.async_read(*id, buffer));
        const auto write = flatten_result(co_await connection.async_write(*id, reply, false));
        if (read || read.error() != make_error_code(quic_errc::invalid_state) ||
            write || write.error() != make_error_code(quic_errc::stream_reset)) break;
        ++result.server_rounds;
    }
    const auto bogus = connection.reset_stream(1u << 20, stream_error);
    if (bogus || bogus.error() != make_error_code(quic_errc::invalid_argument)) co_return;
    // Let the final RESET_STREAM reach the client before the close.
    while (result.client_rounds < control_rounds) (void)co_await sleep_for(loop, 1ms);
    result.closed_at = event_loop::clock::now();
    connection.close_application(0x100);
    result.server_closed = true;
}

auto control_client(event_loop& loop, quic_endpoint& client, ip_endpoint server,
                    control_outcome& result) -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(server, "localhost"));
    if (!connected) co_return;
    auto connection = std::move(*connected);
    std::array<std::byte, 8> buffer {};
    for (std::size_t round = 0; round < control_rounds; ++round) {
        auto id = flatten_result(co_await connection.async_open_stream(
            quic_stream_direction::bidirectional));
        for (int retry = 0; !id && retry < 400; ++retry) {
            if (id.error() != make_error_code(quic_errc::stream_limit)) break;
            (void)co_await sleep_for(loop, 5ms);
            id = flatten_result(co_await connection.async_open_stream(
                quic_stream_direction::bidirectional));
        }
        if (!id || !flatten_result(co_await connection.async_write(*id, reply, false)))
            co_return;
        const auto read = flatten_result(co_await connection.async_read(*id, buffer));
        if (read || read.error() != make_error_code(quic_errc::stream_reset)) co_return;
        // The peer's STOP_SENDING turns local writes into stream_reset.
        bool stopped = false;
        for (int attempt = 0; attempt < 400 && !stopped; ++attempt) {
            const auto write = flatten_result(co_await connection.async_write(*id, reply, false));
            stopped = !write && write.error() == make_error_code(quic_errc::stream_reset);
            if (!stopped) (void)co_await sleep_for(loop, 5ms);
        }
        if (!stopped) co_return;
        ++result.client_rounds;
    }
    // A peer CONNECTION_CLOSE ends the connection without an idle timeout.
    const auto next = flatten_result(co_await connection.async_accept_stream());
    result.observed_at = event_loop::clock::now();
    result.client_saw_close = !next && result.server_closed;
}

auto control_watch(event_loop& loop, quic_endpoint& server, quic_endpoint& client,
                   control_outcome& result) -> task<void>
{
    for (int i = 0; i < 2000 && !result.client_saw_close; ++i)
        (void)co_await sleep_for(loop, 5ms);
    co_await server.async_close();
    co_await client.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

auto control_scenario(const std::filesystem::path& certificate) -> bool
{
    event_loop loop;
    quic_server_options server_options;
    server_options.certificate_chain = certificate / "cert.pem";
    server_options.private_key = certificate / "key.pem";
    server_options.alpn = protocol;
    quic_client_options client_options;
    client_options.alpn = protocol;
    client_options.trusted_ca = certificate / "cert.pem";
    quic_endpoint server(loop, ip_endpoint::loopback_v4(0), std::move(server_options));
    quic_endpoint client(loop, ip_endpoint::loopback_v4(0), std::move(client_options));
    control_outcome result;
    check(loop.spawn(control_server(loop, server, result)) == task_spawn_result::accepted,
          "spawn control server");
    check(loop.spawn(control_client(loop, client, server.local_endpoint(), result)) ==
              task_spawn_result::accepted, "spawn control client");
    check(loop.spawn(control_watch(loop, server, client, result)) ==
              task_spawn_result::accepted, "spawn control watch");
    (void)loop.run();
    check(result.server_rounds == control_rounds, "server stream reset and STOP_SENDING");
    check(result.client_rounds == control_rounds, "client observed reset and STOP_SENDING");
    check(result.client_saw_close &&
              result.observed_at - result.closed_at < std::chrono::seconds(2),
          "application CONNECTION_CLOSE reaches the peer");
    return true;
}

// Closing the server endpoint sends CONNECTION_CLOSE (NO_ERROR) on every
// connection before the socket closes, so peers do not wait for idle timeout.
struct shutdown_outcome {
    bool accepted {false};
    bool client_saw_close {false};
    event_loop::clock::time_point closed_at {};
    event_loop::clock::time_point observed_at {};
};

auto shutdown_server(event_loop& loop, quic_endpoint& server, shutdown_outcome& result)
    -> task<void>
{
    auto accepted = flatten_result(co_await server.async_accept());
    if (!accepted) co_return;
    result.accepted = true;
    (void)co_await sleep_for(loop, 20ms);
    result.closed_at = event_loop::clock::now();
    co_await server.async_close();
}

auto shutdown_client(event_loop&, quic_endpoint& client, ip_endpoint server,
                     shutdown_outcome& result) -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(server, "localhost"));
    if (!connected) co_return;
    auto connection = std::move(*connected);
    const auto next = flatten_result(co_await connection.async_accept_stream());
    result.observed_at = event_loop::clock::now();
    result.client_saw_close = !next;
}

auto shutdown_watch(event_loop& loop, quic_endpoint& client, shutdown_outcome& result)
    -> task<void>
{
    for (int i = 0; i < 1000 && !result.client_saw_close; ++i)
        (void)co_await sleep_for(loop, 5ms);
    co_await client.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

auto shutdown_scenario(const std::filesystem::path& certificate) -> bool
{
    event_loop loop;
    quic_server_options server_options;
    server_options.certificate_chain = certificate / "cert.pem";
    server_options.private_key = certificate / "key.pem";
    server_options.alpn = protocol;
    quic_client_options client_options;
    client_options.alpn = protocol;
    client_options.trusted_ca = certificate / "cert.pem";
    quic_endpoint server(loop, ip_endpoint::loopback_v4(0), std::move(server_options));
    quic_endpoint client(loop, ip_endpoint::loopback_v4(0), std::move(client_options));
    shutdown_outcome result;
    check(loop.spawn(shutdown_server(loop, server, result)) == task_spawn_result::accepted,
          "spawn shutdown server");
    check(loop.spawn(shutdown_client(loop, client, server.local_endpoint(), result)) ==
              task_spawn_result::accepted, "spawn shutdown client");
    check(loop.spawn(shutdown_watch(loop, client, result)) == task_spawn_result::accepted,
          "spawn shutdown watch");
    (void)loop.run();
    check(result.accepted, "shutdown scenario connected");
    check(result.client_saw_close &&
              result.observed_at - result.closed_at < std::chrono::seconds(2),
          "endpoint close reaches the peer");
    return true;
}

// Two server endpoints on separate loop threads share one port. Each client
// connection must be served end to end by whichever endpoint owns it.
constexpr std::size_t shared_port_clients = 12;
constexpr std::array<std::byte, 4> ping {std::byte {'p'}, std::byte {'i'},
                                         std::byte {'n'}, std::byte {'g'}};

auto shared_port_echo(event_loop&, quic_connection connection, std::atomic<std::size_t>& served)
    -> task<void>
{
    const auto stream = flatten_result(co_await connection.async_accept_stream());
    if (!stream) co_return;
    std::array<std::byte, 16> buffer {};
    std::size_t size = 0;
    for (;;) {
        const auto count = flatten_result(co_await connection.async_read(
            *stream, std::span(buffer).subspan(size)));
        if (!count) co_return;
        if (*count == 0) break;
        size += *count;
        if (size == buffer.size()) co_return;
    }
    const auto sent = flatten_result(co_await connection.async_write(
        *stream, std::span(buffer).first(size), true));
    if (sent && *sent == size) served.fetch_add(1);
    // Hold the connection until the client closes it.
    (void)co_await connection.async_accept_stream();
}

auto shared_port_accept(event_loop& loop, quic_endpoint& server,
                        std::atomic<std::size_t>& served) -> task<void>
{
    for (;;) {
        auto accepted = flatten_result(co_await server.async_accept());
        if (!accepted && accepted.error() == std::errc::operation_canceled) co_return;
        if (!accepted) {
            // A connection's own failure; pause so a persistent error fails
            // the scenario's checks instead of spinning here.
            (void)co_await sleep_for(loop, 1ms);
            continue;
        }
        if (loop.spawn(shared_port_echo(loop, std::move(*accepted), served)) !=
            task_spawn_result::accepted) co_return;
    }
}

auto shared_port_stop(event_loop& loop, quic_endpoint& server,
                      const std::atomic<bool>& done) -> task<void>
{
    while (!done.load()) (void)co_await sleep_for(loop, 5ms);
    co_await server.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

auto shared_port_client(event_loop&, quic_endpoint& client, ip_endpoint server,
                        std::size_t& completed) -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(server, "localhost"));
    if (!connected) co_return;
    auto connection = std::move(*connected);
    const auto stream = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!stream) { connection.close(); co_return; }
    const auto sent = flatten_result(co_await connection.async_write(*stream, ping, true));
    std::array<std::byte, 16> buffer {};
    std::size_t size = 0;
    while (sent && *sent == ping.size() && size < buffer.size()) {
        const auto count = flatten_result(co_await connection.async_read(
            *stream, std::span(buffer).subspan(size)));
        if (!count || *count == 0) break;
        size += *count;
    }
    if (size == ping.size() && std::ranges::equal(std::span(buffer).first(size), ping))
        ++completed;
    connection.close();
}

auto shared_port_watch(event_loop& loop,
                       std::array<std::unique_ptr<quic_endpoint>, shared_port_clients>& clients,
                       const std::size_t& completed) -> task<void>
{
    for (int i = 0; i < 1000 && completed < shared_port_clients; ++i)
        (void)co_await sleep_for(loop, 5ms);
    for (auto& client : clients) co_await client->async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

auto shared_port_scenario(const std::filesystem::path& certificate) -> bool
{
    std::atomic<std::uint16_t> port {0};
    std::atomic<std::size_t> ready {0};
    std::atomic<bool> failed {false};
    std::atomic<bool> done {false};
    std::array<std::atomic<std::size_t>, 2> served {};
    auto worker = [&](std::size_t index) {
        try {
            while (index != 0 && port.load() == 0 && !failed.load())
                std::this_thread::yield();
            if (failed.load()) return;
            event_loop loop;
            quic_server_options options;
            options.certificate_chain = certificate / "cert.pem";
            options.private_key = certificate / "key.pem";
            options.alpn = protocol;
            options.connection_capacity = 2 * shared_port_clients;
            options.reuse_port = true;
            quic_endpoint server(loop, ip_endpoint::loopback_v4(port.load()),
                                 std::move(options));
            port.store(server.local_endpoint().port);
            (void)loop.spawn(shared_port_accept(loop, server, served[index]));
            (void)loop.spawn(shared_port_stop(loop, server, done));
            ready.fetch_add(1);
            (void)loop.run();
        } catch (...) {
            failed.store(true);
        }
    };
    std::jthread first(worker, 0);
    std::jthread second(worker, 1);
    while (ready.load() < 2 && !failed.load()) std::this_thread::yield();

    std::size_t completed = 0;
    if (!failed.load()) {
        event_loop loop;
        std::array<std::unique_ptr<quic_endpoint>, shared_port_clients> clients;
        for (auto& client : clients) {
            quic_client_options options;
            options.alpn = protocol;
            options.trusted_ca = certificate / "cert.pem";
            client = std::make_unique<quic_endpoint>(
                loop, ip_endpoint::loopback_v4(0), std::move(options));
            (void)loop.spawn(shared_port_client(
                loop, *client, ip_endpoint::loopback_v4(port.load()), completed));
        }
        (void)loop.spawn(shared_port_watch(loop, clients, completed));
        (void)loop.run();
    }
    done.store(true);
    first.join();
    second.join();
    check(!failed.load(), "shared-port servers bind");
    check(completed == shared_port_clients, "every shared-port client is served");
    check(served[0].load() + served[1].load() == shared_port_clients,
          "each shared-port connection is served once");
#ifdef __linux__
    // Linux hashes the client addresses across both sockets.
    check(served[0].load() != 0 && served[1].load() != 0,
          "shared-port connections spread across servers");
#endif
    return true;
}

// A relay between client and server reads the source connection ID of every
// server long-header packet; each must start with the worker index.
constexpr std::uint8_t worker_index = 0xa7;

struct relay_outcome {
    std::size_t server_ids {0};
    bool all_indexed {true};
    bool served {false};
};

auto relay(event_loop&, udp_socket& socket, std::span<std::byte> buffer,
           std::uint16_t server_port, relay_outcome& result) -> task<void>
{
    ip_endpoint client {};
    for (;;) {
        const auto received = co_await socket.async_receive_from(buffer);
        if (!received) co_return;
        const auto datagram = buffer.first(received->size);
        const bool from_server = received->source.port == server_port;
        if (!from_server) client = received->source;
        // Long header: flags, version, DCID length + DCID, SCID length + SCID.
        if (from_server && datagram.size() > 6 &&
            (std::to_integer<unsigned>(datagram[0]) & 0x80U) != 0) {
            const auto dcid = std::to_integer<std::size_t>(datagram[5]);
            const auto scid_at = 6 + dcid;
            if (datagram.size() > scid_at + 1 &&
                std::to_integer<std::size_t>(datagram[scid_at]) != 0) {
                ++result.server_ids;
                result.all_indexed = result.all_indexed &&
                    std::to_integer<std::uint8_t>(datagram[scid_at + 1]) == worker_index;
            }
        }
        (void)co_await socket.async_send_to(
            datagram, from_server ? client : ip_endpoint::loopback_v4(server_port));
    }
}

auto indexed_server(event_loop& loop, quic_endpoint& server, relay_outcome& result)
    -> task<void>
{
    auto accepted = flatten_result(co_await server.async_accept());
    if (!accepted) co_return;
    std::atomic<std::size_t> served {0};
    co_await shared_port_echo(loop, std::move(*accepted), served);
    result.served = served.load() == 1;
}

template<typename Server>
auto indexed_watch(event_loop& loop, Server& server, quic_endpoint& client,
                   udp_socket& socket, const std::size_t& completed) -> task<void>
{
    for (int i = 0; i < 1000 && completed == 0; ++i)
        (void)co_await sleep_for(loop, 5ms);
    co_await client.async_close();
    co_await server.async_close();
    socket.close();
    loop.shutdown(event_loop::clock::duration::zero());
}

auto worker_index_scenario(const std::filesystem::path& certificate) -> bool
{
    event_loop loop;
    quic_server_options server_options;
    server_options.certificate_chain = certificate / "cert.pem";
    server_options.private_key = certificate / "key.pem";
    server_options.alpn = protocol;
    server_options.worker_index = worker_index;
    quic_client_options client_options;
    client_options.alpn = protocol;
    client_options.trusted_ca = certificate / "cert.pem";
    quic_endpoint server(loop, ip_endpoint::loopback_v4(0), std::move(server_options));
    quic_endpoint client(loop, ip_endpoint::loopback_v4(0), std::move(client_options));
    auto owned = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4(0));
    auto& socket = *owned;
    const auto relay_address = socket.local_endpoint();
    loop.add(std::move(owned));
    relay_outcome result;
    std::size_t completed = 0;
    std::vector<std::byte> buffer(65536);
    check(loop.spawn(relay(loop, socket, buffer, server.local_endpoint().port, result)) ==
              task_spawn_result::accepted, "spawn relay");
    check(loop.spawn(indexed_server(loop, server, result)) == task_spawn_result::accepted,
          "spawn indexed server");
    check(loop.spawn(shared_port_client(loop, client, relay_address, completed)) ==
              task_spawn_result::accepted, "spawn indexed client");
    check(loop.spawn(indexed_watch(loop, server, client, socket, completed)) ==
              task_spawn_result::accepted, "spawn indexed watch");
    (void)loop.run();
    check(completed == 1 && result.served, "indexed connection is served");
    check(result.server_ids != 0, "relay saw server connection IDs");
    check(result.all_indexed, "server connection IDs start with the worker index");
    return true;
}

auto h3_connect(event_loop&, quic_endpoint& client, ip_endpoint server,
                std::size_t& completed) -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(server, "localhost"));
    if (!connected) co_return;
    ++completed;
    connected->close();
}

auto http3_worker_index_scenario(const std::filesystem::path& certificate) -> bool
{
    static constexpr std::array<std::uint8_t, 2> h3 {'h', '3'};
    event_loop loop;
    http::http3_server server(loop, ip_endpoint::loopback_v4(0),
        certificate / "cert.pem", certificate / "key.pem",
        http::server_options {.document_root = certificate, .worker_index = worker_index});
    quic_client_options client_options;
    client_options.alpn = h3;
    client_options.trusted_ca = certificate / "cert.pem";
    quic_endpoint client(loop, ip_endpoint::loopback_v4(0), std::move(client_options));
    auto owned = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4(0));
    auto& socket = *owned;
    const auto relay_address = socket.local_endpoint();
    loop.add(std::move(owned));
    relay_outcome result;
    std::size_t completed = 0;
    std::vector<std::byte> buffer(65536);
    check(loop.spawn(relay(loop, socket, buffer, server.local_endpoint().port, result)) ==
              task_spawn_result::accepted, "spawn HTTP/3 relay");
    check(loop.spawn(server.run()) == task_spawn_result::accepted, "spawn HTTP/3 server");
    check(loop.spawn(h3_connect(loop, client, relay_address, completed)) ==
              task_spawn_result::accepted, "spawn HTTP/3 client");
    check(loop.spawn(indexed_watch(loop, server, client, socket, completed)) ==
              task_spawn_result::accepted, "spawn HTTP/3 watch");
    (void)loop.run();
    check(completed == 1, "HTTP/3 indexed connection completes");
    check(result.server_ids != 0, "relay saw HTTP/3 server connection IDs");
    check(result.all_indexed, "HTTP/3 server connection IDs start with the worker index");
    return true;
}

// NAT rebinding across workers: a relay moves the client's traffic to a new
// source port every round, so the kernel may hash it to the worker that does
// not own the connection. Every round must still complete an echo.
constexpr std::size_t rebind_rounds = 10;

struct rebind_relay {
    udp_socket* front {};               // client-facing, fixed
    udp_socket* back {};                // server-facing, replaced each round
    ip_endpoint client {};
    std::uint16_t server_port {};
    bool rebind {false};
    std::vector<std::vector<std::byte>> buffers;
};

auto rebind_back(event_loop&, rebind_relay& relay, udp_socket& socket,
                 std::span<std::byte> buffer) -> task<void>
{
    for (;;) {
        const auto received = co_await socket.async_receive_from(buffer);
        if (!received) co_return; // closed by a rebind
        (void)co_await relay.front->async_send_to(buffer.first(received->size), relay.client);
    }
}

// The only sender on the back socket, so a rebind happens between sends.
auto rebind_front(event_loop& loop, rebind_relay& relay) -> task<void>
{
    std::size_t generation = 0;
    for (;;) {
        const auto received = co_await relay.front->async_receive_from(relay.buffers[0]);
        if (!received) co_return;
        relay.client = received->source;
        if (relay.rebind || relay.back == nullptr) {
            relay.rebind = false;
            if (relay.back) relay.back->close();
            auto owned = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4(0));
            relay.back = owned.get();
            loop.add(std::move(owned));
            ++generation;
            check(generation < relay.buffers.size(), "rebind buffers");
            check(loop.spawn(rebind_back(loop, relay, *relay.back, relay.buffers[generation])) ==
                      task_spawn_result::accepted, "spawn rebind back pump");
        }
        (void)co_await relay.back->async_send_to(
            std::span(relay.buffers[0]).first(received->size),
            ip_endpoint::loopback_v4(relay.server_port));
    }
}

auto rebind_echo_server(event_loop&, quic_connection connection) -> task<void>
{
    for (;;) {
        const auto stream = flatten_result(co_await connection.async_accept_stream());
        if (!stream) co_return;
        std::array<std::byte, 16> buffer {};
        std::size_t size = 0;
        for (;;) {
            const auto count = flatten_result(co_await connection.async_read(
                *stream, std::span(buffer).subspan(size)));
            if (!count) co_return;
            if (*count == 0) break;
            size += *count;
            if (size == buffer.size()) co_return;
        }
        (void)co_await connection.async_write(*stream, std::span(buffer).first(size), true);
    }
}

auto rebind_accept(event_loop& loop, quic_endpoint& server) -> task<void>
{
    for (;;) {
        auto accepted = flatten_result(co_await server.async_accept());
        if (!accepted && accepted.error() == std::errc::operation_canceled) co_return;
        if (!accepted) {
            // A connection's own failure; pause so a persistent error fails
            // the scenario's checks instead of spinning here.
            (void)co_await sleep_for(loop, 1ms);
            continue;
        }
        if (loop.spawn(rebind_echo_server(loop, std::move(*accepted))) !=
            task_spawn_result::accepted) co_return;
    }
}

auto rebind_round(event_loop&, quic_connection& connection) -> task<bool>
{
    const auto stream = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!stream) co_return false;
    const auto sent = flatten_result(co_await connection.async_write(*stream, ping, true));
    if (!sent || *sent != ping.size()) co_return false;
    std::array<std::byte, 16> buffer {};
    std::size_t size = 0;
    while (size < buffer.size()) {
        const auto count = flatten_result(co_await connection.async_read(
            *stream, std::span(buffer).subspan(size)));
        if (!count) co_return false;
        if (*count == 0) break;
        size += *count;
    }
    co_return size == ping.size() && std::ranges::equal(std::span(buffer).first(size), ping);
}

auto rebind_client(event_loop& loop, quic_endpoint& client, rebind_relay& relay,
                   std::size_t& completed) -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(
        relay.front->local_endpoint(), "localhost"));
    if (connected) {
        auto connection = std::move(*connected);
        for (std::size_t round = 0; round < rebind_rounds; ++round) {
            // The first round confirms the handshake; RFC 9000 9 lets a
            // server drop packets from a new address before that.
            relay.rebind = round > 0;
            auto attempt = co_await with_timeout(loop, rebind_round(loop, connection), 3s);
            if (!(attempt && attempt->result && *attempt->result && **attempt->result)) break;
            ++completed;
        }
        connection.close();
    }
    co_await client.async_close();
    relay.front->close();
    if (relay.back) relay.back->close();
    loop.shutdown(event_loop::clock::duration::zero());
}

auto rebind_scenario(const std::filesystem::path& certificate, std::size_t workers) -> bool
{
    std::atomic<std::uint16_t> port {0};
    std::atomic<std::size_t> ready {0};
    std::atomic<bool> failed {false};
    std::atomic<bool> done {false};
    const auto group = std::make_shared<quic_worker_group>(workers);
    auto worker = [&](std::size_t index) {
        try {
            while (index != 0 && port.load() == 0 && !failed.load())
                std::this_thread::yield();
            if (failed.load()) return;
            event_loop loop;
            quic_server_options options;
            options.certificate_chain = certificate / "cert.pem";
            options.private_key = certificate / "key.pem";
            options.alpn = protocol;
            options.reuse_port = true;
            options.worker_index = static_cast<std::uint8_t>(index);
            options.worker_group = group;
            quic_endpoint server(loop, ip_endpoint::loopback_v4(port.load()),
                                 std::move(options));
            port.store(server.local_endpoint().port);
            (void)loop.spawn(rebind_accept(loop, server));
            (void)loop.spawn(shared_port_stop(loop, server, done));
            ready.fetch_add(1);
            (void)loop.run();
        } catch (...) {
            failed.store(true);
        }
    };
    std::vector<std::jthread> threads;
    for (std::size_t index = 0; index < workers; ++index) threads.emplace_back(worker, index);
    while (ready.load() < workers && !failed.load()) std::this_thread::yield();

    std::size_t completed = 0;
    if (!failed.load()) {
        event_loop loop;
        quic_client_options options;
        options.alpn = protocol;
        options.trusted_ca = certificate / "cert.pem";
        quic_endpoint client(loop, ip_endpoint::loopback_v4(0), std::move(options));
        rebind_relay relay;
        relay.server_port = port.load();
        relay.buffers.assign(rebind_rounds + 3, std::vector<std::byte>(65536));
        auto front = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4(0));
        relay.front = front.get();
        loop.add(std::move(front));
        check(loop.spawn(rebind_front(loop, relay)) == task_spawn_result::accepted,
              "spawn rebind front pump");
        check(loop.spawn(rebind_client(loop, client, relay, completed)) ==
                  task_spawn_result::accepted, "spawn rebind client");
        (void)loop.run();
    }
    done.store(true);
    threads.clear();
    check(!failed.load(), "rebind servers bind");
    std::fprintf(stderr, "rebind rounds with %zu workers: %zu of %zu\n", workers, completed,
                 rebind_rounds);
    check(completed == rebind_rounds, "connection survives rebinding across workers");
    return true;
}

auto close_then_stop(event_loop& loop, quic_endpoint& endpoint) -> task<void>
{
    co_await endpoint.async_close();
    loop.stop();
}

// Group sizes, missing or out-of-range indexes, and indexes held by an open
// endpoint are rejected; closing an endpoint frees its index.
auto worker_group_rules(const std::filesystem::path& certificate) -> bool
{
    const auto throws = [](auto&& make) {
        try { make(); } catch (const std::invalid_argument&) { return true; }
        return false;
    };
    check(throws([] { quic_worker_group group(0); }), "empty worker group");
    check(throws([] { quic_worker_group group(257); }), "oversized worker group");
    event_loop loop;
    const auto group = std::make_shared<quic_worker_group>(2);
    const auto options = [&](std::optional<std::uint8_t> index) {
        quic_server_options result;
        result.certificate_chain = certificate / "cert.pem";
        result.private_key = certificate / "key.pem";
        result.alpn = protocol;
        result.worker_index = index;
        result.worker_group = group;
        return result;
    };
    const auto make = [&](std::optional<std::uint8_t> index) {
        return std::make_unique<quic_endpoint>(loop, ip_endpoint::loopback_v4(0), options(index));
    };
    check(throws([&] { (void)make(std::nullopt); }), "worker group without an index");
    check(throws([&] { (void)make(2); }), "worker index outside its group");
    auto holder = make(1);
    check(throws([&] { (void)make(1); }), "worker index already held");
    check(loop.spawn(close_then_stop(loop, *holder)) == task_spawn_result::accepted,
          "spawn worker close");
    (void)loop.run();
    holder.reset();
    auto replacement = make(1);
    check(loop.spawn(close_then_stop(loop, *replacement)) == task_spawn_result::accepted,
          "spawn replacement close");
    (void)loop.run();
    return true;
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
    // Unique per process: concurrent runs must not delete each other's files.
    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-quic-public-" + std::to_string(std::random_device {}()));
    std::filesystem::create_directories(directory);
    if (!make_certificate(directory)) {
        std::fprintf(stderr, "certificate generation failed\n");
        return 1;
    }
    const bool v1 = scenario(quic_version::v1, directory);
    const bool v2 = scenario(quic_version::v2, directory);
    const bool small_v1 = scenario(quic_version::v1, directory, true);
    const bool small_v2 = scenario(quic_version::v2, directory, true);
    const bool control = control_scenario(directory);
    const bool shutdown = shutdown_scenario(directory);
    const bool indexed = worker_index_scenario(directory);
    const bool http3_indexed = http3_worker_index_scenario(directory);
    const bool group_rules = worker_group_rules(directory);
#ifdef __linux__
    const bool rebind = rebind_scenario(directory, 1) && rebind_scenario(directory, 2);
#else
    const bool rebind = true; // relies on the kernel spreading the shared port
#endif
#ifndef _WIN32
    const bool shared_port = shared_port_scenario(directory);
#else
    const bool shared_port = true; // SO_REUSEPORT is unavailable
#endif
    std::filesystem::remove_all(directory);
#ifdef _WIN32
    (void)WSACleanup();
#endif
    check(v1, "QUIC v1 public API scenario");
    check(v2, "QUIC v2 public API scenario");
    check(small_v1, "QUIC v1 small receive windows");
    check(small_v2, "QUIC v2 small receive windows");
    check(control, "QUIC stream control and application close");
    check(shutdown, "QUIC endpoint close notifies peers");
    check(indexed, "QUIC worker index in connection IDs");
    check(http3_indexed, "HTTP/3 worker index in connection IDs");
    check(rebind, "QUIC connection survives rebinding across workers");
    check(group_rules, "QUIC worker group validation");
    check(shared_port, "QUIC endpoints share a port across loops");
    std::puts("QUIC public API tests passed (v1 and v2)");
    return 0;
}
