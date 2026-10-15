// RESET_STREAM_AT end to end over loopback with real client and server
// endpoints: reliable prefix delivery before stream_reset, lowering the reliable
// size, one-sided transport parameter negotiation, invalid calls, the peer's
// reset, STOP_SENDING and final-size accessors, and peer datagram limits.
#include "eventloop/event_loop.h"
#include "eventloop/quic.h"
#include "eventloop/task_composition.h"

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
#include <string_view>
#include <vector>

namespace {

using namespace eventloop;
using namespace std::chrono_literals;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::fprintf(stderr, "QUIC RESET_STREAM_AT: %.*s\n",
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
    std::FILE* file = std::fopen(path.string().c_str(), "wb");
    if (file == nullptr) return false;
    const bool written_all = std::fwrite(data, 1, static_cast<std::size_t>(size), file) ==
        static_cast<std::size_t>(size);
    std::fclose(file);
    return written_all;
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
constexpr std::uint64_t reset_code = 0x2a;
constexpr std::uint64_t stop_code = 0x55;

// Deterministic payload, so the reader can check every byte it receives.
auto pattern(std::size_t size) -> std::vector<std::byte>
{
    std::vector<std::byte> bytes(size);
    for (std::size_t i = 0; i < size; ++i) bytes[i] = static_cast<std::byte>(i % 251);
    return bytes;
}

// One scenario's outcome. The first failure names the check that did not hold.
struct scenario {
    const char* failure {nullptr};
    bool server_done {false};
    bool client_done {false};
};

auto expect(scenario& s, bool ok, const char* where) -> bool
{
    if (!ok && s.failure == nullptr) s.failure = where;
    return ok;
}

// Reads until the peer's FIN (zero) or an error, appending the bytes read.
auto read_all(event_loop&, quic_connection& connection, std::uint64_t id,
              std::vector<std::byte>& out) -> task<std::error_code>
{
    std::array<std::byte, 256> buffer {};
    for (;;) {
        const auto count = flatten_result(co_await connection.async_read(id, buffer));
        if (!count) co_return count.error();
        if (*count == 0) co_return std::error_code {};
        out.insert(out.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*count));
    }
}

auto same_prefix(const std::vector<std::byte>& received, std::size_t size) -> bool
{
    const auto expected = pattern(size);
    return received.size() <= expected.size() &&
        std::equal(received.begin(), received.end(), expected.begin());
}

auto watch(event_loop& loop, quic_endpoint& server, quic_endpoint& client,
           scenario& s) -> task<void>
{
    for (int i = 0; i < 2000 && !s.failure && !(s.server_done && s.client_done); ++i)
        (void)co_await sleep_for(loop, 5ms);
    co_await server.async_close();
    co_await client.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

// Holds the connection open until the other side has finished its checks.
auto hold_until_server_done(event_loop& loop, scenario& s) -> task<void>
{
    for (int i = 0; i < 2000 && !s.server_done && !s.failure; ++i)
        (void)co_await sleep_for(loop, 1ms);
}

using server_body = task<void> (*)(event_loop&, quic_endpoint&, scenario&);
using client_body = task<void> (*)(event_loop&, quic_endpoint&, ip_endpoint, scenario&);

auto run(const char* name, const std::filesystem::path& certificate,
         quic_transport_limits server_limits, quic_transport_limits client_limits,
         server_body serve, client_body drive) -> bool
{
    event_loop loop;
    quic_server_options server_options;
    server_options.certificate_chain = certificate / "cert.pem";
    server_options.private_key = certificate / "key.pem";
    server_options.alpn = protocol;
    server_options.limits = server_limits;
    quic_client_options client_options;
    client_options.alpn = protocol;
    client_options.trusted_ca = certificate / "cert.pem";
    client_options.limits = client_limits;
    quic_endpoint server(loop, ip_endpoint::loopback_v4(0), std::move(server_options));
    quic_endpoint client(loop, ip_endpoint::loopback_v4(0), std::move(client_options));
    scenario s;
    check(loop.spawn(serve(loop, server, s)) == task_spawn_result::accepted, "spawn server");
    check(loop.spawn(drive(loop, client, server.local_endpoint(), s)) ==
              task_spawn_result::accepted, "spawn client");
    check(loop.spawn(watch(loop, server, client, s)) == task_spawn_result::accepted,
          "spawn watch");
    (void)loop.run();
    if (s.failure != nullptr) {
        std::fprintf(stderr, "QUIC RESET_STREAM_AT %s: %s\n", name, s.failure);
        return false;
    }
    if (!s.server_done || !s.client_done) {
        std::fprintf(stderr, "QUIC RESET_STREAM_AT %s: scenario did not finish\n", name);
        return false;
    }
    return true;
}

// Both sides advertise. The client writes 1500 bytes, then reliably resets with
// a 700-byte reliable prefix. The server reads at least that prefix, then
// stream_reset, and the codes and final size are visible synchronously.
auto prefix_server(event_loop& loop, quic_endpoint& server, scenario& s) -> task<void>
{
    auto accepted = flatten_result(co_await server.async_accept());
    if (!expect(s, accepted.has_value(), "server accept")) co_return;
    auto connection = std::move(*accepted);
    expect(s, connection.peer_reset_stream_at(), "server sees reset_stream_at");
    expect(s, connection.peer_max_datagram_frame_size() == 1232,
           "server sees peer datagram limit");
    auto id = flatten_result(co_await connection.async_accept_stream());
    if (!expect(s, id.has_value(), "server accept stream")) co_return;
    std::vector<std::byte> received;
    const auto error = (co_await read_all(loop, connection, *id, received))
        .value_or(make_error_code(quic_errc::not_connected));
    if (!expect(s, error == make_error_code(quic_errc::stream_reset), "read ends with stream_reset")) co_return;
    expect(s, received.size() >= 700 && same_prefix(received, received.size()),
           "reliable prefix delivered in order");
    expect(s, connection.stream_reset_code(*id) == reset_code, "reset code visible after read");
    const auto final_size = connection.stream_final_size(*id);
    expect(s, final_size && *final_size >= 700 && *final_size <= 1500,
           "final size visible after read");
    expect(s, !connection.stream_stop_sending_code(*id), "no STOP_SENDING from the client");
    // Both directions finish here, so the stream retires; its peer facts must survive that.
    (void)flatten_result(co_await connection.async_write(*id, {}, true));
    for (int i = 0; i < 40; ++i) (void)co_await sleep_for(loop, 5ms);
    expect(s, connection.stream_reset_code(*id) == reset_code,
           "reset code outlives retirement");
    expect(s, final_size && connection.stream_final_size(*id) == final_size,
           "final size outlives retirement");
    s.server_done = true;
}

auto prefix_client(event_loop& loop, quic_endpoint& client, ip_endpoint server, scenario& s)
    -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(server, "localhost"));
    if (!expect(s, connected.has_value(), "client connect")) co_return;
    auto connection = std::move(*connected);
    expect(s, connection.peer_reset_stream_at(), "client sees server advertisement");
    expect(s, connection.peer_max_datagram_frame_size() == 0,
           "client sees no server datagram limit");
    auto id = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!expect(s, id.has_value(), "client open")) co_return;
    const auto data = pattern(1500);
    const auto sent = flatten_result(co_await connection.async_write(*id, data, false));
    if (!expect(s, sent.has_value() && *sent == data.size(), "client write")) co_return;
    expect(s, connection.reset_stream_at(*id, reset_code, 700).has_value(),
           "reliable reset accepted");
    // Writes after a reliable reset fail as after reset_stream.
    const auto after = flatten_result(co_await connection.async_write(*id, data, false));
    expect(s, !after && after.error() == make_error_code(quic_errc::stream_reset),
           "write after reliable reset");
    co_await hold_until_server_done(loop, s);
    s.client_done = true;
}

// The client lowers its reliable size, rejects a raise, a code change, and
// data it has not written, then writes after the reset.
auto lowering_server(event_loop& loop, quic_endpoint& server, scenario& s) -> task<void>
{
    auto accepted = flatten_result(co_await server.async_accept());
    if (!expect(s, accepted.has_value(), "lowering accept")) co_return;
    auto connection = std::move(*accepted);
    auto id = flatten_result(co_await connection.async_accept_stream());
    if (!expect(s, id.has_value(), "lowering accept stream")) co_return;
    std::vector<std::byte> received;
    const auto error = (co_await read_all(loop, connection, *id, received))
        .value_or(make_error_code(quic_errc::not_connected));
    expect(s, error == make_error_code(quic_errc::stream_reset), "lowering ends with stream_reset");
    expect(s, received.size() >= 300 && same_prefix(received, received.size()),
           "lowered reliable prefix delivered");
    expect(s, connection.stream_reset_code(*id) == reset_code, "lowering reset code");
    s.server_done = true;
}

auto lowering_client(event_loop& loop, quic_endpoint& client, ip_endpoint server, scenario& s)
    -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(server, "localhost"));
    if (!expect(s, connected.has_value(), "lowering connect")) co_return;
    auto connection = std::move(*connected);
    auto id = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!expect(s, id.has_value(), "lowering open")) co_return;
    const auto data = pattern(600);
    const auto sent = flatten_result(co_await connection.async_write(*id, data, false));
    if (!expect(s, sent.has_value() && *sent == data.size(), "lowering write")) co_return;
    expect(s, connection.reset_stream_at(*id, reset_code, 500).has_value(), "first reset");
    expect(s, connection.reset_stream_at(*id, reset_code, 300).has_value(), "lowering reset");
    expect(s, connection.reset_stream_at(*id, reset_code, 400) ==
               std::unexpected(make_error_code(quic_errc::invalid_argument)),
           "raising the reliable size is refused");
    expect(s, connection.reset_stream_at(*id, reset_code + 1, 100) ==
               std::unexpected(make_error_code(quic_errc::invalid_argument)),
           "changing the error code is refused");
    expect(s, connection.reset_stream_at(*id, reset_code, 900) ==
               std::unexpected(make_error_code(quic_errc::invalid_argument)),
           "a reliable size beyond the accepted bytes is refused");
    co_await hold_until_server_done(loop, s);
    s.client_done = true;
}

// The server advertises reset_stream_at, the client does not. The server may not
// send RESET_STREAM_AT, but the client may send it to the server.
auto one_sided_server(event_loop& loop, quic_endpoint& server, scenario& s) -> task<void>
{
    auto accepted = flatten_result(co_await server.async_accept());
    if (!expect(s, accepted.has_value(), "one-sided accept")) co_return;
    auto connection = std::move(*accepted);
    expect(s, !connection.peer_reset_stream_at(), "client did not advertise");
    auto opened = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!expect(s, opened.has_value(), "one-sided server open")) co_return;
    expect(s, connection.reset_stream_at(*opened, reset_code, 0) ==
               std::unexpected(make_error_code(quic_errc::invalid_state)),
           "server may not send RESET_STREAM_AT to a peer that did not advertise");
    auto id = flatten_result(co_await connection.async_accept_stream());
    if (!expect(s, id.has_value(), "one-sided accept stream")) co_return;
    std::vector<std::byte> received;
    const auto error = (co_await read_all(loop, connection, *id, received))
        .value_or(make_error_code(quic_errc::not_connected));
    expect(s, error == make_error_code(quic_errc::stream_reset), "one-sided stream_reset");
    expect(s, connection.stream_reset_code(*id) == reset_code, "one-sided reset code");
    s.server_done = true;
}

auto one_sided_client(event_loop& loop, quic_endpoint& client, ip_endpoint server, scenario& s)
    -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(server, "localhost"));
    if (!expect(s, connected.has_value(), "one-sided connect")) co_return;
    auto connection = std::move(*connected);
    expect(s, connection.peer_reset_stream_at(), "server advertised");
    auto id = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!expect(s, id.has_value(), "one-sided open")) co_return;
    const auto data = pattern(100);
    const auto sent = flatten_result(co_await connection.async_write(*id, data, false));
    if (!expect(s, sent.has_value() && *sent == data.size(), "one-sided write")) co_return;
    expect(s, connection.reset_stream_at(*id, reset_code, 50).has_value(),
           "client may send RESET_STREAM_AT");
    co_await hold_until_server_done(loop, s);
    s.client_done = true;
}

// A reliable size beyond the accepted bytes is refused; the exact size is accepted.
auto bounds_server(event_loop& loop, quic_endpoint& server, scenario& s) -> task<void>
{
    auto accepted = flatten_result(co_await server.async_accept());
    if (!expect(s, accepted.has_value(), "bounds accept")) co_return;
    auto connection = std::move(*accepted);
    auto id = flatten_result(co_await connection.async_accept_stream());
    if (!expect(s, id.has_value(), "bounds accept stream")) co_return;
    std::vector<std::byte> received;
    const auto error = (co_await read_all(loop, connection, *id, received))
        .value_or(make_error_code(quic_errc::not_connected));
    expect(s, error == make_error_code(quic_errc::stream_reset), "bounds stream_reset");
    expect(s, received.size() == 10 && same_prefix(received, received.size()),
           "exact reliable prefix of ten bytes");
    const auto final_size = connection.stream_final_size(*id);
    expect(s, final_size == std::optional<std::uint64_t> {10}, "final size equals the prefix");
    s.server_done = true;
}

auto bounds_client(event_loop& loop, quic_endpoint& client, ip_endpoint server, scenario& s)
    -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(server, "localhost"));
    if (!expect(s, connected.has_value(), "bounds connect")) co_return;
    auto connection = std::move(*connected);
    auto id = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!expect(s, id.has_value(), "bounds open")) co_return;
    const auto data = pattern(10);
    const auto sent = flatten_result(co_await connection.async_write(*id, data, false));
    if (!expect(s, sent.has_value() && *sent == data.size(), "bounds write")) co_return;
    expect(s, connection.reset_stream_at(*id, reset_code, 11) ==
               std::unexpected(make_error_code(quic_errc::invalid_argument)),
           "reliable size beyond accepted bytes refused");
    expect(s, connection.reset_stream_at(*id, reset_code, 10).has_value(),
           "reliable size equal to accepted bytes accepted");
    co_await hold_until_server_done(loop, s);
    s.client_done = true;
}

// The server stops the client's stream. The client's write fails with
// stream_reset, and the STOP_SENDING code is visible right after that.
auto stop_server(event_loop& loop, quic_endpoint& server, scenario& s) -> task<void>
{
    auto accepted = flatten_result(co_await server.async_accept());
    if (!expect(s, accepted.has_value(), "stop accept")) co_return;
    auto connection = std::move(*accepted);
    auto id = flatten_result(co_await connection.async_accept_stream());
    if (!expect(s, id.has_value(), "stop accept stream")) co_return;
    expect(s, connection.stop_sending(*id, stop_code).has_value(), "stop_sending");
    for (int i = 0; i < 400 && !s.client_done; ++i) (void)co_await sleep_for(loop, 5ms);
    s.server_done = true;
}

auto stop_client(event_loop& loop, quic_endpoint& client, ip_endpoint server, scenario& s)
    -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(server, "localhost"));
    if (!expect(s, connected.has_value(), "stop connect")) co_return;
    auto connection = std::move(*connected);
    auto id = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!expect(s, id.has_value(), "stop open")) co_return;
    const std::array<std::byte, 16> chunk {};
    bool stopped = false;
    for (int attempt = 0; attempt < 400 && !stopped; ++attempt) {
        const auto write = flatten_result(co_await connection.async_write(*id, chunk, false));
        stopped = !write && write.error() == make_error_code(quic_errc::stream_reset);
        if (!stopped) (void)co_await sleep_for(loop, 5ms);
    }
    expect(s, stopped, "write fails after peer STOP_SENDING");
    expect(s, connection.stream_stop_sending_code(*id) == stop_code,
           "STOP_SENDING code visible after write");
    expect(s, !connection.stream_reset_code(*id), "no peer reset on a stopped send side");
    s.client_done = true;
}

// A FIN fixes the final size, visible once the reader sees end of stream.
auto final_server(event_loop& loop, quic_endpoint& server, scenario& s) -> task<void>
{
    auto accepted = flatten_result(co_await server.async_accept());
    if (!expect(s, accepted.has_value(), "final accept")) co_return;
    auto connection = std::move(*accepted);
    auto id = flatten_result(co_await connection.async_accept_stream());
    if (!expect(s, id.has_value(), "final accept stream")) co_return;
    std::vector<std::byte> received;
    const auto error = (co_await read_all(loop, connection, *id, received))
        .value_or(make_error_code(quic_errc::not_connected));
    expect(s, !error && received.size() == 333 && same_prefix(received, received.size()),
           "FIN delivers all bytes");
    expect(s, connection.stream_final_size(*id) == std::optional<std::uint64_t> {333},
           "final size visible after FIN");
    expect(s, !connection.stream_reset_code(*id), "no reset code after FIN");
    s.server_done = true;
}

auto final_client(event_loop& loop, quic_endpoint& client, ip_endpoint server, scenario& s)
    -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(server, "localhost"));
    if (!expect(s, connected.has_value(), "final connect")) co_return;
    auto connection = std::move(*connected);
    auto id = flatten_result(co_await connection.async_open_stream(
        quic_stream_direction::bidirectional));
    if (!expect(s, id.has_value(), "final open")) co_return;
    const auto data = pattern(333);
    const auto sent = flatten_result(co_await connection.async_write(*id, data, true));
    expect(s, sent.has_value() && *sent == data.size(), "final write with FIN");
    co_await hold_until_server_done(loop, s);
    s.client_done = true;
}

// Transport limits for one endpoint: its reset_stream_at advertisement and its
// max_datagram_frame_size, which the peer reads back.
auto with_limits(bool reset_at, std::uint64_t datagram) -> quic_transport_limits
{
    quic_transport_limits limits;
    limits.reset_stream_at = reset_at;
    limits.max_datagram_frame_size = datagram;
    return limits;
}

} // namespace

auto main() -> int
{
    const auto directory = std::filesystem::temp_directory_path() / "eventloop-quic-reset-stream-at";
    std::filesystem::create_directories(directory);
    if (!make_certificate(directory)) {
        std::fprintf(stderr, "QUIC RESET_STREAM_AT: certificate generation failed\n");
        return 1;
    }
    const auto both = with_limits(true, 0);
    const bool prefix = run("prefix", directory, with_limits(true, 0),
                            with_limits(true, 1232), prefix_server, prefix_client);
    const bool lowering = run("lowering", directory, both, both, lowering_server, lowering_client);
    const bool one_sided = run("one_sided", directory, with_limits(true, 0),
                               with_limits(false, 0), one_sided_server, one_sided_client);
    const bool bounds = run("bounds", directory, both, both, bounds_server, bounds_client);
    const bool stopped = run("stop_sending", directory, both, both, stop_server, stop_client);
    const bool final_size = run("final_size", directory, both, both, final_server, final_client);
    std::filesystem::remove_all(directory);
    if (!(prefix && lowering && one_sided && bounds && stopped && final_size))
        return 1;
    std::puts("QUIC RESET_STREAM_AT tests passed");
    return 0;
}
