#include "eventloop/tls_stream.h"
#include "tls_test_certificate.h"

#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <csignal>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

using namespace eventloop;
namespace {
thread_local bool count_allocations = false;
thread_local std::size_t allocation_count = 0;
thread_local std::size_t allocation_bytes = 0;
thread_local std::size_t largest_allocation = 0;
thread_local std::size_t record_buffers = 0;
constexpr std::size_t record_size = 16384;
auto track(std::size_t size) -> void
{
    if (!count_allocations) return;
    ++allocation_count;
    allocation_bytes += size;
    // Record buffers are freed once drained and allocated for the next record.
    if (size >= record_size) ++record_buffers;
    else largest_allocation = std::max(largest_allocation, size);
}
auto tracked_malloc(std::size_t size, const char*, int) -> void*
{
    track(size);
    return std::malloc(size);
}
auto tracked_realloc(void* pointer, std::size_t size, const char*, int) -> void*
{
    track(size);
    return std::realloc(pointer, size);
}
auto tracked_free(void* pointer, const char*, int) -> void { std::free(pointer); }
constexpr std::size_t rounds = 32;

auto receive_records(event_loop& loop, tls_stream& peer, bool& passed) -> task<void>
{
    auto handshake = flatten_result(co_await peer.async_handshake());
    if (!handshake) { peer.close(); loop.stop(); co_return; }
    // A maximum-size peer record must drain through tiny caller spans without
    // a plaintext spill allocation. Warm the crypto/record contexts first.
    std::array<std::byte, 317> buffer {};
    bool valid = true;
    for (std::size_t round = 0; round < rounds && valid; ++round) {
        std::size_t total = 0;
        count_allocations = round > 0;
        while (total < record_size) {
            const auto result = flatten_result(co_await peer.async_read_some(buffer));
            if (!result || *result == 0 || *result > record_size - total) { valid = false; break; }
            for (std::size_t i = 0; i < *result; ++i)
                valid = valid && buffer[i] == static_cast<std::byte>((total + i + round) % 251);
            total += *result;
        }
        const std::array<std::byte, 1> ack {std::byte {'a'}};
        const auto sent = flatten_result(co_await peer.async_write_some(ack));
        count_allocations = false;
        valid = valid && sent && *sent == 1;
    }
    const auto eof = flatten_result(co_await peer.async_read_some(buffer));
    passed = valid && eof && *eof == 0;
    peer.close();
    loop.stop();
}

auto run(const std::filesystem::path& certificate, const std::filesystem::path& key,
         int version) -> bool
{
    unique_fd listener(::socket(AF_INET, SOCK_STREAM, 0));
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof(address);
    if (!listener || ::bind(listener.get(), reinterpret_cast<sockaddr*>(&address), length) != 0 ||
        ::listen(listener.get(), 1) != 0 ||
        ::getsockname(listener.get(), reinterpret_cast<sockaddr*>(&address), &length) != 0) return false;
    unique_fd client_fd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!client_fd || ::connect(client_fd.get(), reinterpret_cast<sockaddr*>(&address), length) != 0) return false;
    unique_fd server_fd(::accept(listener.get(), nullptr, nullptr));
    if (!server_fd) return false;
    bool server_ok = false;
    std::jthread server([&, descriptor = std::move(server_fd)] {
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx {SSL_CTX_new(TLS_method()), SSL_CTX_free};
        if (!ctx || SSL_CTX_set_min_proto_version(ctx.get(), version) != 1 ||
            SSL_CTX_set_max_proto_version(ctx.get(), version) != 1 ||
            SSL_CTX_use_certificate_chain_file(ctx.get(), certificate.string().c_str()) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx.get(), key.string().c_str(), SSL_FILETYPE_PEM) != 1) return;
        SSL_CTX_set_num_tickets(ctx.get(), 0);
        std::unique_ptr<SSL, decltype(&SSL_free)> ssl {SSL_new(ctx.get()), SSL_free};
        if (!ssl || SSL_set_fd(ssl.get(), descriptor.get()) != 1 || SSL_accept(ssl.get()) != 1) return;
        std::array<std::byte, record_size> payload {};
        for (std::size_t round = 0; round < rounds; ++round) {
            for (std::size_t i = 0; i < payload.size(); ++i)
                payload[i] = static_cast<std::byte>((i + round) % 251);
            std::size_t written = 0;
            if (SSL_write_ex(ssl.get(), payload.data(), payload.size(), &written) != 1 || written != payload.size()) return;
            char ack = 0;
            if (SSL_read(ssl.get(), &ack, 1) != 1 || ack != 'a') return;
        }
        server_ok = SSL_shutdown(ssl.get()) >= 0;
    });
    event_loop loop;
    auto stream = std::make_unique<tls_stream>(loop, std::move(client_fd),
        tls_context::make_client(certificate),
        tls_client_options {.hostname = "localhost", .application_protocols = {}});
    auto* peer = stream.get();
    loop.add(std::move(stream));
    bool passed = false;
    allocation_count = allocation_bytes = largest_allocation = record_buffers = 0;
    if (loop.spawn(receive_records(loop, *peer, passed)) != task_spawn_result::accepted) {
        peer->close(); return false;
    }
    (void)loop.run();
    server.join();
    std::cout << (version == TLS1_2_VERSION ? "TLS 1.2" : "TLS 1.3")
              << ": " << allocation_count << " OpenSSL allocations (" << allocation_bytes
              << " bytes, " << record_buffers << " record buffers, largest other "
              << largest_allocation << " bytes) over " << rounds - 1 << " warm record exchanges\n";
    // Each exchange allocates at most two read buffers (one for the peer's
    // record, one for the read that follows it) and one write buffer for the
    // acknowledgement. Other OpenSSL packet metadata
    // may allocate; in OpenSSL 3.5 these are 40-byte WPACKET subpacket
    // objects, observed through the allocator hooks above.
    return passed && server_ok && record_buffers <= 3 * (rounds - 1) &&
           largest_allocation < 4096 &&
           loop.coroutine_statistics().live == 0;
}
} // namespace

auto check_credentials(const std::filesystem::path& directory) -> void
{
    const auto certificate = directory / "cert.pem";
    const auto key = directory / "key.pem";
    const auto encrypted_key = directory / "encrypted.pem";
    std::unique_ptr<BIO, decltype(&BIO_free)> input {
        BIO_new_file(key.string().c_str(), "rb"), BIO_free};
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> private_key {
        input ? PEM_read_bio_PrivateKey(input.get(), nullptr, nullptr, nullptr) : nullptr, EVP_PKEY_free};
    std::unique_ptr<BIO, decltype(&BIO_free)> output {
        BIO_new_file(encrypted_key.string().c_str(), "wb"), BIO_free};
    unsigned char password[] = "test-password";
    if (!private_key || !output || PEM_write_bio_PrivateKey(output.get(), private_key.get(),
        EVP_aes_256_cbc(), password, sizeof(password) - 1, nullptr, nullptr) != 1 || BIO_flush(output.get()) != 1)
        throw std::runtime_error("write encrypted TLS test key");
    output.reset();
    (void)tls_context::make_server(certificate, encrypted_key, "test-password");
    for (const auto pass : {std::string_view {}, std::string_view {"wrong-password"}}) {
        bool rejected = false;
        try { (void)tls_context::make_server(certificate, encrypted_key, pass); }
        catch (const std::invalid_argument&) { rejected = true; }
        if (!rejected) throw std::runtime_error("encrypted TLS key accepted invalid password");
    }
    const auto other_certificate = directory / "other-cert.pem";
    const auto other_key = directory / "other-key.pem";
    eventloop::test::make_localhost_certificate(other_certificate, other_key);
    bool rejected = false;
    try { (void)tls_context::make_server(certificate, other_key); }
    catch (const std::invalid_argument&) { rejected = true; }
    if (!rejected) throw std::runtime_error("TLS certificate accepted mismatched key");
}

auto main() -> int
{
    if (CRYPTO_set_mem_functions(tracked_malloc, tracked_realloc, tracked_free) != 1) return 1;
    std::signal(SIGPIPE, SIG_IGN);
    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-openssl-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    struct directory_guard {
        std::filesystem::path path;
        ~directory_guard() { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
    } guard {directory};
    try {
        std::filesystem::create_directory(directory);
        const auto certificate = directory / "cert.pem";
        const auto key = directory / "key.pem";
        eventloop::test::make_localhost_certificate(certificate, key);
        check_credentials(directory);
        return run(certificate, key, TLS1_2_VERSION) && run(certificate, key, TLS1_3_VERSION) ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
