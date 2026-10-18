// Minimal loop-affine QUIC echo server used to exercise the public API against
// an independent stack (for example `openssl s_client -quic`).
//
// Usage: quic_echo_server <port> <certificate.pem> <key.pem> <alpn>
#include "eventloop/quic.h"
#include "eventloop/event_loop.h"
#include "eventloop/util/arg_parser.h"
#include "port.h"

#include <array>
#include <cstddef>
#include <cstdio>
#include <span>
#include <string_view>

namespace {

using namespace eventloop;


auto serve(event_loop& loop, quic_endpoint& endpoint,
           std::span<std::byte> buffer) -> task<void>
{
    auto accepted = flatten_result(co_await endpoint.async_accept());
    if (!accepted) {
        std::fprintf(stderr, "accept failed\n");
        co_await endpoint.async_close();
        loop.shutdown(event_loop::clock::duration::zero());
        co_return;
    }
    auto connection = std::move(*accepted);
    std::fprintf(stderr, "connection established\n");
    for (;;) {
        auto id = flatten_result(co_await connection.async_accept_stream());
        if (!id) break;
        std::fprintf(stderr, "stream %llu accepted\n",
                     static_cast<unsigned long long>(*id));
        for (;;) {
            auto count = flatten_result(co_await connection.async_read(*id, buffer));
            if (!count || *count == 0) break;
            std::fwrite(buffer.data(), 1, *count, stdout);
            std::fflush(stdout);
            (void)flatten_result(co_await connection.async_write(*id,
                std::span(buffer).first(*count), false));
        }
        (void)flatten_result(co_await connection.async_write(*id, {}, true));
        std::fprintf(stderr, "stream closed\n");
    }
    connection.close();
    co_await endpoint.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

} // namespace

auto main(int argc, char** argv) -> int
{
    std::uint16_t port = 0;
    std::string certificate, private_key, alpn;
    const std::array positionals {
        arg_parser::positional {"PORT", basics::port_argument(port), true},
        arg_parser::positional {"CERTIFICATE", &certificate, true},
        arg_parser::positional {"PRIVATE-KEY", &private_key, true},
        arg_parser::positional {"ALPN", &alpn, true},
    };
    arg_parser arguments({}, positionals);
    arguments.set_usage("usage: quic_echo_server <port> <cert.pem> <key.pem> <alpn>\n");
    try {
        arguments.parse(argc, argv);
    } catch (const std::invalid_argument& error) {
        std::fprintf(stderr, "quic_echo_server: %s\n", error.what());
        return 2;
    }

    event_loop loop;
    quic_server_options options;
    options.certificate_chain = certificate;
    options.private_key = private_key;
    options.alpn = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(alpn.data()), alpn.size());
    options.limits.max_datagram_frame_size = 1200;

    quic_endpoint endpoint(loop, ip_endpoint::loopback_v4(port),
                           std::move(options));
    std::array<std::byte, 512> buffer {};
    if (loop.spawn(serve(loop, endpoint, buffer)) != task_spawn_result::accepted)
        return 1;
    (void)loop.run();
    return 0;
}
