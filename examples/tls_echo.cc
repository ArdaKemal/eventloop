#include "eventloop/event_loop.h"
#include "eventloop/tls_acceptor.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"

#include <charconv>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace {
class echo_session final : public tls_stream {
public:
    using tls_stream::tls_stream;

private:
    auto on_data(std::span<const std::byte> data) -> void override
    {
        write(data);
    }
};

class echo_acceptor final : public tls_acceptor {
public:
    using tls_acceptor::tls_acceptor;

private:
    auto make_stream(int descriptor) -> std::unique_ptr<tls_stream> override
    {
        return std::make_unique<echo_session>(
            owner(), descriptor, context(),
            tls_server_options {.application_protocols = {"echo"}});
    }
};

[[nodiscard]] auto parse_port(std::string_view text) -> std::uint16_t
{
    unsigned int port = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
    if (error != std::errc {} || end != text.data() + text.size() || port == 0 ||
        port > 65535) {
        throw std::invalid_argument("port must be between 1 and 65535");
    }
    return static_cast<std::uint16_t>(port);
}
} // namespace

auto main(int argc, char* argv[]) -> int
{
    if (argc < 3 || argc > 4) {
        std::cerr << "usage: tls_echo <certificate-chain.pem> <private-key.pem> [port]\n";
        return 1;
    }

    try {
        const auto port = argc == 4 ? parse_port(argv[3]) : std::uint16_t {7443};
        auto context = tls_context::make_server(argv[1], argv[2]);
        event_loop loop;
        loop.add(std::make_unique<echo_acceptor>(loop, port, std::move(context)));
        std::cout << "TLS echo server listening on 127.0.0.1:" << port << '\n';
        loop.run();
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
