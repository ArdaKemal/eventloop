#include "eventloop/event_loop.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"

#include <charconv>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace {
class echo_session final : public tcp_stream {
public:
    using tcp_stream::tcp_stream;

private:
    auto on_data(std::span<const std::byte> data) -> void override
    {
        write(data);
    }
};

class echo_acceptor final : public tcp_acceptor {
public:
    using tcp_acceptor::tcp_acceptor;

private:
    auto on_accept(int descriptor) -> void override
    {
        owner().add(std::make_unique<echo_session>(owner(), descriptor));
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
    try {
        const auto port = argc > 1 ? parse_port(argv[1]) : std::uint16_t {7000};
        event_loop loop;
        loop.add(std::make_unique<echo_acceptor>(loop, port));
        std::cout << "echo server listening on 127.0.0.1:" << port << '\n';
        loop.run();
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
