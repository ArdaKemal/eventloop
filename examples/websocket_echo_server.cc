#include "eventloop/event_loop.h"
#include "eventloop/task.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/ws/web_socket.h"
#include "eventloop/util/arg_parser.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

using namespace eventloop;

namespace {
constexpr std::string_view websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr std::size_t maximum_request_size = 8192;

[[nodiscard]] auto trim(std::string_view value) -> std::string_view
{
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    return value;
}

[[nodiscard]] auto equal_ci(std::string_view left, std::string_view right) -> bool
{
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0; i < left.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(left[i])) !=
            std::tolower(static_cast<unsigned char>(right[i]))) return false;
    }
    return true;
}

[[nodiscard]] auto has_token(std::string_view value, std::string_view token) -> bool
{
    while (!value.empty()) {
        const auto comma = value.find(',');
        if (equal_ci(trim(value.substr(0, comma)), token)) return true;
        if (comma == std::string_view::npos) break;
        value.remove_prefix(comma + 1);
    }
    return false;
}

[[nodiscard]] auto accept_key(std::string_view key) -> std::string
{
    if (key.size() != 24 || key.substr(22) != "==") return {};
    std::array<unsigned char, 18> decoded {};
    if (EVP_DecodeBlock(decoded.data(),
                        reinterpret_cast<const unsigned char*>(key.data()),
                        static_cast<int>(key.size())) != 18) return {};

    std::string source(key);
    source += websocket_guid;
    std::array<unsigned char, SHA_DIGEST_LENGTH> digest {};
    if (SHA1(reinterpret_cast<const unsigned char*>(source.data()), source.size(),
             digest.data()) == nullptr) return {};
    std::array<unsigned char, 4 * ((SHA_DIGEST_LENGTH + 2) / 3) + 1> encoded {};
    const auto size = EVP_EncodeBlock(encoded.data(), digest.data(), SHA_DIGEST_LENGTH);
    return {reinterpret_cast<const char*>(encoded.data()), static_cast<std::size_t>(size)};
}

[[nodiscard]] auto response_for(std::string_view request) -> std::string
{
    const auto first_end = request.find("\r\n");
    if (first_end == std::string_view::npos ||
        request.substr(0, first_end) != "GET / HTTP/1.1") return {};
    bool upgrade = false;
    bool connection = false;
    bool version = false;
    std::string accept;
    auto position = first_end + 2;
    while (position < request.size()) {
        const auto end = request.find("\r\n", position);
        if (end == std::string_view::npos || end == position) break;
        const auto line = request.substr(position, end - position);
        const auto colon = line.find(':');
        if (colon == std::string_view::npos) return {};
        const auto name = line.substr(0, colon);
        const auto value = trim(line.substr(colon + 1));
        if (equal_ci(name, "upgrade")) upgrade = has_token(value, "websocket");
        else if (equal_ci(name, "connection")) connection = has_token(value, "upgrade");
        else if (equal_ci(name, "sec-websocket-version")) version = value == "13";
        else if (equal_ci(name, "sec-websocket-key")) accept = accept_key(value);
        position = end + 2;
    }
    if (!upgrade || !connection || !version || accept.empty()) return {};
    return "HTTP/1.1 101 Switching Protocols\r\n"
           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
           "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
}

[[nodiscard]] auto session(event_loop& loop, tcp_stream& stream) -> task<void>
{
    std::string request;
    request.reserve(1024);
    std::array<std::byte, 1> byte {};
    while (request.size() < maximum_request_size && !request.ends_with("\r\n\r\n")) {
        const auto read = co_await stream.async_read_some(byte);
        if (!read || *read == 0) { stream.close(); co_return; }
        request.push_back(static_cast<char>(byte[0]));
    }
    const auto response = response_for(request);
    if (response.empty()) { stream.close(); co_return; }
    std::size_t offset = 0;
    while (offset < response.size()) {
        const auto written = co_await stream.async_write_some(
            {reinterpret_cast<const std::byte*>(response.data() + offset),
             response.size() - offset});
        if (!written || *written == 0) { stream.close(); co_return; }
        offset += *written;
    }

    auto socket = std::make_unique<ws::web_socket<tcp_stream>>(loop, stream);
    for (;;) {
        const auto received = co_await socket->async_receive();
        if (!received || !*received) break;
        const auto& message = **received;
        if (message.type == ws::message_type::close) break;
        if (message.type == ws::message_type::text) {
            const auto text = std::u8string_view {
                reinterpret_cast<const char8_t*>(message.payload.data()),
                message.payload.size()};
            const auto sent = co_await socket->async_send_text(text);
            if (!sent || !*sent) break;
        } else if (message.type == ws::message_type::binary) {
            const auto sent = co_await socket->async_send_binary(message.payload);
            if (!sent || !*sent) break;
        }
    }
    stream.close();
}

[[nodiscard]] auto serve(event_loop& loop, tcp_acceptor& listener) -> task<void>
{
    for (;;) {
        auto accepted = co_await listener.async_accept();
        if (!accepted) co_return;
        auto stream = std::make_unique<tcp_stream>(loop, std::move(*accepted));
        auto* active = stream.get();
        loop.add(std::move(stream));
        if (loop.spawn(session(loop, *active)) != task_spawn_result::accepted) {
            std::cerr << "WebSocket session capacity exhausted\n";
            active->close();
        }
    }
}

[[nodiscard]] auto parse_port(std::string_view text) -> std::uint16_t
{
    unsigned int port = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
    if (error != std::errc {} || end != text.data() + text.size() || port == 0 ||
        port > 65535) throw std::invalid_argument("port must be between 1 and 65535");
    return static_cast<std::uint16_t>(port);
}
} // namespace

auto main(int argc, char* argv[]) -> int
{
    try {
        std::uint16_t port = 7001;
        const std::array positionals {arg_parser::positional {"PORT",
            arg_parser::value_handler([&port](std::string_view value) { port = parse_port(value); }),
            false}};
        arg_parser arguments({}, positionals);
        arguments.set_usage("usage: websocket_echo_server [port]  (default 7001)\n");
        arguments.parse(argc, argv);
        event_loop loop;
        auto listener = std::make_unique<tcp_acceptor>(loop, ip_endpoint::loopback_v4(port));
        auto* accepting = listener.get();
        loop.add(std::move(listener));
        if (loop.spawn(serve(loop, *accepting)) != task_spawn_result::accepted)
            throw std::runtime_error("cannot start WebSocket listener");
        std::cout << "WebSocket echo server listening on ws://127.0.0.1:" << port << "/\n";
        if (loop.run() == event_loop_result::interrupted) {
            loop.shutdown(std::chrono::seconds {0});
            (void)loop.run();
        }
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
