// websocket_routing_server certificate.pem private-key.pem [port]
// /chat accepts RFC 8441/9220 WebSockets; /hello remains ordinary HTTP.
#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"
#include "eventloop/http/server.h"
#include "eventloop/ws/web_socket.h"
#include "eventloop/util/arg_parser.h"

#include <charconv>
#include <array>
#include <chrono>
#include <iostream>
#include <memory>

using namespace eventloop;

namespace {
auto chat(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    // Apply application authentication and Origin policy here, before accepting.
    auto accepted = flatten_result(co_await request.async_accept_websocket());
    if (!accepted) {
        const std::array<http::header, 1> version {{{"sec-websocket-version", "13"}}};
        (void)co_await response.async_send(400, version);
        co_return;
    }
    // The transport borrows this handler's exchange; neither object escapes.
    // Allocate framing state once per session to keep the handler frame small.
    auto socket = std::make_unique<ws::web_socket<http::websocket_stream>>(
        loop, *accepted, 16 * 1024);
    for (;;) {
        auto message = flatten_result(co_await socket->async_receive());
        if (!message || message->type == ws::message_type::close) co_return;
        if (message->type == ws::message_type::text) {
            const std::u8string_view text(reinterpret_cast<const char8_t*>(message->payload.data()),
                                          message->payload.size());
            if (!flatten_result(co_await socket->async_send_text(text))) co_return;
        } else if (message->type == ws::message_type::binary) {
            if (!flatten_result(co_await socket->async_send_binary(message->payload))) co_return;
        }
    }
}
auto hello(event_loop&, http::request&, http::response& response) -> task<void>
{
    constexpr std::string_view message = "hello\n";
    (void)co_await response.async_send(200, {}, std::as_bytes(std::span(message)));
}
} // namespace

auto main(int argc, char** argv) -> int
{
    std::string certificate, private_key, port_text = "8443";
    const std::array positionals {
        arg_parser::positional {"CERTIFICATE", &certificate, true},
        arg_parser::positional {"PRIVATE-KEY", &private_key, true},
        arg_parser::positional {"PORT", &port_text, false},
    };
    arg_parser arguments({}, positionals);
    arguments.set_usage("usage: websocket_routing_server certificate.pem private-key.pem [port]\n");
    arguments.parse(argc, argv);
    std::uint16_t port = 0;
    const auto parsed = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (parsed.ec != std::errc{} || parsed.ptr != port_text.data() + port_text.size() || port == 0) return 1;
    try {
        auto routes = std::make_shared<http::router>();
        if (!routes->add(http::method_type::connect, "/chat", chat) ||
            !routes->add(http::method_type::get, "/hello", hello)) return 1;
        event_loop_options loop_options;
        // HTTP/3 retains a 2 KiB request frame per live WebSocket. Allow the
        // thirty-two request slots in the default server to stay occupied.
        loop_options.coroutine_frame_capacities[4] = 64;
        event_loop loop(loop_options);
        auto tls = std::make_unique<http::https_server>(loop, ip_endpoint::loopback_v4(port),
            tls_context::make_server(certificate, private_key), http::server_options {.routes = routes});
        auto* listener = tls.get();
        loop.add(std::move(tls));
        http::http3_server quic(loop, ip_endpoint::loopback_v4(port), certificate, private_key,
                               {.routes = routes});
        task_handle<void> serving;
        if (loop.spawn(listener->run()) != task_spawn_result::accepted ||
            loop.spawn(quic.run(), serving) != task_spawn_result::accepted) {
            loop.shutdown(std::chrono::seconds{0});
            (void)loop.run();
            return 1;
        }
        std::cout << "WebSocket /chat over TLS h2 and QUIC h3 on loopback port " << port << '\n';
        while (loop.run() == event_loop_result::interrupted)
            loop.shutdown(std::chrono::seconds{0});
    } catch (const std::exception& error) {
        std::cerr << "websocket_routing_server: " << error.what() << '\n';
        return 1;
    }
}
