// The WebTransport echo example's routes (examples/webtransport_echo.h), served
// by a real http3_server and checked with the test client: one echo of each kind.
#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/router.h"
#include "eventloop/task.h"
#include "fixtures/webtransport_client.h"
#include "tls_test_certificate.h"
#include "webtransport_echo.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <random>
#include <string>
#include <string_view>

namespace {

using namespace eventloop;
using namespace eventloop::webtransport_fixture;
using namespace std::chrono_literals;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::fprintf(stderr, "webtransport example: %.*s\n", static_cast<int>(message.size()), message.data());
    std::abort();
}

auto to_bytes(std::string_view text) -> std::vector<std::byte>
{
    std::vector<std::byte> bytes(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) bytes[i] = static_cast<std::byte>(text[i]);
    return bytes;
}

auto to_text(std::span<const std::byte> bytes) -> std::string
{
    std::string text(bytes.size(), '\0');
    for (std::size_t i = 0; i < bytes.size(); ++i) text[i] = static_cast<char>(bytes[i]);
    return text;
}

auto echo_example(event_loop& loop, webtransport_client& client, http::http3_server& server, bool& done)
    -> task<void>
{
    auto connected = flatten_result(co_await client.async_connect(server.local_endpoint()));
    check(connected.has_value(), "client connects");
    request_options request;
    request.available_protocols = "\"echo/1\"";
    auto session = flatten_result(co_await client.async_send_request(request));
    check(session.has_value(), "send CONNECT");
    auto head = flatten_result(co_await client.async_read_response(*session));
    check(head.has_value() && head->status == 200, "session accepted");
    check(head->wt_protocol == std::optional<std::string>("\"echo/1\""), "echo/1 selected");
    const auto id = session->id();

    auto bidi = flatten_result(co_await client.async_open_stream(id, true));
    check(bidi.has_value(), "open bidi");
    check(flatten_result(co_await client.async_write_all(*bidi, to_bytes("bidi"), true)).has_value(), "write bidi");
    std::vector<std::byte> echoed(4);
    auto count = flatten_result(co_await client.async_read_all(*bidi, echoed));
    check(count.has_value() && to_text(echoed) == "bidi", "bidi echoed");

    auto uni = flatten_result(co_await client.async_open_stream(id, false));
    check(uni.has_value(), "open uni");
    check(flatten_result(co_await client.async_write_all(*uni, to_bytes("uni!"), true)).has_value(), "write uni");
    auto peer = flatten_result(co_await client.async_accept_peer_stream());
    check(peer.has_value() && peer->session_id == id, "uni echo on a server uni stream");
    std::vector<std::byte> reply(4);
    count = flatten_result(co_await client.async_read_all(peer->id, reply));
    check(count.has_value() && to_text(reply) == "uni!", "uni echoed");

    check(flatten_result(co_await client.async_send_datagram(id, to_bytes("dgram"))).has_value(), "send datagram");
    auto datagram = flatten_result(co_await client.async_receive_datagram());
    check(datagram.has_value() && datagram->session_id == id && to_text(datagram->payload) == "dgram",
          "datagram echoed");

    done = true;
    co_await client.async_close();
    co_await server.async_close();
    loop.shutdown(event_loop::clock::duration::zero());
}

} // namespace

auto main() -> int
{
    const auto directory = std::filesystem::temp_directory_path() /
        ("eventloop-webtransport-example-" + std::to_string(std::random_device {}()));
    std::filesystem::create_directories(directory);
    struct cleanup {
        std::filesystem::path directory;
        ~cleanup() { std::filesystem::remove_all(directory); }
    } remove_directory {directory};
    test::make_localhost_certificate(directory / "cert.pem", directory / "key.pem");

    auto routes = std::make_shared<http::router>();
    check(routes->add(http::method_type::connect, "/echo", webtransport_echo::echo_session).has_value(),
          "register /echo");
    event_loop loop;
    http::server_options options;
    options.routes = routes;
    options.webtransport.enabled = true;
    http::http3_server server(loop, ip_endpoint::loopback_v4(0), directory / "cert.pem",
                              directory / "key.pem", options);
    client_options client_config;
    client_config.trusted_ca = directory / "cert.pem";
    webtransport_client client(loop, ip_endpoint::loopback_v4(0), client_config);
    bool done = false;
    task_handle<void> serving;
    task_handle<void> scenario;
    check(loop.spawn(server.run(), serving) == task_spawn_result::accepted, "spawn server");
    check(loop.spawn(echo_example(loop, client, server, done), scenario) == task_spawn_result::accepted,
          "spawn scenario");
    (void)loop.run();
    check(done, "example echoes every kind of traffic");
    std::puts("WebTransport echo example test passed");
}
