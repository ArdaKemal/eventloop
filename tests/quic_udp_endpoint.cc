#include "quic/udp_endpoint.h"

#include <chrono>
#include <cstdlib>
#include <iostream>

using namespace eventloop;
using namespace eventloop::quic::detail;
using namespace std::chrono_literals;
namespace {
auto check(bool value) -> void { if (!value) std::abort(); }
constexpr std::array<std::byte, 13> payload {std::byte {0xe0}, std::byte {0},
    std::byte {0}, std::byte {0}, std::byte {1}, std::byte {2}, std::byte {1},
    std::byte {2}, std::byte {1}, std::byte {3}, std::byte {2}, std::byte {0}, std::byte {0}};
auto packet(void* argument, std::span<const std::byte> bytes, const packet_header& header,
            ip_endpoint) noexcept -> bool
{
    if (bytes.size() != payload.size() || header.kind != packet_kind::handshake) return false;
    ++*static_cast<int*>(argument);
    return true;
}
auto receive(event_loop&, udp_endpoint& server, bool& cancelled) -> task<void>
{
    const auto error = co_await server.run();
    cancelled = error && error->value() == ECANCELED;
}
auto transmit(event_loop& loop, udp_endpoint& client, endpoint_connection handle,
              int& packets, bool& sent) -> task<void>
{
    const auto result = co_await client.async_send(handle, payload);
    sent = result && *result && **result == payload.size();
    for (unsigned i = 0; i != 100 && packets == 0; ++i)
        if (co_await sleep_for(loop, 1ms) != timer_wait_result::expired) co_return;
    loop.shutdown(event_loop::clock::duration::zero());
}
auto watchdog(event_loop& loop) -> task<void>
{
    if (co_await sleep_for(loop, 2s) == timer_wait_result::expired)
        loop.shutdown(event_loop::clock::duration::zero());
}
auto roundtrip() -> void
{
    event_loop loop;
    udp_endpoint server(loop, ip_endpoint::loopback_v4(), path_endpoint_role::server, 2);
    udp_endpoint client(loop, ip_endpoint::loopback_v4(), path_endpoint_role::client, 2);
    constexpr std::array cid {std::byte {1}, std::byte {2}};
    int packets = 0;
    bool cancelled = false;
    bool sent = false;
    check(server.router().add(cid, client.local_endpoint(), {&packets, packet}).has_value());
    const auto handle = client.router().add(cid, server.local_endpoint(), {&packets, packet});
    check(handle.has_value());
    check(loop.spawn(receive(loop, server, cancelled)) == task_spawn_result::accepted);
    check(loop.spawn(transmit(loop, client, *handle, packets, sent)) == task_spawn_result::accepted);
    check(loop.spawn(watchdog(loop)) == task_spawn_result::accepted);
    (void)loop.run();
    check(cancelled && sent && packets == 1);
    check(loop.coroutine_statistics().live == 0);
    // Destructors run after shutdown has removed both loop-owned sockets.
    server.close();
    client.close();
}
}
int main()
{
#ifdef _WIN32
    WSADATA data {};
    check(WSAStartup(MAKEWORD(2, 2), &data) == 0);
#endif
    roundtrip();
#ifdef _WIN32
    (void)WSACleanup();
#endif
    std::cout << "QUIC UDP endpoint passed\n";
}
