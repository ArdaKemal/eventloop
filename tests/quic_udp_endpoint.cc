#include "quic/udp_endpoint.h"
#include "quic/worker_group.h"
#include "eventloop/udp_socket.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>

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
              int& packets, bool& sent, std::span<const std::byte> datagram = payload) -> task<void>
{
    const auto result = co_await client.async_send(handle, datagram);
    sent = result && *result && **result == datagram.size();
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

// Retry the same buffered Initial without waiting for peer loss recovery;
// permanent refusal remains bounded and shutdown retires the receiver.
auto initial_retry(bool accept) -> void
{
    struct state { int attempts = 0, packets = 0; bool accept; } record {0, 0, accept};
    event_loop loop;
    udp_endpoint server(loop, ip_endpoint::loopback_v4(), path_endpoint_role::server, 2,
        {&record, [](void* argument, endpoint_router& router, const packet_header& header,
                    ip_endpoint source) noexcept -> bool {
            auto& value = *static_cast<state*>(argument);
            if (++value.attempts == 1 || !value.accept) return false;
            return router.add(header.destination_cid, source,
                {&value.packets, [](void* count, std::span<const std::byte> bytes,
                                    const packet_header& packet, ip_endpoint) noexcept {
                    check(bytes.size() == 1200 && packet.kind == packet_kind::initial);
                    ++*static_cast<int*>(count);
                    return true;
                }}).has_value();
        }});
    udp_endpoint client(loop, ip_endpoint::loopback_v4(), path_endpoint_role::client, 2);
    constexpr std::array<std::byte, 1200> initial {std::byte {0xc0}, std::byte {0},
        std::byte {0}, std::byte {0}, std::byte {1}, std::byte {2}, std::byte {1},
        std::byte {2}, std::byte {1}, std::byte {3}, std::byte {0}, std::byte {2}};
    constexpr std::array cid {std::byte {1}, std::byte {2}};
    const auto handle = client.router().add(cid, server.local_endpoint(), {&record.packets, packet});
    check(handle.has_value());
    bool cancelled = false, sent = false;
    check(loop.spawn(receive(loop, server, cancelled)) == task_spawn_result::accepted);
    check(loop.spawn(transmit(loop, client, *handle, record.packets, sent, initial)) == task_spawn_result::accepted);
    check(loop.spawn(watchdog(loop)) == task_spawn_result::accepted);
    (void)loop.run();
    check(cancelled && sent && record.attempts == 2 && record.packets == (accept ? 1 : 0));
    check(loop.coroutine_statistics().live == 0);
}

// Worker group forwarding: short-header packets for a connection owned by
// worker 0 arrive at worker 1, once with the QUIC bit set and once greased
// (RFC 9287); worker 0 must receive both.
auto short_packet(void* argument, std::span<const std::byte>, const packet_header& header,
                  ip_endpoint) noexcept -> bool
{
    if (header.kind != packet_kind::short_header) return false;
    ++*static_cast<int*>(argument);
    return true;
}
auto misroute(event_loop& loop, udp_socket& sender, ip_endpoint other, int& packets)
    -> task<void>
{
    for (const auto first : {std::byte {0x41}, std::byte {0x01}}) {
        std::array<std::byte, 24> datagram {};
        datagram[0] = first;            // short header; 0x40 is the QUIC bit
        datagram[1] = std::byte {0};    // connection ID: worker 0's index...
        datagram[2] = std::byte {7};    // ...then the rest of the ID
        (void)co_await sender.async_send_to(datagram, other);
    }
    for (unsigned i = 0; i != 200 && packets < 2; ++i)
        if (co_await sleep_for(loop, 1ms) != timer_wait_result::expired) co_return;
    loop.shutdown(event_loop::clock::duration::zero());
}
auto receive_quietly(event_loop&, udp_endpoint& endpoint) -> task<void>
{
    (void)co_await endpoint.run();
}
auto forwarding() -> void
{
    event_loop loop;
    const auto group = std::make_shared<quic_worker_group>(2);
    udp_endpoint owner(loop, ip_endpoint::loopback_v4(), path_endpoint_role::server, 2, {},
                       true, 16, false, group, 0);
    udp_endpoint other(loop, ip_endpoint::loopback_v4(), path_endpoint_role::server, 2, {},
                       true, 16, false, group, 1);
    auto owned = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto& sender = *owned;
    const auto source = sender.local_endpoint();
    loop.add(std::move(owned));
    constexpr std::array cid {std::byte {0}, std::byte {7}};
    int packets = 0;
    check(owner.router().add(cid, source, {&packets, short_packet}).has_value());
    check(loop.spawn(receive_quietly(loop, owner)) == task_spawn_result::accepted);
    check(loop.spawn(receive_quietly(loop, other)) == task_spawn_result::accepted);
    check(loop.spawn(misroute(loop, sender, other.local_endpoint(), packets)) ==
          task_spawn_result::accepted);
    check(loop.spawn(watchdog(loop)) == task_spawn_result::accepted);
    (void)loop.run();
    check(packets == 2);
    owner.close();
    other.close();
}
// Large datagrams end a batch before it exceeds one GSO send's payload limit.
auto large_batches() -> void
{
    event_loop loop;
    udp_endpoint server(loop, ip_endpoint::loopback_v4(), path_endpoint_role::server, 2);
    udp_endpoint client(loop, ip_endpoint::loopback_v4(), path_endpoint_role::client, 2);
    constexpr std::array cid {std::byte {1}, std::byte {2}};
    int packets = 0;
    const auto handle = client.router().add(cid, server.local_endpoint(), {&packets, packet});
    check(handle.has_value());
    for (int i = 0; i != 9; ++i) {
        check(!client.reserve_send(*handle, 8192, false));
        check(!client.commit_send(8192));
    }
    check(!client.flush_send());
    server.close();
    client.close();
}
// A full inbox whose drain could not be posted still drains once the loop's
// post queue has room, on the next push.
auto inbox_backlog(event_loop& loop, worker_inbox& inbox, int& packets) -> task<void>
{
    std::array<std::byte, 24> datagram {};
    datagram[0] = std::byte {0x41};
    datagram[2] = std::byte {7};
    for (std::size_t i = 0; i != worker_inbox::capacity; ++i) inbox.push(datagram, {});
    // The timer runs after the posts that filled the queue have drained.
    if (co_await sleep_for(loop, 1ms) != timer_wait_result::expired) co_return;
    inbox.push(datagram, {});
    for (unsigned i = 0; i != 200 && packets < 64; ++i)
        if (co_await sleep_for(loop, 1ms) != timer_wait_result::expired) co_return;
    loop.shutdown(event_loop::clock::duration::zero());
}
auto forwarding_backlog() -> void
{
    event_loop_options options;
    options.post_capacity = 2;
    event_loop loop(options);
    udp_endpoint owner(loop, ip_endpoint::loopback_v4(), path_endpoint_role::server, 2);
    constexpr std::array cid {std::byte {0}, std::byte {7}};
    int packets = 0;
    check(owner.router().add(cid, ip_endpoint {}, {&packets, short_packet}).has_value());
    const auto inbox = std::make_shared<worker_inbox>(loop, owner, 64);
    check(loop.post([]() noexcept {}) && loop.post([]() noexcept {}) && !loop.post([]() noexcept {}));
    check(loop.spawn(inbox_backlog(loop, *inbox, packets)) == task_spawn_result::accepted);
    check(loop.spawn(watchdog(loop)) == task_spawn_result::accepted);
    (void)loop.run();
    check(packets == static_cast<int>(worker_inbox::capacity));
    inbox->close();
    owner.close();
}
}
int main()
{
#ifdef _WIN32
    WSADATA data {};
    check(WSAStartup(MAKEWORD(2, 2), &data) == 0);
#endif
    // Local send failures become packet loss; others still fail the send.
    check(transient_send_error(std::make_error_code(std::errc::no_buffer_space)) &&
          transient_send_error(std::make_error_code(std::errc::network_unreachable)) &&
          transient_send_error(std::make_error_code(std::errc::resource_unavailable_try_again)) &&
          !transient_send_error(std::make_error_code(std::errc::operation_canceled)) &&
          !transient_send_error(std::make_error_code(std::errc::message_size)));
#ifndef _WIN32
    check(transient_send_error(std::error_code(ENOBUFS, std::system_category())));
#endif
    roundtrip();
    initial_retry(true);
    initial_retry(false);
    forwarding();
    forwarding_backlog();
    large_batches();
#ifdef _WIN32
    (void)WSACleanup();
#endif
    std::cout << "QUIC UDP endpoint passed\n";
}
