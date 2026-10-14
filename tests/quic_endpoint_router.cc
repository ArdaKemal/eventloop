#include "quic/endpoint_router.h"

#include <cstdlib>
#include <iostream>

using namespace eventloop;
using namespace eventloop::quic::detail;
namespace {
auto check(bool value) -> void { if (!value) std::abort(); }
auto packet(void* argument, std::span<const std::byte>, const packet_header&,
            ip_endpoint) noexcept -> bool
{ ++*static_cast<int*>(argument); return true; }
auto authenticate(void*, std::span<const std::byte> bytes, const packet_header&,
                  ip_endpoint) noexcept -> bool
{ return bytes.back() == std::byte{99}; }
constexpr std::array cid {std::byte {1}, std::byte {2}};
auto long_packet(std::span<std::byte> out, std::byte destination = std::byte {1}) -> void
{
    constexpr std::array<std::byte, 13> bytes {std::byte {0xe0}, std::byte {0},
        std::byte {0}, std::byte {0}, std::byte {1}, std::byte {2}, std::byte {1},
        std::byte {2}, std::byte {1}, std::byte {3}, std::byte {2}, std::byte {0},
        std::byte {0}};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    out[6] = destination;
}
}
int main()
{
    {
        // An unroutable datagram from the peer that ends in the connection's
        // stateless reset token reaches its owner (RFC 9000 10.3.1).
        int resets = 0;
        const auto reset = [](void* argument) noexcept { ++*static_cast<int*>(argument); };
        endpoint_router paths(path_endpoint_role::client, 2);
        const auto peer = ip_endpoint::loopback_v4(7000);
        const auto handle = paths.add(cid, peer, {&resets, packet, nullptr, reset}, true);
        check(handle.has_value());
        stateless_reset_token token {};
        token.fill(std::byte {5});
        std::array<std::byte, 40> datagram {};
        datagram[0] = std::byte {0x40};
        datagram[1] = std::byte {9};    // an unknown connection ID
        std::ranges::copy(token, datagram.end() - 16);
        check(!paths.dispatch(datagram, peer) && resets == 0);
        check(paths.set_reset_token(*handle, token).has_value());
        check(!paths.dispatch(datagram, ip_endpoint::loopback_v4(7001)) && resets == 0);
        check(!paths.dispatch(datagram, peer) && resets == 1);
        check(paths.set_reset_token(*handle, {}).has_value());
        check(!paths.dispatch(datagram, peer) && resets == 1);
    }
    {
        // A client discards authenticated packets from an address other than
        // the server's (RFC 9000 9).
        int accepted = 0;
        endpoint_router paths(path_endpoint_role::client, 2);
        const auto server = ip_endpoint::loopback_v4(7000);
        const auto handle = paths.add(cid, server, {&accepted, packet, authenticate}, true);
        check(handle.has_value());
        const std::array<std::byte, 4> bytes{std::byte{0x40}, cid[0], cid[1], std::byte{99}};
        check(!paths.dispatch(bytes, ip_endpoint::loopback_v4(7001)));
        check(!paths.candidate_peer(*handle) && accepted == 0);
        check(paths.dispatch(bytes, server) == std::size_t{1} && accepted == 1);
    }
    {
        int accepted = 0;
        endpoint_router paths(path_endpoint_role::server, 2);
        const auto original = ip_endpoint::loopback_v4(7000);
        const auto rebound = ip_endpoint::loopback_v4(7001);
        const auto handle = paths.add(cid, original, {&accepted, packet, authenticate}, true);
        check(handle.has_value());
        std::array<std::byte, 4> bytes{std::byte{0x40}, cid[0], cid[1], std::byte{0}};
        check(!paths.dispatch(bytes, rebound));
        check(!paths.candidate_peer(*handle));
        check(accepted == 0);
        bytes.back() = std::byte{99};
        check(paths.dispatch(bytes, rebound) == std::size_t{1});
        check(paths.peer(*handle)->port == original.port);
        check(paths.candidate_peer(*handle)->port == rebound.port);
        check(!paths.begin_send_to(*handle, 13, true));
        check(paths.begin_send_to(*handle, 12, true)->port == rebound.port);
        paths.finish_send(*handle, 12, false);
        check(paths.begin_send_to(*handle, 12, true).has_value());
        paths.finish_send(*handle, 12, true);
        check(!paths.begin_send_to(*handle, 1, true));
        check(paths.begin_send(*handle, 10000)->port == original.port);
        paths.finish_send(*handle, 10000, true);
        const path_challenge token{std::byte{7}};
        check(paths.issue_candidate_challenge(*handle, token).has_value());
        check(!paths.accept_path_response(*handle, path_challenge{}));
        check(paths.peer(*handle)->port == original.port);
        check(!paths.dispatch(bytes, ip_endpoint::loopback_v4(7002)));
        check(paths.accept_path_response(*handle, token).has_value());
        check(paths.peer(*handle)->port == rebound.port);
        check(!paths.accept_path_response(*handle, token));
        check(paths.begin_send(*handle, 10000).has_value());
        paths.finish_send(*handle, 10000, false);
        check(paths.dispatch(bytes, original) == std::size_t{1});
        check(paths.cancel_candidate(*handle).has_value());
        check(paths.peer(*handle)->port == rebound.port);
        check(!paths.candidate_peer(*handle));
    }
    int count = 0;
    const auto peer = ip_endpoint::loopback_v4(443);
    endpoint_router router(path_endpoint_role::server, 2);
    const auto handle = router.add(cid, peer, {&count, packet});
    check(handle.has_value());
    constexpr std::array alias {std::byte {4}, std::byte {5}};
    check(router.add_cid(*handle, alias).has_value());
    check(router.lookup(alias) == *handle);
    check(router.remove_cid(*handle, alias).has_value());
    check(router.lookup(alias) == 0);
    check(!router.add(cid, peer, {&count, packet}));
    check(!router.begin_send(*handle, 1));
    std::array<std::byte, 26> coalesced {};
    long_packet(std::span(coalesced).first(13));
    long_packet(std::span(coalesced).subspan(13));
    check(router.dispatch(coalesced, peer) == std::size_t {2});
    check(count == std::size_t {2});
    check(!router.begin_send(*handle, 79)); // Credit is 26 * 3, not 52 * 3.
    check(router.begin_send(*handle, 78).has_value());
    check(!router.remove(*handle));
    router.finish_send(*handle, 78, false);
    check(router.begin_send(*handle, 78).has_value());
    router.finish_send(*handle, 78, true);
    check(!router.begin_send(*handle, 1));
    check(!router.dispatch(coalesced, ip_endpoint::loopback_v4(444)));
    long_packet(std::span(coalesced).subspan(13), std::byte {9});
    check(router.dispatch(coalesced, peer) == std::size_t {1});
    long_packet(std::span(coalesced).subspan(13));
    coalesced[13] = std::byte {0xc0};
    // The second packet is an Initial with an empty token, a one-byte
    // protected payload, and a matching DCID. It must not reach the callback.
    coalesced[23] = std::byte {0};
    coalesced[24] = std::byte {1};
    check(router.dispatch(coalesced, peer) == std::size_t {1});
    check(router.validate_peer(*handle).has_value());
    check(router.begin_send(*handle, 65527).has_value());
    router.finish_send(*handle, 65527, false);
    check(router.remove(*handle).has_value());
    check(router.lookup(cid) == 0);
    const auto replacement = router.add(cid, peer, {&count, packet});
    check(replacement && *replacement != *handle);
    check(!router.begin_send(*handle, 1));
    for (unsigned i = 0; i < 15; ++i) {
        const std::array unique {std::byte {9}, static_cast<std::byte>(i)};
        check(router.add(unique, peer, {&count, packet}).has_value());
    }
    constexpr std::array other {std::byte {8}};
    check(!router.add(other, peer, {&count, packet}));

    // Runtime reservations extend routing and path state together.
    endpoint_router larger(path_endpoint_role::server, 2, false, 24);
    for (unsigned i = 0; i < 24; ++i) {
        const std::array unique {std::byte {10}, static_cast<std::byte>(i)};
        check(larger.add(unique, peer, {&count, packet}).has_value());
    }
    check(!larger.add(other, peer, {&count, packet}));

    std::array<std::byte, 1200> unknown {};
    long_packet(unknown);
    unknown[4] = std::byte {77};
    std::array<std::byte, 600> output {};
    const auto size = endpoint_version_response(unknown, 7, output);
    check(size == 18);
    const auto vn = parse_packet_header(std::span(output).first(size));
    check(vn && vn->kind == packet_kind::version_negotiation &&
          vn->destination_cid.size() == 1 && vn->source_cid.size() == std::size_t {2});
    check(endpoint_version_response(std::span(unknown).first(1199), 0, output) == 0);
    unknown[4] = std::byte {1};
    check(endpoint_version_response(unknown, 0, output) == 0);
    std::cout << "QUIC endpoint router passed\n";
}
