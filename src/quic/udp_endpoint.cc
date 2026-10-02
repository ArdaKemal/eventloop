#include "quic/udp_endpoint.h"

#include <cerrno>
#include <memory>
#include <openssl/rand.h>

namespace eventloop::quic::detail {

udp_endpoint::udp_endpoint(event_loop& loop, ip_endpoint local, path_endpoint_role role,
    std::size_t short_cid_length, endpoint_accept_callback accept, bool grease_quic_bit,
    std::size_t connection_capacity)
    : loop_(loop), router_(role, short_cid_length, grease_quic_bit,
                          connection_capacity), accept_(accept)
{
    auto socket = std::make_unique<udp_socket>(loop, local);
    local_ = socket->local_endpoint();
    socket_ = socket.get();
    socket->set_lifetime_observer(this, socket_destroyed);
    loop.add(std::move(socket));
}

udp_endpoint::~udp_endpoint()
{
    check_owner();
    if (receiving_ || sending_) std::terminate();
    close();
}

auto udp_endpoint::check_owner() const noexcept -> void
{ if (owner_ != std::this_thread::get_id()) std::terminate(); }

auto udp_endpoint::socket_destroyed(void* argument) noexcept -> void
{ static_cast<udp_endpoint*>(argument)->socket_ = nullptr; }

auto udp_endpoint::close() -> void
{
    check_owner();
    auto* socket = std::exchange(socket_, nullptr);
    if (socket) {
        socket->set_lifetime_observer(nullptr, nullptr);
        socket->close();
    }
}

auto udp_endpoint::run() -> task<std::error_code>
{ check_owner(); return receive_loop(loop_, *this); }

auto udp_endpoint::async_send(endpoint_connection handle, std::span<const std::byte> bytes)
    -> task<std::expected<std::size_t, std::error_code>>
{ check_owner(); return send(loop_, *this, handle, bytes, false); }

auto udp_endpoint::async_send_candidate(endpoint_connection handle, std::span<const std::byte> bytes)
    -> task<std::expected<std::size_t, std::error_code>>
{ check_owner(); return send(loop_, *this, handle, bytes, true); }

auto udp_endpoint::receive_loop(event_loop&, udp_endpoint& endpoint) -> task<std::error_code>
{
    endpoint.check_owner();
    if (endpoint.receiving_) co_return std::error_code(EBUSY, std::generic_category());
    endpoint.receiving_ = true;
    struct reset { udp_endpoint& endpoint; ~reset() { endpoint.receiving_ = false; } }
        guard {endpoint};
    while (endpoint.socket_) {
        const auto received = co_await endpoint.socket_->async_receive_from(endpoint.receive_buffer_);
        if (!received) {
            if (received.error().value() == EMSGSIZE) continue;
            endpoint.close();
            co_return received.error();
        }
        const auto datagram = std::span<const std::byte>(endpoint.receive_buffer_)
                                  .first(received->size);
        if (endpoint.router_.role() == path_endpoint_role::server) {
            // VN packets use random unused bits and are always smaller than the
            // triggering 1200-byte datagram, so stateless amplification is bounded.
            const auto vn = endpoint_version_response(datagram, 0, endpoint.version_buffer_);
            if (vn) {
                std::uint8_t unused = 0;
                if (RAND_bytes(&unused, 1) != 1) continue;
                endpoint.version_buffer_[0] = static_cast<std::byte>(0x80U | (unused & 0x7fU));
                if (!endpoint.sending_) {
                    endpoint.sending_ = true;
                    const auto sent = co_await endpoint.socket_->async_send_to(
                        std::span<const std::byte>(endpoint.version_buffer_).first(vn), received->source);
                    endpoint.sending_ = false;
                    if (!sent && sent.error().value() == ECANCELED) {
                        endpoint.close();
                        co_return sent.error();
                    }
                }
                continue;
            }
            const auto header = parse_packet_header(datagram, 0, endpoint.router_.short_cid_length());
            if (header && header->kind == packet_kind::initial && datagram.size() >= 1200 &&
                !endpoint.router_.lookup(header->destination_cid) && endpoint.accept_.initial) {
                if (!endpoint.accept_.initial(endpoint.accept_.argument, endpoint.router_,
                                               *header, received->source)) continue;
            }
        }
        (void)endpoint.router_.dispatch(datagram, received->source);
    }
    co_return std::error_code(ECANCELED, std::generic_category());
}

auto udp_endpoint::send(event_loop&, udp_endpoint& endpoint, endpoint_connection handle,
    std::span<const std::byte> bytes, bool candidate) -> task<std::expected<std::size_t, std::error_code>>
{
    endpoint.check_owner();
    if (!endpoint.socket_) co_return std::unexpected(std::error_code(ECANCELED, std::generic_category()));
    if (endpoint.sending_) co_return std::unexpected(std::error_code(EBUSY, std::generic_category()));
    if (bytes.empty() || bytes.size() > maximum_datagram_size)
        co_return std::unexpected(std::error_code(EMSGSIZE, std::generic_category()));
    if (bytes.size() < 1200) {
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const auto header = parse_packet_header(bytes, offset, endpoint.router_.short_cid_length());
            if (!header) break;
            if (header->kind == packet_kind::initial)
                co_return std::unexpected(std::error_code(EMSGSIZE, std::generic_category()));
            offset = header->packet_end_offset;
        }
    }
    const auto peer = endpoint.router_.begin_send_to(handle, bytes.size(), candidate);
    if (!peer) co_return std::unexpected(std::error_code(
        peer.error() == endpoint_error::amplification_limited ? EAGAIN : EINVAL,
        std::generic_category()));
    endpoint.sending_ = true;
    const auto result = co_await endpoint.socket_->async_send_to(bytes, *peer);
    endpoint.sending_ = false;
    endpoint.router_.finish_send(handle, bytes.size(), result.has_value());
    co_return result;
}

} // namespace eventloop::quic::detail
