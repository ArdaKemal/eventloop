#include "quic/udp_endpoint.h"

#include <cerrno>
#include <memory>
#include <openssl/rand.h>

namespace eventloop::quic::detail {

udp_endpoint::udp_endpoint(event_loop& loop, ip_endpoint local, path_endpoint_role role,
    std::size_t short_cid_length, endpoint_accept_callback accept, bool grease_quic_bit,
    std::size_t connection_capacity, bool reuse_port,
    std::shared_ptr<quic_worker_group> group, std::uint8_t worker_index,
    std::size_t forward_size)
    : loop_(loop), router_(role, short_cid_length, grease_quic_bit,
                          connection_capacity), accept_(accept),
      group_(std::move(group)), worker_index_(worker_index)
{
    // Join before the socket exists, so a refused index leaves nothing open.
    if (group_) {
        inbox_ = std::make_shared<worker_inbox>(loop, *this, forward_size);
        worker_group_access::join(*group_, worker_index_, inbox_);
    }
    try {
        auto socket = std::make_unique<udp_socket>(loop, local, reuse_port);
        local_ = socket->local_endpoint();
        socket_ = socket.get();
        dont_fragment_ = socket->prepare_quic(local_.address_family == ip_endpoint::family::ipv6);
        socket->set_lifetime_observer(this, socket_destroyed);
        loop.add(std::move(socket));
    } catch (...) {
        if (inbox_) {
            inbox_->close();
            worker_group_access::leave(*group_, worker_index_, *inbox_);
        }
        throw;
    }
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
    if (inbox_) {
        inbox_->close();
        worker_group_access::leave(*group_, worker_index_, *inbox_);
        inbox_.reset();
    }
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

auto udp_endpoint::reserve_send(endpoint_connection handle, std::size_t size,
    bool candidate) -> std::error_code
{
    check_owner();
    if (socket_ == nullptr) return std::error_code(ECANCELED, std::generic_category());
    if (size == 0 || size > send_segment_capacity)
        return std::error_code(EMSGSIZE, std::generic_category());
    std::error_code flush_error {};
    const bool needs_new_batch = send_batch_active_ &&
        (send_batch_handle_ != handle || send_batch_candidate_ != candidate ||
         send_batch_count_ == send_batch_capacity ||
         send_batch_write_ + size > send_batch_bytes_.size());
    if (needs_new_batch) flush_error = flush_send();
    if (!send_batch_active_) {
        send_batch_handle_ = handle;
        send_batch_candidate_ = candidate;
        send_batch_active_ = true;
        send_batch_count_ = 0;
        send_batch_segment_ = 0;
        send_batch_write_ = 0;
    }
    send_batch_reserved_ = size;
    return flush_error;
}

auto transient_send_error(std::error_code error) noexcept -> bool
{
    for (const auto code : {std::errc::resource_unavailable_try_again, std::errc::operation_would_block,
             std::errc::device_or_resource_busy, std::errc::no_buffer_space, std::errc::not_enough_memory,
             std::errc::host_unreachable, std::errc::network_unreachable, std::errc::network_down,
             std::errc::connection_refused, std::errc::operation_not_permitted,
             std::errc::permission_denied})
        if (error == code) return true;
    return false;
}

auto udp_endpoint::reserved() noexcept -> std::span<std::uint8_t>
{
    return {reinterpret_cast<std::uint8_t*>(send_batch_bytes_.data()) + send_batch_write_,
            send_batch_reserved_};
}

auto udp_endpoint::send_credit(endpoint_connection handle, bool candidate) const
    -> std::uint64_t
{
    const auto credit = router_.send_credit(handle, candidate);
    const auto queued = send_batch_active_ && send_batch_handle_ == handle &&
        send_batch_candidate_ == candidate ? send_batch_write_ : 0;
    return credit > queued ? credit - queued : 0;
}

auto udp_endpoint::commit_send(std::size_t size) noexcept -> std::error_code
{
    if (!send_batch_active_ || size > send_batch_reserved_) return {};
    if (send_batch_count_ == 0) {
        send_batch_segment_ = size;
        send_batch_write_ = size;
        send_batch_count_ = 1;
        return {};
    }
    if (size == send_batch_segment_) {
        send_batch_write_ += size;
        ++send_batch_count_;
        return {};
    }
    // GSO permits a shorter final datagram. Flush it with the uniform prefix
    // now so no later datagram can change the segment boundaries.
    if (size != 0 && size < send_batch_segment_) {
        send_batch_write_ += size;
        ++send_batch_count_;
        return flush_send();
    }
    // A larger datagram cannot join this GSO batch. Flush the prefix, then
    // keep this datagram as the first of the next batch.
    const auto offset = send_batch_write_;
    const auto handle = send_batch_handle_;
    const auto candidate = send_batch_candidate_;
    const auto flush_error = flush_send();
    if (offset != 0)
        std::memmove(send_batch_bytes_.data(), send_batch_bytes_.data() + offset, size);
    send_batch_handle_ = handle;
    send_batch_candidate_ = candidate;
    send_batch_active_ = true;
    send_batch_segment_ = size;
    send_batch_write_ = size;
    send_batch_count_ = 1;
    return flush_error;
}

auto udp_endpoint::flush_send() -> std::error_code
{
    check_owner();
    const auto total = send_batch_write_;
    const auto segment = send_batch_segment_;
    const auto handle = send_batch_handle_;
    const auto candidate = send_batch_candidate_;
    send_batch_active_ = false;
    send_batch_count_ = 0;
    send_batch_segment_ = 0;
    send_batch_write_ = 0;
    send_batch_reserved_ = 0;
    if (total == 0) return {};
    if (socket_ == nullptr) return std::error_code(ECANCELED, std::generic_category());
    const auto peer = router_.begin_send_to(handle, total, candidate);
    if (!peer)
        return std::error_code(
            peer.error() == endpoint_error::amplification_limited ? EAGAIN : EINVAL,
            std::generic_category());
    const auto sent = socket_->send_batch(
        std::span<const std::byte>(send_batch_bytes_).first(total), segment, *peer);
    // Count the bytes that left, even when a fallback send stopped early.
    router_.finish_send(handle, sent ? *sent : 0, sent.has_value());
    if (!sent && !transient_send_error(sent.error())) return sent.error();
    if (!sent || *sent != total) return std::error_code(EAGAIN, std::generic_category());
    return {};
}

namespace {

struct queue_behind_wakeups {
    event_loop& loop;
    eventloop::detail::wakeup_node node {};
    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }
    auto await_suspend(std::coroutine_handle<> handle) noexcept -> void
    {
        node.handle = handle;
        eventloop::detail::coroutine_frame_access::schedule_wakeup(loop, node);
    }
    static auto await_resume() noexcept -> void {}
};

} // namespace

auto udp_endpoint::receive_loop(event_loop& loop, udp_endpoint& endpoint) -> task<std::error_code>
{
    endpoint.check_owner();
    if (endpoint.receiving_) co_return std::error_code(EBUSY, std::generic_category());
    endpoint.receiving_ = true;
    struct reset { udp_endpoint& endpoint; ~reset() { endpoint.receiving_ = false; } }
        guard {endpoint};
    std::size_t burst = 0;
    while (endpoint.socket_) {
        const auto received = co_await endpoint.socket_->async_receive_from(endpoint.receive_buffer_);
        if (!received) {
            if (received.error().value() == EMSGSIZE) continue;
            endpoint.close();
            co_return received.error();
        }
        const auto* const base = endpoint.receive_buffer_.data();
        const auto total = received->size;
        const auto segment = endpoint.socket_->receive_segment_;
        // UDP_GRO may coalesce consecutive equal-sized datagrams into one
        // receive; the final datagram may be shorter than `segment`. Without
        // coalescing the loop below runs exactly once for the whole datagram.
        const bool coalesced = segment != 0 && total > segment;
        std::size_t offset = 0;
        do {
            // Receives complete synchronously while datagrams are queued, so
            // a burst could overrun a connection's bounded queue and starve
            // other work. Between bursts, queue behind drivers that yielded
            // (posted work) and then behind drivers it woke (wakeups).
            if (++burst > receive_burst) {
                burst = 1;
                (void)co_await yield(loop);
                co_await queue_behind_wakeups {loop};
                if (!endpoint.socket_) co_return std::error_code(ECANCELED, std::generic_category());
            }
            const auto size = coalesced ? std::min(segment, total - offset) : total;
            const auto datagram = std::span<const std::byte>(base + offset, size);
            bool handled = false;
            if (endpoint.router_.role() == path_endpoint_role::server) {
                // VN packets use random unused bits and are always smaller than
                // the triggering 1200-byte datagram, so stateless amplification
                // is bounded.
                const auto vn = endpoint_version_response(datagram, 0, endpoint.version_buffer_);
                if (vn) {
                    std::uint8_t unused = 0;
                    if (RAND_bytes(&unused, 1) == 1) {
                        endpoint.version_buffer_[0] =
                            static_cast<std::byte>(0x80U | (unused & 0x7fU));
                        if (!endpoint.sending_) {
                            endpoint.sending_ = true;
                            const auto sent = co_await endpoint.socket_->async_send_to(
                                std::span<const std::byte>(endpoint.version_buffer_).first(vn),
                                received->source);
                            endpoint.sending_ = false;
                            if (!sent && sent.error().value() == ECANCELED) {
                                endpoint.close();
                                co_return sent.error();
                            }
                        }
                    }
                    handled = true;
                } else {
                    const auto header = parse_packet_header(
                        datagram, 0, endpoint.router_.short_cid_length());
                    if (header && header->kind == packet_kind::initial &&
                        datagram.size() >= 1200 &&
                        !endpoint.router_.lookup(header->destination_cid) &&
                        endpoint.accept_.initial) {
                        handled = !endpoint.accept_.initial(endpoint.accept_.argument,
                            endpoint.router_, *header, received->source);
                    } else if (endpoint.inbox_) {
                        // Parse as the router does: a peer that negotiated
                        // greasing clears the QUIC bit (RFC 9287).
                        const auto routed = parse_packet_header(datagram, 0,
                            endpoint.router_.short_cid_length(),
                            endpoint.router_.grease_quic_bit());
                        if (routed)
                            handled = endpoint.forward(datagram, *routed, received->source);
                    }
                }
            }
            if (!handled) (void)endpoint.router_.dispatch(datagram, received->source);
            offset += size;
        } while (offset < total);
    }
    co_return std::error_code(ECANCELED, std::generic_category());
}

auto udp_endpoint::forward(std::span<const std::byte> datagram, const packet_header& header,
                           ip_endpoint source) noexcept -> bool
{
    // Initial and 0-RTT may carry a client-chosen ID; only IDs this group
    // issued (short header and Handshake) name an owner.
    if (!inbox_ || (header.kind != packet_kind::short_header &&
                    header.kind != packet_kind::handshake))
        return false;
    const auto cid = header.destination_cid;
    if (cid.size() != router_.short_cid_length()) return false;
    const auto index = std::to_integer<std::uint8_t>(cid[0]);
    if (index == worker_index_ || router_.lookup(cid)) return false;
    if (const auto owner = worker_group_access::find(*group_, index))
        owner->push(datagram, source);
    return true;
}

auto udp_endpoint::deliver_forwarded(std::span<const std::byte> datagram,
                                     ip_endpoint source) noexcept -> void
{
    check_owner();
    if (socket_) (void)router_.dispatch(datagram, source);
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
    if (!result && transient_send_error(result.error()))
        co_return std::unexpected(std::error_code(EAGAIN, std::generic_category()));
    co_return result;
}

} // namespace eventloop::quic::detail
