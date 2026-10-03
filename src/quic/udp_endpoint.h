#pragma once

#include "eventloop/udp_socket.h"
#include "quic/endpoint_router.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace eventloop::quic::detail {

struct endpoint_accept_callback {
    void* argument {};
    // Register caller-owned connection state with router before returning true.
    // The callback may add the original Initial DCID as a routing alias.
    bool (*initial)(void*, endpoint_router&, const packet_header&,
                    ip_endpoint) noexcept {};
};

// Internal transport adapter. Endpoint and registered connection objects must
// outlive all receive/send tasks. run() permits one receiver; async_send permits
// one sender. Caller drives connection deadlines and packet scheduling.
class udp_endpoint {
public:
    static constexpr std::size_t maximum_datagram_size = 65527;
    udp_endpoint(event_loop&, ip_endpoint local, path_endpoint_role,
                 std::size_t short_cid_length = 8,
                 endpoint_accept_callback accept = {},
                 bool grease_quic_bit = true,
                 std::size_t connection_capacity = 16);
    ~udp_endpoint();
    udp_endpoint(const udp_endpoint&) = delete;
    auto operator=(const udp_endpoint&) -> udp_endpoint& = delete;

    [[nodiscard]] auto router() noexcept -> endpoint_router& { return router_; }
    [[nodiscard]] auto local_endpoint() const noexcept -> ip_endpoint { return local_; }
    auto close() -> void;
    [[nodiscard]] auto run() -> task<std::error_code>;
    // Bytes remain caller-owned until completion. No outbound queue is hidden
    // behind this operation; successful sends must be recorded by the owner.
    [[nodiscard]] auto async_send(endpoint_connection, std::span<const std::byte>)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Candidate probes/responses use its own anti-amplification budget. The
    // connection owner builds/authenticates PATH_CHALLENGE/PATH_RESPONSE frames.
    [[nodiscard]] auto async_send_candidate(endpoint_connection, std::span<const std::byte>)
        -> task<std::expected<std::size_t, std::error_code>>;

    // Batching built packets directly into the offload buffer avoids a copy.
    // reserve_send() prepares the next datagram slot (flushing a completed
    // batch first) and returns any error from that flush; the caller builds
    // into reserved() and then commit_send()s the built length. A length that
    // differs from the batch's segment size flushes the uniform prefix and
    // starts a new batch, so every batch stays uniformly segmented.
    [[nodiscard]] auto reserve_send(endpoint_connection, std::size_t, bool candidate)
        -> std::error_code;
    [[nodiscard]] auto reserved() noexcept -> std::span<std::uint8_t>;
    [[nodiscard]] auto commit_send(std::size_t size) noexcept -> std::error_code;
    // Flush queued datagrams with one offload/syscall batch. Always clears the
    // pending batch, even on failure.
    [[nodiscard]] auto flush_send() -> std::error_code;

private:
    static constexpr std::size_t send_batch_capacity = 32;
    static constexpr std::size_t send_segment_capacity = 8448;
    static auto receive_loop(event_loop&, udp_endpoint&) -> task<std::error_code>;
    static auto send(event_loop&, udp_endpoint&, endpoint_connection,
                     std::span<const std::byte>, bool candidate)
        -> task<std::expected<std::size_t, std::error_code>>;
    static auto socket_destroyed(void*) noexcept -> void;
    auto check_owner() const noexcept -> void;
    event_loop& loop_;
    std::thread::id owner_ {std::this_thread::get_id()};
    udp_socket* socket_ {};
    ip_endpoint local_ {};
    endpoint_router router_;
    endpoint_accept_callback accept_;
    std::array<std::byte, maximum_datagram_size> receive_buffer_ {};
    std::array<std::byte, 600> version_buffer_ {};
    std::array<std::byte, send_batch_capacity * send_segment_capacity> send_batch_bytes_ {};
    std::size_t send_batch_count_ {};
    std::size_t send_batch_segment_ {};
    std::size_t send_batch_write_ {};
    std::size_t send_batch_reserved_ {};
    endpoint_connection send_batch_handle_ {};
    bool send_batch_candidate_ {};
    bool send_batch_active_ {};
    bool receiving_ {};
    bool sending_ {};
};

} // namespace eventloop::quic::detail
