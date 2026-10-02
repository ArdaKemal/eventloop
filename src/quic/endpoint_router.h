#pragma once

#include "eventloop/ip_endpoint.h"
#include "quic/packet_header.h"
#include "quic/path_validation.h"
#include "quic/version_negotiation.h"

#include <array>
#include <exception>
#include <thread>
#include <vector>

namespace eventloop::quic::detail {

// Unsupported versions have an unknown packet-type/length format. Inspect only
// the version-independent CID envelope, then consume the whole UDP payload.
[[nodiscard]] inline auto endpoint_version_response(std::span<const std::byte> datagram,
    std::uint8_t unused_bits, std::span<std::byte> output) noexcept -> std::size_t
{
    if (datagram.size() < 1200 || (std::to_integer<unsigned>(datagram[0]) & 0x80U) == 0)
        return 0;
    const auto version = version_at(datagram.subspan(1, 4), 0);
    if (version == 0 || is_supported_version(version)) return 0;
    std::size_t cursor = 5;
    const auto dcid_size = std::to_integer<std::size_t>(datagram[cursor++]);
    if (dcid_size >= datagram.size() - cursor) return 0;
    const auto dcid = datagram.subspan(cursor, dcid_size);
    cursor += dcid_size;
    const auto scid_size = std::to_integer<std::size_t>(datagram[cursor++]);
    if (scid_size > datagram.size() - cursor) return 0;
    constexpr std::array versions {version_1, version_2};
    const auto result = encode_version_negotiation(dcid, datagram.subspan(cursor, scid_size),
                                                  versions, unused_bits, output);
    return result ? *result : 0;
}

enum class endpoint_error { invalid_argument, capacity_exceeded, duplicate_cid,
    unknown_connection, malformed_packet, amplification_limited, wrong_peer, busy };
using endpoint_connection = std::uint64_t;

struct endpoint_callbacks {
    void* argument {};
    // Views expire on return. Reentrant dispatch/removal is a programming error.
    bool (*packet)(void*, std::span<const std::byte>, const packet_header&,
                   eventloop::ip_endpoint) noexcept {};
    // Must verify 1-RTT authentication without committing packet/stream state.
    // The ordinary packet callback may enqueue work and is not authentication.
    bool (*authenticate_changed_peer)(void*, std::span<const std::byte>,
                    const packet_header&, eventloop::ip_endpoint) noexcept {};
};

// Caller-owned connection objects must outlive their registrations. This layer
// retains one authenticated candidate per connection while its path is probed.
class endpoint_router {
public:
    explicit endpoint_router(path_endpoint_role role, std::size_t short_cid_length = 8,
                             bool grease_quic_bit = false,
                             std::size_t connection_capacity = 16)
        : role_(role), short_cid_length_(short_cid_length),
          grease_quic_bit_(grease_quic_bit),
          connections_(checked_capacity(connection_capacity)),
          cids_(connection_capacity * 4),
          path_slots_(connection_capacity), paths_(path_slots_, role),
          candidate_slots_(connection_capacity),
          candidate_paths_(candidate_slots_, role)
    {
        if (short_cid_length == 0 || short_cid_length > 20)
            throw std::invalid_argument("QUIC endpoint CID length");
    }
    endpoint_router(const endpoint_router&) = delete;
    auto operator=(const endpoint_router&) -> endpoint_router& = delete;

    [[nodiscard]] auto add(std::span<const std::byte> cid, ip_endpoint peer,
                           endpoint_callbacks callbacks, bool validated = false)
        -> std::expected<endpoint_connection, endpoint_error>
    {
        check_owner();
        if (dispatching_ || !callbacks.packet || cid.empty() || cid.size() > 20)
            return std::unexpected(endpoint_error::invalid_argument);
        if (lookup(cid)) return std::unexpected(endpoint_error::duplicate_cid);
        auto* route = free_cid();
        if (!route || next_handle_ == UINT64_MAX)
            return std::unexpected(endpoint_error::capacity_exceeded);
        for (auto& connection : connections_) {
            if (connection.handle) continue;
            const auto handle = ++next_handle_;
            if (!paths_.add(handle, validated))
                return std::unexpected(endpoint_error::capacity_exceeded);
            connection = {handle, peer, callbacks};
            store_cid(*route, handle, cid);
            return handle;
        }
        return std::unexpected(endpoint_error::capacity_exceeded);
    }

    [[nodiscard]] auto add_cid(endpoint_connection handle, std::span<const std::byte> cid)
        -> std::expected<void, endpoint_error>
    {
        check_owner();
        if (dispatching_ || cid.empty() || cid.size() > 20)
            return std::unexpected(endpoint_error::invalid_argument);
        if (!find(handle)) return std::unexpected(endpoint_error::unknown_connection);
        if (lookup(cid)) return std::unexpected(endpoint_error::duplicate_cid);
        auto* route = free_cid();
        if (!route) return std::unexpected(endpoint_error::capacity_exceeded);
        store_cid(*route, handle, cid);
        return {};
    }

    [[nodiscard]] auto remove(endpoint_connection handle)
        -> std::expected<void, endpoint_error>
    {
        check_owner();
        if (dispatching_) return std::unexpected(endpoint_error::busy);
        auto* connection = find(handle);
        if (!connection) return std::unexpected(endpoint_error::unknown_connection);
        if (connection->sending) return std::unexpected(endpoint_error::busy);
        for (auto& cid : cids_) if (cid.handle == handle) cid = {};
        *connection = {};
        (void)paths_.remove(handle);
        (void)candidate_paths_.remove(handle);
        return {};
    }

    // The connection owner retains retired-CID routing tombstones for the
    // required period, then releases the alias through this operation.
    [[nodiscard]] auto remove_cid(endpoint_connection handle, std::span<const std::byte> cid)
        -> std::expected<void, endpoint_error>
    {
        check_owner();
        if (dispatching_) return std::unexpected(endpoint_error::busy);
        if (!find(handle)) return std::unexpected(endpoint_error::unknown_connection);
        for (auto& route : cids_) {
            if (route.handle == handle && std::equal(cid.begin(), cid.end(),
                route.bytes.begin(), route.bytes.begin() + route.size)) {
                route = {};
                return {};
            }
        }
        return std::unexpected(endpoint_error::unknown_connection);
    }

    [[nodiscard]] auto validate_peer(endpoint_connection handle)
        -> std::expected<void, endpoint_error>
    {
        check_owner();
        if (!paths_.validate(handle))
            return std::unexpected(endpoint_error::unknown_connection);
        return {};
    }

    [[nodiscard]] auto peer(endpoint_connection handle) const
        -> std::expected<ip_endpoint, endpoint_error>
    {
        check_owner();
        const auto* connection = find(handle);
        if (!connection) return std::unexpected(endpoint_error::unknown_connection);
        return connection->peer;
    }

    [[nodiscard]] auto begin_send(endpoint_connection handle, std::size_t bytes)
        -> std::expected<ip_endpoint, endpoint_error>
    { return begin_send_to(handle, bytes, false); }

    [[nodiscard]] auto candidate_peer(endpoint_connection handle) const
        -> std::expected<ip_endpoint, endpoint_error>
    {
        check_owner();
        const auto* connection = find(handle);
        if (!connection || !connection->candidate)
            return std::unexpected(endpoint_error::unknown_connection);
        return connection->candidate_peer;
    }

    // Supply an unpredictable token; retries retain the same token until the
    // owner cancels this candidate at its path-validation deadline.
    [[nodiscard]] auto issue_candidate_challenge(endpoint_connection handle,
        path_challenge token) -> std::expected<void, endpoint_error>
    {
        check_owner();
        const auto* connection = find(handle);
        if (!connection || !connection->candidate)
            return std::unexpected(endpoint_error::unknown_connection);
        if (!candidate_paths_.issue_challenge(handle, token))
            return std::unexpected(endpoint_error::invalid_argument);
        return {};
    }

    // Invoke only while processing an authenticated PATH_RESPONSE. A response
    // received on another path validates the challenge's candidate path too.
    [[nodiscard]] auto accept_path_response(endpoint_connection handle,
        path_challenge token) -> std::expected<void, endpoint_error>
    {
        check_owner();
        auto* connection = find(handle);
        if (!connection || !connection->candidate)
            return std::unexpected(endpoint_error::unknown_connection);
        if (connection->sending) return std::unexpected(endpoint_error::busy);
        // Match locally first: another connection must not consume this token.
        const auto matched = candidate_paths_.response_matches(handle, token);
        if (!matched || !*matched) return std::unexpected(endpoint_error::invalid_argument);
        if (!candidate_paths_.accept_response(token))
            return std::unexpected(endpoint_error::invalid_argument);
        connection->peer = connection->candidate_peer;
        connection->candidate = false;
        (void)paths_.remove(handle);
        (void)paths_.add(handle, true);
        (void)candidate_paths_.remove(handle);
        return {};
    }

    [[nodiscard]] auto cancel_candidate(endpoint_connection handle)
        -> std::expected<void, endpoint_error>
    {
        check_owner();
        auto* connection = find(handle);
        if (!connection) return std::unexpected(endpoint_error::unknown_connection);
        if (connection->sending) return std::unexpected(endpoint_error::busy);
        connection->candidate = false;
        (void)candidate_paths_.remove(handle);
        return {};
    }

    [[nodiscard]] auto begin_send_to(endpoint_connection handle, std::size_t bytes,
        bool candidate) -> std::expected<ip_endpoint, endpoint_error>
    {
        check_owner();
        auto* connection = find(handle);
        if (!connection) return std::unexpected(endpoint_error::unknown_connection);
        if (connection->sending) return std::unexpected(endpoint_error::busy);
        if (candidate && !connection->candidate)
            return std::unexpected(endpoint_error::unknown_connection);
        const auto allowed = (candidate ? candidate_paths_ : paths_).can_send(handle, bytes);
        if (!allowed || !*allowed)
            return std::unexpected(endpoint_error::amplification_limited);
        connection->sending = true;
        connection->sending_candidate = candidate;
        return candidate ? connection->candidate_peer : connection->peer;
    }

    auto finish_send(endpoint_connection handle, std::size_t bytes, bool success) -> void
    {
        check_owner();
        auto* connection = find(handle);
        if (!connection || !connection->sending) std::terminate();
        connection->sending = false;
        if (success && !(connection->sending_candidate ? candidate_paths_ : paths_)
                .record_sent(handle, bytes)) std::terminate();
    }

    [[nodiscard]] auto lookup(std::span<const std::byte> cid) const
        -> endpoint_connection
    {
        check_owner();
        for (const auto& route : cids_)
            if (route.handle && std::equal(cid.begin(), cid.end(),
                route.bytes.begin(), route.bytes.begin() + route.size)) return route.handle;
        return 0;
    }

    // Unknown Initial acceptance is performed by the endpoint before dispatch.
    // Each UDP payload earns credit once, even if it contains multiple packets.
    [[nodiscard]] auto dispatch(std::span<const std::byte> datagram, ip_endpoint source)
        -> std::expected<std::size_t, endpoint_error>
    {
        check_owner();
        if (dispatching_) std::terminate();
        const auto first = parse_packet_header(datagram, 0, short_cid_length_,
                                               grease_quic_bit_);
        if (!first) return std::unexpected(endpoint_error::malformed_packet);
        const auto handle = lookup(first->destination_cid);
        auto* connection = find(handle);
        if (!connection) return std::unexpected(endpoint_error::unknown_connection);
        dispatching_ = true;
        struct reset { bool& flag; ~reset() { flag = false; } } guard {dispatching_};
        const bool changed_peer = !same_peer(connection->peer, source);
        if (changed_peer) {
            if (first->kind != packet_kind::short_header ||
                !connection->callbacks.authenticate_changed_peer ||
                (connection->candidate && !same_peer(connection->candidate_peer, source)) ||
                !connection->callbacks.authenticate_changed_peer(connection->callbacks.argument,
                    datagram, *first, source))
                return std::unexpected(endpoint_error::wrong_peer);
            if (!connection->candidate) {
                if (!candidate_paths_.add(handle))
                    return std::unexpected(endpoint_error::capacity_exceeded);
                connection->candidate_peer = source;
                connection->candidate = true;
            }
        }
        if (role_ == path_endpoint_role::server && first->kind == packet_kind::initial &&
            datagram.size() < 1200) return std::unexpected(endpoint_error::malformed_packet);
        if (!(changed_peer ? candidate_paths_ : paths_).record_received(handle, datagram.size()))
            return std::unexpected(endpoint_error::capacity_exceeded);
        std::size_t offset = 0;
        std::size_t processed = 0;
        while (offset < datagram.size()) {
            const auto header = parse_packet_header(datagram, offset, short_cid_length_,
                                                    grease_quic_bit_);
            if (!header) break;
            if (!std::equal(header->destination_cid.begin(), header->destination_cid.end(),
                            first->destination_cid.begin(), first->destination_cid.end())) break;
            if (role_ == path_endpoint_role::server && header->kind == packet_kind::initial &&
                datagram.size() < 1200) break;
            if (role_ == path_endpoint_role::server &&
                (header->kind == packet_kind::retry ||
                 header->kind == packet_kind::version_negotiation)) break;
            if (!connection->callbacks.packet(connection->callbacks.argument,
                    datagram, *header, source)) break;
            ++processed;
            offset = header->packet_end_offset;
        }
        return processed;
    }

    [[nodiscard]] auto short_cid_length() const noexcept -> std::size_t
    { return short_cid_length_; }
    [[nodiscard]] auto role() const noexcept -> path_endpoint_role { return role_; }

private:
    [[nodiscard]] static auto checked_capacity(std::size_t capacity) -> std::size_t
    {
        if (capacity == 0 || capacity > 256)
            throw std::invalid_argument("QUIC connection capacity must be 1..256");
        return capacity;
    }
    struct connection_slot {
        endpoint_connection handle {};
        ip_endpoint peer {};
        endpoint_callbacks callbacks {};
        bool sending {};
        ip_endpoint candidate_peer {};
        bool candidate {};
        bool sending_candidate {};
    };
    struct cid_slot {
        endpoint_connection handle {};
        std::array<std::byte, 20> bytes {};
        std::size_t size {};
    };
    auto check_owner() const noexcept -> void
    { if (owner_ != std::this_thread::get_id()) std::terminate(); }
    static auto same_peer(const ip_endpoint& a, const ip_endpoint& b) noexcept -> bool
    {
        const auto length = a.address_family == ip_endpoint::family::ipv4 ? 4 : 16;
        return a.address_family == b.address_family && a.port == b.port &&
            a.scope_id == b.scope_id && std::equal(a.address.begin(),
                a.address.begin() + length, b.address.begin());
    }
    auto find(endpoint_connection handle) noexcept -> connection_slot*
    { for (auto& slot : connections_) if (handle && slot.handle == handle) return &slot;
      return nullptr; }
    auto find(endpoint_connection handle) const noexcept -> const connection_slot*
    { for (const auto& slot : connections_) if (handle && slot.handle == handle) return &slot;
      return nullptr; }
    auto free_cid() noexcept -> cid_slot*
    { for (auto& cid : cids_) if (!cid.handle) return &cid; return nullptr; }
    static auto store_cid(cid_slot& slot, endpoint_connection handle,
                          std::span<const std::byte> cid) noexcept -> void
    { slot.handle = handle; slot.size = cid.size();
      std::copy(cid.begin(), cid.end(), slot.bytes.begin()); }

    std::thread::id owner_ {std::this_thread::get_id()};
    path_endpoint_role role_;
    std::size_t short_cid_length_;
    bool grease_quic_bit_ {};
    endpoint_connection next_handle_ {};
    bool dispatching_ {};
    std::vector<connection_slot> connections_;
    std::vector<cid_slot> cids_;
    std::vector<path_validation_slot> path_slots_;
    path_validation paths_;
    std::vector<path_validation_slot> candidate_slots_;
    path_validation candidate_paths_;
};

} // namespace eventloop::quic::detail
