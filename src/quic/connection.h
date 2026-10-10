#pragma once

#include "quic/connection_id_registry.h"
#include "quic/datagram_queue.h"
#include "quic/flow_control.h"
#include "quic/local_connection_id_registry.h"
#include "quic/path_validation.h"
#include "quic/path_recovery_state.h"
#include "quic/recovery_orchestration.h"
#include "quic/stream_receive_buffer.h"
#include "quic/stream_send_buffer.h"
#include "quic/stream_state.h"
#include "quic/transport_parameters.h"
#include "quic/connection_core.h"

namespace eventloop::quic::detail {

// Fixed storage per connection. The endpoint owns routing, pacing and UDP.
// Its parameter validator MUST bind authenticated CID/Retry/version observations.
// Control-frame retransmission, migration and key updates remain endpoint work.
class bounded_connection {
public:
    // Each initiator has an active reservation, across both directions. Local
    // opens cannot consume storage promised to the peer in transport parameters.
    static constexpr std::size_t bidi_stream_capacity = 32;
    static constexpr std::size_t uni_stream_capacity = 8;
    static constexpr std::size_t stream_capacity =
        2 * (bidi_stream_capacity + uni_stream_capacity);
    static constexpr std::size_t stream_bytes = 4096;
    // Application send queue per stream. Larger than the receive quantum so a
    // whole datagram can be queued without task churn; keep receive accounting
    // on stream_bytes.
    static constexpr std::size_t send_bytes = 16384;
    static constexpr std::size_t receive_bytes = 32 * stream_bytes;
    static constexpr std::size_t packet_capacity = 128;
    static constexpr std::size_t frames_per_packet = 8;
    // Compile-time bound for a single UDP datagram. The active send size is
    // negotiated per connection; the member below stays at the QUIC minimum
    // until peer transport parameters are validated.
    static constexpr std::size_t datagram_buffer_size = 8448;
    struct transmitted_range {
        bool crypto {false};
        std::uint64_t stream_id {0}, offset {0};
        std::size_t size {0};
        bool fin {false};
    };
    struct stream_slot {
        std::uint64_t id {};
        std::array<std::byte, stream_bytes> bytes {};
        std::array<std::byte, stream_bytes / 8> coverage {};
        std::optional<stream_receive_buffer> receive;
        stream_send_buffer<send_bytes> send;
        stream_state state;
        std::uint64_t sent_highest {}, receive_window {}, receive_limit {}, consumed {};
        // Application codes carried by queued RESET_STREAM and STOP_SENDING.
        std::uint64_t reset_error {}, stop_sending_error {};
        bool credit_pending {false}, reset_pending {false};
        bool stop_sending_pending {false};
        // The application stopped reading: data and a peer reset are consumed
        // here so the slot can retire without further application reads.
        bool receive_abandoned {false};
        bool accepted {false};
        bool occupied {false};
        // Ranges of this stream in occupied sent records; the slot cannot
        // retire while any are outstanding.
        std::size_t in_flight {0};
    };

    explicit bounded_connection(endpoint_role role, connection_callbacks callbacks,
                                lifecycle_time_point started = {})
        : role_(role), callbacks_(callbacks),
          registry_(role == endpoint_role::client ? stream_role::client : stream_role::server),
          paths_(path_slots_, role == endpoint_role::client ? path_endpoint_role::client : path_endpoint_role::server),
          core_(role, {this, validate_parameters, dispatch}, started)
    {
        for (std::size_t i = 0; i < datagram_slots_.size(); ++i)
            datagram_slots_[i].storage = datagram_bytes_[i];
        for (std::size_t i = 0; i < outgoing_datagram_slots_.size(); ++i)
            outgoing_datagram_slots_[i].storage = outgoing_datagram_bytes_[i];
        (void)recovery_.reset(1200);
        (void)path_recovery_.set_active(0);
    }
    bounded_connection(const bounded_connection&) = delete;
    auto operator=(const bounded_connection&) -> bounded_connection& = delete;
    ~bounded_connection() { check_owner(); }

    [[nodiscard]] auto initialize(SSL_CTX* context, const tls_options& options,
        std::uint32_t version, std::span<const std::uint8_t> dcid)
        -> std::expected<void, connection_error>
    {
        check_owner();
        const auto local = decode_transport_parameters(std::as_bytes(options.transport_parameters),
            role_ == endpoint_role::client ? parameter_sender::client : parameter_sender::server);
        if (!local || !callbacks_.validate_parameters)
            return std::unexpected(connection_error::invalid_configuration);
        local_ = limits(*local);
        // Every byte of advertised receive credit must fit reserved storage,
        // including sparse STREAM ranges while the application is suspended.
        if (local_.data > receive_bytes || local_.bidi_local > stream_bytes ||
            local_.bidi_remote > stream_bytes || local_.stream_uni > stream_bytes ||
            local_.bidi > bidi_stream_capacity || local_.uni > uni_stream_capacity)
            return std::unexpected(connection_error::invalid_configuration);
        if (!registry_.set_local_limit(stream_direction::bidirectional, local_.bidi) ||
            !registry_.set_local_limit(stream_direction::unidirectional, local_.uni))
            return std::unexpected(connection_error::invalid_configuration);
        flow_ = *flow_control<stream_capacity>::create(0, local_.data);
        datagrams_.reset(local_.datagram);
        return core_.initialize(context, options, version, dcid);
    }
    // Caller has retired the driver and all sends before replacing Initial keys.
    [[nodiscard]] auto apply_retry(std::span<const std::uint8_t> dcid)
        -> std::expected<void, connection_error>
    {
        check_owner();
        if (const auto applied = core_.apply_retry(dcid); !applied) return applied;
        if (!recovery_.reset(1200)) return std::unexpected(connection_error::invalid_state);
        for (auto& record : sent_) record = {};
        sent_keys_.fill(no_record);
        for (auto& slot : slots_) slot.in_flight = 0;
        return {};
    }

    [[nodiscard]] auto core() noexcept -> connection_core& { check_owner(); return core_; }
    [[nodiscard]] auto streams() const noexcept -> const stream_registry<stream_capacity>&
    { check_owner(); return registry_; }
    [[nodiscard]] auto flow() const noexcept -> const flow_control<stream_capacity>&
    { check_owner(); return flow_; }
    [[nodiscard]] auto send_datagram_size() const noexcept -> std::size_t
    { check_owner(); return send_datagram_size_; }
    [[nodiscard]] auto recovery() noexcept -> recovery_orchestration<packet_capacity>&
    { check_owner(); return recovery_; }
    [[nodiscard]] auto peer_ids() noexcept -> peer_connection_id_registry<8>&
    { check_owner(); return peer_ids_; }
    [[nodiscard]] auto local_ids() noexcept -> local_connection_id_registry<8>&
    { check_owner(); return local_ids_; }
    [[nodiscard]] auto paths() noexcept -> path_validation& { check_owner(); return paths_; }

    // Path migration (RFC 9000 Section 9.4). The active path starts at handle 0.
    // Register a candidate before sending its PATH_CHALLENGE, mark it validated
    // only after the caller confirms the authenticated PATH_RESPONSE, and
    // promote it only then. Promotion resets path-specific RTT and congestion
    // control while packet-number spaces, ACK ranges, sent-packet history, and
    // loss detection stay connection-wide. Cancellation and rejected
    // transitions preserve the active path and its recovery state.
    [[nodiscard]] auto path_recovery() noexcept -> path_recovery_state<4>&
    { check_owner(); return path_recovery_; }
    [[nodiscard]] auto begin_path_candidate(path_handle handle)
        -> std::expected<void, path_recovery_error>
    { check_owner(); return path_recovery_.begin_candidate(handle); }
    [[nodiscard]] auto mark_path_validated()
        -> std::expected<void, path_recovery_error>
    { check_owner(); return path_recovery_.mark_validated(); }
    [[nodiscard]] auto promote_path_candidate()
        -> std::expected<void, path_recovery_error>
    {
        check_owner();
        const auto promoted = path_recovery_.promote_candidate();
        if (!promoted) return promoted;
        if (!recovery_.reset_path_recovery(1200))
            return std::unexpected(path_recovery_error::invalid_datagram_size);
        return {};
    }
    [[nodiscard]] auto cancel_path_candidate()
        -> std::expected<void, path_recovery_error>
    { check_owner(); return path_recovery_.cancel_candidate(); }

    [[nodiscard]] auto open_stream(stream_direction direction)
        -> std::expected<std::uint64_t, connection_error>
    {
        check_owner();
        if (core_.state() != connection_state::active)
            return std::unexpected(connection_error::invalid_state);
        const auto capacity = direction == stream_direction::bidirectional
            ? bidi_stream_capacity : uni_stream_capacity;
        const auto role = role_ == endpoint_role::client ? stream_role::client : stream_role::server;
        std::size_t active = 0;
        for (const auto& slot : slots_)
            active += slot.occupied && stream_initiator(slot.id) == role &&
                stream_type(slot.id) == direction;
        if (active >= capacity)
            return std::unexpected(connection_error::capacity_exceeded);
        const auto id = registry_.open_local(direction);
        if (!id) return std::unexpected(connection_error::capacity_exceeded);
        if (!admit(*id)) return std::unexpected(connection_error::capacity_exceeded);
        return *id;
    }
    [[nodiscard]] auto stream(std::uint64_t id) noexcept -> stream_slot*
    {
        check_owner();
        // Scan the compact id array rather than the large slots.
        for (std::size_t i = 0; i < slot_ids_.size(); ++i)
            if (slot_ids_[i] == id) return &slots_[i];
        return nullptr;
    }
    [[nodiscard]] auto stream_slots() noexcept -> std::span<stream_slot>
    { check_owner(); return slots_; }
    [[nodiscard]] auto stream_slots() const noexcept -> std::span<const stream_slot>
    { check_owner(); return slots_; }
    // Occupied slots in ascending slot order, so iterating matches a scan of
    // stream_slots() that skips empty slots, but touches only active entries.
    [[nodiscard]] auto active_slots() noexcept -> std::span<stream_slot*>
    { check_owner(); return {active_slots_.data(), active_count_}; }
    using retirement_callback = void (*)(void*, tls_level, std::uint64_t,
                                         retirement_reason) noexcept;
    auto set_retirement_observer(void* argument, retirement_callback callback) noexcept -> void
    { check_owner(); retirement_argument_ = argument; retirement_callback_ = callback; }
    // Capacity-only preview on the owner thread before UDP submission. Stream,
    // flow-credit, and state validation happens once in record_sent after the
    // send is staged; the scheduler serializes prepare/complete, so no
    // connection state changes between the preview and the commit.
    [[nodiscard]] auto preflight_sent(tls_level level, sent_packet packet,
        bool probe = false) const -> std::expected<void, connection_error>
    {
        check_owner();
        if (static_cast<std::size_t>(level) >= 3)
            return std::unexpected(connection_error::invalid_configuration);
        if (std::ranges::find(sent_keys_, no_record) == sent_keys_.end())
            return std::unexpected(connection_error::capacity_exceeded);
        if (!recovery_.preflight_record(static_cast<packet_number_space>(level), packet, probe))
            return std::unexpected(connection_error::capacity_exceeded);
        return {};
    }
    [[nodiscard]] auto consume_stream(std::uint64_t id, std::size_t size)
        -> std::expected<void, connection_error>
    {
        auto* s = stream(id);
        if (!s || !s->receive || size > s->receive->readable().size() ||
            s->state.receiving() == stream_receive_state::reset_received ||
            s->state.receiving() == stream_receive_state::reset_read)
            return std::unexpected(connection_error::invalid_state);
        auto next_flow = flow_;
        if (!next_flow.consume(id, size))
            return std::unexpected(connection_error::invalid_state);
        const auto data_limit = next_flow.replenish_receive_max_data(local_.data);
        const auto stream_limit = next_flow.replenish_receive_stream_limit(id, s->receive_window);
        if (!data_limit || !stream_limit || !s->receive->consume(size) ||
            !s->receive->extend_flow_limit(*stream_limit))
            return std::unexpected(connection_error::invalid_state);
        data_credit_pending_ |= *data_limit > flow_.receive_max_data();
        s->credit_pending |= *stream_limit > s->receive_limit;
        if (s->credit_pending) stream_control_pending_ = true;
        s->receive_limit = *stream_limit;
        s->consumed += size;
        flow_ = next_flow;
        if (!s->state.receive_contiguous(s->receive->next_offset() + s->receive->readable().size()))
            return std::unexpected(connection_error::invalid_state);
        if (s->receive->complete() && !s->state.read_all_data())
            return std::unexpected(connection_error::invalid_state);
        retire_closed_streams();
        return {};
    }
    [[nodiscard]] auto consume_reset(std::uint64_t id)
        -> std::expected<void, connection_error>
    {
        auto* s = stream(id);
        if (!s || s->state.receiving() != stream_receive_state::reset_received)
            return std::unexpected(connection_error::invalid_state);
        const auto final = *s->state.receive_final_size();
        auto next_flow = flow_;
        if (final < s->consumed || !next_flow.consume(id, final - s->consumed))
            return std::unexpected(connection_error::invalid_state);
        const auto limit = next_flow.replenish_receive_max_data(local_.data);
        if (!limit || !s->state.read_reset()) return std::unexpected(connection_error::invalid_state);
        data_credit_pending_ |= *limit > flow_.receive_max_data();
        s->consumed = final;
        s->receive.reset();
        flow_ = next_flow;
        retire_closed_streams();
        return {};
    }
    [[nodiscard]] auto finish_read(std::uint64_t id) noexcept -> bool
    {
        auto* s = stream(id);
        if (!s || !s->receive || !s->receive->complete() ||
            !s->receive->readable().empty()) return false;
        if (!s->state.read_all_data()) return false;
        retire_closed_streams();
        return true;
    }
    // Local RESET_STREAM (RFC 9000 3.1). Unsent queued bytes are discarded;
    // the final size is the highest offset already transmitted. A stream whose
    // send side already ended in reset or acknowledged data is left unchanged.
    [[nodiscard]] auto reset_stream(std::uint64_t id, std::uint64_t error)
        -> std::expected<void, connection_error>
    {
        check_owner();
        auto* s = stream(id);
        if (!s || s->state.sending() == stream_send_state::absent || error > max_varint_value)
            return std::unexpected(connection_error::invalid_configuration);
        const auto sending = s->state.sending();
        if (sending == stream_send_state::reset_sent || sending == stream_send_state::reset_received ||
            sending == stream_send_state::data_received) return {};
        return queue_reset(*s, error)
            ? std::expected<void, connection_error> {}
            : std::unexpected(connection_error::invalid_state);
    }
    // Local STOP_SENDING (RFC 9000 3.5). Buffered and later data are discarded,
    // and the peer's answering RESET_STREAM is consumed without an application
    // read. A receive side that already finished is left unchanged.
    [[nodiscard]] auto stop_sending(std::uint64_t id, std::uint64_t error)
        -> std::expected<void, connection_error>
    {
        check_owner();
        auto* s = stream(id);
        if (!s || s->state.receiving() == stream_receive_state::absent ||
            error > max_varint_value)
            return std::unexpected(connection_error::invalid_configuration);
        // A consumed peer reset already released the receive buffer.
        if (s->receive_abandoned || !s->receive) return {};
        s->receive_abandoned = true;
        const auto receiving = s->state.receiving();
        if ((receiving == stream_receive_state::receive ||
             receiving == stream_receive_state::size_known) && s->state.send_stop_sending()) {
            s->stop_sending_error = error;
            s->stop_sending_pending = true;
            stream_control_pending_ = true;
        }
        return drain_abandoned(*s)
            ? std::expected<void, connection_error> {}
            : std::unexpected(connection_error::invalid_state);
    }
    [[nodiscard]] auto receive_abandoned(std::uint64_t id) const noexcept -> bool
    {
        check_owner();
        for (const auto& s : slots_) if (s.occupied && s.id == id) return s.receive_abandoned;
        return false;
    }
    // Pending controls stay in fixed connection storage until copied into the
    // scheduler's reliable control queue. New credit supersedes older credit.
    [[nodiscard]] auto pending_control() noexcept -> std::optional<decoded_frame>
    {
        check_owner();
        // Fast path: most application packets carry no pending control frame.
        if (!stream_control_pending_ && !data_credit_pending_ &&
            !stream_credit_pending_[0] && !stream_credit_pending_[1])
            return {};
        decoded_frame frame;
        for (auto* active : active_slots()) if (auto& s = *active; s.reset_pending) {
            frame.type = 4; frame.stream_id = s.id;
            frame.final_size = *s.state.send_final_size();
            frame.error_code = s.reset_error; return frame;
        }
        for (auto* active : active_slots()) if (auto& s = *active; s.stop_sending_pending) {
            frame.type = 5; frame.stream_id = s.id;
            frame.error_code = s.stop_sending_error; return frame;
        }
        if (data_credit_pending_) { frame.type = 0x10; frame.limit = flow_.receive_max_data(); return frame; }
        for (auto* active : active_slots()) if (auto& s = *active; s.credit_pending) {
            frame.type = 0x11; frame.stream_id = s.id; frame.limit = s.receive_limit; return frame;
        }
        stream_control_pending_ = false;
        for (std::size_t i = 0; i < stream_credit_pending_.size(); ++i)
            if (stream_credit_pending_[i]) {
                frame.type = i == 0 ? 0x12 : 0x13;
                frame.limit = registry_.local_limit(i == 0 ? stream_direction::bidirectional
                                                      : stream_direction::unidirectional);
                return frame;
            }
        return {};
    }
    auto control_queued(const decoded_frame& frame) noexcept -> void
    {
        check_owner();
        if (frame.type == 0x10) data_credit_pending_ = false;
        else if (frame.type == 0x12 || frame.type == 0x13)
            stream_credit_pending_[frame.type == 0x12 ? 0 : 1] = false;
        else if (auto* s = stream(frame.stream_id)) {
            if (frame.type == 4) s->reset_pending = false;
            if (frame.type == 5) s->stop_sending_pending = false;
            if (frame.type == 0x11) s->credit_pending = false;
        }
    }
    auto control_acked(std::uint64_t type, std::uint64_t id) noexcept -> void
    { check_owner(); if (type == 4) if (auto* s = stream(id)) {
        (void)s->state.reset_acked(); retire_closed_streams(); } }

    // Synchronize packet-number-space retirement with TLS key retirement.
    // Call after core.advance(), receive(), and a successful Handshake send.
    [[nodiscard]] auto synchronize_discarded_spaces()
        -> std::expected<void, connection_error>
    {
        check_owner();
        for (std::size_t index = 0; index < recovery_discarded_.size(); ++index) {
            const auto level = static_cast<tls_level>(index);
            if (!core_.level_discarded(level) || recovery_discarded_[index]) continue;
            const auto discarded = recovery_.discard_space(
                static_cast<packet_number_space>(index), retired_);
            if (!discarded || !retire(discarded->retired))
                return std::unexpected(connection_error::invalid_state);
            recovery_discarded_[index] = true;
        }
        return {};
    }

    [[nodiscard]] auto application_pto() const noexcept
        -> std::optional<lifecycle_duration>
    {
        check_owner();
        const auto ack_delay = std::chrono::duration_cast<recovery_duration>(
            std::chrono::milliseconds(peer_.ack_delay));
        const auto duration = recovery_.rtt().pto_duration(
            packet_number_space::application_data, core_.handshake_confirmed(),
            ack_delay, recovery_.pto_count());
        if (!duration) return {};
        return std::chrono::duration_cast<lifecycle_duration>(*duration);
    }
    [[nodiscard]] auto receive_datagram(std::span<std::byte> output)
        -> std::expected<std::size_t, datagram_queue_error>
    { check_owner(); return datagrams_.consume(output); }
    [[nodiscard]] auto queue_datagram(std::span<const std::byte> data)
        -> std::expected<void, datagram_queue_error>
    { check_owner(); return outgoing_datagrams_.push(data); }
    // Remove only after a successful UDP send. DATAGRAMs are never retransmitted.
    [[nodiscard]] auto outgoing_datagrams() noexcept -> datagram_queue&
    { check_owner(); return outgoing_datagrams_; }

    [[nodiscard]] auto receive(std::span<const std::uint8_t> datagram, std::size_t offset,
        std::size_t short_cid_length, std::span<std::uint8_t> packet_scratch,
        std::span<std::uint8_t> plaintext, std::span<std::uint8_t> auth_scratch,
        lifecycle_time_point now, lifecycle_duration pto)
        -> std::expected<opened_protected_packet, connection_error>
    {
        check_owner();
        const auto header = parse_packet_header(std::as_bytes(datagram), offset, short_cid_length,
            core_.local_grease_quic_bit());
        if (!header) return std::unexpected(connection_error::malformed_packet);
        receive_time_ = now;
        destination_ = header->destination_cid;
        const auto result = core_.receive(datagram, offset, short_cid_length,
            packet_scratch, plaintext, auth_scratch, now, pto);
        destination_ = {};
        recovery_.set_handshake_confirmed(core_.handshake_confirmed());
        return result;
    }

    // Called after successful UDP transmission. A bookkeeping failure requires
    // retiring the connection; the endpoint must reserve capacity before send.
    // Each packet's retransmittable byte ranges are retained until ACK or loss.
    // The optional `range_slots` are the stream slots that produced `ranges`,
    // in order, so callers that already selected them avoid a stream lookup.
    [[nodiscard]] auto record_sent(tls_level level, sent_packet packet,
        std::span<const transmitted_range> ranges, bool probe = false,
        std::span<stream_slot* const> range_slots = {},
        std::optional<std::uint64_t> carried_ack_largest = {},
        std::optional<std::uint64_t> acknowledged_peer_packet = {})
        -> std::expected<void, connection_error>
    {
        check_owner();
        const auto space = static_cast<packet_number_space>(level);
        if (static_cast<std::size_t>(level) >= 3 || ranges.size() > frames_per_packet)
            return std::unexpected(connection_error::invalid_configuration);
        const auto free_key = std::ranges::find(sent_keys_, no_record);
        if (free_key == sent_keys_.end()) return std::unexpected(connection_error::capacity_exceeded);
        auto* record = &sent_[static_cast<std::size_t>(free_key - sent_keys_.begin())];
        auto next_flow = flow_.stage_send<frames_per_packet>();
        std::array<stream_slot*, frames_per_packet> range_streams {};
        std::size_t range_index = 0;
        for (const auto& range : ranges) {
            if (range.crypto) { ++range_index; continue; }
            auto* s = range_index < range_slots.size() ? range_slots[range_index]
                                                       : stream(range.stream_id);
            if (!s || !next_flow.send_stream_range(range.stream_id, range.offset, range.size, range.fin))
                return std::unexpected(connection_error::protocol_violation);
            auto state = s->state;
            if (!s->send.preflight_mark_sent(range.offset, range.size, range.fin) ||
                !state.send_stream(range.offset, range.size, range.fin))
                return std::unexpected(connection_error::invalid_state);
            range_streams[range_index++] = s;
        }
        if (!recovery_.record(space, packet, probe))
            return std::unexpected(connection_error::capacity_exceeded);
        next_flow.commit();
        record->occupied = true; record->space = space; record->number = packet.number;
        *free_key = record_key(space, packet.number);
        record->carried_ack_largest = carried_ack_largest;
        record->count = ranges.size();
        std::copy(ranges.begin(), ranges.end(), record->ranges.begin());
        record->stream_slots = range_streams;
        for (std::size_t j = 0; j < ranges.size(); ++j)
            if (!ranges[j].crypto) ++range_streams[j]->in_flight;
        range_index = 0;
        for (const auto& range : ranges) {
            if (range.crypto) {
                if (!core_.mark_crypto_sent(level, range.offset, range.size))
                    return std::unexpected(connection_error::invalid_state);
            } else {
                auto* s = range_streams[range_index];
                // preflight_mark_sent validated this range in the first pass.
                s->send.mark_sent_trusted(range.offset, range.size, range.fin);
                (void)s->state.send_stream(range.offset, range.size, range.fin);
                s->sent_highest = (std::max)(s->sent_highest, range.offset + range.size);
            }
            ++range_index;
        }
        if (!core_.packet_sent(packet.sent_time, packet.ack_eliciting))
            return std::unexpected(connection_error::invalid_state);
        if (level == tls_level::application &&
            !core_.application_packet_sent(packet.number, acknowledged_peer_packet))
            return std::unexpected(connection_error::key_update_violation);
        core_.encryption_level_sent(level);
        if (!synchronize_discarded_spaces())
            return std::unexpected(connection_error::invalid_state);
        return {};
    }
    [[nodiscard]] auto on_timeout(lifecycle_time_point now)
        -> std::expected<recovery_result, connection_error>
    {
        check_owner();
        const auto result = recovery_.on_timeout(now, retired_);
        if (!result) return std::unexpected(connection_error::protocol_violation);
        if (!retire(result->retired)) return std::unexpected(connection_error::invalid_state);
        return *result;
    }

private:
    struct parameter_limits {
        std::uint64_t data {}, bidi_local {}, bidi_remote {}, stream_uni {}, bidi {}, uni {}, datagram {};
        std::uint64_t udp_payload {65527};
        std::uint64_t ack_exponent {3}, ack_delay {25};
    };
    struct packet_record {
        packet_number_space space {};
        std::uint64_t number {};
        std::array<transmitted_range, frames_per_packet> ranges {};
        // Stream slot that produced each non-crypto range, parallel to `ranges`.
        // The slot cannot be reused while this record is occupied, so the
        // pointer stays valid until retirement (see retire_closed_streams).
        std::array<stream_slot*, frames_per_packet> stream_slots {};
        std::size_t count {};
        std::optional<std::uint64_t> carried_ack_largest;
        bool occupied {false};
    };
    auto check_owner() const noexcept -> void
    { if (owner_ != std::this_thread::get_id()) std::terminate(); }
    static auto limits(const transport_parameters& parameters) noexcept -> parameter_limits
    {
        parameter_limits result;
        const auto get = [&](parameter_id id, std::uint64_t fallback = 0) {
            const auto* p = parameters.find(static_cast<std::uint64_t>(id));
            return p ? parameter_integer(p->value).value_or(fallback) : fallback;
        };
        result.data = get(parameter_id::initial_max_data);
        result.bidi_local = get(parameter_id::initial_max_stream_data_bidi_local);
        result.bidi_remote = get(parameter_id::initial_max_stream_data_bidi_remote);
        result.stream_uni = get(parameter_id::initial_max_stream_data_uni);
        result.bidi = get(parameter_id::initial_max_streams_bidi);
        result.uni = get(parameter_id::initial_max_streams_uni);
        result.datagram = get(parameter_id::max_datagram_frame_size);
        result.udp_payload = get(parameter_id::max_udp_payload_size, 65527);
        result.ack_exponent = get(parameter_id::ack_delay_exponent, 3);
        result.ack_delay = get(parameter_id::max_ack_delay, 25);
        return result;
    }
    static auto validate_parameters(void* argument, std::span<const std::uint8_t> bytes) noexcept -> bool
    {
        auto& self = *static_cast<bounded_connection*>(argument);
        if (!self.callbacks_.validate_parameters(self.callbacks_.argument, bytes)) return false;
        const auto parsed = decode_transport_parameters(std::as_bytes(bytes),
            self.role_ == endpoint_role::client ? parameter_sender::server : parameter_sender::client);
        if (!parsed) return false;
        self.peer_ = limits(*parsed);
        const auto buffer_cap = static_cast<std::uint64_t>(datagram_buffer_size);
        const auto local_cap = std::clamp<std::uint64_t>(self.local_.udp_payload, 1200, buffer_cap);
        const auto peer_cap = std::clamp<std::uint64_t>(self.peer_.udp_payload, 1200, buffer_cap);
        self.send_datagram_size_ = static_cast<std::size_t>(std::min(local_cap, peer_cap));
        if (!self.recovery_.reset(self.send_datagram_size_)) return false;
        self.outgoing_datagrams_.reset(self.peer_.datagram);
        self.recovery_.set_max_ack_delay(std::chrono::milliseconds(self.peer_.ack_delay));
        return self.registry_.set_peer_limit(stream_direction::bidirectional, self.peer_.bidi).has_value() &&
            self.registry_.set_peer_limit(stream_direction::unidirectional, self.peer_.uni).has_value() &&
            self.flow_.update_send_max_data(self.peer_.data).has_value();
    }
    auto admit(std::uint64_t id) noexcept -> stream_slot*
    {
        if (auto* existing = stream(id)) return existing;
        const auto role = role_ == endpoint_role::client ? stream_role::client : stream_role::server;
        if (!registry_.find(id) && !registry_.observe_peer(id)) return nullptr;
        const bool local = stream_initiator(id) == role;
        const bool bidi = stream_type(id) == stream_direction::bidirectional;
        const auto send_limit = bidi ? (local ? peer_.bidi_remote : peer_.bidi_local) : peer_.stream_uni;
        const auto receive_limit = bidi ? (local ? local_.bidi_local : local_.bidi_remote) : local_.stream_uni;
        for (auto& s : slots_) {
            if (s.occupied) continue;
            if (!flow_.add_stream(id, send_limit, receive_limit)) return nullptr;
            s.id = id; s.occupied = true; s.state = *stream_state::create(id, role);
            slot_ids_[static_cast<std::size_t>(&s - slots_.data())] = id;
            s.receive_window = s.receive_limit = receive_limit;
            s.receive.emplace(s.bytes, s.coverage, receive_limit);
            (void)s.send.extend_flow_limit(send_limit);
            const auto position = std::lower_bound(active_slots_.begin(),
                active_slots_.begin() + active_count_, &s);
            std::move_backward(position, active_slots_.begin() + active_count_,
                active_slots_.begin() + active_count_ + 1);
            *position = &s;
            ++active_count_;
            return &s;
        }
        return nullptr;
    }
    auto queue_reset(stream_slot& s, std::uint64_t error) noexcept -> bool
    {
        const auto final = s.state.send_final_size().value_or(s.sent_highest);
        if (!flow_.set_send_final_size(s.id, final) || !s.state.send_reset(final)) return false;
        s.reset_error = error;
        s.reset_pending = true;
        stream_control_pending_ = true;
        return true;
    }
    // Consume everything an abandoned receive side holds. This may retire the
    // slot, so callers must not use it afterwards.
    auto drain_abandoned(stream_slot& s) noexcept -> bool
    {
        const auto id = s.id;
        if (s.state.receiving() == stream_receive_state::reset_received)
            return consume_reset(id).has_value();
        if (!s.receive) return true;
        if (const auto readable = s.receive->readable().size(); readable != 0)
            if (!consume_stream(id, readable)) return false;
        if (auto* current = stream(id); current && current->receive && current->receive->complete())
            (void)finish_read(id);
        return true;
    }
    auto retire_closed_streams() noexcept -> void
    {
        const auto local_role = role_ == endpoint_role::client ? stream_role::client : stream_role::server;
        std::size_t active = 0;
        while (active < active_count_) {
            auto& slot = *active_slots_[active];
            if (!slot.occupied || !slot.state.closed()) { ++active; continue; }
            if (slot.in_flight != 0 || !registry_.close(slot.id)) { ++active; continue; }
            const auto peer = stream_initiator(slot.id) != local_role;
            const auto direction = stream_type(slot.id);
            (void)flow_.remove_stream(slot.id);
            slot.receive.reset();
            slot.send.reset();
            slot.state = {};
            slot.id = slot.sent_highest = slot.receive_window = 0;
            slot.receive_limit = slot.consumed = 0;
            slot.credit_pending = slot.reset_pending = false;
            slot.reset_error = slot.stop_sending_error = 0;
            slot.stop_sending_pending = slot.receive_abandoned = false;
            slot.accepted = slot.occupied = false;
            slot_ids_[static_cast<std::size_t>(&slot - slots_.data())] = no_stream;
            std::move(active_slots_.begin() + active + 1,
                active_slots_.begin() + active_count_,
                active_slots_.begin() + active);
            --active_count_;
            if (peer && registry_.local_limit(direction) < max_stream_count) {
                (void)registry_.set_local_limit(direction,
                    registry_.local_limit(direction) + 1);
                stream_credit_pending_[direction == stream_direction::bidirectional ? 0 : 1] = true;
            }
        }
    }
    auto release(packet_record& record) noexcept -> void
    {
        for (std::size_t j = 0; j < record.count; ++j)
            if (!record.ranges[j].crypto && record.stream_slots[j] != nullptr)
                --record.stream_slots[j]->in_flight;
        record.occupied = false;
        sent_keys_[static_cast<std::size_t>(&record - sent_.data())] = no_record;
    }
    auto retire(std::size_t count) noexcept -> bool
    {
        for (std::size_t i = 0; i < count; ++i) {
            const auto& retired = retired_[i];
            const auto key = std::ranges::find(sent_keys_, record_key(retired.space, retired.packet.number));
            if (key != sent_keys_.end()) {
                auto& record = sent_[static_cast<std::size_t>(key - sent_keys_.begin())];
                if (retired.reason == retirement_reason::discarded) {
                    release(record);
                    if (retirement_callback_) retirement_callback_(retirement_argument_,
                        static_cast<tls_level>(record.space), record.number,
                        retirement_reason::discarded);
                    continue;
                }
                if (retired.reason == retirement_reason::acknowledged &&
                    record.space == packet_number_space::application_data) {
                    const auto pto = application_pto().value_or(
                        std::chrono::duration_cast<lifecycle_duration>(initial_rtt));
                    if (!core_.acknowledge_application_packet(record.number,
                            receive_time_, pto)) return false;
                }
                if (retired.reason == retirement_reason::acknowledged && record.carried_ack_largest &&
                    !core_.retire_ack(static_cast<tls_level>(record.space), *record.carried_ack_largest)) return false;
                for (std::size_t j = 0; j < record.count; ++j) {
                    const auto& range = record.ranges[j];
                    const bool ack = retired.reason == retirement_reason::acknowledged;
                    if (range.crypto) {
                        const auto level = static_cast<tls_level>(record.space);
                        if (!(ack ? core_.acknowledge_crypto(level, range.offset, range.size) :
                                    core_.lose_crypto(level, range.offset, range.size))) return false;
                    } else {
                        auto* s = record.stream_slots[j];
                        if (s == nullptr) return false;
                        if (s->state.sending() == stream_send_state::reset_sent ||
                            s->state.sending() == stream_send_state::reset_received) continue;
                        if (!(ack ? s->send.acknowledge(range.offset, range.size, range.fin) :
                                    s->send.mark_lost(range.offset, range.size, range.fin))) return false;
                        if (s->send.complete() && !s->state.all_data_acked()) return false;
                    }
                }
                release(record);
                if (retirement_callback_) retirement_callback_(retirement_argument_,
                    static_cast<tls_level>(record.space), record.number,
                    retired.reason);
            }
        }
        retire_closed_streams();
        return true;
    }
    static auto dispatch(void* argument, tls_level level, const decoded_frame& frame) noexcept -> bool
    { return static_cast<bounded_connection*>(argument)->on_frame(level, frame); }
    auto on_frame(tls_level level, const decoded_frame& frame) noexcept -> bool
    {
        const auto local_role = role_ == endpoint_role::client ? stream_role::client : stream_role::server;
        const bool local_uni = stream_type(frame.stream_id) == stream_direction::unidirectional &&
            stream_initiator(frame.stream_id) == local_role;
        const bool peer_uni = stream_type(frame.stream_id) == stream_direction::unidirectional &&
            stream_initiator(frame.stream_id) != local_role;
        if ((((frame.type >= 8 && frame.type <= 15) || frame.type == 4 ||
              frame.type == 0x15) && local_uni) ||
            (frame.type == 5 && peer_uni)) return false;
        if (((frame.type >= 8 && frame.type <= 15) || frame.type == 4 ||
             frame.type == 5 || frame.type == 0x11 || frame.type == 0x15) &&
            registry_.is_retired(frame.stream_id)) return true;
        if (frame.type == 2 || frame.type == 3) {
            // ECN marking is not enabled by this owner. Ignore optional counters.
            const auto us = frame.ack_delay > (std::uint64_t(INT64_MAX) >> peer_.ack_exponent)
                ? INT64_MAX : static_cast<std::int64_t>(frame.ack_delay << peer_.ack_exponent);
            const auto result = recovery_.on_ack(static_cast<packet_number_space>(level), frame,
                receive_time_, std::chrono::microseconds(us), retired_);
            return result && retire(result->retired);
        }
        if (frame.type >= 8 && frame.type <= 15) {
            auto* s = admit(frame.stream_id);
            if (!s || !s->state.receive_stream(frame.offset, frame.data.size(), frame.fin) ||
                !flow_.receive_stream_range(frame.stream_id, frame.offset, frame.data.size(), frame.fin)) return false;
            if (s->state.receiving() == stream_receive_state::reset_received ||
                s->state.receiving() == stream_receive_state::reset_read) return true;
            if (!s->receive->insert(frame.offset, frame.data, frame.fin)) return false;
            if (!s->state.receive_contiguous(s->receive->next_offset() + s->receive->readable().size()))
                return false;
            return !s->receive_abandoned || drain_abandoned(*s);
        }
        switch (frame.type) {
        case 4: {
            auto* s = admit(frame.stream_id);
            if (!s || !flow_.set_receive_final_size(frame.stream_id, frame.final_size) ||
                !s->state.receive_reset(frame.final_size)) return false;
            return !s->receive_abandoned || drain_abandoned(*s);
        }
        case 5: {
            auto* s = admit(frame.stream_id);
            if (!s || !s->state.receive_stop_sending(frame.error_code)) return false;
            if (!s->state.reset_required()) return true;
            return queue_reset(*s, frame.error_code);
        }
        case 0x10: return flow_.update_send_max_data(frame.limit).has_value();
        case 0x11: {
            auto* s = admit(frame.stream_id);
            return s && s->state.receive_max_stream_data() &&
                flow_.update_send_stream_limit(frame.stream_id, frame.limit) &&
                (frame.limit <= s->send.flow_limit() || s->send.extend_flow_limit(frame.limit).has_value());
        }
        case 0x12: case 0x13:
            return registry_.set_peer_limit(frame.type == 0x12 ? stream_direction::bidirectional : stream_direction::unidirectional, frame.limit).has_value();
        case 0x18: return peer_ids_.add(frame.sequence_number, frame.retire_prior_to, frame.connection_id, frame.stateless_reset_token).has_value();
        case 0x19: return local_ids_.retire(frame.sequence_number, destination_).has_value();
        case 0x1b: {
            path_challenge token; std::copy(frame.data.begin(), frame.data.end(), token.begin());
            (void)paths_.accept_response(token); return true;
        }
        case 0x1a: return true; // The endpoint sends PATH_RESPONSE on the arrival path.
        case 0x30: case 0x31:
            if (local_.datagram == 0 || frame.encoded_size > local_.datagram) return false;
            // A full application receive queue discards unreliable DATAGRAMs.
            { const auto r = datagrams_.push(frame.data, frame.type == 0x31);
              return r.has_value() || r.error() == datagram_queue_error::full ||
                     r.error() == datagram_queue_error::frame_too_large; }
        case 0x14: case 0x16: case 0x17: return true;
        case 0x15: { auto* s = admit(frame.stream_id); return s && s->state.receive_data_blocked(); }
        default: return callbacks_.frame && callbacks_.frame(callbacks_.argument, level, frame);
        }
    }
    std::thread::id owner_ {std::this_thread::get_id()};
    endpoint_role role_;
    connection_callbacks callbacks_;
    bool data_credit_pending_ {false};
    bool stream_control_pending_ {false};
    std::array<bool, 2> stream_credit_pending_ {};
    void* retirement_argument_ {};
    retirement_callback retirement_callback_ {};
    parameter_limits local_, peer_;
    std::size_t send_datagram_size_ {1200};
    stream_registry<stream_capacity> registry_;
    flow_control<stream_capacity> flow_;
    std::array<stream_slot, stream_capacity> slots_;
    std::array<stream_slot*, stream_capacity> active_slots_ {};
    // Stream id of each occupied slot, no_stream otherwise (ids stay below 2^62).
    static constexpr std::uint64_t no_stream = ~std::uint64_t {0};
    std::array<std::uint64_t, stream_capacity> slot_ids_ = [] {
        std::array<std::uint64_t, stream_capacity> ids {};
        ids.fill(no_stream);
        return ids;
    }();
    std::size_t active_count_ {0};
    recovery_orchestration<packet_capacity> recovery_;
    path_recovery_state<4> path_recovery_ {};
    std::array<packet_record, packet_capacity * 3> sent_ {};
    // Space and number of each occupied record in sent_, no_record otherwise,
    // so lookups scan 3 KiB instead of the records themselves.
    static constexpr std::uint64_t no_record = ~std::uint64_t {0};
    static constexpr auto record_key(packet_number_space space, std::uint64_t number) noexcept
        -> std::uint64_t
    { return number << 2 | static_cast<std::uint64_t>(space); }
    std::array<std::uint64_t, packet_capacity * 3> sent_keys_ = [] {
        std::array<std::uint64_t, packet_capacity * 3> keys {};
        keys.fill(no_record);
        return keys;
    }();
    std::array<retired_packet, packet_capacity * 3> retired_ {};
    peer_connection_id_registry<8> peer_ids_;
    local_connection_id_registry<8> local_ids_;
    std::array<path_validation_slot, 4> path_slots_ {};
    path_validation paths_;
    std::array<std::array<std::byte, 1200>, 8> datagram_bytes_ {};
    std::array<datagram_slot, 8> datagram_slots_ {};
    datagram_queue datagrams_ {datagram_slots_};
    std::array<std::array<std::byte, 1200>, 8> outgoing_datagram_bytes_ {};
    std::array<datagram_slot, 8> outgoing_datagram_slots_ {};
    datagram_queue outgoing_datagrams_ {outgoing_datagram_slots_};
    lifecycle_time_point receive_time_ {};
    std::span<const std::byte> destination_;
    std::array<bool, 2> recovery_discarded_ {};
    connection_core core_;
};

} // namespace eventloop::quic::detail
