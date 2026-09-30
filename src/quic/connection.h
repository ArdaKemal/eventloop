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
    static constexpr std::size_t stream_capacity = 32;
    static constexpr std::size_t stream_bytes = 4096;
    static constexpr std::size_t receive_bytes = stream_capacity * stream_bytes;
    static constexpr std::size_t packet_capacity = 128;
    static constexpr std::size_t frames_per_packet = 8;
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
        stream_send_buffer<stream_bytes> send;
        stream_state state;
        std::uint64_t sent_highest {}, receive_window {}, receive_limit {}, consumed {};
        bool credit_pending {false}, reset_pending {false};
        bool occupied {false};
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
            local_.bidi_remote > stream_bytes || local_.stream_uni > stream_bytes)
            return std::unexpected(connection_error::invalid_configuration);
        if (!registry_.set_local_limit(stream_direction::bidirectional, local_.bidi) ||
            !registry_.set_local_limit(stream_direction::unidirectional, local_.uni))
            return std::unexpected(connection_error::invalid_configuration);
        flow_ = *flow_control<stream_capacity>::create(0, local_.data);
        datagrams_.reset(local_.datagram);
        return core_.initialize(context, options, version, dcid);
    }
    [[nodiscard]] auto core() noexcept -> connection_core& { check_owner(); return core_; }
    [[nodiscard]] auto streams() const noexcept -> const stream_registry<stream_capacity>&
    { check_owner(); return registry_; }
    [[nodiscard]] auto flow() const noexcept -> const flow_control<stream_capacity>&
    { check_owner(); return flow_; }
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
        const auto id = registry_.open_local(direction);
        if (!id) return std::unexpected(connection_error::capacity_exceeded);
        if (!admit(*id)) return std::unexpected(connection_error::capacity_exceeded);
        return *id;
    }
    [[nodiscard]] auto stream(std::uint64_t id) noexcept -> stream_slot*
    { check_owner(); for (auto& s : slots_) if (s.occupied && s.id == id) return &s; return nullptr; }
    [[nodiscard]] auto stream_slots() const noexcept -> std::span<const stream_slot>
    { check_owner(); return slots_; }
    using retirement_callback = void (*)(void*, tls_level, std::uint64_t,
                                         retirement_reason) noexcept;
    auto set_retirement_observer(void* argument, retirement_callback callback) noexcept -> void
    { check_owner(); retirement_argument_ = argument; retirement_callback_ = callback; }
    // Preview on the owner thread before UDP submission. Until completion the
    // owner must serialize sends and retain the selected stream/CRYPTO ranges.
    [[nodiscard]] auto preflight_sent(tls_level level, sent_packet packet,
        std::span<const transmitted_range> ranges, bool probe = false) const
        -> std::expected<void, connection_error>
    {
        check_owner();
        if (static_cast<std::size_t>(level) >= 3 || ranges.size() > frames_per_packet)
            return std::unexpected(connection_error::invalid_configuration);
        if (std::ranges::none_of(sent_, [](const auto& r) { return !r.occupied; }))
            return std::unexpected(connection_error::capacity_exceeded);
        auto preview = recovery_;
        if (!preview.record(static_cast<packet_number_space>(level), packet, probe))
            return std::unexpected(connection_error::capacity_exceeded);
        auto flow = flow_;
        for (const auto& range : ranges) {
            if (range.crypto) continue;
            const stream_slot* slot = nullptr;
            for (const auto& s : slots_) if (s.occupied && s.id == range.stream_id) slot = &s;
            if (!slot || !flow.send_stream_range(range.stream_id, range.offset, range.size, range.fin))
                return std::unexpected(connection_error::protocol_violation);
            auto send = slot->send;
            auto state = slot->state;
            if (!send.mark_sent(range.offset, range.size, range.fin) ||
                !state.send_stream(range.offset, range.size, range.fin))
                return std::unexpected(connection_error::invalid_state);
        }
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
        s->receive_limit = *stream_limit;
        s->consumed += size;
        flow_ = next_flow;
        if (!s->state.receive_contiguous(s->receive->next_offset() + s->receive->readable().size()))
            return std::unexpected(connection_error::invalid_state);
        if (s->receive->complete() && !s->state.read_all_data())
            return std::unexpected(connection_error::invalid_state);
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
        return {};
    }
    // Pending controls stay in fixed connection storage until copied into the
    // scheduler's reliable control queue. New credit supersedes older credit.
    [[nodiscard]] auto pending_control() noexcept -> std::optional<decoded_frame>
    {
        check_owner();
        decoded_frame frame;
        for (auto& s : slots_) if (s.occupied && s.reset_pending) {
            frame.type = 4; frame.stream_id = s.id;
            frame.final_size = *s.state.send_final_size();
            frame.error_code = *s.state.stop_error(); return frame;
        }
        if (data_credit_pending_) { frame.type = 0x10; frame.limit = flow_.receive_max_data(); return frame; }
        for (auto& s : slots_) if (s.occupied && s.credit_pending) {
            frame.type = 0x11; frame.stream_id = s.id; frame.limit = s.receive_limit; return frame;
        }
        return {};
    }
    auto control_queued(const decoded_frame& frame) noexcept -> void
    {
        check_owner();
        if (frame.type == 0x10) data_credit_pending_ = false;
        else if (auto* s = stream(frame.stream_id)) {
            if (frame.type == 4) s->reset_pending = false;
            if (frame.type == 0x11) s->credit_pending = false;
        }
    }
    auto control_acked(std::uint64_t type, std::uint64_t id) noexcept -> void
    { check_owner(); if (type == 4) if (auto* s = stream(id)) (void)s->state.reset_acked(); }

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
    [[nodiscard]] auto record_sent(tls_level level, sent_packet packet,
        std::span<const transmitted_range> ranges, bool probe = false,
        std::optional<std::uint64_t> carried_ack_largest = {},
        std::optional<std::uint64_t> acknowledged_peer_packet = {})
        -> std::expected<void, connection_error>
    {
        check_owner();
        const auto space = static_cast<packet_number_space>(level);
        if (static_cast<std::size_t>(level) >= 3 || ranges.size() > frames_per_packet)
            return std::unexpected(connection_error::invalid_configuration);
        packet_record* record = nullptr;
        for (auto& candidate : sent_) if (!candidate.occupied) { record = &candidate; break; }
        if (!record) return std::unexpected(connection_error::capacity_exceeded);
        auto next_flow = flow_;
        for (const auto& range : ranges) {
            if (range.crypto) continue;
            auto* s = stream(range.stream_id);
            if (!s || !next_flow.send_stream_range(range.stream_id, range.offset, range.size, range.fin))
                return std::unexpected(connection_error::protocol_violation);
            auto send = s->send;
            auto state = s->state;
            if (!send.mark_sent(range.offset, range.size, range.fin) ||
                !state.send_stream(range.offset, range.size, range.fin))
                return std::unexpected(connection_error::invalid_state);
        }
        if (!recovery_.record(space, packet, probe))
            return std::unexpected(connection_error::capacity_exceeded);
        flow_ = next_flow;
        record->occupied = true; record->space = space; record->number = packet.number;
        record->carried_ack_largest = carried_ack_largest;
        record->count = ranges.size();
        std::copy(ranges.begin(), ranges.end(), record->ranges.begin());
        for (const auto& range : ranges) {
            if (range.crypto) {
                if (!core_.mark_crypto_sent(level, range.offset, range.size))
                    return std::unexpected(connection_error::invalid_state);
            } else {
                auto* s = stream(range.stream_id);
                (void)s->send.mark_sent(range.offset, range.size, range.fin);
                (void)s->state.send_stream(range.offset, range.size, range.fin);
                s->sent_highest = (std::max)(s->sent_highest, range.offset + range.size);
            }
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
        std::uint64_t ack_exponent {3}, ack_delay {25};
    };
    struct packet_record {
        packet_number_space space {};
        std::uint64_t number {};
        std::array<transmitted_range, frames_per_packet> ranges {};
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
            s.receive_window = s.receive_limit = receive_limit;
            s.receive.emplace(s.bytes, s.coverage, receive_limit);
            (void)s.send.extend_flow_limit(send_limit);
            return &s;
        }
        return nullptr;
    }
    auto retire(std::size_t count) noexcept -> bool
    {
        for (std::size_t i = 0; i < count; ++i) {
            const auto& retired = retired_[i];
            for (auto& record : sent_) {
                if (!record.occupied || record.space != retired.space || record.number != retired.packet.number) continue;
                if (retired.reason == retirement_reason::discarded) {
                    record.occupied = false;
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
                        auto* s = stream(range.stream_id);
                        if (s && (s->state.sending() == stream_send_state::reset_sent ||
                                  s->state.sending() == stream_send_state::reset_received)) continue;
                        if (!s || !(ack ? s->send.acknowledge(range.offset, range.size, range.fin) :
                                         s->send.mark_lost(range.offset, range.size, range.fin))) return false;
                        if (s->send.complete() && !s->state.all_data_acked()) return false;
                    }
                }
                record.occupied = false;
                if (retirement_callback_) retirement_callback_(retirement_argument_,
                    static_cast<tls_level>(record.space), record.number,
                    retired.reason);
            }
        }
        return true;
    }
    static auto dispatch(void* argument, tls_level level, const decoded_frame& frame) noexcept -> bool
    { return static_cast<bounded_connection*>(argument)->on_frame(level, frame); }
    auto on_frame(tls_level level, const decoded_frame& frame) noexcept -> bool
    {
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
            return s->state.receive_contiguous(s->receive->next_offset() + s->receive->readable().size()).has_value();
        }
        switch (frame.type) {
        case 4: {
            auto* s = admit(frame.stream_id);
            return s && flow_.set_receive_final_size(frame.stream_id, frame.final_size) && s->state.receive_reset(frame.final_size);
        }
        case 5: {
            auto* s = admit(frame.stream_id);
            if (!s || !s->state.receive_stop_sending(frame.error_code)) return false;
            if (!s->state.reset_required()) return true;
            const auto final = s->state.send_final_size().value_or(s->sent_highest);
            if (!flow_.set_send_final_size(s->id, final) || !s->state.send_reset(final)) return false;
            s->reset_pending = true;
            return true;
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
    void* retirement_argument_ {};
    retirement_callback retirement_callback_ {};
    parameter_limits local_, peer_;
    stream_registry<stream_capacity> registry_;
    flow_control<stream_capacity> flow_;
    std::array<stream_slot, stream_capacity> slots_;
    recovery_orchestration<packet_capacity> recovery_;
    path_recovery_state<4> path_recovery_ {};
    std::array<packet_record, packet_capacity * 3> sent_ {};
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
