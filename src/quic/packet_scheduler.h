#pragma once
#include "quic/connection.h"
#include "quic/ack_ranges.h"

#include <algorithm>

namespace eventloop::quic::detail {

// One outstanding packet; caller-owned output remains live through UDP send.
// prepare consumes a packet number; failed UDP sends consume no stream credit.
// The owner serializes prepare/complete and defers connection mutation,
// including inbound ACK processing, while a packet is pending. This preserves
// the preflight reservation without heap allocation or overlapping sends.
class packet_scheduler {
public:
    static constexpr std::size_t maximum_packet = 1200;
    static constexpr std::size_t maximum_datagram = bounded_connection::datagram_buffer_size;
    explicit packet_scheduler(bounded_connection& connection) : connection_(connection)
    { connection_.set_retirement_observer(this, retire); }
    ~packet_scheduler() { connection_.set_retirement_observer(nullptr, nullptr); }
    packet_scheduler(const packet_scheduler&) = delete;
    auto operator=(const packet_scheduler&) -> packet_scheduler& = delete;
    // Application packets may use the negotiated datagram size; handshake
    // packets stay at the QUIC minimum so anti-amplification is unaffected.
    [[nodiscard]] auto datagram_limit(tls_level level) const noexcept -> std::size_t
    {
        return level == tls_level::application
            ? std::clamp<std::size_t>(connection_.send_datagram_size(), 1200, maximum_datagram)
            : std::size_t {1200};
    }
    // Each PTO's probes start from the oldest unacknowledged CRYPTO data and
    // continue past one another (RFC 9002 6.2.4).
    auto begin_probes() noexcept -> void { probe_next_ = {}; }
    auto request_ack(tls_level level) noexcept -> void
    { if (static_cast<std::size_t>(level) < 3) ++ack_pending_[static_cast<std::size_t>(level)]; }
    // Notes when the largest 1-RTT packet number arrived, so ACKs report the
    // delay since then (RFC 9000 13.2.5). Peers ignore the field in Initial
    // and Handshake ACKs (RFC 9002 5.3), which keep sending zero.
    auto packet_received(tls_level level, std::uint64_t number, lifecycle_time_point now) noexcept -> void
    {
        if (level != tls_level::application || (largest_received_ && number <= *largest_received_)) return;
        largest_received_ = number;
        largest_received_time_ = now;
    }
    // Control frames are copied and bounded. The connection retirement
    // observer drives their retransmission. One scheduler owns that observer
    // and must be destroyed before its connection.
    [[nodiscard]] auto queue_control(tls_level level, const decoded_frame& frame)
        -> std::expected<void, connection_error>
    {
        if (pending_ || static_cast<std::size_t>(level) >= 3 || frame.type == 0 ||
            frame.type == 2 || frame.type == 3 || frame.type == 6 ||
            (frame.type >= 8 && frame.type <= 15) || frame.type == 0x30 || frame.type == 0x31)
            return std::unexpected(connection_error::invalid_configuration);
        if (level != tls_level::application && frame.type != 1 && frame.type != 0x1c)
            return std::unexpected(connection_error::invalid_configuration);
        for (auto& slot : controls_) if (!slot.occupied ||
            (((frame.type >= 0x10 && frame.type <= 0x17) || frame.type == 4 || frame.type == 5) &&
             slot.type == frame.type && slot.stream_id == frame.stream_id)) {
            const auto size = encode_frame(frame, slot.bytes);
            if (!size) return std::unexpected(connection_error::output_too_small);
            slot.size = *size; slot.level = level; slot.occupied = true; slot.ready = true;
            slot.type = frame.type; slot.stream_id = frame.stream_id; slot.transmitted = false;
            slot.eliciting = frame.type != 0x1c && frame.type != 0x1d;
            return {};
        }
        return std::unexpected(connection_error::capacity_exceeded);
    }
    auto acknowledge_control(tls_level level, std::uint64_t number) noexcept -> void
    { for (auto& c : controls_) if (c.occupied && c.transmitted && c.level == level && c.sent == number) {
        connection_.control_acked(c.type, c.stream_id); c = {}; } }
    auto lose_control(tls_level level, std::uint64_t number) noexcept -> void
    { for (auto& c : controls_) if (c.occupied && c.transmitted && c.level == level && c.sent == number) c.ready = true; }
    [[nodiscard]] auto prepare(tls_level level, protected_packet_fields fields,
        lifecycle_time_point now, std::span<std::uint8_t> output,
        std::span<std::uint8_t> scratch, bool probe = false)
        -> std::expected<std::size_t, connection_error>
    {
        if (pending_) return std::unexpected(connection_error::invalid_state);
        if (level == tls_level::application) {
            while (const auto frame = connection_.pending_control()) {
                if (!queue_control(level, *frame)) break;
                connection_.control_queued(*frame);
            }
        }
        const auto index = static_cast<std::size_t>(level);
        if (index >= 3) return std::unexpected(connection_error::output_too_small);
        const auto level_max = datagram_limit(level);
        if (output.size() < level_max)
            return std::unexpected(connection_error::output_too_small);
        fields.kind = level == tls_level::initial ? packet_kind::initial :
            level == tls_level::handshake ? packet_kind::handshake : packet_kind::short_header;
        fields.packet_number_length = connection_.core().packet_number_length(level);
        payload_limit_ = level == tls_level::application
            ? level_max - bounded_connection::packet_overhead : payload_limit;
        if (level == tls_level::initial) {
            // Retry tokens consume Initial wire space. Split CRYPTO across
            // packets rather than selecting a chunk that cannot fit afterward.
            const auto overhead = 7 + fields.destination_cid.size() + fields.source_cid.size() +
                varint_size(fields.token.size()) + fields.token.size() + 2 + fields.packet_number_length + 16;
            if (overhead >= level_max)
                return std::unexpected(connection_error::output_too_small);
            payload_limit_ = std::min(payload_limit_, level_max - overhead);
        }
        const auto number = connection_.core().next_packet_number(level);
        if (!number) return std::unexpected(connection_error::unavailable_keys);
        ack_generation_ = ack_pending_[index]; used_ = range_count_ = control_count_ = 0;
        datagram_ = false; ack_ = false; acknowledged_peer_update_.reset();
        bool eliciting = false;
        std::size_t ack_size = 0;
        if (ack_pending_[index]) {
            // Units of 8 microseconds: the default ack_delay_exponent of 3,
            // since the endpoint does not advertise one.
            const auto delay = level == tls_level::application && largest_received_
                ? static_cast<std::uint64_t>(std::max<std::int64_t>(0,
                      std::chrono::duration_cast<std::chrono::microseconds>(
                          now - largest_received_time_).count())) >> 3
                : 0;
            const auto ack = connection_.core().make_ack(level, delay, ack_storage_);
            if (ack && append(*ack)) {
                ack_ = true; ack_largest_ = ack->largest_acknowledged; ack_size = used_;
                const auto peer_update = connection_.core().peer_update_packet();
                if (peer_update && covers(*ack, *peer_update))
                    acknowledged_peer_update_ = peer_update;
            }
        }
        const auto append_controls = [&] {
        for (std::size_t i = 0; i < controls_.size(); ++i) {
            const auto& c = controls_[i];
            if (!c.occupied || (!c.ready && !(probe && c.transmitted)) || c.level != level || used_ + c.size > payload_limit_) continue;
            std::copy_n(c.bytes.begin(), c.size, payload_.begin() + used_); used_ += c.size;
            control_indices_[control_count_++] = i; eliciting |= c.eliciting;
        }
        };
        if (!probe) append_controls();
        // Probes prefer unprobed outstanding data, then new data, then the
        // oldest outstanding data again.
        auto crypto = probe ? connection_.core().next_crypto_probe(level, remaining(), probe_next_[index])
            : crypto_send_chunk{};
        if (crypto.data.empty()) crypto = connection_.core().next_crypto(level, remaining());
        if (crypto.data.empty() && probe) crypto = connection_.core().next_crypto_probe(level, remaining());
        if (!crypto.data.empty()) {
            decoded_frame frame; frame.type = 6; frame.offset = crypto.offset; frame.data = crypto.data;
            if (append(frame)) {
                range_slots_[range_count_] = nullptr;
                ranges_[range_count_++] = {true,0,crypto.offset,crypto.data.size(),false};
                eliciting = true;
            }
        }
        if (level == tls_level::application) {
            // ACK/control-only packets need no packet-local flow snapshot.
            // A read-only transaction stages only the streams this packet
            // touches, so no full flow table is copied per packet.
            auto flow = connection_.flow().stage_send<bounded_connection::frames_per_packet>();
            auto credit = flow.send_max_data() - flow.sent_total();
            // Across all streams, transmitted data precedes new data in a PTO
            // packet. Selection does not declare the original packet lost.
            for (unsigned pass = 0; pass < (probe ? 2u : 1u) && range_count_ < ranges_.size(); ++pass) {
            for (auto* active : connection_.active_slots()) {
                if (range_count_ == ranges_.size()) break;
                auto& stream = *active;
                if (!stream.occupied ||
                    stream.state.sending() == stream_send_state::reset_sent ||
                    stream.state.sending() == stream_send_state::reset_received) continue;
                auto chunk = stream_send_chunk{};
                if (probe) {
                    const auto outstanding = stream.send.next_unacknowledged(remaining());
                    if (pass == 0) chunk = outstanding;
                    else {
                        // The first pass already covered this stream; do not
                        // append overlapping pending loss ranges a second time.
                        if (!outstanding.data.empty() || outstanding.fin) continue;
                        chunk = stream.send.next_pending(remaining());
                    }
                } else chunk = stream.send.next_pending(remaining());
                if (stream.send.next_offset() > stream.send.flow_limit())
                    connection_.stream_data_blocked(stream);
                if (chunk.data.empty() && !chunk.fin) continue;
                const auto retransmitted = stream.sent_highest > chunk.offset ? stream.sent_highest - chunk.offset : 0;
                const auto allowed = std::min<std::uint64_t>(chunk.data.size(), credit + retransmitted);
                if (allowed < chunk.data.size()) connection_.data_blocked(flow.send_max_data());
                if (allowed < chunk.data.size()) { chunk.data = chunk.data.first(static_cast<std::size_t>(allowed)); chunk.fin = false; }
                if (chunk.data.empty() && !chunk.fin) continue;
                decoded_frame frame; frame.type = 0x0e | (chunk.fin ? 1 : 0);
                frame.stream_id = stream.id; frame.offset = chunk.offset; frame.data = chunk.data; frame.fin = chunk.fin;
                // Encode into uncommitted packet space first. Flow updates
                // are failure-atomic; committing used_ only after both succeed
                // avoids copying the whole flow table for each STREAM frame.
                const auto size = encode_frame(frame,std::span(payload_).subspan(used_,payload_limit_-used_));
                if (!size) continue;
                if (!flow.send_stream_range(stream.id, chunk.offset, chunk.data.size(), chunk.fin)) continue;
                credit = flow.send_max_data() - flow.sent_total();
                used_ += *size;
                range_slots_[range_count_] = &stream;
                ranges_[range_count_++] = {false,stream.id,chunk.offset,chunk.data.size(),chunk.fin}; eliciting = true;
            }
            }
            if (probe) append_controls();
            const auto data = connection_.outgoing_datagrams().front();
            if (data) {
                decoded_frame frame; frame.type = 0x31; frame.data = data->data;
                if (append(frame)) { datagram_ = true; eliciting = true; }
            }
        }
        else if (probe) append_controls();
        if (probe && !eliciting) { decoded_frame ping; ping.type = 1; if (append(ping)) eliciting = true; }
        if (!used_) return std::unexpected(connection_error::invalid_state);
        for (;;) {
            // Clients pad every Initial datagram, servers only ack-eliciting
            // ones (RFC 9000 14.1); padding an ACK spends amplification credit.
            const bool padded = level == tls_level::initial &&
                (eliciting || connection_.role() == endpoint_role::client);
            if (padded) {
                const auto overhead = 7 + fields.destination_cid.size() + fields.source_cid.size() +
                    varint_size(fields.token.size()) + fields.token.size() + 2 + fields.packet_number_length + 16;
                if (overhead > level_max || used_ > level_max - overhead)
                    return std::unexpected(connection_error::output_too_small);
                std::fill(payload_.begin() + used_, payload_.begin() + level_max - overhead, std::byte{});
                used_ = level_max - overhead;
            }
            const auto size = connection_.core().build(fields,
                {reinterpret_cast<const std::uint8_t*>(payload_.data()),used_}, output.first(level_max), scratch);
            if (!size) return std::unexpected(size.error());
            packet_ = {*number,now,eliciting,eliciting || padded,*size};
            const auto preview = connection_.preflight_sent(level, packet_, probe);
            if (preview) {
                pending_ = true; level_ = level; probe_ = probe;
                return *size;
            }
            // A refused packet is never sent; reuse its PN for the next one.
            connection_.core().unbuild(level);
            // A full congestion window must not hold back a pending ACK
            // (RFC 9002 7): retry with the ACK alone, outside bytes in flight.
            if (!ack_ || !eliciting || probe) return std::unexpected(preview.error());
            used_ = ack_size; range_count_ = control_count_ = 0;
            datagram_ = false; eliciting = false;
        }
    }
    [[nodiscard]] auto complete(bool sent, lifecycle_time_point now)
        -> std::expected<void, connection_error>
    {
        if (!pending_) return std::unexpected(connection_error::invalid_state);
        pending_ = false;
        if (!sent) return {};
        if (probe_)
            for (std::size_t i = 0; i < range_count_; ++i)
                if (ranges_[i].crypto) probe_next_[static_cast<std::size_t>(level_)] = ranges_[i].offset + ranges_[i].size;
        packet_.sent_time = now;
        const auto result = connection_.record_sent(level_,packet_,{ranges_.data(),range_count_},probe_,
            {range_slots_.data(),range_count_},
            ack_ ? std::optional<std::uint64_t>(ack_largest_) : std::nullopt,
            acknowledged_peer_update_);
        if (!result) return result;
        for (std::size_t i=0;i<control_count_;++i) {
            auto& c = controls_[control_indices_[i]]; c.ready=false; c.transmitted=true; c.sent=packet_.number;
        }
        if (datagram_) (void)connection_.outgoing_datagrams().pop();
        if (ack_ && ack_pending_[static_cast<std::size_t>(level_)] == ack_generation_) ack_pending_[static_cast<std::size_t>(level_)]=0;
        return {};
    }
    [[nodiscard]] auto pending() const noexcept -> bool { return pending_; }
    [[nodiscard]] auto packet_number() const noexcept -> std::uint64_t { return packet_.number; }
    [[nodiscard]] auto acknowledged_peer_update_packet() const noexcept
        -> std::optional<std::uint64_t> { return acknowledged_peer_update_; }
private:
    static auto retire(void* argument, tls_level level, std::uint64_t number,
        retirement_reason reason) noexcept -> void
    {
        auto& self = *static_cast<packet_scheduler*>(argument);
        if (reason == retirement_reason::acknowledged) self.acknowledge_control(level, number);
        else if (reason == retirement_reason::lost) self.lose_control(level, number);
        else self.discard_control(level, number);
    }
    [[nodiscard]] static auto covers(const decoded_frame& frame, std::uint64_t packet_number)
        noexcept -> bool
    {
        auto cursor = ack_range_cursor::from_frame(frame);
        if (!cursor) return false;
        for (;;) {
            const auto range = cursor->next();
            if (!range || !*range) return false;
            if (packet_number >= (**range).smallest && packet_number <= (**range).largest)
                return true;
            if ((**range).largest < packet_number) return false;
        }
    }
    auto discard_control(tls_level level, std::uint64_t number) noexcept -> void
    { for (auto& c : controls_) if (c.occupied && c.transmitted && c.level == level && c.sent == number) c = {}; }
    static constexpr std::size_t payload_limit = 1100;
    std::size_t payload_limit_ {payload_limit};
    auto remaining() const noexcept -> std::size_t { return used_ + 32 < payload_limit_ ? payload_limit_-used_-32 : 0; }
    auto append(const decoded_frame& frame) -> bool
    { const auto size=encode_frame(frame,std::span(payload_).subspan(used_,payload_limit_-used_)); if (!size) return false; used_+=*size; return true; }
    struct control_slot { std::array<std::byte,128> bytes{}; std::size_t size{}; tls_level level{}; std::uint64_t sent{}, type{}, stream_id{}; bool occupied{}, ready{}, transmitted{}, eliciting{}; };
    bounded_connection& connection_;
    std::array<std::byte,maximum_datagram> payload_{};
    std::array<std::byte,1024> ack_storage_{};
    std::array<bounded_connection::transmitted_range,bounded_connection::frames_per_packet> ranges_{};
    std::array<bounded_connection::stream_slot*,bounded_connection::frames_per_packet> range_slots_{};
    std::array<control_slot,16> controls_{};
    std::array<std::size_t,16> control_indices_{};
    std::array<std::uint64_t,3> ack_pending_{}, probe_next_{};
    sent_packet packet_{};
    std::size_t used_{},range_count_{},control_count_{};
    std::uint64_t ack_largest_{}, ack_generation_{};
    std::optional<std::uint64_t> acknowledged_peer_update_, largest_received_;
    lifecycle_time_point largest_received_time_{};
    tls_level level_{};
    bool pending_{},probe_{},datagram_{},ack_{};
};
} // namespace eventloop::quic::detail
