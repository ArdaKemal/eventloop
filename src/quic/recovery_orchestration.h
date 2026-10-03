#pragma once

#include "quic/congestion_control.h"
#include "quic/sent_packet_history.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <ratio>
#include <span>
#include <type_traits>

namespace eventloop::quic::detail {

enum class recovery_error_kind {
    invalid_space, space_discarded, history, congestion, output_full,
    capacity_exhausted
};

struct recovery_error {
    recovery_error_kind kind;
    sent_packet_error history {sent_packet_error::invalid_ack};
    congestion_error congestion {congestion_error::invalid_packet_size};
};

enum class retirement_reason { acknowledged, lost, discarded };

struct retired_packet {
    packet_number_space space;
    sent_packet packet;
    retirement_reason reason;
};

struct recovery_result {
    std::size_t retired {0};
    std::optional<packet_number_space> probe_space {};
    std::uint8_t probe_count {0};
    bool persistent_congestion {false};
};

struct recovery_alarm {
    packet_number_space space;
    recovery_time_point deadline;
    bool loss;
};

// Caller-owned recovery state. A packet must be recorded once, after it has
// actually been sent. Retransmitted contents belong to a new packet number.
// One instance belongs to one path; it owns shared RTT/NewReno state for that
// path's three packet-number spaces. No socket, CRYPTO, or stream state is owned
// here. The endpoint enforces pacing and amplification limits before recording
// transmissions, and configures the handshake PTO controls below.
template<std::size_t Capacity, std::size_t SentRangeCapacity = Capacity>
class recovery_orchestration {
public:
    [[nodiscard]] constexpr auto reset(std::size_t max_datagram_size,
                                       recovery_duration starting_rtt = initial_rtt)
        noexcept -> std::expected<void, recovery_error>
    {
        auto controller = congestion_;
        if (const auto result = controller.reset(max_datagram_size); !result)
            return std::unexpected(congestion_failure(result.error()));
        for (auto& history : histories_) history.reset();
        congestion_ = controller;
        rtt_.reset(starting_rtt);
        loss_deadlines_ = {};
        discarded_ = {};
        event_count_ = 0;
        first_sample_highest_sent_.reset();
        last_persistent_endpoint_.reset();
        pto_count_ = 0;
        handshake_confirmed_ = false;
        max_ack_delay_ = recovery_duration::zero();
        last_ack_eliciting_sent_ = {};
        peer_address_validated_ = true;
        pto_blocked_ = false;
        client_handshake_probe_.reset();
        return {};
    }

    constexpr auto set_handshake_confirmed(bool value) noexcept -> void
    {
        handshake_confirmed_ = value;
        if (value) set_peer_address_validated(true);
    }

    // Servers leave peer_address_validated true: clients implicitly validate
    // the server's address. Clients set false until a Handshake ACK or handshake
    // confirmation proves that the server validated their address.
    constexpr auto set_peer_address_validated(bool value) noexcept -> void
    {
        peer_address_validated_ = value;
        if (value) client_handshake_probe_.reset();
    }

    // RFC 9000 Section 9.4: migrating to a new path resets only the
    // path-specific RTT estimator and congestion controller. Packet-number
    // spaces, ACK ranges, sent-packet history, and loss detection remain
    // connection-wide. Call after path validation promotes a new path.
    [[nodiscard]] constexpr auto reset_path_recovery(
        std::size_t max_datagram_size,
        recovery_duration starting_rtt = initial_rtt) noexcept
        -> std::expected<void, recovery_error>
    {
        auto controller = congestion_;
        if (const auto result = controller.reset(max_datagram_size); !result)
            return std::unexpected(congestion_failure(result.error()));
        congestion_ = controller;
        rtt_.reset(starting_rtt);
        pto_count_ = 0;
        refresh_loss_deadlines();
        return {};
    }

    // A server blocked by anti-amplification MUST suppress PTO, while loss
    // timers remain active. Clear this after receiving amplification credit.
    constexpr auto set_pto_blocked(bool value) noexcept -> void
    { pto_blocked_ = value; }

    // Clients arm the handshake anti-deadlock timer even without flight. Choose
    // Handshake when its keys are available, otherwise Initial (whose probe must
    // occupy a >=1200-byte UDP datagram). Update this when Handshake keys arrive.
    [[nodiscard]] constexpr auto configure_client_handshake_probe(
        packet_number_space space, recovery_time_point now) noexcept
        -> std::expected<void, recovery_error>
    {
        const auto index = space_index(space);
        if (!index || space == packet_number_space::application_data)
            return std::unexpected(invalid_space());
        if (discarded_[*index])
            return std::unexpected(recovery_error {
                recovery_error_kind::space_discarded});
        if (handshake_confirmed_) return {};
        peer_address_validated_ = false;
        client_handshake_probe_ = recovery_alarm {space, now, false};
        return {};
    }

    constexpr auto set_max_ack_delay(recovery_duration value) noexcept -> void
    { max_ack_delay_ = nonnegative(value); }

    // The endpoint first validates cumulative ACK_ECN counters and identifies
    // the path/send time of the largest newly ACKed ECT packet. Apply this
    // before on_ack so that CE starts recovery before ACK-driven cwnd growth.
    [[nodiscard]] constexpr auto on_ecn_ce(recovery_time_point sent_time,
                                         recovery_time_point now) noexcept
        -> std::expected<void, recovery_error>
    {
        auto controller = congestion_;
        if (const auto result = controller.on_ecn_ce(sent_time, now); !result)
            return std::unexpected(congestion_failure(result.error()));
        congestion_ = controller;
        return {};
    }

    // Validate on the owner thread without copying the bounded packet ledger.
    [[nodiscard]] constexpr auto preflight_record(packet_number_space space,
        sent_packet packet, bool bypass_window = false) const noexcept
        -> std::expected<void, recovery_error>
    {
        const auto controller = prepare_record(space, packet, bypass_window);
        if (!controller) return std::unexpected(controller.error());
        return {};
    }

    [[nodiscard]] constexpr auto record(packet_number_space space,
                                        sent_packet packet,
                                        bool bypass_window = false) noexcept
        -> std::expected<void, recovery_error>
    {
        const auto controller = prepare_record(space, packet, bypass_window);
        if (!controller) return std::unexpected(controller.error());
        const auto index = *space_index(space);
        // prepare_record checks every history/congestion failure before commit.
        (void)histories_[index].record(packet);
        congestion_ = *controller;
        if (packet.ack_eliciting) {
            last_ack_eliciting_sent_[index] = packet.sent_time;
            if (client_handshake_probe_)
                client_handshake_probe_->deadline = packet.sent_time;
        }
        return {};
    }

    // The output span receives ACKed packets followed by lost packets. All
    // validation, capacity checks, and flight retirements precede commit.
    [[nodiscard]] constexpr auto on_ack(
        packet_number_space space, const decoded_frame& frame,
        recovery_time_point now, recovery_duration decoded_ack_delay,
        std::span<retired_packet> output, bool app_or_flow_limited = false)
        noexcept -> std::expected<recovery_result, recovery_error>
    {
        const auto index = space_index(space);
        if (!index) return std::unexpected(invalid_space());
        if (discarded_[*index])
            return std::unexpected(recovery_error {
                recovery_error_kind::space_discarded});
        auto history = histories_[*index];
        auto controller = congestion_;
        auto estimator = rtt_;
        std::array<sent_packet, Capacity> acked {};
        std::array<sent_packet, Capacity> lost {};
        const auto ack_count = history.acknowledge_with_rtt(
            frame, now, decoded_ack_delay, max_ack_delay_, space,
            handshake_confirmed_, estimator, acked);
        if (!ack_count)
            return std::unexpected(history_failure(ack_count.error()));
        const auto detected = history.detect_lost(
            *history.largest_acked(), now, estimator.latest_rtt(),
            estimator.smoothed_rtt(), lost);
        if (!detected)
            return std::unexpected(history_failure(detected.error()));
        const auto total = *ack_count + detected->count;
        if (total > output.size())
            return std::unexpected(recovery_error {recovery_error_kind::output_full});
        // Appendix A.7 applies congestion loss before ACK growth, so ACKs of
        // packets from the just-started recovery period do not inflate cwnd.
        for (std::size_t i = 0; i < detected->count; ++i) {
            if (const auto result = controller.on_packet_lost(
                    as_congestion_packet(lost[i]), now); !result)
                return std::unexpected(congestion_failure(result.error()));
        }
        for (std::size_t i = 0; i < *ack_count; ++i) {
            if (const auto result = controller.on_packet_acked(
                    as_congestion_packet(acked[i]), app_or_flow_limited); !result)
                return std::unexpected(congestion_failure(result.error()));
        }
        auto first_sample = first_sample_highest_sent_;
        if (!first_sample && estimator.has_sample()) {
            std::array<std::optional<std::uint64_t>, 3> boundary {};
            for (std::size_t i = 0; i < boundary.size(); ++i)
                boundary[i] = histories_[i].highest_sent();
            first_sample = boundary;
        }
        std::array<persistent_event, 6 * Capacity> events {};
        std::copy_n(events_.begin(), event_count_, events.begin());
        auto event_count = event_count_;
        if (*ack_count > events.size() - event_count ||
            detected->count > events.size() - event_count - *ack_count)
            return std::unexpected(recovery_error {
                recovery_error_kind::capacity_exhausted});
        mark_late_acknowledgments(events, event_count, space, frame);
        for (std::size_t i = 0; i < *ack_count; ++i)
            events[event_count++] = {space, acked[i], true, false};
        for (std::size_t i = 0; i < detected->count; ++i)
            events[event_count++] = {space, lost[i], false,
                                     sampled_before_send(space, lost[i].number,
                                                         first_sample)};
        const auto endpoint = persistent_endpoint(events, event_count, estimator);
        const bool persistent = endpoint &&
            (!last_persistent_endpoint_ ||
             *endpoint > *last_persistent_endpoint_);
        if (persistent) controller.on_persistent_congestion();
        auto histories = histories_;
        histories[*index] = history;
        prune_events(events, event_count, histories);
        if (event_count > events_.size())
            return std::unexpected(recovery_error {
                recovery_error_kind::capacity_exhausted});
        histories_[*index] = history;
        congestion_ = controller;
        rtt_ = estimator;
        first_sample_highest_sent_ = first_sample;
        if (persistent) last_persistent_endpoint_ = endpoint;
        event_count_ = event_count;
        std::copy_n(events.begin(), event_count, events_.begin());
        if (*ack_count != 0) {
            if (space == packet_number_space::handshake)
                set_peer_address_validated(true);
            if (peer_address_validated_) pto_count_ = 0;
            else if (client_handshake_probe_)
                client_handshake_probe_->deadline = now;
        }
        refresh_loss_deadlines();
        for (std::size_t i = 0; i < *ack_count; ++i)
            output[i] = {space, acked[i], retirement_reason::acknowledged};
        for (std::size_t i = 0; i < detected->count; ++i)
            output[*ack_count + i] = {space, lost[i], retirement_reason::lost};
        return recovery_result {total, {}, 0, persistent};
    }

    // Expired loss deadlines retire packets. An expired PTO returns a request
    // for at most two probes; the caller chooses their contents and records
    // each transmitted probe through record(..., bypass_window=true).
    [[nodiscard]] constexpr auto on_timeout(recovery_time_point now,
                                            std::span<retired_packet> output)
        noexcept -> std::expected<recovery_result, recovery_error>
    {
        const auto alarm = next_alarm();
        if (!alarm || now < alarm->deadline) return recovery_result {};
        if (!alarm->loss) {
            if (pto_count_ != std::numeric_limits<std::uint32_t>::max())
                ++pto_count_;
            return recovery_result {0, alarm->space, 2};
        }

        auto histories = histories_;
        auto controller = congestion_;
        std::array<retired_packet, 3 * Capacity> staged {};
        std::array<sent_packet, Capacity> lost {};
        std::size_t count = 0;
        for (std::size_t index = 0; index < histories.size(); ++index) {
            const auto largest = histories[index].largest_acked();
            if (!largest) continue;
            const auto result = histories[index].detect_lost(
                *largest, now, rtt_.latest_rtt(), rtt_.smoothed_rtt(), lost);
            if (!result)
                return std::unexpected(history_failure(result.error()));
            for (std::size_t i = 0; i < result->count; ++i) {
                if (const auto retired = controller.on_packet_lost(
                        as_congestion_packet(lost[i]), now); !retired)
                    return std::unexpected(congestion_failure(retired.error()));
                staged[count++] = {static_cast<packet_number_space>(index),
                                   lost[i], retirement_reason::lost};
            }
        }
        if (count > output.size())
            return std::unexpected(recovery_error {recovery_error_kind::output_full});
        std::array<persistent_event, 6 * Capacity> events {};
        std::copy_n(events_.begin(), event_count_, events.begin());
        auto event_count = event_count_;
        if (count > events.size() - event_count)
            return std::unexpected(recovery_error {
                recovery_error_kind::capacity_exhausted});
        for (std::size_t i = 0; i < count; ++i) {
            const auto& retired = staged[i];
            events[event_count++] = {retired.space, retired.packet, false,
                                     sampled_before_send(
                                         retired.space, retired.packet.number,
                                         first_sample_highest_sent_)};
        }
        const auto endpoint = persistent_endpoint(events, event_count, rtt_);
        const bool persistent = endpoint &&
            (!last_persistent_endpoint_ ||
             *endpoint > *last_persistent_endpoint_);
        if (persistent) controller.on_persistent_congestion();
        prune_events(events, event_count, histories);
        if (event_count > events_.size())
            return std::unexpected(recovery_error {
                recovery_error_kind::capacity_exhausted});
        histories_ = histories;
        congestion_ = controller;
        if (persistent) last_persistent_endpoint_ = endpoint;
        event_count_ = event_count;
        std::copy_n(events.begin(), event_count, events_.begin());
        refresh_loss_deadlines();
        std::copy_n(staged.begin(), count, output.begin());
        return recovery_result {count, {}, 0, persistent};
    }

    [[nodiscard]] constexpr auto discard_space(packet_number_space space,
                                                std::span<retired_packet> output)
        noexcept -> std::expected<recovery_result, recovery_error>
    {
        const auto index = space_index(space);
        if (!index) return std::unexpected(invalid_space());
        const auto remaining = histories_[*index].remaining();
        if (remaining.size() > output.size())
            return std::unexpected(recovery_error {recovery_error_kind::output_full});
        auto controller = congestion_;
        for (const auto& packet : remaining) {
            if (const auto result = controller.on_packet_discarded(
                    as_congestion_packet(packet)); !result)
                return std::unexpected(congestion_failure(result.error()));
        }
        for (std::size_t i = 0; i < remaining.size(); ++i)
            output[i] = {space, remaining[i], retirement_reason::discarded};
        const auto count = remaining.size();
        histories_[*index].reset();
        congestion_ = controller;
        loss_deadlines_[*index].reset();
        last_ack_eliciting_sent_[*index].reset();
        discarded_[*index] = true;
        if (space != packet_number_space::application_data) pto_count_ = 0;
        if (client_handshake_probe_ && client_handshake_probe_->space == space)
            client_handshake_probe_.reset();
        return recovery_result {count};
    }

    [[nodiscard]] constexpr auto next_alarm() const noexcept
        -> std::optional<recovery_alarm>
    {
        if (const auto loss = earliest_loss_deadline(loss_deadlines_))
            return recovery_alarm {loss->space, loss->deadline, true};
        if (pto_blocked_) return std::nullopt;
        std::optional<recovery_alarm> earliest;
        for (std::size_t index = 0; index < histories_.size(); ++index) {
            const auto space = static_cast<packet_number_space>(index);
            const auto duration = rtt_.pto_duration(
                space, handshake_confirmed_, max_ack_delay_, pto_count_);
            if (!duration) continue;
            bool ack_eliciting_in_flight = false;
            for (const auto& packet : histories_[index].remaining()) {
                if (packet.in_flight && packet.ack_eliciting) {
                    ack_eliciting_in_flight = true;
                    break;
                }
            }
            if (!ack_eliciting_in_flight || !last_ack_eliciting_sent_[index]) continue;
            const auto deadline = saturated_deadline(
                *last_ack_eliciting_sent_[index], *duration);
            if (!earliest || deadline < earliest->deadline)
                earliest = recovery_alarm {space, deadline, false};
        }
        if (!earliest && !peer_address_validated_ && client_handshake_probe_) {
            const auto probe = *client_handshake_probe_;
            const auto duration = rtt_.pto_duration(
                probe.space, handshake_confirmed_, max_ack_delay_, pto_count_);
            if (duration)
                earliest = recovery_alarm {probe.space,
                    saturated_deadline(probe.deadline, *duration), false};
        }
        return earliest;
    }

    [[nodiscard]] constexpr auto history(packet_number_space space) const
        noexcept -> const sent_packet_history<Capacity, SentRangeCapacity>*
    {
        const auto index = space_index(space);
        return index ? &histories_[*index] : nullptr;
    }
    [[nodiscard]] constexpr auto rtt() const noexcept -> const rtt_estimator&
    { return rtt_; }
    [[nodiscard]] constexpr auto congestion() const noexcept
        -> const newreno_congestion_controller& { return congestion_; }
    [[nodiscard]] constexpr auto pto_count() const noexcept -> std::uint32_t
    { return pto_count_; }

private:
    [[nodiscard]] constexpr auto prepare_record(packet_number_space space,
        sent_packet packet, bool bypass_window) const noexcept
        -> std::expected<newreno_congestion_controller, recovery_error>
    {
        const auto index = space_index(space);
        if (!index) return std::unexpected(invalid_space());
        if (discarded_[*index])
            return std::unexpected(recovery_error {recovery_error_kind::space_discarded});
        if (const auto result = histories_[*index].preflight_record(packet); !result)
            return std::unexpected(history_failure(result.error()));
        auto controller = congestion_;
        if (const auto result = controller.on_packet_sent(
                packet.bytes, packet.in_flight, bypass_window); !result)
            return std::unexpected(congestion_failure(result.error()));
        return controller;
    }

    struct persistent_event {
        packet_number_space space {};
        sent_packet packet {};
        bool acknowledged {false};
        bool eligible {false};
    };

    [[nodiscard]] static constexpr auto sampled_before_send(
        packet_number_space space, std::uint64_t number,
        const std::optional<
            std::array<std::optional<std::uint64_t>, 3>>& boundary) noexcept
        -> bool
    {
        if (!boundary) return false;
        const auto initial_highest = (*boundary)[static_cast<std::size_t>(space)];
        return !initial_highest || number > *initial_highest;
    }

    static constexpr auto mark_late_acknowledgments(
        std::span<persistent_event> events, std::size_t count,
        packet_number_space space, const decoded_frame& frame) noexcept -> void
    {
        for (std::size_t index = 0; index < count; ++index) {
            auto& event = events[index];
            if (event.space != space || event.acknowledged) continue;
            auto cursor = ack_range_cursor::from_frame(frame);
            for (;;) {
                const auto range = cursor->next();
                if (!*range) break; // The history has validated this ACK.
                if (event.packet.number >= (*range)->smallest &&
                    event.packet.number <= (*range)->largest) {
                    event.acknowledged = true;
                    break;
                }
            }
        }
    }

    [[nodiscard]] constexpr auto persistent_endpoint(
        std::span<const persistent_event> events, std::size_t count,
        const rtt_estimator& estimator) const noexcept
        -> std::optional<recovery_time_point>
    {
        const auto variance = saturated_multiply(estimator.rttvar(), 4);
        const auto base = saturated_add(
            saturated_add(estimator.smoothed_rtt(),
                          std::max(variance, recovery_duration {timer_granularity})),
            max_ack_delay_);
        const auto threshold = saturated_multiply(base, 3);
        std::optional<recovery_time_point> endpoint;
        for (std::size_t first = 0; first < count; ++first) {
            const auto& earlier = events[first];
            if (earlier.acknowledged || !earlier.eligible ||
                !earlier.packet.in_flight || !earlier.packet.ack_eliciting)
                continue;
            for (std::size_t second = 0; second < count; ++second) {
                const auto& later = events[second];
                if (later.acknowledged || !later.eligible ||
                    !later.packet.in_flight || !later.packet.ack_eliciting ||
                    later.packet.sent_time <= earlier.packet.sent_time ||
                    later.packet.sent_time <= saturated_deadline(
                        earlier.packet.sent_time, threshold))
                    continue;
                bool blocked = false;
                for (std::size_t middle = 0; middle < count; ++middle) {
                    const auto& event = events[middle];
                    if (event.acknowledged &&
                        event.packet.sent_time > earlier.packet.sent_time &&
                        event.packet.sent_time < later.packet.sent_time) {
                        blocked = true;
                        break;
                    }
                }
                if (!blocked && (!endpoint || later.packet.sent_time > *endpoint))
                    endpoint = later.packet.sent_time;
            }
        }
        return endpoint;
    }

    static constexpr auto prune_events(
        std::span<persistent_event> events, std::size_t& count,
        const std::array<sent_packet_history<Capacity, SentRangeCapacity>, 3>&
            histories) noexcept -> void
    {
        std::optional<recovery_time_point> safe_barrier;
        for (std::size_t index = 0; index < count; ++index) {
            const auto& event = events[index];
            if (!event.acknowledged) continue;
            bool prior_outstanding = false;
            for (const auto& history : histories) {
                for (const auto& packet : history.remaining()) {
                    if (packet.sent_time <= event.packet.sent_time) {
                        prior_outstanding = true;
                        break;
                    }
                }
                if (prior_outstanding) break;
            }
            if (!prior_outstanding &&
                (!safe_barrier || event.packet.sent_time > *safe_barrier))
                safe_barrier = event.packet.sent_time;
        }
        if (!safe_barrier) return;
        std::size_t kept = 0;
        for (std::size_t index = 0; index < count; ++index) {
            if (events[index].packet.sent_time > *safe_barrier)
                events[kept++] = events[index];
        }
        count = kept;
    }

    [[nodiscard]] static constexpr auto space_index(packet_number_space space)
        noexcept -> std::optional<std::size_t>
    {
        const auto index = static_cast<std::size_t>(space);
        if (index >= 3) return std::nullopt;
        return index;
    }
    [[nodiscard]] static constexpr auto invalid_space() noexcept -> recovery_error
    { return {recovery_error_kind::invalid_space}; }
    [[nodiscard]] static constexpr auto history_failure(sent_packet_error error)
        noexcept -> recovery_error
    { return {recovery_error_kind::history, error}; }
    [[nodiscard]] static constexpr auto congestion_failure(congestion_error error)
        noexcept -> recovery_error
    { return {recovery_error_kind::congestion,
              sent_packet_error::invalid_ack, error}; }
    [[nodiscard]] static constexpr auto as_congestion_packet(sent_packet packet)
        noexcept -> congestion_packet
    { return {packet.sent_time, packet.bytes, packet.in_flight}; }
    [[nodiscard]] static constexpr auto saturated_deadline(
        recovery_time_point start, recovery_duration delay) noexcept
        -> recovery_time_point
    {
        using clock_duration = recovery_time_point::duration;
        using clock_rep = clock_duration::rep;
        using unsigned_rep = std::make_unsigned_t<clock_rep>;
        using conversion = std::ratio_divide<recovery_duration::period,
                                             clock_duration::period>;
        static_assert(std::is_signed_v<clock_rep> && sizeof(clock_rep) <= 8);
        static_assert(conversion::den == 1);
        const auto available = static_cast<unsigned_rep>(
            recovery_time_point::max().time_since_epoch().count()) -
            static_cast<unsigned_rep>(start.time_since_epoch().count());
        const auto micros = static_cast<unsigned_rep>(nonnegative(delay).count());
        if (micros > available / static_cast<unsigned_rep>(conversion::num))
            return recovery_time_point::max();
        const auto ticks = micros * static_cast<unsigned_rep>(conversion::num);
        const auto start_ticks = start.time_since_epoch().count();
        if (start_ticks >= 0)
            return recovery_time_point {clock_duration {
                start_ticks + static_cast<clock_rep>(ticks)}};
        const auto magnitude = unsigned_rep {0} -
            static_cast<unsigned_rep>(start_ticks);
        if (ticks >= magnitude)
            return recovery_time_point {clock_duration {
                static_cast<clock_rep>(ticks - magnitude)}};
        const auto negative = magnitude - ticks;
        if (negative == static_cast<unsigned_rep>(
                            std::numeric_limits<clock_rep>::max()) + 1)
            return recovery_time_point::min();
        return recovery_time_point {clock_duration {
            -static_cast<clock_rep>(negative)}};
    }
    constexpr auto refresh_loss_deadlines() noexcept -> void
    {
        const auto delay = loss_delay(rtt_.latest_rtt(), rtt_.smoothed_rtt());
        for (std::size_t index = 0; index < histories_.size(); ++index) {
            loss_deadlines_[index].reset();
            const auto largest = histories_[index].largest_acked();
            if (!largest) continue;
            for (const auto& packet : histories_[index].remaining()) {
                if (!packet.in_flight || packet.number >= *largest) continue;
                const auto deadline = saturated_deadline(packet.sent_time, delay);
                if (!loss_deadlines_[index] ||
                    deadline < *loss_deadlines_[index])
                    loss_deadlines_[index] = deadline;
            }
        }
    }

    std::array<sent_packet_history<Capacity, SentRangeCapacity>, 3> histories_ {};
    newreno_congestion_controller congestion_ {};
    rtt_estimator rtt_ {};
    std::array<std::optional<recovery_time_point>, 3> loss_deadlines_ {};
    std::array<persistent_event, 3 * Capacity> events_ {};
    std::size_t event_count_ {0};
    std::optional<std::array<std::optional<std::uint64_t>, 3>>
        first_sample_highest_sent_ {};
    std::optional<recovery_time_point> last_persistent_endpoint_ {};
    std::array<bool, 3> discarded_ {};
    std::uint32_t pto_count_ {0};
    recovery_duration max_ack_delay_ {};
    bool handshake_confirmed_ {false};
    std::array<std::optional<recovery_time_point>, 3> last_ack_eliciting_sent_ {};
    std::optional<recovery_alarm> client_handshake_probe_ {};
    bool peer_address_validated_ {true};
    bool pto_blocked_ {false};
};

} // namespace eventloop::quic::detail
