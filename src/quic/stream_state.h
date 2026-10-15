#pragma once

#include "quic/stream_registry.h"

#include <algorithm>
#include <cstdint>
#include <expected>
#include <optional>

namespace eventloop::quic::detail {

enum class stream_send_state { absent, ready, send, data_sent, data_received,
                               reset_sent, reset_received };
enum class stream_receive_state { absent, receive, size_known, data_received,
                                  data_read, reset_received, reset_read };
enum class stream_state_error {
    invalid_value,       // Local input outside the QUIC integer domain.
    invalid_transition,  // Local operation or completion in an invalid state.
    stream_state,        // RFC 9000 STREAM_STATE_ERROR (0x05).
    final_size,          // RFC 9000 FINAL_SIZE_ERROR (0x06).
    frame_encoding,      // RFC 9000 FRAME_ENCODING_ERROR (0x07).
};

[[nodiscard]] constexpr auto stream_state_transport_error(stream_state_error error)
    noexcept -> std::optional<std::uint64_t>
{
    switch (error) {
    case stream_state_error::stream_state: return 0x05;
    case stream_state_error::final_size: return 0x06;
    case stream_state_error::frame_encoding: return 0x07;
    default: return std::nullopt;
    }
}

// One already-opened stream, including one implicitly opened by a higher ID.
// Registry admission/stream limits, flow credit, reassembly, and ACK ranges are
// external. send_stream() is called for actual transmission, with the send
// buffer enforcing that Data Sent only retransmits previously sent ranges.
// The buffer owner supplies proven contiguous receive progress and
// the recovery owner reports ACK of ALL data including FIN. These are not
// inferred from the highest observed offset, which may contain gaps.
class stream_state {
public:
    using result = std::expected<void, stream_state_error>;

    [[nodiscard]] static constexpr auto create(std::uint64_t id, stream_role role)
        noexcept -> std::expected<stream_state, stream_state_error>
    {
        if (id > max_varint_value)
            return std::unexpected(stream_state_error::invalid_value);
        stream_state s;
        s.id_ = id;
        const bool local = stream_initiator(id) == role;
        const bool bidi = stream_type(id) == stream_direction::bidirectional;
        s.send_ = local || bidi ? stream_send_state::ready : stream_send_state::absent;
        s.receive_ = !local || bidi ? stream_receive_state::receive : stream_receive_state::absent;
        return s;
    }

    [[nodiscard]] constexpr auto id() const noexcept { return id_; }
    [[nodiscard]] constexpr auto sending() const noexcept { return send_; }
    [[nodiscard]] constexpr auto receiving() const noexcept { return receive_; }
    [[nodiscard]] constexpr auto send_final_size() const noexcept { return send_final_; }
    [[nodiscard]] constexpr auto receive_final_size() const noexcept { return receive_final_; }
    // Smallest reliable size from RESET_STREAM_AT, zero for RESET_STREAM.
    [[nodiscard]] constexpr auto reliable_size() const noexcept { return reliable_; }
    [[nodiscard]] constexpr auto reset_required() const noexcept { return reset_required_; }
    [[nodiscard]] constexpr auto stop_error() const noexcept { return stop_error_; }
    [[nodiscard]] constexpr auto stop_sending_pending() const noexcept -> bool
    {
        return stop_sent_ && (receive_ == stream_receive_state::receive ||
                              receive_ == stream_receive_state::size_known);
    }
    [[nodiscard]] constexpr auto closed() const noexcept -> bool
    {
        const bool sent = send_ == stream_send_state::absent ||
            send_ == stream_send_state::data_received || send_ == stream_send_state::reset_received;
        const bool read = receive_ == stream_receive_state::absent ||
            receive_ == stream_receive_state::data_read || receive_ == stream_receive_state::reset_read;
        return sent && read;
    }

    [[nodiscard]] constexpr auto send_stream(std::uint64_t offset,
        std::uint64_t length, bool fin = false) noexcept -> result
    {
        if (send_ == stream_send_state::absent) return fail(stream_state_error::stream_state);
        if (send_ != stream_send_state::ready && send_ != stream_send_state::send &&
            send_ != stream_send_state::data_sent) return fail(stream_state_error::invalid_transition);
        if (!valid_range(offset, length)) return fail(stream_state_error::invalid_value);
        const auto end = offset + length;
        if (send_final_ && (end > *send_final_ || (fin && end != *send_final_)))
            return fail(stream_state_error::final_size);
        if (fin && end < send_highest_) return fail(stream_state_error::final_size);
        if (end > send_highest_) send_highest_ = end;
        if (fin) send_final_ = end;
        send_ = send_final_ ? stream_send_state::data_sent : stream_send_state::send;
        return {};
    }

    // RESET_STREAM_AT (RSA 4): commits the final size but keeps Data Sent, so
    // the reliable prefix can still be transmitted. Terminal state follows
    // all_data_acked() once the frame and that prefix are acknowledged.
    [[nodiscard]] constexpr auto send_reset_at(std::uint64_t final_size) noexcept -> result
    {
        if (send_ != stream_send_state::ready && send_ != stream_send_state::send &&
            send_ != stream_send_state::data_sent) return fail(stream_state_error::invalid_transition);
        if (final_size > max_varint_value) return fail(stream_state_error::invalid_value);
        if ((send_final_ && final_size != *send_final_) || final_size < send_highest_)
            return fail(stream_state_error::final_size);
        send_final_ = final_size;
        send_ = stream_send_state::data_sent;
        return {};
    }

    [[nodiscard]] constexpr auto send_data_blocked() noexcept -> result
    {
        if (send_ == stream_send_state::absent) return fail(stream_state_error::stream_state);
        if (send_ != stream_send_state::ready && send_ != stream_send_state::send)
            return fail(stream_state_error::invalid_transition);
        send_ = stream_send_state::send;
        return {};
    }

    [[nodiscard]] constexpr auto send_reset(std::uint64_t final_size) noexcept -> result
    {
        if (send_ == stream_send_state::absent) return fail(stream_state_error::stream_state);
        if (final_size > max_varint_value) return fail(stream_state_error::invalid_value);
        if ((send_final_ && final_size != *send_final_) || final_size < send_highest_)
            return fail(stream_state_error::final_size);
        if (send_ == stream_send_state::reset_sent) return {};
        if (send_ == stream_send_state::reset_received || send_ == stream_send_state::data_received)
            return fail(stream_state_error::invalid_transition);
        send_final_ = final_size;
        send_ = stream_send_state::reset_sent;
        reset_required_ = false;
        return {};
    }

    [[nodiscard]] constexpr auto all_data_acked() noexcept -> result
    {
        if (send_ == stream_send_state::data_received) return {};
        // Late data ACKs after reset do not complete the reset.
        if (send_ == stream_send_state::reset_sent || send_ == stream_send_state::reset_received) return {};
        if (send_ != stream_send_state::data_sent) return fail(stream_state_error::invalid_transition);
        send_ = stream_send_state::data_received;
        reset_required_ = false;
        return {};
    }

    [[nodiscard]] constexpr auto reset_acked() noexcept -> result
    {
        if (send_ == stream_send_state::reset_received) return {};
        if (send_ != stream_send_state::reset_sent) return fail(stream_state_error::invalid_transition);
        send_ = stream_send_state::reset_received;
        return {};
    }

    // Choose the RFC-permitted immediate reset policy even in Data Sent.
    // Caller MUST transmit RESET_STREAM when reset_required() becomes true.
    [[nodiscard]] constexpr auto receive_stop_sending(std::uint64_t error) noexcept -> result
    {
        if (send_ == stream_send_state::absent) return fail(stream_state_error::stream_state);
        if (error > max_varint_value) return fail(stream_state_error::frame_encoding);
        if (!stop_error_) stop_error_ = error;
        if (send_ == stream_send_state::ready || send_ == stream_send_state::send ||
            send_ == stream_send_state::data_sent) reset_required_ = true;
        return {};
    }

    [[nodiscard]] constexpr auto receive_stream(std::uint64_t offset,
        std::uint64_t length, bool fin = false) noexcept -> result
    {
        if (receive_ == stream_receive_state::absent) return fail(stream_state_error::stream_state);
        if (!valid_range(offset, length)) return fail(stream_state_error::frame_encoding);
        const auto end = offset + length;
        if (receive_final_ && (end > *receive_final_ || (fin && end != *receive_final_)))
            return fail(stream_state_error::final_size);
        if (fin && end < receive_highest_) return fail(stream_state_error::final_size);
        if (end > receive_highest_) receive_highest_ = end;
        if (fin) receive_final_ = end;
        if (receive_ == stream_receive_state::receive && fin)
            receive_ = stream_receive_state::size_known;
        complete_receive();
        return {};
    }

    // Proven watermark from reassembly; duplicates/stale watermarks are safe.
    [[nodiscard]] constexpr auto receive_contiguous(std::uint64_t end) noexcept -> result
    {
        if (receive_ == stream_receive_state::absent) return fail(stream_state_error::stream_state);
        if (end > receive_highest_) return fail(stream_state_error::invalid_transition);
        if (end > receive_contiguous_) receive_contiguous_ = end;
        complete_receive();
        return {};
    }

    // RESET_STREAM (reliable size 0) and RESET_STREAM_AT (RSA 4-5). The final
    // size is fixed, and the smallest reliable size seen is kept. A zero reliable
    // size with no fully received data surfaces the reset at once; otherwise
    // receive_reset_progress() surfaces it after the reliable prefix is consumed.
    [[nodiscard]] constexpr auto receive_reset(std::uint64_t final_size,
        std::uint64_t reliable_size = 0) noexcept -> result
    {
        if (receive_ == stream_receive_state::absent) return fail(stream_state_error::stream_state);
        if (final_size > max_varint_value || reliable_size > final_size)
            return fail(stream_state_error::frame_encoding);
        if ((receive_final_ && final_size != *receive_final_) || final_size < receive_highest_)
            return fail(stream_state_error::final_size);
        receive_final_ = final_size;
        reset_received_ = true;
        reliable_ = reliable_ ? std::min(*reliable_, reliable_size) : reliable_size;
        if (*reliable_ == 0 && (receive_ == stream_receive_state::receive ||
                                receive_ == stream_receive_state::size_known))
            receive_ = stream_receive_state::reset_received;
        return {};
    }

    // Call after the reader's consumed offset advances and after a reset arrives.
    // Once the reliable prefix is consumed the reader sees stream_reset; bytes
    // beyond it that already arrived may still be read first (RSA 5 allows
    // delivering them). A fully received stream keeps its data (suppressed
    // reset) only when the reliable size is zero.
    constexpr auto receive_reset_progress(std::uint64_t consumed) noexcept -> void
    {
        if (!reliable_ || consumed < *reliable_) return;
        if (receive_ == stream_receive_state::receive ||
            receive_ == stream_receive_state::size_known ||
            (receive_ == stream_receive_state::data_received && *reliable_ > 0))
            receive_ = stream_receive_state::reset_received;
    }

    [[nodiscard]] constexpr auto read_all_data() noexcept -> result
    {
        if (receive_ == stream_receive_state::data_read) return {};
        if (receive_ != stream_receive_state::data_received) return fail(stream_state_error::invalid_transition);
        receive_ = stream_receive_state::data_read;
        return {};
    }
    [[nodiscard]] constexpr auto read_reset() noexcept -> result
    {
        if (receive_ == stream_receive_state::reset_read) return {};
        if (receive_ != stream_receive_state::reset_received) return fail(stream_state_error::invalid_transition);
        receive_ = stream_receive_state::reset_read;
        return {};
    }
    [[nodiscard]] constexpr auto send_stop_sending() noexcept -> result
    {
        if (receive_ == stream_receive_state::absent) return fail(stream_state_error::stream_state);
        if (reset_received_) return fail(stream_state_error::invalid_transition);
        stop_sent_ = true;
        return {};
    }
    [[nodiscard]] constexpr auto send_max_stream_data() const noexcept -> result
    {
        if (receive_ == stream_receive_state::absent) return fail(stream_state_error::stream_state);
        if (receive_ != stream_receive_state::receive) return fail(stream_state_error::invalid_transition);
        return {};
    }
    [[nodiscard]] constexpr auto receive_max_stream_data() const noexcept -> result
    {
        return send_ == stream_send_state::absent ? fail(stream_state_error::stream_state) : result {};
    }
    [[nodiscard]] constexpr auto receive_data_blocked() const noexcept -> result
    {
        return receive_ == stream_receive_state::absent ? fail(stream_state_error::stream_state) : result {};
    }

private:
    static constexpr auto fail(stream_state_error e) noexcept -> result { return std::unexpected(e); }
    static constexpr auto valid_range(std::uint64_t offset, std::uint64_t length) noexcept -> bool
    { return offset <= max_varint_value && length <= max_varint_value - offset; }
    constexpr auto complete_receive() noexcept -> void
    {
        if (receive_ == stream_receive_state::size_known &&
            receive_contiguous_ == *receive_final_) receive_ = stream_receive_state::data_received;
    }
    std::uint64_t id_ {0}, send_highest_ {0}, receive_highest_ {0}, receive_contiguous_ {0};
    std::optional<std::uint64_t> send_final_, receive_final_, stop_error_, reliable_;
    stream_send_state send_ {stream_send_state::absent};
    stream_receive_state receive_ {stream_receive_state::absent};
    bool reset_required_ {false}, stop_sent_ {false}, reset_received_ {false};
};

} // namespace eventloop::quic::detail
