#include "webtransport_session.h"

#include "errors.h"
#include "peer_streams.h"
#include "request_stream.h"
#include "webtransport_wire.h"

#include "eventloop/event_loop.h"
#include "eventloop/quic.h"
#include "eventloop/task.h"
#include "eventloop/wakeup.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace eventloop::http {

auto make_error_code(webtransport_errc value) noexcept -> std::error_code
{
    class category final : public std::error_category {
    public:
        [[nodiscard]] auto name() const noexcept -> const char* override { return "webtransport"; }
        [[nodiscard]] auto message(int value) const -> std::string override
        {
            switch (static_cast<webtransport_errc>(value)) {
            case webtransport_errc::session_closed: return "WebTransport session closed";
            case webtransport_errc::stream_reset: return "WebTransport stream reset by peer";
            case webtransport_errc::stream_closed: return "WebTransport stream closed";
            case webtransport_errc::capacity_exceeded: return "WebTransport capacity exceeded";
            case webtransport_errc::datagram_size: return "WebTransport datagram size";
            case webtransport_errc::flow_control_error: return "WebTransport flow control error";
            }
            return "unknown WebTransport error";
        }
    };
    static const category instance;
    return {static_cast<int>(value), instance};
}

namespace detail {

using namespace http3::detail;

namespace {

// Sizes fixed by the design contract.
constexpr std::size_t stream_table_size = 216;
constexpr std::size_t stream_prefix_capacity = 16;
constexpr std::size_t read_buffer_size = 1024;
// Capsules are encoded after frame_reserve bytes, which leaves room for the DATA
// frame header written in front of them.
constexpr std::size_t frame_reserve = 16;
constexpr std::size_t capsule_buffer_size = 1100;
constexpr std::size_t datagram_scratch_size = 1240;
constexpr std::size_t datagram_payload_limit = 1200;
constexpr std::size_t protocol_capacity = 128;

constexpr auto code_of(http3::detail::h3_error error) noexcept -> std::uint64_t
{
    return static_cast<std::uint64_t>(error);
}

constexpr auto gone_code() noexcept -> std::uint64_t
{
    return code_of(http3::detail::h3_error::wt_session_gone);
}

constexpr auto rejected_code() noexcept -> std::uint64_t
{
    return code_of(http3::detail::h3_error::wt_buffered_stream_rejected);
}

// Counts an application operation on a session record, so the record's slot is
// not reused while a coroutine may still resume against it.
class pending_guard {
public:
    explicit pending_guard(std::uint32_t* counter) noexcept : counter_(counter)
    {
        if (counter_ != nullptr) ++*counter_;
    }
    ~pending_guard()
    {
        if (counter_ != nullptr) --*counter_;
    }
    pending_guard(const pending_guard&) = delete;
    auto operator=(const pending_guard&) -> pending_guard& = delete;

private:
    std::uint32_t* counter_;
};

// Marks an operation pending for its lifetime (one read and one write per stream).
class busy_guard {
public:
    explicit busy_guard(bool& flag) noexcept : flag_(flag) { flag_ = true; }
    ~busy_guard() { flag_ = false; }
    busy_guard(const busy_guard&) = delete;
    auto operator=(const busy_guard&) -> busy_guard& = delete;

private:
    bool& flag_;
};

auto handle_idle(const std::optional<task_handle<void>>& handle) noexcept -> bool
{
    return !handle || handle->done();
}

auto session_closed_error() noexcept -> std::unexpected<std::error_code>
{
    return std::unexpected(make_error_code(webtransport_errc::session_closed));
}

auto stream_closed_error() noexcept -> std::unexpected<std::error_code>
{
    return std::unexpected(make_error_code(webtransport_errc::stream_closed));
}

auto invalid_argument_error() noexcept -> std::unexpected<std::error_code>
{
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
}

auto in_progress_error() noexcept -> std::unexpected<std::error_code>
{
    return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
}

// Maps QUIC results onto the WebTransport error surface. Cancellation and codes
// not listed here pass through unchanged.
auto map_quic(std::error_code error) noexcept -> std::error_code
{
    if (error == quic_errc::not_connected) return make_error_code(webtransport_errc::session_closed);
    if (error == quic_errc::stream_reset) return make_error_code(webtransport_errc::stream_reset);
    if (error == quic_errc::invalid_state) return make_error_code(webtransport_errc::stream_closed);
    if (error == quic_errc::capacity_exceeded || error == quic_errc::stream_limit)
        return make_error_code(webtransport_errc::capacity_exceeded);
    if (error == quic_errc::invalid_argument) return std::make_error_code(std::errc::invalid_argument);
    return error;
}

} // namespace

// The per-connection engine. Every table is reserved at construction and referenced
// by index plus generation, so no per-stream, datagram, or capsule allocation occurs.
// Sessions go through: free -> admitting -> reserved -> active -> terminated.
// A terminated record stays owned by its handler and handle until both retire;
// its reader, writer, and pending operations must also finish before reuse.
class webtransport_connection::state {
public:
    enum class phase : std::uint8_t { free, admitting, reserved, active, terminated };

    struct stream_entry {
        bool in_use {false};
        bool handle_owned {false};
        bool buffered {false};
        bool queued {false};
        bool opening {false};
        bool local {false};
        bool unidirectional {false};
        bool write_finished {false}; // FIN or reset sent on the send side
        bool reset_sent {false};
        bool read_finished {false}; // peer FIN observed, or peer reset
        bool stop_sent {false};     // receive side stopped
        bool peer_reset {false};
        bool read_busy {false};
        bool write_busy {false};
        std::uint32_t generation {0};
        std::uint32_t session {0};
        std::uint32_t session_generation {0};
        std::uint64_t id {0};
        std::uint64_t session_id {0};
        std::uint64_t header_length {0};
        std::uint64_t counted_bytes {0};
        std::uint8_t prefix_size {0};
        std::uint8_t prefix_offset {0};
        std::array<std::byte, stream_prefix_capacity> prefix {};
        std::optional<std::uint32_t> peer_code {};

        [[nodiscard]] auto has_send() const noexcept -> bool { return !unidirectional || local; }
        [[nodiscard]] auto has_receive() const noexcept -> bool { return !(unidirectional && local); }
    };

    struct session_record {
        phase phase_ {phase::free};
        std::uint32_t generation {0};
        std::uint64_t id {0};
        std::uint32_t pending_ops {0};
        bool handler_active {false};
        bool handle_owned {false};
        bool open_busy {false};
        bool accept_busy {false};
        bool send_busy {false};
        bool receive_busy {false};
        bool draining {false};
        bool drain_pending {false};
        bool fin_pending {false};
        bool close_pending {false};
        bool connect_send_closed {false};
        bool has_close_info {false};
        // WT_CLOSE_SESSION received: any later CONNECT stream data is H3_MESSAGE_ERROR.
        bool close_received {false};
        bool close_remote {false};
        std::uint32_t close_code {0};
        std::size_t close_reason_size {0};
        std::array<char, wt_max_close_message> close_reason {};
        std::size_t protocol_size {0};
        std::array<char, protocol_capacity> protocol {};
        std::optional<std::uint64_t> max_data_out;
        std::array<std::optional<std::uint64_t>, 2> max_streams_out {};
        std::optional<std::uint64_t> data_blocked_out;
        std::array<std::optional<std::uint64_t>, 2> streams_blocked_out {};
        std::array<std::uint32_t, stream_table_size> accept_queue {};
        std::size_t accept_head {0};
        std::size_t accept_count {0};
        std::size_t datagram_head {0};
        std::size_t datagram_count {0};
        http3::detail::request_frames frames {std::span<std::byte> {}};
        capsule_parser parser {false, datagram_payload_limit};
        session_flow flow {false, {}, {}};
        std::array<std::byte, read_buffer_size> read_buffer {};
        std::array<std::byte, capsule_buffer_size> send_buffer {};
        std::array<std::byte, datagram_scratch_size> datagram_scratch {};
        std::optional<task_handle<void>> reader;
        std::optional<task_handle<void>> writer;
        std::optional<task_handle<std::expected<void, std::error_code>>> sender;
        std::unique_ptr<wakeup> accept_wakeup;
        std::unique_ptr<wakeup> open_wakeup;
        std::unique_ptr<wakeup> datagram_wakeup;
        std::unique_ptr<wakeup> writer_wakeup;
        std::unique_ptr<wakeup> settings_wakeup;
    };

    enum class route_kind { deliver, buffer, gone };
    struct route {
        route_kind kind;
        std::uint32_t slot;
    };

    state(event_loop& loop, webtransport_connection& owner, const webtransport_options& options)
        : loop_(loop), owner_(owner), options_(options)
    {
        constexpr std::uint64_t limit = http3::detail::wt_max_stream_count;
        if (options.max_sessions < 1 || options.max_sessions > 16 || options.datagram_queue < 1 ||
            options.datagram_queue > 64 || options.buffered_streams > 64 ||
            options.buffered_datagrams > 64 || options.initial_max_streams_bidi >= limit ||
            options.initial_max_streams_uni >= limit || options.initial_max_data >= limit)
            throw std::invalid_argument("invalid webtransport_options");
        session_storage_ = std::make_unique<session_record[]>(options.max_sessions);
        sessions_ = std::span<session_record>(session_storage_.get(), options.max_sessions);
        for (auto& record : sessions_) {
            record.accept_wakeup = std::make_unique<wakeup>(loop_);
            record.open_wakeup = std::make_unique<wakeup>(loop_);
            record.datagram_wakeup = std::make_unique<wakeup>(loop_);
            record.writer_wakeup = std::make_unique<wakeup>(loop_);
            record.settings_wakeup = std::make_unique<wakeup>(loop_);
        }
        streams_.resize(stream_table_size);
        for (std::size_t i = 0; i < stream_table_size; ++i)
            stream_wakeups_.push_back(std::make_unique<wakeup>(loop_));
        datagram_bytes_.resize(options.max_sessions * options.datagram_queue * datagram_payload_limit);
        datagram_lengths_.resize(options.max_sessions * options.datagram_queue);
        buffered_datagram_bytes_.resize(options.buffered_datagrams * datagram_payload_limit);
        buffered_datagram_meta_.resize(options.buffered_datagrams);
    }

    event_loop& loop_;
    webtransport_connection& owner_;
    webtransport_options options_;
    quic_connection* connection_ {nullptr};
    http3::detail::peer_critical_streams* critical_ {nullptr};
    bool (*request_open_)(void*, std::uint64_t) noexcept {nullptr};
    void* request_context_ {nullptr};
    bool flow_enabled_ {false};
    bool connection_ended_ {false};
    std::optional<task_handle<void>> dispatcher_;
    // Records hold task handles, which cannot move, so they live in fixed storage.
    std::unique_ptr<session_record[]> session_storage_;
    std::span<session_record> sessions_;
    std::vector<stream_entry> streams_;
    std::vector<std::unique_ptr<wakeup>> stream_wakeups_;
    std::size_t buffered_stream_count_ {0};
    std::vector<std::byte> datagram_bytes_;
    std::vector<std::size_t> datagram_lengths_;
    std::vector<std::byte> buffered_datagram_bytes_;
    struct buffered_datagram {
        bool used {false};
        std::uint64_t session_id {0};
        std::size_t length {0};
    };
    std::vector<buffered_datagram> buffered_datagram_meta_;
    std::array<std::byte, datagram_scratch_size> dispatch_buffer_ {};

    // ---- Lookup ----

    auto stream_at(std::uint32_t index, std::uint32_t generation) noexcept -> stream_entry*
    {
        if (index >= streams_.size()) return nullptr;
        auto& entry = streams_[index];
        return entry.in_use && entry.generation == generation ? &entry : nullptr;
    }

    // The active session owning a stream entry, or nullptr.
    auto session_of(const stream_entry& entry) noexcept -> session_record*
    {
        if (!entry.in_use || entry.buffered || entry.session >= sessions_.size()) return nullptr;
        auto& record = sessions_[entry.session];
        if (record.generation != entry.session_generation || record.phase_ != phase::active)
            return nullptr;
        return &record;
    }

    // The record a handle names, unless it has been reused or freed.
    auto record_for(std::uint32_t slot, std::uint32_t generation) noexcept -> session_record*
    {
        if (slot >= sessions_.size()) return nullptr;
        auto& record = sessions_[slot];
        if (record.generation != generation || record.phase_ == phase::free) return nullptr;
        return &record;
    }

    auto active_record(std::uint32_t slot, std::uint32_t generation) noexcept -> session_record*
    {
        auto* record = record_for(slot, generation);
        return record != nullptr && record->phase_ == phase::active ? record : nullptr;
    }

    auto allocate_stream() noexcept -> std::optional<std::uint32_t>
    {
        for (std::uint32_t i = 0; i < streams_.size(); ++i) {
            if (streams_[i].in_use) continue;
            streams_[i].in_use = true;
            return i;
        }
        return std::nullopt;
    }

    auto free_stream(std::uint32_t index) noexcept -> void
    {
        auto& entry = streams_[index];
        const auto generation = entry.generation + 1;
        entry = stream_entry {};
        entry.generation = generation;
        stream_wakeups_[index]->notify();
    }

    auto wake_streams(std::uint32_t slot, std::uint32_t generation) noexcept -> void
    {
        for (std::uint32_t i = 0; i < streams_.size(); ++i) {
            const auto& entry = streams_[i];
            if (entry.in_use && !entry.buffered && entry.session == slot &&
                entry.session_generation == generation)
                stream_wakeups_[i]->notify();
        }
    }

    auto reusable(const session_record& record) const noexcept -> bool
    {
        return record.phase_ == phase::terminated && !record.handler_active &&
               !record.handle_owned && record.pending_ops == 0 &&
               handle_idle(record.reader) && handle_idle(record.writer);
    }

    auto acquire_record() noexcept -> std::optional<std::uint32_t>
    {
        for (std::uint32_t i = 0; i < sessions_.size(); ++i)
            if (sessions_[i].phase_ == phase::free) return i;
        for (std::uint32_t i = 0; i < sessions_.size(); ++i) {
            auto& record = sessions_[i];
            if (!reusable(record)) continue;
            record.reader.reset();
            record.writer.reset();
            record.phase_ = phase::free;
            return i;
        }
        return std::nullopt;
    }

    auto reset_record(session_record& record) noexcept -> void
    {
        ++record.generation;
        record.draining = false;
        record.drain_pending = false;
        record.fin_pending = false;
        record.close_pending = false;
        record.connect_send_closed = false;
        record.has_close_info = false;
        record.close_received = false;
        record.close_remote = false;
        record.max_data_out.reset();
        record.max_streams_out = {};
        record.data_blocked_out.reset();
        record.streams_blocked_out = {};
        record.accept_head = 0;
        record.accept_count = 0;
        record.datagram_head = 0;
        record.datagram_count = 0;
        record.open_busy = false;
        record.accept_busy = false;
        record.send_busy = false;
        record.receive_busy = false;
        record.protocol_size = 0;
        record.handler_active = true;
        record.handle_owned = false;
    }

    // ---- Stream send and receive sides ----

    static auto on_stream_reset(void* context, std::uint64_t id,
                                std::uint64_t final, std::uint64_t queued) noexcept -> void
    {
        auto& s = *static_cast<state*>(context);
        for (const auto& entry : s.streams_) {
            if (!entry.in_use || entry.opening || entry.id != id) continue;
            if (auto* record = s.session_of(entry)) {
                const auto header = entry.local ? entry.header_length : 0;
                record->flow.release_send(queued - std::max(final, header));
                s.wake_streams(entry.session, entry.session_generation);
            }
            return;
        }
    }

    // Resets the send side. A local stream's header is reliable (draft-16 4.4), so
    // the reset keeps it; a peer stream has no header of ours to keep.
    auto abandon_send(stream_entry& entry, std::uint64_t code) noexcept -> void
    {
        entry.write_finished = true;
        entry.reset_sent = true;
        if (connection_ == nullptr) return;
        const auto reliable = entry.local ? entry.header_length : 0;
        auto result = connection_->reset_stream_at(entry.id, code, reliable);
        if (!result && reliable != 0) (void)connection_->reset_stream(entry.id, code);
    }

    auto abandon_receive(stream_entry& entry, std::uint64_t code) noexcept -> void
    {
        entry.stop_sent = true;
        if (connection_ != nullptr) (void)connection_->stop_sending(entry.id, code);
    }

    // Refuses a stream that never reached a session.
    auto refuse_stream(std::uint64_t id, bool bidirectional, std::uint64_t code) noexcept -> void
    {
        if (connection_ == nullptr) return;
        if (bidirectional) (void)connection_->reset_stream(id, code);
        (void)connection_->stop_sending(id, code);
    }

    // ---- Session termination ----

    // Ends an active session: resets every stream send side and stops every receive
    // side with WT_SESSION_GONE, drops queued streams, and wakes every waiter. The
    // caller decides how the CONNECT stream ends.
    auto terminate(std::uint32_t slot, bool remote, std::uint32_t code, std::string_view reason) noexcept
        -> void
    {
        auto& record = sessions_[slot];
        if (record.phase_ != phase::active) return;
        record.phase_ = phase::terminated;
        if (record.sender) (void)record.sender->cancel();
        if (!record.has_close_info) {
            record.has_close_info = true;
            record.close_remote = remote;
            record.close_code = code;
            record.close_reason_size = std::min(reason.size(), record.close_reason.size());
            std::copy_n(reason.data(), record.close_reason_size, record.close_reason.data());
        }
        record.max_data_out.reset();
        record.max_streams_out = {};
        record.data_blocked_out.reset();
        record.streams_blocked_out = {};
        record.accept_count = 0;
        record.datagram_count = 0;
        for (std::uint32_t i = 0; i < streams_.size(); ++i) {
            auto& entry = streams_[i];
            if (!entry.in_use || entry.buffered || entry.opening || entry.session != slot ||
                entry.session_generation != record.generation)
                continue;
            if (entry.has_send() && !entry.write_finished) abandon_send(entry, gone_code());
            if (entry.has_receive() && !entry.read_finished && !entry.stop_sent)
                abandon_receive(entry, gone_code());
            stream_wakeups_[i]->notify();
            if (!entry.handle_owned) free_stream(i);
        }
        record.accept_wakeup->notify();
        record.open_wakeup->notify();
        record.datagram_wakeup->notify();
        record.writer_wakeup->notify();
    }

    // Protocol violation on the session: the CONNECT stream is reset and stopped
    // with the matching HTTP/3 code. The session ends without a close capsule.
    // Data after WT_CLOSE_SESSION: the CONNECT stream is reset with H3_MESSAGE_ERROR
    // even when our FIN is already out (draft-16 6). The peer's close stays recorded.
    auto reset_after_close(std::uint32_t slot) noexcept -> void
    {
        auto& record = sessions_[slot];
        const auto code = code_of(http3::detail::h3_error::message_error);
        terminate(slot, true, 0, {});
        if (connection_ != nullptr) {
            (void)connection_->reset_stream(record.id, code);
            (void)connection_->stop_sending(record.id, code);
        }
        record.connect_send_closed = true;
        record.fin_pending = false;
        record.close_pending = false;
        record.writer_wakeup->notify();
    }

    // An HTTP/3 error on the CONNECT stream. Stream-scoped codes reset the stream;
    // every other code (for example H3_FRAME_UNEXPECTED, RFC 9114 8.1) closes the
    // connection, and the session ends with the connection.
    auto fail_connect(std::uint32_t slot, http3::detail::h3_error error) noexcept -> void
    {
        if (http3::detail::stream_scoped(error)) {
            abort_connect(slot, code_of(error));
            return;
        }
        auto& record = sessions_[slot];
        terminate(slot, true, 0, {});
        record.connect_send_closed = true;
        record.fin_pending = false;
        record.close_pending = false;
        record.writer_wakeup->notify();
        if (connection_ != nullptr) connection_->close_application(code_of(error));
    }

    auto abort_connect(std::uint32_t slot, std::uint64_t code) noexcept -> void
    {
        auto& record = sessions_[slot];
        terminate(slot, false, 0, {});
        if (connection_ != nullptr) {
            if (!record.connect_send_closed) (void)connection_->reset_stream(record.id, code);
            (void)connection_->stop_sending(record.id, code);
        }
        record.connect_send_closed = true;
        record.fin_pending = false;
        record.close_pending = false;
        record.writer_wakeup->notify();
    }

    // The peer closed the session (WT_CLOSE_SESSION, FIN, or reset of CONNECT).
    auto remote_close(std::uint32_t slot, std::uint32_t code, std::string_view reason) noexcept -> void
    {
        auto& record = sessions_[slot];
        if (record.phase_ != phase::active) return;
        terminate(slot, true, code, reason);
        record.fin_pending = true;
        record.writer_wakeup->notify();
    }

    // The application closed the session (async_close, handle destruction, or the
    // route handler returning).
    auto begin_close(std::uint32_t slot, std::uint32_t generation, std::uint32_t code,
                     std::string_view reason) noexcept -> std::expected<void, std::error_code>
    {
        auto* record = active_record(slot, generation);
        if (record == nullptr) return session_closed_error();
        terminate(slot, false, code, reason);
        record->close_pending = true;
        record->writer_wakeup->notify();
        return {};
    }

    auto connection_lost() noexcept -> void
    {
        connection_ended_ = true;
        for (std::uint32_t i = 0; i < sessions_.size(); ++i) {
            auto& record = sessions_[i];
            if (record.phase_ == phase::active) {
                terminate(i, true, 0, {});
                record.connect_send_closed = true;
            }
            if (record.phase_ == phase::admitting) record.settings_wakeup->notify();
        }
    }

    // ---- Flow control ----

    auto renew_data(session_record& record) noexcept -> void
    {
        if (auto value = record.flow.take_max_data_update()) {
            record.max_data_out = value;
            record.writer_wakeup->notify();
        }
    }

    auto renew_streams(session_record& record, bool bidirectional) noexcept -> void
    {
        if (auto value = record.flow.take_max_streams_update(bidirectional)) {
            record.max_streams_out[bidirectional ? 0 : 1] = value;
            record.writer_wakeup->notify();
        }
    }

    // Counts body bytes the application has taken from the peer.
    auto account_read(std::uint32_t slot, stream_entry& entry, std::uint64_t bytes) noexcept
        -> std::expected<void, std::error_code>
    {
        auto& record = sessions_[slot];
        entry.counted_bytes += bytes;
        if (!record.flow.on_peer_data(bytes)) {
            abort_connect(slot, code_of(http3::detail::h3_error::wt_flow_control_error));
            return std::unexpected(make_error_code(webtransport_errc::flow_control_error));
        }
        record.flow.on_data_consumed(bytes);
        renew_data(record);
        return {};
    }

    // Accounts a peer reset: the final size fixes how much body the peer sent.
    auto observe_peer_reset(std::uint32_t slot, stream_entry& entry) noexcept
        -> std::expected<void, std::error_code>
    {
        entry.read_finished = true;
        const auto code = connection_->stream_reset_code(entry.id);
        if (code && *code == gone_code()) {
            // The peer ended the session; the reset carries no application code.
            return session_closed_error();
        }
        entry.peer_reset = true;
        entry.peer_code = code ? http3_to_webtransport_error(*code) : std::nullopt;
        const auto final_size = connection_->stream_final_size(entry.id);
        const auto header = entry.local ? 0 : entry.header_length;
        if (final_size && *final_size >= header) {
            const auto body = *final_size - header;
            if (body > entry.counted_bytes) {
                auto counted = account_read(slot, entry, body - entry.counted_bytes);
                if (!counted) return std::unexpected(counted.error());
            }
        }
        return std::unexpected(make_error_code(webtransport_errc::stream_reset));
    }

    auto observe_peer_stop(stream_entry& entry) noexcept -> std::unexpected<std::error_code>
    {
        const auto code = connection_->stream_stop_sending_code(entry.id);
        if (code && *code == gone_code()) return session_closed_error();
        entry.peer_code = code ? http3_to_webtransport_error(*code) : std::nullopt;
        return std::unexpected(make_error_code(webtransport_errc::stream_reset));
    }

    // ---- CONNECT stream input ----

    // Feeds CONNECT stream bytes through the request parser and the capsule parser.
    // Returns false once the stream must not be read further.
    auto consume(std::uint32_t slot, std::span<const std::byte> input) noexcept -> bool
    {
        auto& record = sessions_[slot];
        while (!input.empty()) {
            // Only a FIN may follow WT_CLOSE_SESSION (draft-16 6).
            if (record.close_received) {
                reset_after_close(slot);
                return false;
            }
            const auto event = record.frames.receive(input);
            if (!event) {
                fail_connect(slot, event.error());
                return false;
            }
            if (*event == http3::detail::request_frames::event::need_input) break;
            if (*event != http3::detail::request_frames::event::data) {
                fail_connect(slot, http3::detail::h3_error::frame_unexpected);
                return false;
            }
            auto payload = record.frames.data();
            while (!payload.empty()) {
                if (record.close_received) {
                    reset_after_close(slot);
                    return false;
                }
                auto capsule = record.parser.next(payload);
                if (!capsule) {
                    abort_connect(slot, static_cast<std::uint64_t>(capsule.error()));
                    return false;
                }
                if (!*capsule) break;
                if (!handle_capsule(slot, **capsule)) return false;
            }
        }
        return true;
    }

    auto handle_capsule(std::uint32_t slot, const capsule_event& event) noexcept -> bool
    {
        auto& record = sessions_[slot];
        if (const auto* close = std::get_if<wt_close_session>(&event)) {
            record.close_received = true;
            remote_close(slot, close->code, close->message);
            return true;
        }
        if (record.phase_ != phase::active) return true;
        if (std::holds_alternative<wt_drain_session>(event)) {
            record.draining = true;
            return true;
        }
        if (const auto* max_data = std::get_if<wt_max_data>(&event)) {
            if (!record.flow.on_max_data(max_data->maximum)) {
                abort_connect(slot, code_of(http3::detail::h3_error::wt_flow_control_error));
                return false;
            }
            wake_streams(slot, record.generation);
            return true;
        }
        if (const auto* max_streams = std::get_if<wt_max_streams>(&event)) {
            if (!record.flow.on_max_streams(max_streams->bidirectional, max_streams->maximum)) {
                abort_connect(slot, code_of(http3::detail::h3_error::wt_flow_control_error));
                return false;
            }
            record.open_wakeup->notify();
            return true;
        }
        if (const auto* datagram = std::get_if<wt_datagram>(&event))
            enqueue_datagram(slot, datagram->payload);
        // DATA_BLOCKED and STREAMS_BLOCKED need no reply: renewals go out as the
        // application consumes data and closes streams.
        return true;
    }

    // ---- Datagrams ----

    auto enqueue_datagram(std::uint32_t slot, std::span<const std::byte> payload) noexcept -> void
    {
        auto& record = sessions_[slot];
        if (record.phase_ != phase::active || payload.size() > datagram_payload_limit) return;
        if (record.datagram_count == options_.datagram_queue) return; // unreliable: drop
        const auto index = (record.datagram_head + record.datagram_count) % options_.datagram_queue;
        const auto position = slot * options_.datagram_queue + index;
        std::copy(payload.begin(), payload.end(),
                  datagram_bytes_.begin() + static_cast<std::ptrdiff_t>(position * datagram_payload_limit));
        datagram_lengths_[position] = payload.size();
        ++record.datagram_count;
        record.datagram_wakeup->notify();
    }

    auto buffer_datagram(std::uint64_t session_id, std::span<const std::byte> payload) noexcept -> void
    {
        if (payload.size() > datagram_payload_limit) return;
        for (std::size_t i = 0; i < buffered_datagram_meta_.size(); ++i) {
            auto& meta = buffered_datagram_meta_[i];
            if (meta.used) continue;
            meta = {true, session_id, payload.size()};
            std::copy(payload.begin(), payload.end(),
                      buffered_datagram_bytes_.begin() +
                          static_cast<std::ptrdiff_t>(i * datagram_payload_limit));
            return;
        }
        // Buffer full: the datagram is dropped.
    }

    auto max_datagram_size(const session_record& record) const noexcept -> std::size_t
    {
        if (connection_ == nullptr) return 0;
        const auto peer = connection_->max_datagram_payload();
        const auto prefix = quic::detail::varint_size(record.id / 4);
        if (peer <= prefix) return 0;
        return static_cast<std::size_t>(std::min<std::uint64_t>(datagram_payload_limit, peer - prefix));
    }

    // ---- Peer streams ----

    auto route_for(std::uint64_t session_id) noexcept -> route
    {
        for (std::uint32_t i = 0; i < sessions_.size(); ++i) {
            const auto& record = sessions_[i];
            if (record.phase_ == phase::free || record.id != session_id) continue;
            if (record.phase_ == phase::active) return {route_kind::deliver, i};
            if (record.phase_ == phase::terminated) return {route_kind::gone, i};
            return {route_kind::buffer, i};
        }
        if (request_open_ != nullptr && request_open_(request_context_, session_id))
            return {route_kind::buffer, 0};
        return {route_kind::gone, 0};
    }

    // Queues an accepted stream on its session. A stream beyond the advertised stream
    // limit ends the session with WT_FLOW_CONTROL_ERROR.
    auto enqueue_stream(std::uint32_t slot, std::uint32_t index) noexcept -> bool
    {
        auto& record = sessions_[slot];
        auto& entry = streams_[index];
        const bool bidirectional = !entry.unidirectional;
        if (record.phase_ != phase::active) {
            refuse_stream(entry.id, bidirectional, gone_code());
            free_stream(index);
            return false;
        }
        if (!record.flow.on_peer_stream_opened(bidirectional)) {
            refuse_stream(entry.id, bidirectional, gone_code());
            abort_connect(slot, code_of(http3::detail::h3_error::wt_flow_control_error));
            return false;
        }
        record.accept_queue[(record.accept_head + record.accept_count) % stream_table_size] = index;
        ++record.accept_count;
        entry.queued = true;
        record.accept_wakeup->notify();
        renew_streams(record, bidirectional);
        return true;
    }

    auto peer_stream(bool bidirectional, std::uint64_t id, std::uint64_t session_id, std::size_t header,
                     std::span<const std::byte> body) noexcept -> void
    {
        if (!valid_session_id(session_id)) {
            connection_->close_application(code_of(http3::detail::h3_error::id_error));
            return;
        }
        const auto target = route_for(session_id);
        if (target.kind == route_kind::gone) {
            refuse_stream(id, bidirectional, gone_code());
            return;
        }
        const bool buffer = target.kind == route_kind::buffer;
        if (buffer && buffered_stream_count_ >= options_.buffered_streams) {
            refuse_stream(id, bidirectional, rejected_code());
            return;
        }
        const auto index = allocate_stream();
        if (!index) {
            refuse_stream(id, bidirectional, rejected_code());
            return;
        }
        auto& entry = streams_[*index];
        entry.id = id;
        entry.unidirectional = !bidirectional;
        entry.local = false;
        entry.header_length = header;
        entry.prefix_size = static_cast<std::uint8_t>(std::min(body.size(), stream_prefix_capacity));
        std::copy_n(body.begin(), entry.prefix_size, entry.prefix.begin());
        if (buffer) {
            entry.buffered = true;
            entry.session_id = session_id;
            ++buffered_stream_count_;
            return;
        }
        entry.session = target.slot;
        entry.session_generation = sessions_[target.slot].generation;
        (void)enqueue_stream(target.slot, *index);
    }

    // Moves streams and datagrams that arrived before establishment.
    auto adopt_buffered(std::uint32_t slot) noexcept -> void
    {
        auto& record = sessions_[slot];
        for (std::uint32_t i = 0; i < streams_.size(); ++i) {
            auto& entry = streams_[i];
            if (!entry.in_use || !entry.buffered || entry.session_id != record.id) continue;
            entry.buffered = false;
            --buffered_stream_count_;
            entry.session = slot;
            entry.session_generation = record.generation;
            (void)enqueue_stream(slot, i);
        }
        for (std::size_t i = 0; i < buffered_datagram_meta_.size(); ++i) {
            auto& meta = buffered_datagram_meta_[i];
            if (!meta.used || meta.session_id != record.id) continue;
            enqueue_datagram(slot, std::span<const std::byte>(
                                       buffered_datagram_bytes_.data() +
                                           static_cast<std::ptrdiff_t>(i * datagram_payload_limit),
                                       meta.length));
            meta.used = false;
        }
    }

    // A request that finished without establishing a session: its buffered streams
    // are refused and its buffered datagrams dropped.
    auto refuse_buffered(std::uint64_t request_id) noexcept -> void
    {
        for (std::uint32_t i = 0; i < streams_.size(); ++i) {
            auto& entry = streams_[i];
            if (!entry.in_use || !entry.buffered || entry.session_id != request_id) continue;
            refuse_stream(entry.id, !entry.unidirectional, gone_code());
            entry.buffered = false;
            --buffered_stream_count_;
            free_stream(i);
        }
        for (auto& meta : buffered_datagram_meta_)
            if (meta.used && meta.session_id == request_id) meta.used = false;
    }

    // Whether any application operation or admission still uses the engine.
    auto busy() const noexcept -> bool
    {
        for (const auto& record : sessions_)
            if (record.pending_ops != 0 || record.phase_ == phase::admitting) return true;
        return false;
    }
};

// Builds handles and runs the coroutines behind them. It is a friend of both public
// handles and of webtransport_connection, which keeps the engine private.
struct webtransport_access {
    using state = webtransport_connection::state;
    using admission = webtransport_connection::admission;
    using route_kind = state::route_kind;

    static auto make_session(webtransport_connection* connection, std::uint32_t slot,
                             std::uint32_t generation) -> webtransport_session
    {
        webtransport_session session;
        session.connection_ = connection;
        session.slot_ = slot;
        session.generation_ = generation;
        return session;
    }

    static auto make_stream(webtransport_connection* connection, std::uint32_t index,
                            std::uint32_t generation) -> webtransport_stream
    {
        webtransport_stream stream;
        stream.connection_ = connection;
        stream.slot_ = index;
        stream.generation_ = generation;
        return stream;
    }

    static auto engine(webtransport_connection* connection) noexcept -> state&
    {
        return *connection->state_;
    }

    static auto on_settings(void* context) noexcept -> void
    {
        auto& s = *static_cast<state*>(context);
        if (s.critical_ == nullptr || s.connection_ == nullptr) return;
        if (s.critical_->h3_datagram && s.connection_->peer_max_datagram_frame_size() == 0)
            s.connection_->close_application(code_of(http3::detail::h3_error::settings_error));
        for (auto& record : s.sessions_)
            if (record.phase_ == state::phase::admitting) record.settings_wakeup->notify();
    }

    static auto admit(event_loop& loop, state& s, std::uint64_t connect_id, std::uint32_t& slot)
        -> task<admission>
    {
        (void)loop;
        if (s.connection_ended_) co_return admission::cancelled;
        const auto index = s.acquire_record();
        if (!index) co_return admission::rejected;
        auto& record = s.sessions_[*index];
        s.reset_record(record);
        record.id = connect_id;
        record.phase_ = state::phase::admitting;
        for (;;) {
            if (s.critical_->settings_received) break;
            if (s.connection_ended_) {
                record.phase_ = state::phase::free;
                co_return admission::cancelled;
            }
            auto waited = co_await record.settings_wakeup->async_wait();
            if (!waited) {
                record.phase_ = state::phase::free;
                co_return admission::cancelled;
            }
        }
        const auto& critical = *s.critical_;
        const bool requirements = critical.h3_datagram && critical.wt_enabled &&
                                  s.connection_->peer_max_datagram_frame_size() > 0 &&
                                  s.connection_->peer_reset_stream_at();
        if (!requirements) {
            record.phase_ = state::phase::free;
            co_return admission::malformed;
        }
        const bool local_flow = s.options_.initial_max_data != 0 ||
                                s.options_.initial_max_streams_bidi != 0 ||
                                s.options_.initial_max_streams_uni != 0;
        const bool peer_flow = critical.wt_initial_max_data != 0 ||
                               critical.wt_initial_max_streams_bidi != 0 ||
                               critical.wt_initial_max_streams_uni != 0;
        s.flow_enabled_ = local_flow && peer_flow;
        if (!s.flow_enabled_) {
            for (std::uint32_t i = 0; i < s.sessions_.size(); ++i) {
                if (i == *index) continue;
                const auto other = s.sessions_[i].phase_;
                if (other == state::phase::reserved || other == state::phase::active) {
                    record.phase_ = state::phase::free;
                    co_return admission::rejected;
                }
            }
        }
        record.phase_ = state::phase::reserved;
        slot = *index;
        co_return admission::accepted;
    }

    // Reads the CONNECT stream: request_frames for DATA framing, the capsule parser
    // for capsules. Session-ending errors reset the stream.
    static auto reader(event_loop& loop, state& s, std::uint32_t slot) -> task<void>
    {
        (void)loop;
        auto& record = s.sessions_[slot];
        for (;;) {
            auto received = flatten_result(co_await s.connection_->async_read(record.id, record.read_buffer));
            if (!received) {
                // A reset, a closed connection, or the stop after our own close: only
                // the first changes the session.
                s.remote_close(slot, 0, {});
                co_return;
            }
            if (*received == 0) {
                if (auto finished = record.frames.finish(); !finished) {
                    s.fail_connect(slot, finished.error());
                    co_return;
                }
                if (!record.parser.finish()) {
                    s.abort_connect(slot, code_of(http3::detail::h3_error::message_error));
                    co_return;
                }
                s.remote_close(slot, 0, {});
                co_return;
            }
            std::span<const std::byte> input(record.read_buffer.data(), *received);
            if (!s.consume(slot, input)) co_return;
        }
    }

    // Writes bytes on the CONNECT stream, retrying partial writes.
    static auto write_connect(event_loop& loop, state& s, std::uint32_t slot,
                              std::span<const std::byte> bytes, bool fin) -> task<bool>
    {
        (void)loop;
        auto& record = s.sessions_[slot];
        std::size_t written = 0;
        while (written < bytes.size()) {
            auto accepted = flatten_result(co_await s.connection_->async_write(record.id, bytes.subspan(written), false));
            if (!accepted) co_return false;
            written += *accepted;
        }
        if (fin) {
            auto closed = flatten_result(co_await s.connection_->async_write(record.id, {}, true));
            if (!closed) co_return false;
        }
        co_return true;
    }

    // Writes one DATA frame whose capsule of capsule_size bytes sits at frame_reserve.
    static auto write_capsule(event_loop& loop, state& s, std::uint32_t slot, std::size_t capsule_size)
        -> task<bool>
    {
        auto& record = s.sessions_[slot];
        const auto length_size = quic::detail::varint_size(capsule_size);
        const auto header = 1 + length_size;
        auto* base = record.send_buffer.data() + frame_reserve - header;
        (void)quic::detail::encode_varint(0, std::span<std::byte>(base, 1));
        (void)quic::detail::encode_varint(capsule_size, std::span<std::byte>(base + 1, length_size));
        co_return (co_await write_connect(loop, s, slot,
                                         std::span<const std::byte>(base, header + capsule_size), false)).value_or(false);
    }

    // Sends the queued capsules, then FIN (after WT_CLOSE_SESSION, or for a peer
    // close), and stops the CONNECT receive side after a local close.
    static auto writer(event_loop& loop, state& s, std::uint32_t slot) -> task<void>
    {
        auto& record = s.sessions_[slot];
        auto* capsule = record.send_buffer.data() + frame_reserve;
        constexpr std::size_t room = capsule_buffer_size - frame_reserve;
        for (;;) {
            if (record.connect_send_closed) co_return;
            // Each pending capsule goes out as its own DATA frame, one per turn.
            using encoded_size = std::expected<std::size_t, wt_encode_error>;
            std::optional<encoded_size> encoded;
            const auto out = std::span<std::byte>(capsule, room);
            if (record.max_data_out) {
                encoded = encode_max_data(*std::exchange(record.max_data_out, std::nullopt), out);
            } else if (record.max_streams_out[0]) {
                encoded = encode_max_streams(true, *std::exchange(record.max_streams_out[0], std::nullopt), out);
            } else if (record.max_streams_out[1]) {
                encoded = encode_max_streams(false, *std::exchange(record.max_streams_out[1], std::nullopt), out);
            } else if (record.data_blocked_out) {
                encoded = encode_data_blocked(*std::exchange(record.data_blocked_out, std::nullopt), out);
            } else if (record.streams_blocked_out[0]) {
                encoded = encode_streams_blocked(true, *std::exchange(record.streams_blocked_out[0], std::nullopt), out);
            } else if (record.streams_blocked_out[1]) {
                encoded = encode_streams_blocked(false, *std::exchange(record.streams_blocked_out[1], std::nullopt), out);
            } else if (record.drain_pending) {
                record.drain_pending = false;
                encoded = encode_drain_session(out);
            }
            if (encoded) {
                if (!*encoded || !(co_await write_capsule(loop, s, slot, **encoded)).value_or(false)) {
                    record.connect_send_closed = true;
                    co_return;
                }
                continue;
            }
            if (record.close_pending) {
                record.close_pending = false;
                const std::string_view reason(record.close_reason.data(), record.close_reason_size);
                const auto size = http3::detail::encode_close_session(
                    record.close_code, reason, std::span<std::byte>(capsule, room));
                if (!size || !(co_await write_capsule(loop, s, slot, *size)).value_or(false)) {
                    record.connect_send_closed = true;
                    co_return;
                }
                (void)co_await write_connect(loop, s, slot, {}, true);
                record.connect_send_closed = true;
                (void)s.connection_->stop_sending(record.id, gone_code());
                co_return;
            }
            if (record.fin_pending) {
                record.fin_pending = false;
                (void)co_await write_connect(loop, s, slot, {}, true);
                record.connect_send_closed = true;
                co_return;
            }
            auto waited = co_await record.writer_wakeup->async_wait();
            if (!waited) co_return;
        }
    }

    // Peer datagrams reach the session queues here, one receive at a time.
    static auto dispatcher(event_loop& loop, state& s) -> task<void>
    {
        (void)loop;
        for (;;) {
            auto received = flatten_result(co_await s.connection_->async_receive_datagram(s.dispatch_buffer_));
            if (!received) {
                if (received.error() != make_error_code(quic_errc::datagram_not_supported) &&
                    received.error() != std::errc::operation_canceled)
                    s.connection_lost();
                co_return;
            }
            const std::span<const std::byte> payload(s.dispatch_buffer_.data(), *received);
            const auto datagram = http3::detail::parse_http_datagram(payload);
            if (!datagram) {
                s.connection_->close_application(code_of(http3::detail::h3_error::datagram_error));
                co_return;
            }
            const auto target = s.route_for(datagram->session_id);
            if (target.kind == route_kind::deliver)
                s.enqueue_datagram(target.slot, datagram->payload);
            else if (target.kind == route_kind::buffer)
                s.buffer_datagram(datagram->session_id, datagram->payload);
        }
    }

    static auto shutdown(event_loop& loop, state& s) -> task<void>
    {
        s.connection_ended_ = true;
        for (std::uint32_t i = 0; i < s.sessions_.size(); ++i) {
            auto& record = s.sessions_[i];
            if (record.phase_ == state::phase::admitting) record.settings_wakeup->notify();
            if (record.phase_ == state::phase::active) {
                s.terminate(i, true, 0, {});
                record.connect_send_closed = true;
            }
        }
        if (s.dispatcher_) (void)s.dispatcher_->cancel();
        for (auto& record : s.sessions_) {
            if (record.reader) (void)record.reader->cancel();
            if (record.writer) (void)record.writer->cancel();
        }
        if (s.dispatcher_ && !s.dispatcher_->done()) (void)co_await *s.dispatcher_;
        for (auto& record : s.sessions_) {
            if (record.reader && !record.reader->done()) (void)co_await *record.reader;
            if (record.writer && !record.writer->done()) (void)co_await *record.writer;
        }
        while (s.busy()) (void)co_await yield(loop);
        s.dispatcher_.reset();
        for (std::uint32_t i = 0; i < s.sessions_.size(); ++i) {
            auto& record = s.sessions_[i];
            record.reader.reset();
            record.writer.reset();
            record.phase_ = state::phase::free;
            record.pending_ops = 0;
        }
        for (std::uint32_t i = 0; i < s.streams_.size(); ++i)
            if (s.streams_[i].in_use) s.free_stream(i);
        s.buffered_stream_count_ = 0;
        for (auto& meta : s.buffered_datagram_meta_) meta.used = false;
        if (s.critical_ != nullptr) {
            s.critical_->on_settings = nullptr;
            s.critical_->settings_context = nullptr;
        }
        s.critical_ = nullptr;
        s.connection_ = nullptr;
        co_return;
    }

    // ---- Session operations ----

    static auto accept(event_loop& loop, state& s, std::uint32_t slot, std::uint32_t generation)
        -> task<std::expected<webtransport_stream, std::error_code>>
    {
        (void)loop;
        auto* record = s.record_for(slot, generation);
        if (record == nullptr) co_return session_closed_error();
        if (record->accept_busy) co_return in_progress_error();
        pending_guard guard(&record->pending_ops);
        for (;;) {
            if (record->phase_ != state::phase::active) co_return session_closed_error();
            if (record->accept_count != 0) {
                const auto index = record->accept_queue[record->accept_head];
                record->accept_head = (record->accept_head + 1) % stream_table_size;
                --record->accept_count;
                auto& entry = s.streams_[index];
                entry.queued = false;
                entry.handle_owned = true;
                co_return webtransport_access::make_stream(&s.owner_, index, entry.generation);
            }
            record->accept_busy = true;
            auto waited = co_await record->accept_wakeup->async_wait();
            record->accept_busy = false;
            if (!waited) co_return std::unexpected(waited.error());
        }
    }

    static auto open(event_loop& loop, state& s, std::uint32_t slot, std::uint32_t generation,
                     quic_stream_direction direction)
        -> task<std::expected<webtransport_stream, std::error_code>>
    {
        (void)loop;
        auto* record = s.record_for(slot, generation);
        if (record == nullptr) co_return session_closed_error();
        if (record->open_busy) co_return in_progress_error();
        pending_guard guard(&record->pending_ops);
        const bool bidirectional = direction == quic_stream_direction::bidirectional;
        const auto index = s.allocate_stream();
        if (!index) co_return std::unexpected(make_error_code(webtransport_errc::capacity_exceeded));
        auto& entry = s.streams_[*index];
        entry.local = true;
        entry.unidirectional = !bidirectional;
        entry.opening = true;
        entry.session = slot;
        entry.session_generation = generation;
        for (;;) {
            if (record->phase_ != state::phase::active) {
                s.free_stream(*index);
                co_return session_closed_error();
            }
            if (record->flow.open_stream(bidirectional)) break;
            if (auto value = record->flow.take_streams_blocked(bidirectional)) {
                record->streams_blocked_out[bidirectional ? 0 : 1] = value;
                record->writer_wakeup->notify();
            }
            record->open_busy = true;
            auto waited = co_await record->open_wakeup->async_wait();
            record->open_busy = false;
            if (!waited) {
                s.free_stream(*index);
                co_return std::unexpected(waited.error());
            }
        }
        auto opened = flatten_result(co_await s.connection_->async_open_stream(direction));
        if (!opened) {
            record->flow.release_stream(bidirectional);
            s.free_stream(*index);
            co_return std::unexpected(map_quic(opened.error()));
        }
        entry.id = *opened;
        std::array<std::byte, frame_reserve> header {};
        const auto encoded = http3::detail::encode_stream_header(!bidirectional, record->id, header);
        if (!encoded) {
            s.free_stream(*index);
            co_return invalid_argument_error();
        }
        std::size_t written = 0;
        while (written < *encoded) {
            auto sent = flatten_result(co_await s.connection_->async_write(
                entry.id, std::span<const std::byte>(header.data() + written, *encoded - written), false));
            if (!sent) {
                (void)s.connection_->reset_stream(entry.id, 0);
                s.free_stream(*index);
                co_return std::unexpected(map_quic(sent.error()));
            }
            written += *sent;
        }
        entry.header_length = *encoded;
        entry.opening = false;
        if (record->phase_ != state::phase::active) {
            s.abandon_send(entry, gone_code());
            if (bidirectional) s.abandon_receive(entry, gone_code());
            s.free_stream(*index);
            co_return session_closed_error();
        }
        entry.handle_owned = true;
        co_return webtransport_access::make_stream(&s.owner_, *index, entry.generation);
    }

    static auto send_datagram(event_loop& loop, state& s, std::uint32_t slot, std::uint32_t generation,
                              std::span<const std::byte> payload) -> task<std::expected<void, std::error_code>>
    {
        auto* record = s.active_record(slot, generation);
        if (record == nullptr) co_return session_closed_error();
        if (record->send_busy) co_return in_progress_error();
        if (payload.size() > s.max_datagram_size(*record))
            co_return std::unexpected(make_error_code(webtransport_errc::datagram_size));
        pending_guard guard(&record->pending_ops);
        const auto prefix = http3::detail::encode_http_datagram_prefix(record->id, record->datagram_scratch);
        if (!prefix) co_return invalid_argument_error();
        std::copy(payload.begin(), payload.end(), record->datagram_scratch.begin() + static_cast<std::ptrdiff_t>(*prefix));
        busy_guard busy(record->send_busy);
        record->sender.emplace();
        if (loop.spawn(s.connection_->async_send_datagram(
                std::span<const std::byte>(record->datagram_scratch.data(), *prefix + payload.size())),
                *record->sender) != task_spawn_result::accepted) {
            record->sender.reset();
            co_return std::unexpected(make_error_code(webtransport_errc::capacity_exceeded));
        }
        auto sent = flatten_result(co_await *record->sender);
        record->sender.reset();
        if (record->phase_ != state::phase::active) co_return session_closed_error();
        if (!sent) {
            if (sent.error() == quic_errc::invalid_argument)
                co_return std::unexpected(make_error_code(webtransport_errc::datagram_size));
            co_return std::unexpected(map_quic(sent.error()));
        }
        co_return std::expected<void, std::error_code> {};
    }

    static auto receive_datagram(event_loop& loop, state& s, std::uint32_t slot, std::uint32_t generation,
                                 std::span<std::byte> buffer) -> task<std::expected<std::size_t, std::error_code>>
    {
        (void)loop;
        auto* record = s.record_for(slot, generation);
        if (record == nullptr) co_return session_closed_error();
        if (record->receive_busy) co_return in_progress_error();
        pending_guard guard(&record->pending_ops);
        for (;;) {
            if (record->phase_ != state::phase::active) co_return session_closed_error();
            if (record->datagram_count != 0) {
                const auto position = slot * s.options_.datagram_queue + record->datagram_head;
                const auto length = s.datagram_lengths_[position];
                if (buffer.size() < length)
                    co_return std::unexpected(make_error_code(webtransport_errc::datagram_size));
                std::copy_n(s.datagram_bytes_.begin() + static_cast<std::ptrdiff_t>(position * datagram_payload_limit),
                            length, buffer.begin());
                record->datagram_head = (record->datagram_head + 1) % s.options_.datagram_queue;
                --record->datagram_count;
                co_return length;
            }
            record->receive_busy = true;
            auto waited = co_await record->datagram_wakeup->async_wait();
            record->receive_busy = false;
            if (!waited) co_return std::unexpected(waited.error());
        }
    }

    static auto drain(event_loop& loop, state& s, std::uint32_t slot, std::uint32_t generation)
        -> task<std::expected<void, std::error_code>>
    {
        (void)loop;
        auto* record = s.active_record(slot, generation);
        if (record == nullptr) co_return session_closed_error();
        record->drain_pending = true;
        record->writer_wakeup->notify();
        co_return std::expected<void, std::error_code> {};
    }

    static auto close(event_loop& loop, state& s, std::uint32_t slot, std::uint32_t generation,
                      std::uint32_t code, std::string_view reason) -> task<std::expected<void, std::error_code>>
    {
        (void)loop;
        if (!http3::detail::valid_utf8(reason)) co_return invalid_argument_error();
        co_return s.begin_close(slot, generation, code,
                                http3::detail::utf8_truncate(reason, wt_max_close_message));
    }

    // ---- Stream operations ----

    static auto read(event_loop& loop, state& s, std::uint32_t index, std::uint32_t generation,
                     std::span<std::byte> buffer) -> task<std::expected<std::size_t, std::error_code>>
    {
        (void)loop;
        auto* entry = s.stream_at(index, generation);
        if (entry == nullptr) co_return session_closed_error();
        if (!entry->has_receive()) co_return invalid_argument_error();
        if (entry->read_busy) co_return in_progress_error();
        auto* record = s.session_of(*entry);
        if (record == nullptr) co_return session_closed_error();
        busy_guard busy(entry->read_busy);
        pending_guard guard(&record->pending_ops);
        const auto slot = entry->session;
        if (entry->stop_sent) co_return stream_closed_error();
        if (entry->peer_reset) co_return std::unexpected(make_error_code(webtransport_errc::stream_reset));
        if (entry->read_finished || buffer.empty()) co_return std::size_t {0};
        if (entry->prefix_offset < entry->prefix_size) {
            const auto count = std::min<std::size_t>(buffer.size(), entry->prefix_size - entry->prefix_offset);
            std::copy_n(entry->prefix.begin() + entry->prefix_offset, count, buffer.begin());
            entry->prefix_offset = static_cast<std::uint8_t>(entry->prefix_offset + count);
            if (auto counted = s.account_read(slot, *entry, count); !counted)
                co_return std::unexpected(counted.error());
            co_return count;
        }
        auto received = flatten_result(co_await s.connection_->async_read(entry->id, buffer));
        if (record->phase_ != state::phase::active) co_return session_closed_error();
        if (!received) {
            if (received.error() == quic_errc::stream_reset) {
                auto observed = s.observe_peer_reset(slot, *entry);
                co_return std::unexpected(observed.error());
            }
            co_return std::unexpected(map_quic(received.error()));
        }
        if (*received == 0) {
            entry->read_finished = true;
            co_return std::size_t {0};
        }
        if (auto counted = s.account_read(slot, *entry, *received); !counted)
            co_return std::unexpected(counted.error());
        co_return *received;
    }

    static auto write(event_loop& loop, state& s, std::uint32_t index, std::uint32_t generation,
                      std::span<const std::byte> buffer, bool fin)
        -> task<std::expected<std::size_t, std::error_code>>
    {
        (void)loop;
        auto* entry = s.stream_at(index, generation);
        if (entry == nullptr) co_return session_closed_error();
        if (!entry->has_send()) co_return invalid_argument_error();
        if (entry->write_busy) co_return in_progress_error();
        auto* record = s.session_of(*entry);
        if (record == nullptr) co_return session_closed_error();
        busy_guard busy(entry->write_busy);
        pending_guard guard(&record->pending_ops);
        for (;;) {
            if (record->phase_ != state::phase::active) co_return session_closed_error();
            if (entry->reset_sent || entry->write_finished) co_return stream_closed_error();
            if (s.connection_->stream_stop_sending_code(entry->id))
                co_return s.observe_peer_stop(*entry);
            if (buffer.empty()) {
                if (!fin) co_return std::size_t {0};
                auto finished = flatten_result(co_await s.connection_->async_write(entry->id, {}, true));
                if (record->phase_ != state::phase::active) co_return session_closed_error();
                if (!finished) co_return std::unexpected(map_quic(finished.error()));
                entry->write_finished = true;
                co_return std::size_t {0};
            }
            // Reserve before the QUIC write, then return any credit it did not use.
            const auto allowed = record->flow.reserve_send(buffer.size());
            if (allowed == 0) {
                if (auto value = record->flow.take_data_blocked()) {
                    record->data_blocked_out = value;
                    record->writer_wakeup->notify();
                }
                auto waited = co_await s.stream_wakeups_[index]->async_wait();
                if (!waited) co_return std::unexpected(waited.error());
                continue;
            }
            const bool whole = allowed == buffer.size();
            auto written = flatten_result(co_await s.connection_->async_write(entry->id, buffer.first(allowed), fin && whole));
            // Only the bytes QUIC accepted count against the peer's window.
            record->flow.release_send(allowed - (written ? *written : 0));
            if (!written || *written != allowed)
                s.wake_streams(entry->session, entry->session_generation);
            if (record->phase_ != state::phase::active) co_return session_closed_error();
            if (!written) {
                if (entry->reset_sent) co_return stream_closed_error();
                if (written.error() == quic_errc::stream_reset) co_return s.observe_peer_stop(*entry);
                co_return std::unexpected(map_quic(written.error()));
            }
            if (fin && whole && *written == buffer.size()) entry->write_finished = true;
            co_return *written;
        }
    }
};

// ---- webtransport_connection ----

webtransport_connection::webtransport_connection(event_loop& loop, const webtransport_options& options)
    : state_(std::make_unique<state>(loop, *this, options))
{
}

webtransport_connection::~webtransport_connection() = default;

auto webtransport_connection::attach(quic_connection& connection,
                                     http3::detail::peer_critical_streams& critical,
                                     bool (*request_open)(void* context, std::uint64_t id) noexcept,
                                     void* context) noexcept -> bool
{
    auto& s = *state_;
    s.connection_ = &connection;
    s.critical_ = &critical;
    s.request_open_ = request_open;
    s.request_context_ = context;
    s.connection_ended_ = false;
    s.flow_enabled_ = false;
    critical.on_settings = &webtransport_access::on_settings;
    critical.settings_context = &s;
    s.dispatcher_.emplace();
    if (s.loop_.spawn(webtransport_access::dispatcher(s.loop_, s), *s.dispatcher_) !=
        task_spawn_result::accepted) {
        s.dispatcher_.reset();
        return false;
    }
    connection.set_stream_reset_handler(&s, &state::on_stream_reset);
    return true;
}

auto webtransport_connection::shutdown() -> task<void>
{
    if (state_->connection_ != nullptr) state_->connection_->set_stream_reset_handler(nullptr, nullptr);
    return webtransport_access::shutdown(state_->loop_, *state_);
}

auto webtransport_connection::admit(std::uint64_t connect_id, std::uint32_t& slot) -> task<admission>
{
    return webtransport_access::admit(state_->loop_, *state_, connect_id, slot);
}

auto webtransport_connection::establish(std::uint32_t slot, const http3::detail::request_frames& frames,
                                        std::span<const std::byte> pending, std::string_view protocol)
    -> std::expected<webtransport_session, std::error_code>
{
    auto& s = *state_;
    auto& record = s.sessions_[slot];
    if (record.phase_ != state::phase::reserved)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    if (protocol.size() > protocol_capacity)
        return std::unexpected(make_error_code(webtransport_errc::capacity_exceeded));
    record.frames = frames;
    record.frames.set_block_storage({});
    record.parser = capsule_parser(s.flow_enabled_, datagram_payload_limit);
    http3::detail::flow_limits local;
    local.data = s.options_.initial_max_data;
    local.streams = {s.options_.initial_max_streams_bidi, s.options_.initial_max_streams_uni};
    http3::detail::flow_limits peer;
    peer.data = s.critical_->wt_initial_max_data;
    peer.streams = {s.critical_->wt_initial_max_streams_bidi, s.critical_->wt_initial_max_streams_uni};
    record.flow = session_flow(s.flow_enabled_, local, peer);
    std::copy(protocol.begin(), protocol.end(), record.protocol.begin());
    record.protocol_size = protocol.size();
    record.phase_ = state::phase::active;
    s.adopt_buffered(slot);
    std::span<const std::byte> input = pending;
    (void)s.consume(slot, input);

    record.reader.emplace();
    if (s.loop_.spawn(webtransport_access::reader(s.loop_, s, slot), *record.reader) !=
        task_spawn_result::accepted) {
        record.reader.reset();
        s.terminate(slot, false, 0, {});
        record.connect_send_closed = true;
        return std::unexpected(make_error_code(webtransport_errc::capacity_exceeded));
    }
    record.writer.emplace();
    if (s.loop_.spawn(webtransport_access::writer(s.loop_, s, slot), *record.writer) !=
        task_spawn_result::accepted) {
        (void)record.reader->cancel();
        record.writer.reset();
        s.terminate(slot, false, 0, {});
        record.connect_send_closed = true;
        return std::unexpected(make_error_code(webtransport_errc::capacity_exceeded));
    }
    record.handle_owned = true;
    return webtransport_access::make_session(this, slot, record.generation);
}

auto webtransport_connection::release(std::uint32_t slot) noexcept -> void
{
    auto& record = state_->sessions_[slot];
    record.handler_active = false;
    if (record.phase_ == state::phase::reserved) record.phase_ = state::phase::free;
}

auto webtransport_connection::handler_returned(std::uint32_t slot) noexcept -> void
{
    auto& s = *state_;
    auto& record = s.sessions_[slot];
    record.handler_active = false;
    if (record.phase_ == state::phase::active)
        (void)s.begin_close(slot, record.generation, 0, {});
}

auto webtransport_connection::peer_bidirectional(std::uint64_t stream_id, std::uint64_t session_id,
                                                 std::size_t header, std::span<const std::byte> body) noexcept
    -> void
{
    state_->peer_stream(true, stream_id, session_id, header, body);
}

auto webtransport_connection::peer_unidirectional(std::uint64_t stream_id, std::uint64_t session_id,
                                                  std::size_t header, std::span<const std::byte> body) noexcept
    -> void
{
    state_->peer_stream(false, stream_id, session_id, header, body);
}

auto webtransport_connection::request_finished(std::uint64_t request_id) noexcept -> void
{
    state_->refuse_buffered(request_id);
}

} // namespace detail

// ---- webtransport_session ----

webtransport_session::webtransport_session(webtransport_session&& other) noexcept
    : connection_(std::exchange(other.connection_, nullptr)),
      slot_(other.slot_),
      generation_(other.generation_)
{
}

auto webtransport_session::operator=(webtransport_session&& other) noexcept -> webtransport_session&
{
    if (this != &other) {
        auto previous = std::move(*this);
        connection_ = std::exchange(other.connection_, nullptr);
        slot_ = other.slot_;
        generation_ = other.generation_;
    }
    return *this;
}

webtransport_session::~webtransport_session()
{
    if (connection_ == nullptr) return;
    auto& s = detail::webtransport_access::engine(connection_);
    (void)s.begin_close(slot_, generation_, 0, {});
    if (auto* record = s.record_for(slot_, generation_)) record->handle_owned = false;
    connection_ = nullptr;
}

auto webtransport_session::valid() const noexcept -> bool
{
    return connection_ != nullptr;
}

auto webtransport_session::id() const noexcept -> std::uint64_t
{
    if (connection_ == nullptr) return 0;
    const auto* record = detail::webtransport_access::engine(connection_).record_for(slot_, generation_);
    return record != nullptr ? record->id : 0;
}

auto webtransport_session::protocol() const noexcept -> std::string_view
{
    if (connection_ == nullptr) return {};
    const auto* record = detail::webtransport_access::engine(connection_).record_for(slot_, generation_);
    return record != nullptr ? std::string_view(record->protocol.data(), record->protocol_size) : std::string_view {};
}

auto webtransport_session::close_info() const noexcept -> std::optional<webtransport_close_info>
{
    if (connection_ == nullptr) return std::nullopt;
    const auto* record = detail::webtransport_access::engine(connection_).record_for(slot_, generation_);
    if (record == nullptr || record->phase_ != detail::webtransport_access::state::phase::terminated ||
        !record->has_close_info)
        return std::nullopt;
    return webtransport_close_info {record->close_code,
                                    std::string_view(record->close_reason.data(), record->close_reason_size),
                                    record->close_remote};
}

auto webtransport_session::draining() const noexcept -> bool
{
    if (connection_ == nullptr) return false;
    const auto* record = detail::webtransport_access::engine(connection_).record_for(slot_, generation_);
    return record != nullptr && record->draining;
}

auto webtransport_session::max_datagram_size() const noexcept -> std::size_t
{
    if (connection_ == nullptr) return 0;
    auto& s = detail::webtransport_access::engine(connection_);
    const auto* record = s.active_record(slot_, generation_);
    return record != nullptr ? s.max_datagram_size(*record) : 0;
}

auto webtransport_session::async_accept_stream()
    -> task<std::expected<webtransport_stream, std::error_code>>
{
    if (connection_ == nullptr) std::terminate();
    auto& s = detail::webtransport_access::engine(connection_);
    return detail::webtransport_access::accept(s.loop_, s, slot_, generation_);
}

auto webtransport_session::async_open_stream(quic_stream_direction direction)
    -> task<std::expected<webtransport_stream, std::error_code>>
{
    if (connection_ == nullptr) std::terminate();
    auto& s = detail::webtransport_access::engine(connection_);
    return detail::webtransport_access::open(s.loop_, s, slot_, generation_, direction);
}

auto webtransport_session::async_send_datagram(std::span<const std::byte> payload)
    -> task<std::expected<void, std::error_code>>
{
    if (connection_ == nullptr) std::terminate();
    auto& s = detail::webtransport_access::engine(connection_);
    return detail::webtransport_access::send_datagram(s.loop_, s, slot_, generation_, payload);
}

auto webtransport_session::async_receive_datagram(std::span<std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
    if (connection_ == nullptr) std::terminate();
    auto& s = detail::webtransport_access::engine(connection_);
    return detail::webtransport_access::receive_datagram(s.loop_, s, slot_, generation_, buffer);
}

auto webtransport_session::async_drain() -> task<std::expected<void, std::error_code>>
{
    if (connection_ == nullptr) std::terminate();
    auto& s = detail::webtransport_access::engine(connection_);
    return detail::webtransport_access::drain(s.loop_, s, slot_, generation_);
}

auto webtransport_session::async_close(std::uint32_t code, std::string_view reason)
    -> task<std::expected<void, std::error_code>>
{
    if (connection_ == nullptr) std::terminate();
    auto& s = detail::webtransport_access::engine(connection_);
    return detail::webtransport_access::close(s.loop_, s, slot_, generation_, code, reason);
}

// ---- webtransport_stream ----

webtransport_stream::webtransport_stream(webtransport_stream&& other) noexcept
    : connection_(std::exchange(other.connection_, nullptr)),
      slot_(other.slot_),
      generation_(other.generation_)
{
}

auto webtransport_stream::operator=(webtransport_stream&& other) noexcept -> webtransport_stream&
{
    if (this != &other) {
        auto previous = std::move(*this);
        connection_ = std::exchange(other.connection_, nullptr);
        slot_ = other.slot_;
        generation_ = other.generation_;
    }
    return *this;
}

webtransport_stream::~webtransport_stream()
{
    if (connection_ == nullptr) return;
    auto& s = detail::webtransport_access::engine(connection_);
    if (auto* entry = s.stream_at(slot_, generation_)) {
        if (entry->has_send() && !entry->write_finished)
            s.abandon_send(*entry, webtransport_to_http3_error(0));
        if (entry->has_receive() && !entry->read_finished && !entry->stop_sent)
            s.abandon_receive(*entry, webtransport_to_http3_error(0));
        if (!entry->local) {
            if (auto* record = s.session_of(*entry); record != nullptr) {
                record->flow.on_peer_stream_closed(!entry->unidirectional);
                s.renew_streams(*record, !entry->unidirectional);
            }
        }
        s.free_stream(slot_);
    }
    connection_ = nullptr;
}

auto webtransport_stream::valid() const noexcept -> bool
{
    return connection_ != nullptr;
}

auto webtransport_stream::id() const noexcept -> std::uint64_t
{
    if (connection_ == nullptr) return 0;
    const auto* entry = detail::webtransport_access::engine(connection_).stream_at(slot_, generation_);
    return entry != nullptr ? entry->id : 0;
}

auto webtransport_stream::direction() const noexcept -> quic_stream_direction
{
    if (connection_ == nullptr) return quic_stream_direction::bidirectional;
    const auto* entry = detail::webtransport_access::engine(connection_).stream_at(slot_, generation_);
    return entry != nullptr && entry->unidirectional ? quic_stream_direction::unidirectional
                                                      : quic_stream_direction::bidirectional;
}

auto webtransport_stream::local() const noexcept -> bool
{
    if (connection_ == nullptr) return false;
    const auto* entry = detail::webtransport_access::engine(connection_).stream_at(slot_, generation_);
    return entry != nullptr && entry->local;
}

auto webtransport_stream::async_read(std::span<std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
    if (connection_ == nullptr) std::terminate();
    auto& s = detail::webtransport_access::engine(connection_);
    return detail::webtransport_access::read(s.loop_, s, slot_, generation_, buffer);
}

auto webtransport_stream::async_write(std::span<const std::byte> buffer, bool fin)
    -> task<std::expected<std::size_t, std::error_code>>
{
    if (connection_ == nullptr) std::terminate();
    auto& s = detail::webtransport_access::engine(connection_);
    return detail::webtransport_access::write(s.loop_, s, slot_, generation_, buffer, fin);
}

auto webtransport_stream::reset(std::uint32_t code) noexcept -> std::expected<void, std::error_code>
{
    if (connection_ == nullptr) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    auto& s = detail::webtransport_access::engine(connection_);
    auto* entry = s.stream_at(slot_, generation_);
    if (entry == nullptr) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    if (!entry->has_send()) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    if (entry->write_finished) return {};
    s.abandon_send(*entry, webtransport_to_http3_error(code));
    s.stream_wakeups_[slot_]->notify();
    return {};
}

auto webtransport_stream::stop_sending(std::uint32_t code) noexcept -> std::expected<void, std::error_code>
{
    if (connection_ == nullptr) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    auto& s = detail::webtransport_access::engine(connection_);
    auto* entry = s.stream_at(slot_, generation_);
    if (entry == nullptr) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    if (!entry->has_receive()) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    if (entry->stop_sent || entry->read_finished) return {};
    s.abandon_receive(*entry, webtransport_to_http3_error(code));
    return {};
}

auto webtransport_stream::error_code() const noexcept -> std::optional<std::uint32_t>
{
    if (connection_ == nullptr) return std::nullopt;
    const auto* entry = detail::webtransport_access::engine(connection_).stream_at(slot_, generation_);
    return entry != nullptr ? entry->peer_code : std::nullopt;
}

} // namespace eventloop::http
