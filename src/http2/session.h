#pragma once

#include "eventloop/unique_fd.h"
#include "../http/exchange.h"
#include "../http/open_file_cache.h"
#include "hpack.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <vector>

namespace eventloop::http2::detail {

inline constexpr std::size_t max_frame_payload = 16 * 1024;
inline constexpr std::size_t max_concurrent_streams = 32;
inline constexpr std::size_t max_request_body = 1024 * 1024;
inline constexpr std::size_t max_queued_response_body = 4 * 1024 * 1024;
// Routed request bodies are buffered per stream in a pool allocated the
// first time a connection receives one. The stream window equals one slot.
inline constexpr std::size_t route_body_slots = 8;
inline constexpr std::size_t route_body_slot_size = 16 * 1024;

struct request {
    std::uint32_t stream_id = 0;
    std::string method;
    std::string target;
    std::string if_none_match;
    std::string if_modified_since;
    std::string range;
    std::uint64_t body_size = 0;
};

// A request whose path and method have a route handler. Delivered when its
// HEADERS complete; the body follows through read_body().
struct routed_request {
    std::uint32_t stream_id = 0;
    http::detail::route_match match;
    std::vector<field> fields;
    std::optional<std::uint64_t> content_length;
    bool too_large = false;
};

class session final {
public:
    // Called when a routed stream is released; completed tells whether its
    // response ended normally. It must not call back into the session.
    using release_hook = void (*)(void* context, std::uint32_t stream_id,
                                  bool completed) noexcept;

    explicit session(bool file_sendfile = false, const http::router* routes = nullptr,
                     std::uint64_t max_request_body = 0);

    struct file_send {
        http::detail::static_file file;
        std::uint64_t offset = 0;
        std::size_t size = 0;
        std::span<const std::byte> prefix {};
    };
    // Normally available after all preceding bytes drain. With include_prefix,
    // a contiguous preceding queue span can be borrowed for the combined send;
    // consume that prefix only after transport completion, before returning file.
    [[nodiscard]] auto take_file_send(bool include_prefix = false) noexcept
        -> std::optional<file_send>;
    // Return the descriptor after the borrowed transport send has completed.
    auto complete_file_send(http::detail::static_file file) -> void;

    session(const session&) = delete;
    auto operator=(const session&) -> session& = delete;

    [[nodiscard]] auto read_buffer() noexcept -> std::span<std::byte>;
    auto commit_read(std::size_t size) -> void;
    [[nodiscard]] auto output() const noexcept -> std::span<const std::byte>;
    auto consume_output(std::size_t size) -> void;
    // Assigns into value's existing strings, so a caller reusing one request
    // keeps their capacity across requests.
    [[nodiscard]] auto pop_request(request& value) -> bool;

    // Header fields are borrowed only during the call.
    [[nodiscard]] auto respond(std::uint32_t stream_id, unsigned status,
        std::span<const http::header> headers, std::vector<std::byte> body) -> bool;
    [[nodiscard]] auto respond_file(std::uint32_t stream_id, unsigned status,
        std::span<const http::header> headers, http::detail::static_file file,
        std::uint64_t size,
        bool send_body, std::uint64_t offset = 0) -> bool;

    [[nodiscard]] auto closed() const noexcept -> bool;


    // Routed streams. Operations on a released stream report failure.
    auto set_release_hook(release_hook hook, void* context) noexcept -> void;
    [[nodiscard]] auto pop_routed(routed_request& value) -> bool;
    // Returns a finished request's field vector so later header blocks
    // decode into its existing strings.
    auto recycle_fields(std::vector<field>&& fields) noexcept -> void;
    enum class body_state { data, waiting, ended, too_large, failed };
    [[nodiscard]] auto read_body(std::uint32_t stream_id, std::span<std::byte> output,
                                 std::size_t& count) -> body_state;
    // headers then extra are sent after :status; both are borrowed only
    // during the call.
    [[nodiscard]] auto start_streamed(std::uint32_t stream_id, unsigned status,
                                      std::span<const http::header> headers,
                                      std::span<const http::header> extra = {},
                                      bool websocket = false) -> bool;
    // Borrows data until chunk_pending() turns false.
    [[nodiscard]] auto queue_chunk(std::uint32_t stream_id, std::span<const std::byte> data)
        -> bool;
    [[nodiscard]] auto chunk_pending(std::uint32_t stream_id) const noexcept -> bool;
    [[nodiscard]] auto finish_streamed(std::uint32_t stream_id,
                                       std::span<const http::header> trailers) -> bool;
    [[nodiscard]] auto send_streamed_file(std::uint32_t stream_id, unique_fd file,
                                          std::uint64_t offset, std::uint64_t size) -> bool;
    auto abandon(std::uint32_t stream_id, std::uint32_t error) -> void;
    // Input waits while a routed DATA frame does not fit its stream's buffer.
    // That happens only before the client applies the advertised window.
    [[nodiscard]] auto input_paused() const noexcept -> bool { return stalled_; }
    [[nodiscard]] auto stream_open(std::uint32_t stream_id) const noexcept -> bool;
    // read_body() would not report waiting.
    [[nodiscard]] auto body_ready(std::uint32_t stream_id) const noexcept -> bool;
    // Bytes or a file range wait for the transport.
    [[nodiscard]] auto has_output() const noexcept -> bool
    {
        return output_size_ != 0 || file_send_active_;
    }
    auto resume_input() -> void;
    // No complete request is being answered.
    [[nodiscard]] auto idle() const noexcept -> bool;

private:
    enum class connect_state : std::uint8_t { none, unsupported, websocket, accepted };

    struct stream {
        std::uint32_t id = 0;
        std::int64_t receive_window = 65535;
        std::int64_t send_window = 65535;
        std::uint64_t request_body_size = 0;
        std::optional<std::uint64_t> content_length;
        std::string method;
        std::string target;
        std::string if_none_match;
        std::string if_modified_since;
        std::string range;
        bool duplicate_range = false;
        std::uint64_t response_file_start = 0;
        std::vector<std::byte> response_body;
        http::detail::static_file response_file;
        std::uint64_t response_size = 0;
        std::uint64_t response_offset = 0;
        std::size_t response_accounted = 0;
        bool active = false;
        bool initial_headers = false;
        bool remote_closed = false;
        bool request_ready = false;
        bool response_started = false;
        // Routed streams: body buffering and handler-driven responses.
        bool routed = false;
        bool body_ended = false;
        bool too_large = false;
        bool streaming = false;
        bool stream_finished = false;
        connect_state connect = connect_state::none;
        std::uint8_t body_slot = no_slot;
        std::size_t body_begin = 0;
        std::size_t body_end = 0;
        std::span<const std::byte> chunk;
        // RFC 9218 priority; the defaults apply when the client sends none.
        std::uint8_t urgency = 3;
        bool incremental = false;
    };

    static constexpr std::uint8_t no_slot = 0xff;

    auto consume_input(std::span<const std::byte> input) -> void;
    [[nodiscard]] auto route_stream(stream& value) -> bool;
    [[nodiscard]] auto acquire_body_slot() noexcept -> std::uint8_t;
    [[nodiscard]] auto body_slot(const stream& value) noexcept -> std::byte*;
    auto complete_stream(stream& value) -> void;
    // Encodes an optional :status, then first and second, as one block.
    [[nodiscard]] auto append_header_block(stream& value, unsigned status,
                                           std::span<const http::header> first,
                                           std::span<const http::header> second,
                                           bool end_stream) -> bool;
    auto dispatch_frame() -> void;
    auto dispatch_headers() -> void;
    auto dispatch_data() -> void;
    auto dispatch_settings() -> void;
    auto dispatch_window_update() -> void;
    auto dispatch_priority_update() -> void;
    auto finish_header_block() -> void;
    auto finish_request(stream& value) -> void;
    [[nodiscard]] auto validate_initial_headers(stream& value,
        std::span<const field> fields) -> bool;
    [[nodiscard]] auto validate_trailers(std::span<const field> fields) const -> bool;
    // The allocated slots, active or not.
    [[nodiscard]] auto streams() const noexcept
    {
        return std::span(streams_).first(stream_count_) |
               std::views::transform([](const std::unique_ptr<stream>& slot) -> stream& {
                   return *slot;
               });
    }
    [[nodiscard]] auto find_stream(std::uint32_t id) const noexcept -> stream*;
    [[nodiscard]] auto allocate_stream(std::uint32_t id) noexcept -> stream*;
    // How a stream ended decides the RFC 9113 section 5.1 response to frames
    // that arrive afterwards.
    enum class closed_reason : std::uint8_t { ended, peer_reset, local_reset };
    struct closed_stream {
        std::uint32_t id = 0;
        closed_reason reason = closed_reason::local_reset;
    };
    static constexpr std::size_t closed_history = 64;
    auto reset_stream(stream& value,
                      closed_reason reason = closed_reason::ended) noexcept -> void;
    auto record_closed(std::uint32_t id, closed_reason reason) noexcept -> void;
    // Streams evicted from the history count as locally reset, which permits
    // discarding late frames. nullopt means the id was skipped and is idle.
    [[nodiscard]] auto closed_reason_of(std::uint32_t id) const noexcept
        -> std::optional<closed_reason>;
    auto stream_error(std::uint32_t id, std::uint32_t error) -> void;
    auto connection_error(std::uint32_t error) -> void;
    auto send_window_update(std::uint32_t id, std::uint32_t increment) -> void;
    auto complete_frame() -> void;
    auto clear_frame_state() noexcept -> void;
    // Unfilled payload of the current frame when it is large enough to be
    // the next read target; empty otherwise.
    [[nodiscard]] auto payload_read_space() noexcept -> std::span<std::byte>;
    // frame_payload_, allocated on first use; null if allocation fails.
    [[nodiscard]] auto frame_storage() noexcept -> std::byte*;
    auto append_frame(std::uint8_t type, std::uint8_t flags,
                      std::uint32_t stream_id,
                      std::span<const std::byte> payload = {},
                      std::size_t file_payload_size = 0) -> bool;
    enum class file_frame { appended, full, read_failed };
    // Reads the DATA payload from file straight into the output queue.
    auto append_file_frame(std::uint8_t flags, std::uint32_t stream_id,
                           native_socket file, std::uint64_t offset,
                           std::size_t size) -> file_frame;
    [[nodiscard]] auto reserve_output(std::size_t needed,
                                      std::size_t file_payload_size) -> bool;
    auto append_output(std::span<const std::byte> bytes) noexcept -> void;
    [[nodiscard]] static auto frame_header(std::size_t size, std::uint8_t type,
        std::uint8_t flags, std::uint32_t stream_id) noexcept -> std::array<std::byte, 9>;
    auto append_response_headers(stream& value, unsigned status,
                                 std::span<const http::header> headers,
                                 std::span<const http::header> extra, bool end_stream) -> bool;
    auto pump_responses() -> void;
    [[nodiscard]] auto next_response() const noexcept -> std::optional<std::size_t>;

    // One external payload is an ordering barrier in the bounded byte queue.
    file_send file_send_;
    std::size_t file_send_prefix_ = 0;
    std::uint32_t file_send_stream_ = 0;
    std::size_t file_send_index_ = 0;
    std::size_t response_cursor_ = 0;
    bool file_send_active_ = false;
    bool file_sendfile_ = false;
    std::array<std::byte, 4096> read_buffer_ {};
    std::array<std::byte, 9> frame_header_ {};
    // Holds a payload that spans reads or waits while input is paused.
    // Allocated the first time a connection needs it, then kept.
    std::unique_ptr<std::byte[]> frame_payload_;
    // The payload being dispatched: frame_payload_, or input it lies in.
    const std::byte* frame_data_ = nullptr;
    std::size_t frame_header_size_ = 0;
    std::size_t frame_payload_size_ = 0;
    std::size_t expected_payload_size_ = 0;
    std::size_t preface_size_ = 0;
    std::size_t output_offset_ = 0;
    std::size_t output_size_ = 0;
    std::uint32_t frame_stream_id_ = 0;
    std::uint32_t continuation_stream_id_ = 0;
    std::uint32_t header_stream_id_ = 0;
    std::uint32_t last_stream_id_ = 0;
    std::uint32_t header_reject_error_ = 0;
    std::int64_t connection_receive_window_ = 65535;
    std::int64_t connection_send_window_ = 65535;
    std::uint32_t peer_initial_window_ = 65535;
    std::size_t inline_response_bytes_ = 0;
    std::uint8_t frame_type_ = 0;
    std::uint8_t frame_flags_ = 0;
    bool header_end_stream_ = false;
    bool header_trailers_ = false;
    bool header_refused_ = false;
    bool got_first_settings_ = false;
    bool server_settings_acked_ = false;
    bool fatal_ = false;
    bool peer_goaway_ = false;
    bool stalled_ = false;
    std::size_t held_input_ = 0;
    std::size_t stalled_need_ = 0;
    const http::router* routes_ = nullptr;
    std::uint64_t max_routed_body_ = 0;
    release_hook release_hook_ = nullptr;
    void* release_context_ = nullptr;
    std::unique_ptr<std::byte[]> body_arena_;
    std::array<bool, route_body_slots> slot_used_ {};
    // Slots are allocated when concurrency first needs them, then kept.
    std::array<std::unique_ptr<stream>, max_concurrent_streams> streams_ {};
    std::size_t stream_count_ = 0;
    std::array<closed_stream, closed_history> closed_streams_ {};
    std::size_t closed_next_ = 0;
    std::uint32_t closed_floor_ = 0;
    bool header_closed_reply_ = false;

    // Streams whose static request is complete, in arrival order.
    std::vector<std::uint32_t> requests_;
    std::vector<routed_request> routed_;
    std::vector<std::byte> header_block_;
    std::vector<std::byte> output_;
    std::vector<field> decoded_fields_;
    std::vector<std::byte> encoded_block_;
    hpack_decoder decoder_;
};

} // namespace eventloop::http2::detail
