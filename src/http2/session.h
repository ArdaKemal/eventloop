#pragma once

#include "eventloop/unique_fd.h"
#include "hpack.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace eventloop::http2::detail {

inline constexpr std::size_t max_frame_payload = 16 * 1024;
inline constexpr std::size_t max_concurrent_streams = 32;
inline constexpr std::size_t max_request_body = 1024 * 1024;
inline constexpr std::size_t max_queued_response_body = 4 * 1024 * 1024;

struct request {
    std::uint32_t stream_id = 0;
    std::string method;
    std::string target;
    std::string if_none_match;
    std::string if_modified_since;
    std::string range;
    std::uint64_t body_size = 0;
};

class session final {
public:
    session();

    session(const session&) = delete;
    auto operator=(const session&) -> session& = delete;

    [[nodiscard]] auto read_buffer() noexcept -> std::span<std::byte>;
    auto commit_read(std::size_t size) -> void;
    [[nodiscard]] auto output() const noexcept -> std::span<const std::byte>;
    auto consume_output(std::size_t size) -> void;
    [[nodiscard]] auto pop_request(request& value) -> bool;

    [[nodiscard]] auto respond(std::uint32_t stream_id, unsigned status,
        std::span<const field> headers, std::vector<std::byte> body) -> bool;
    [[nodiscard]] auto respond_file(std::uint32_t stream_id, unsigned status,
        std::span<const field> headers, unique_fd file, std::uint64_t size,
        bool send_body, std::uint64_t offset = 0) -> bool;

    [[nodiscard]] auto closed() const noexcept -> bool;

private:
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
        unique_fd response_file;
        std::uint64_t response_size = 0;
        std::uint64_t response_offset = 0;
        std::size_t response_accounted = 0;
        bool active = false;
        bool initial_headers = false;
        bool remote_closed = false;
        bool request_ready = false;
        bool response_started = false;
    };

    auto consume_input(std::span<const std::byte> input) -> void;
    auto dispatch_frame() -> void;
    auto dispatch_headers() -> void;
    auto dispatch_data() -> void;
    auto dispatch_settings() -> void;
    auto dispatch_window_update() -> void;
    auto finish_header_block() -> void;
    auto finish_request(stream& value) -> void;
    [[nodiscard]] auto validate_initial_headers(stream& value,
        std::span<const field> fields) -> bool;
    [[nodiscard]] auto validate_trailers(std::span<const field> fields) const -> bool;
    [[nodiscard]] auto find_stream(std::uint32_t id) noexcept -> stream*;
    [[nodiscard]] auto allocate_stream(std::uint32_t id) noexcept -> stream*;
    auto reset_stream(stream& value) noexcept -> void;
    auto stream_error(std::uint32_t id, std::uint32_t error) -> void;
    auto connection_error(std::uint32_t error) -> void;
    auto send_window_update(std::uint32_t id, std::uint32_t increment) -> void;
    auto append_frame(std::uint8_t type, std::uint8_t flags,
                      std::uint32_t stream_id,
                      std::span<const std::byte> payload = {}) -> bool;
    auto append_response_headers(stream& value, unsigned status,
                                 std::span<const field> headers) -> bool;
    auto pump_responses() -> void;

    std::array<std::byte, 4096> read_buffer_ {};
    std::array<std::byte, 9> frame_header_ {};
    std::array<std::byte, max_frame_payload> frame_payload_ {};
    std::size_t frame_header_size_ = 0;
    std::size_t frame_payload_size_ = 0;
    std::size_t expected_payload_size_ = 0;
    std::size_t preface_size_ = 0;
    std::size_t output_offset_ = 0;
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
    std::array<stream, max_concurrent_streams> streams_ {};
    std::vector<request> requests_;
    std::vector<std::byte> header_block_;
    std::vector<std::byte> output_;
    std::vector<field> decoded_fields_;
    hpack_decoder decoder_;
};

} // namespace eventloop::http2::detail
