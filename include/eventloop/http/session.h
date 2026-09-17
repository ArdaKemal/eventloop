#pragma once

#include "eventloop/byte_stream.h"
#include "eventloop/http/request.h"

#include <array>
#include <cstddef>
#include <span>
#include <system_error>

namespace http {

class session {
public:
    session(byte_stream& stream, int root_descriptor) noexcept;
    ~session();

    session(const session&) = delete;
    auto operator=(const session&) -> session& = delete;

    auto receive(std::span<const std::byte> data) -> void;
    auto write_drained() -> void;
    auto closed() -> void;
    auto failed(std::error_code) -> void;

private:
    enum class path_result { valid, invalid, too_long };

    auto process_requests() -> void;
    auto handle_request() -> void;
    auto serve_file(bool headers_only) -> void;
    auto send_options() -> void;
    auto send_error(parse_status status) -> void;
    auto send_response(std::string_view response) -> void;
    auto pump_file() -> void;
    auto finish_response() -> void;
    auto consume_request(std::size_t size) -> void;
    [[nodiscard]] auto prepare_path(std::string_view target) noexcept -> path_result;

    byte_stream& stream_;
    int root_descriptor_;
    int file_descriptor_ {-1};
    std::array<char, max_message_size> input_ {};
    std::array<char, 4096> response_ {};
    std::array<char, 4096> path_ {};
    std::array<std::byte, 16 * 1024> file_buffer_ {};
    std::size_t input_size_ {0};
    request request_ {};
    bool responding_ {false};
    bool close_after_response_ {false};
};

} // namespace http
