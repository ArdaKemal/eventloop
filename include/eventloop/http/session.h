#pragma once

#include "eventloop/byte_stream.h"
#include "eventloop/http/request.h"

#include <array>
#include <cstddef>
#include <span>
#include <system_error>

#include <dirent.h>
#include <sys/stat.h>

namespace http {

class session {
public:
    session(byte_stream& stream, int root_descriptor,
            bool directory_listing = false) noexcept;
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
    auto serve_open_file(const struct ::stat& info, bool headers_only) -> void;
    auto serve_directory(bool headers_only) -> void;
    auto pump_directory() -> void;
    auto send_directory_redirect() -> void;
    auto send_options() -> void;
    auto send_error(parse_status status) -> void;
    auto send_response(std::string_view response) -> void;
    auto pump_file() -> void;
    auto finish_response() -> void;
    auto consume_request(std::size_t size) -> void;
    [[nodiscard]] auto open_path() noexcept -> int;
    [[nodiscard]] auto prepare_path(std::string_view target) noexcept -> path_result;

    byte_stream& stream_;
    int root_descriptor_;
    int file_descriptor_ {-1};
    DIR* directory_ {nullptr};
    std::array<char, max_message_size> input_ {};
    std::array<char, 20 * 1024> response_ {};
    std::array<char, 4096> path_ {};
    std::array<char, max_target_size + 1> url_path_ {};
    std::size_t input_size_ {0};
    std::size_t url_path_size_ {0};
    request request_ {};
    bool directory_listing_ {false};
    bool directory_started_ {false};
    bool responding_ {false};
    bool close_after_response_ {false};
};

} // namespace http
