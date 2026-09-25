#pragma once

#include "eventloop/byte_stream.h"
#include "eventloop/http/request.h"
#include "eventloop/unique_fd.h"

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>

#include <sys/stat.h>

class tcp_stream;

namespace http {

class session {
public:
    session(byte_stream& stream, int root_descriptor,
            bool directory_listing = false,
            tcp_stream* file_stream = nullptr) noexcept;
    ~session() = default;

    session(const session&) = delete;
    auto operator=(const session&) -> session& = delete;

    auto receive(std::span<const std::byte> data) -> void;
    auto write_drained() -> void;
    auto closed() -> void;
    auto failed(std::error_code) -> void;
    auto shutdown() -> void;

private:
    enum class path_result { valid, invalid, too_long };

    auto process_requests() -> void;
    auto handle_request() -> void;
    auto serve_resource(bool headers_only) -> void;
    auto serve_file(unique_fd descriptor, const struct ::stat& info,
                    bool headers_only, std::string_view mime_path) -> void;
    auto serve_directory(unique_fd descriptor, bool headers_only) -> void;
    auto send_directory_redirect() -> void;
    auto send_options() -> void;
    auto send_error(parse_status status) -> void;
    auto send_response(std::string_view response) -> void;
    auto send_response(std::span<const char> response) -> void;
    auto start_large_response() -> void;
    auto write_next() -> void;
    auto finish_response() -> void;
    auto consume_request(std::size_t size) -> void;
    [[nodiscard]] auto prepare_path(std::string_view target,
                                    std::span<char> output,
                                    std::size_t& size) const noexcept -> path_result;
    [[nodiscard]] auto allocate_response(std::size_t size) -> std::span<char>;

    byte_stream& stream_;
    tcp_stream* file_stream_;
    int root_descriptor_;
    std::array<char, 4096> input_ {};
    std::unique_ptr<char[]> output_;
    std::size_t input_size_ {0};
    std::size_t request_size_ {0};
    std::size_t output_size_ {0};
    std::size_t output_offset_ {0};
    request request_ {};
    bool directory_listing_ {false};
    bool responding_ {false};
    bool close_after_response_ {false};
};

} // namespace http
