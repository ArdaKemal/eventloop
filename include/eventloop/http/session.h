#pragma once

#include "eventloop/http/request.h"
#include "eventloop/native_socket.h"
#include "eventloop/unique_fd.h"

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace eventloop::http {

namespace detail { struct file_info; }

class session {
public:
    session(native_socket root_descriptor, bool directory_listing = false) noexcept;
    ~session() = default;

    session(const session&) = delete;
    auto operator=(const session&) -> session& = delete;

    auto receive(std::span<const std::byte> data) -> void;
    [[nodiscard]] auto read_space() -> std::span<std::byte>;
    auto commit_read(std::size_t size) -> void;
    auto shutdown() -> void;
    [[nodiscard]] auto has_response() const noexcept -> bool { return responding_; }
    [[nodiscard]] auto response() const noexcept -> std::span<const char>;
    [[nodiscard]] auto file_size() const noexcept -> std::size_t { return file_size_; }
    [[nodiscard]] auto take_file() noexcept -> unique_fd { return std::move(file_); }
    [[nodiscard]] auto closed() const noexcept -> bool { return closed_; }
    auto finish_response() -> void;

private:
    auto process_requests() -> void;
    auto handle_request(const request& parsed) -> void;
    auto serve_resource(const request& parsed, bool headers_only) -> void;
    auto serve_file(unique_fd descriptor, const detail::file_info& info,
                    bool headers_only, std::string_view mime_path) -> void;
    auto serve_directory(unique_fd descriptor, bool headers_only) -> void;
    auto send_directory_redirect(std::string_view target) -> void;
    auto send_options() -> void;
    auto send_error(parse_status status) -> void;
    auto send_static_response(std::string_view response) -> void;
    auto send_response(std::span<const char> response) -> void;
    auto start_large_response() -> void;
    auto consume_request(std::size_t size) -> void;
    auto expand_input() -> void;
    [[nodiscard]] auto input_data() noexcept -> char*;
    [[nodiscard]] auto allocate_response(std::size_t size) -> std::span<char>;

    native_socket root_descriptor_;
    std::array<char, 256> input_ {};
    std::unique_ptr<char[]> expanded_input_;
    std::vector<char> output_;
    std::unique_ptr<char[]> file_output_;
    std::size_t file_output_size_ {0};
    std::string_view static_response_;
    unique_fd file_;
    std::size_t file_size_ {0};
    std::size_t input_size_ {0};
    std::size_t request_size_ {0};
    bool directory_listing_ {false};
    bool responding_ {false};
    bool close_after_response_ {false};
    bool closed_ {false};
};

} // namespace eventloop::http
