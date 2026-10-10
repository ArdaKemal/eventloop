#pragma once

#include "exchange.h"
#include "open_file_cache.h"
#include "parser.h"
#include "eventloop/native_socket.h"
#include "eventloop/unique_fd.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace eventloop::http::detail {

struct file_info;

// Per-connection routing storage, owned by the connection. The parsed head
// views the session input until finish_routed().
struct route_state {
    const router* routes {nullptr};
    std::uint64_t max_request_body {0};
    // Set while the server drains: responses close the connection.
    const bool* draining {nullptr};
    parsed_request request;
    route_match match;
    std::size_t head_size {0};
    std::size_t buffered_consumed {0};
    std::array<char, 192> reply {};
};

// The HTTP/1.1 protocol state for one connection. Static responses are
// produced synchronously. A request that matches a route handler is held
// until the connection task calls finish_routed().
class session {
public:
    session(native_socket root_descriptor, bool directory_listing = false,
            route_state* routing = nullptr, bool static_files = true,
            open_file_cache* files = nullptr) noexcept;
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
    [[nodiscard]] auto file_offset() const noexcept -> std::uint64_t { return file_offset_; }
    [[nodiscard]] auto take_file() noexcept -> unique_fd { return std::move(file_); }
    [[nodiscard]] auto closed() const noexcept -> bool { return closed_; }
    auto finish_response() -> void;

    // A routed request head is parsed and waiting for its handler.
    [[nodiscard]] auto routed() const noexcept -> bool { return routed_; }
    // Body bytes of the routed request already in the input buffer; for a
    // chunked request, all input after the head, including framing.
    [[nodiscard]] auto buffered_body() noexcept -> std::span<const std::byte>;
    auto consume_buffered_body(std::size_t size) noexcept -> void;
    // Releases the routed request. Without keep_alive the session closes.
    auto finish_routed(bool keep_alive) -> void;

private:
    auto process_requests() -> void;
    [[nodiscard]] auto dispatch_route(std::size_t head_size) -> bool;
    auto handle_request(const parsed_request& parsed) -> void;
    auto serve_resource(const parsed_request& parsed, bool headers_only) -> void;
    auto serve_file(const parsed_request& parsed, static_file descriptor, const file_info& info,
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
    open_file_cache* files_ {nullptr};
    route_state* routing_ {nullptr};
    std::array<char, 256> input_ {};
    std::unique_ptr<char[]> expanded_input_;
    std::vector<char> output_;
    std::unique_ptr<char[]> file_output_;
    std::size_t file_output_size_ {0};
    std::string_view static_response_;
    unique_fd file_;
    std::size_t file_size_ {0};
    std::uint64_t file_offset_ {0};
    std::size_t input_size_ {0};
    std::size_t request_size_ {0};
    bool directory_listing_ {false};
    bool static_files_ {true};
    bool routed_ {false};
    bool responding_ {false};
    bool close_after_response_ {false};
    bool closed_ {false};
};

} // namespace eventloop::http::detail
