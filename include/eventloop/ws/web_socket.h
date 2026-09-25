#pragma once

#include "eventloop/byte_stream.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace ws {

enum class errc {
    protocol_error,
    invalid_utf8,
    message_too_large,
};

// Server-side WebSocket framing over an already-upgraded byte stream.
class web_socket {
public:
    explicit web_socket(byte_stream& stream,
                        std::size_t maximum_message_size = 1024 * 1024);
    virtual ~web_socket() = default;

    web_socket(const web_socket&) = delete;
    auto operator=(const web_socket&) -> web_socket& = delete;

    auto receive(std::span<const std::byte> data) -> void;
    auto write(std::u8string_view message) -> void;
    auto write_binary(std::span<const std::byte> message) -> void;
    auto ping(std::span<const std::byte> payload = {}) -> void;
    auto pong(std::span<const std::byte> payload = {}) -> void;
    auto close() -> void;
    auto close(std::uint16_t code, std::u8string_view reason = {}) -> void;
    // Forward the underlying stream's write-drained notification here.
    auto write_drained() -> void;

protected:
    virtual auto on_text(std::u8string_view message) -> void = 0;
    virtual auto on_binary(std::span<const std::byte>) -> void {}
    virtual auto on_ping(std::span<const std::byte>) -> void {}
    virtual auto on_pong(std::span<const std::byte>) -> void {}
    virtual auto on_close(std::optional<std::uint16_t>,
                          std::u8string_view) -> void {}
    virtual auto on_error(errc) -> void {}

private:
    enum class opcode : std::uint8_t {
        continuation = 0x00,
        text = 0x01,
        binary = 0x02,
        close = 0x08,
        ping = 0x09,
        pong = 0x0a,
    };

    auto process_frames() -> void;
    auto handle_frame(opcode type, bool final,
                      std::span<const std::byte> payload) -> bool;
    auto handle_data(opcode type, bool final,
                     std::span<const std::byte> payload) -> bool;
    auto handle_close(std::span<const std::byte> payload) -> bool;
    auto send_frame(opcode type, std::span<const std::byte> payload) -> void;
    auto pump_output() -> void;
    auto fail(errc error, std::uint16_t close_code) -> void;
    auto retire_after_exception() noexcept -> void;

    byte_stream& stream_;
    std::size_t maximum_message_size_;
    std::vector<std::byte> input_;
    std::vector<std::byte> fragmented_message_;
    std::optional<opcode> fragmented_type_;
    std::vector<std::byte> output_;
    std::size_t output_offset_ {0};
    bool processing_ {false};
    bool pumping_output_ {false};
    bool awaiting_write_ {false};
    bool close_sent_ {false};
    bool close_received_ {false};
    bool close_after_write_ {false};
    bool failed_ {false};
};

} // namespace ws
