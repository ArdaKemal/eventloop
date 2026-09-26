#include "eventloop/ws/web_socket.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace ws {
namespace {

constexpr std::size_t write_size = 16 * 1024;
constexpr std::size_t retained_buffer_size = 64 * 1024;

auto clear_buffer(std::vector<std::byte>& buffer) -> void
{
    buffer.clear();
    if (buffer.capacity() > retained_buffer_size) {
        std::vector<std::byte> {}.swap(buffer);
    }
}

[[nodiscard]] auto value(std::byte byte) noexcept -> std::uint8_t
{
    return std::to_integer<std::uint8_t>(byte);
}

[[nodiscard]] auto valid_utf8(std::span<const std::byte> input) noexcept -> bool
{
    std::size_t index = 0;
    while (index < input.size()) {
        const auto first = value(input[index++]);
        if (first <= 0x7f) continue;

        if (first >= 0xc2 && first <= 0xdf) {
            if (index == input.size()) return false;
            const auto second = value(input[index++]);
            if (second < 0x80 || second > 0xbf) return false;
            continue;
        }

        if (first >= 0xe0 && first <= 0xef) {
            if (input.size() - index < 2) return false;
            const auto second = value(input[index++]);
            const auto third = value(input[index++]);
            const bool valid_second = first == 0xe0 ? second >= 0xa0 && second <= 0xbf
                : first == 0xed ? second >= 0x80 && second <= 0x9f
                                : second >= 0x80 && second <= 0xbf;
            if (!valid_second || third < 0x80 || third > 0xbf) return false;
            continue;
        }

        if (first >= 0xf0 && first <= 0xf4) {
            if (input.size() - index < 3) return false;
            const auto second = value(input[index++]);
            const auto third = value(input[index++]);
            const auto fourth = value(input[index++]);
            const bool valid_second = first == 0xf0 ? second >= 0x90 && second <= 0xbf
                : first == 0xf4 ? second >= 0x80 && second <= 0x8f
                                : second >= 0x80 && second <= 0xbf;
            if (!valid_second || third < 0x80 || third > 0xbf ||
                fourth < 0x80 || fourth > 0xbf) return false;
            continue;
        }

        return false;
    }
    return true;
}

[[nodiscard]] auto valid_close_code(std::uint16_t code) noexcept -> bool
{
    return code >= 1000 && code < 5000 && code != 1004 && code != 1005 &&
           code != 1006 && code != 1015;
}

[[nodiscard]] auto as_bytes(std::u8string_view input) noexcept
    -> std::span<const std::byte>
{
    return {reinterpret_cast<const std::byte*>(input.data()), input.size()};
}

[[nodiscard]] auto as_utf8(std::span<const std::byte> input) noexcept
    -> std::u8string_view
{
    return {reinterpret_cast<const char8_t*>(input.data()), input.size()};
}

} // namespace

web_socket::web_socket(byte_stream& stream, std::size_t maximum_message_size)
    : stream_(stream), maximum_message_size_(maximum_message_size),
      maximum_pending_output_(maximum_message_size)
{
    constexpr std::size_t frame_and_control_overhead = 137;
    if (maximum_message_size_ == 0 ||
        maximum_message_size_ >
            std::numeric_limits<std::size_t>::max() - frame_and_control_overhead) {
        throw std::invalid_argument("WebSocket maximum message size is invalid");
    }
    maximum_pending_output_ += frame_and_control_overhead;
}

auto web_socket::receive(std::span<const std::byte> data) -> void
{
    if (failed_ || close_received_ || data.empty()) return;
    if (processing_) {
        throw std::logic_error("reentrant WebSocket receive");
    }
    constexpr std::size_t input_chunk_size = 4096;
    while (!data.empty() && !failed_ && !close_received_) {
        const auto chunk = data.first(std::min(data.size(), input_chunk_size));
        input_.insert(input_.end(), chunk.begin(), chunk.end());
        process_frames();
        data = data.subspan(chunk.size());
    }
}

auto web_socket::write(std::u8string_view message) -> void
{
    if (!valid_utf8(as_bytes(message))) {
        throw std::invalid_argument("WebSocket text message is not valid UTF-8");
    }
    if (message.size() > maximum_message_size_) {
        throw std::length_error("WebSocket message is too large");
    }
    send_frame(opcode::text, as_bytes(message));
}

auto web_socket::write_binary(std::span<const std::byte> message) -> void
{
    if (message.size() > maximum_message_size_) {
        throw std::length_error("WebSocket message is too large");
    }
    send_frame(opcode::binary, message);
}

auto web_socket::ping(std::span<const std::byte> payload) -> void
{
    if (payload.size() > 125) {
        throw std::length_error("WebSocket control frame payload is too large");
    }
    send_frame(opcode::ping, payload);
}

auto web_socket::pong(std::span<const std::byte> payload) -> void
{
    if (payload.size() > 125) {
        throw std::length_error("WebSocket control frame payload is too large");
    }
    send_frame(opcode::pong, payload);
}

auto web_socket::close() -> void
{
    if (close_sent_) return;
    try {
        send_frame(opcode::close, {});
    } catch (const std::length_error&) {
        retire_after_exception();
        return;
    }
    close_sent_ = true;
}

auto web_socket::close(std::uint16_t code, std::u8string_view reason) -> void
{
    if (close_sent_) return;
    if (!valid_close_code(code)) {
        throw std::invalid_argument("invalid WebSocket close code");
    }
    if (reason.size() > 123) {
        throw std::length_error("WebSocket close reason is too large");
    }
    if (!valid_utf8(as_bytes(reason))) {
        throw std::invalid_argument("WebSocket close reason is not valid UTF-8");
    }

    std::array<std::byte, 125> payload {};
    payload[0] = static_cast<std::byte>(code >> 8);
    payload[1] = static_cast<std::byte>(code & 0xff);
    if (!reason.empty()) {
        std::memcpy(payload.data() + 2, reason.data(), reason.size());
    }
    try {
        send_frame(opcode::close,
                   std::span {payload}.first(2 + reason.size()));
    } catch (const std::length_error&) {
        retire_after_exception();
        return;
    }
    close_sent_ = true;
}

auto web_socket::write_drained() -> void
{
    awaiting_write_ = false;
    pump_output();
}

auto web_socket::process_frames() -> void try
{
    processing_ = true;
    std::size_t consumed = 0;

    while (!failed_ && !close_received_) {
        const auto remaining = input_.size() - consumed;
        if (remaining < 2) break;

        const auto first = value(input_[consumed]);
        const auto second = value(input_[consumed + 1]);
        const bool final = (first & 0x80u) != 0;
        const bool masked = (second & 0x80u) != 0;
        const auto type_value = static_cast<std::uint8_t>(first & 0x0fu);
        const bool control = (type_value & 0x08u) != 0;

        if ((first & 0x70u) != 0 || !masked ||
            (type_value >= 0x03u && type_value <= 0x07u) || type_value >= 0x0bu ||
            (control && !final)) {
            fail(errc::protocol_error, 1002);
            break;
        }

        std::uint64_t payload_size = second & 0x7fu;
        std::size_t header_size = 2;
        if (payload_size == 126) {
            if (remaining < 4) break;
            payload_size = (static_cast<std::uint64_t>(value(input_[consumed + 2])) << 8) |
                           value(input_[consumed + 3]);
            header_size = 4;
            if (payload_size < 126) {
                fail(errc::protocol_error, 1002);
                break;
            }
        } else if (payload_size == 127) {
            if (remaining < 10) break;
            payload_size = 0;
            for (std::size_t index = 0; index < 8; ++index) {
                payload_size = (payload_size << 8) |
                               value(input_[consumed + 2 + index]);
            }
            header_size = 10;
            if (payload_size <= 0xffff || (payload_size & (std::uint64_t {1} << 63)) != 0) {
                fail(errc::protocol_error, 1002);
                break;
            }
        }

        if ((control && payload_size > 125) ||
            payload_size > std::numeric_limits<std::size_t>::max()) {
            fail(errc::protocol_error, 1002);
            break;
        }
        if (!control && payload_size > maximum_message_size_) {
            fail(errc::message_too_large, 1009);
            break;
        }

        constexpr std::size_t masking_key_size = 4;
        const auto frame_size = static_cast<std::uint64_t>(header_size) +
                                masking_key_size + payload_size;
        if (frame_size > remaining) break;

        const auto size = static_cast<std::size_t>(payload_size);
        const auto key_offset = consumed + header_size;
        const auto payload_offset = key_offset + masking_key_size;
        for (std::size_t index = 0; index < size; ++index) {
            input_[payload_offset + index] ^= input_[key_offset + index % masking_key_size];
        }

        const auto payload = std::span<const std::byte> {input_}.subspan(payload_offset, size);
        if (!handle_frame(static_cast<opcode>(type_value), final, payload)) break;
        consumed += static_cast<std::size_t>(frame_size);
    }

    if (failed_ || close_received_ || consumed == input_.size()) {
        clear_buffer(input_);
    } else if (consumed != 0) {
        input_.erase(input_.begin(), input_.begin() + static_cast<std::ptrdiff_t>(consumed));
    }
    processing_ = false;
}
catch (...) {
    retire_after_exception();
    throw;
}

auto web_socket::handle_frame(opcode type, bool final,
                              std::span<const std::byte> payload) -> bool
{
    switch (type) {
    case opcode::continuation:
    case opcode::text:
    case opcode::binary:
        return handle_data(type, final, payload);
    case opcode::ping:
        pong(payload);
        on_ping(payload);
        return true;
    case opcode::pong:
        on_pong(payload);
        return true;
    case opcode::close:
        return handle_close(payload);
    }
    fail(errc::protocol_error, 1002);
    return false;
}

auto web_socket::handle_data(opcode type, bool final,
                             std::span<const std::byte> payload) -> bool
{
    if (type == opcode::continuation) {
        if (!fragmented_type_) {
            fail(errc::protocol_error, 1002);
            return false;
        }
        if (payload.size() > maximum_message_size_ - fragmented_message_.size()) {
            fail(errc::message_too_large, 1009);
            return false;
        }
        fragmented_message_.insert(fragmented_message_.end(), payload.begin(), payload.end());
        if (!final) return true;

        type = *fragmented_type_;
        fragmented_type_.reset();
        payload = fragmented_message_;
    } else {
        if (fragmented_type_) {
            fail(errc::protocol_error, 1002);
            return false;
        }
        if (!final) {
            fragmented_type_ = type;
            fragmented_message_.assign(payload.begin(), payload.end());
            return true;
        }
    }

    if (type == opcode::text) {
        if (!valid_utf8(payload)) {
            fail(errc::invalid_utf8, 1007);
            return false;
        }
        on_text(as_utf8(payload));
    } else {
        on_binary(payload);
    }
    if (final) clear_buffer(fragmented_message_);
    return true;
}

auto web_socket::handle_close(std::span<const std::byte> payload) -> bool
{
    if (payload.size() == 1) {
        fail(errc::protocol_error, 1002);
        return false;
    }

    std::optional<std::uint16_t> code;
    std::u8string_view reason;
    if (payload.size() >= 2) {
        code = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(value(payload[0])) << 8) | value(payload[1]));
        const auto reason_bytes = payload.subspan(2);
        if (!valid_close_code(*code)) {
            fail(errc::protocol_error, 1002);
            return false;
        }
        if (!valid_utf8(reason_bytes)) {
            fail(errc::invalid_utf8, 1007);
            return false;
        }
        reason = as_utf8(reason_bytes);
    }

    close_received_ = true;
    on_close(code, reason);
    if (!close_sent_) {
        send_frame(opcode::close, payload);
        close_sent_ = true;
    }
    close_after_write_ = true;
    pump_output();
    return false;
}

auto web_socket::send_frame(opcode type, std::span<const std::byte> payload) -> void
{
    if (failed_ && type != opcode::close) {
        throw std::logic_error("cannot write after a WebSocket failure");
    }
    if (close_sent_ && type != opcode::close) {
        throw std::logic_error("cannot write after sending a WebSocket close frame");
    }

    if (output_offset_ != 0) {
        const auto remaining = output_.size() - output_offset_;
        std::memmove(output_.data(), output_.data() + output_offset_, remaining);
        output_.resize(remaining);
        output_offset_ = 0;
    }

    const auto size = static_cast<std::uint64_t>(payload.size());
    const std::size_t header_size = size <= 125 ? 2 : size <= 0xffff ? 4 : 10;
    const auto frame_offset = output_.size();
    if (payload.size() > maximum_pending_output_ - header_size ||
        frame_offset > maximum_pending_output_ - header_size - payload.size()) {
        throw std::length_error("WebSocket output buffer capacity exceeded");
    }
    output_.resize(frame_offset + header_size + payload.size());
    auto* frame = output_.data() + frame_offset;
    frame[0] = static_cast<std::byte>(0x80u | static_cast<std::uint8_t>(type));
    if (header_size == 2) {
        frame[1] = static_cast<std::byte>(size);
    } else if (header_size == 4) {
        frame[1] = static_cast<std::byte>(126);
        frame[2] = static_cast<std::byte>((size >> 8) & 0xff);
        frame[3] = static_cast<std::byte>(size & 0xff);
    } else {
        frame[1] = static_cast<std::byte>(127);
        for (std::size_t index = 0; index < 8; ++index) {
            frame[2 + index] = static_cast<std::byte>(
                (size >> ((7 - index) * 8)) & 0xff);
        }
    }
    std::copy(payload.begin(), payload.end(), frame + header_size);
    pump_output();
}

auto web_socket::pump_output() -> void try
{
    if (pumping_output_ || awaiting_write_) return;
    pumping_output_ = true;

    while (!awaiting_write_ && !output_.empty()) {
        if (output_offset_ == output_.size()) {
            clear_buffer(output_);
            output_offset_ = 0;
            continue;
        }

        const auto size = std::min(write_size, output_.size() - output_offset_);
        const auto chunk = std::span<const std::byte> {output_}.subspan(output_offset_, size);
        output_offset_ += size;
        awaiting_write_ = true;
        stream_.write(chunk);
        if (!stream_.write_pending()) awaiting_write_ = false;
    }
    pumping_output_ = false;
    if (!awaiting_write_ && output_.empty() && close_after_write_) stream_.close();
}
catch (...) {
    retire_after_exception();
    throw;
}

auto web_socket::fail(errc error, std::uint16_t close_code) -> void
{
    if (failed_) return;
    failed_ = true;
    fragmented_type_.reset();
    clear_buffer(fragmented_message_);
    on_error(error);

    if (!close_sent_) {
        std::array<std::byte, 2> payload {
            static_cast<std::byte>(close_code >> 8),
            static_cast<std::byte>(close_code & 0xff),
        };
        try {
            send_frame(opcode::close, payload);
        } catch (const std::length_error&) {
            retire_after_exception();
            return;
        }
        close_sent_ = true;
    }
    close_after_write_ = true;
    pump_output();
}

auto web_socket::retire_after_exception() noexcept -> void
{
    failed_ = true;
    close_sent_ = true;
    close_after_write_ = false;
    processing_ = false;
    pumping_output_ = false;
    awaiting_write_ = false;
    fragmented_type_.reset();
    clear_buffer(input_);
    clear_buffer(fragmented_message_);
    clear_buffer(output_);
    output_offset_ = 0;
    try {
        stream_.close();
    } catch (...) {
    }
}

} // namespace ws
