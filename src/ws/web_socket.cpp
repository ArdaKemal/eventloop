#include "eventloop/ws/web_socket.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

namespace eventloop::ws {
namespace {

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

} // namespace

class websocket_category final : public std::error_category {
public:
    [[nodiscard]] auto name() const noexcept -> const char* override { return "websocket"; }
    [[nodiscard]] auto message(int value) const -> std::string override
    {
        switch (static_cast<errc>(value)) {
        case errc::protocol_error: return "WebSocket protocol error";
        case errc::invalid_utf8: return "invalid WebSocket UTF-8";
        case errc::message_too_large: return "WebSocket message too large";
        case errc::output_full: return "WebSocket output full";
        case errc::closed: return "WebSocket closed";
        case errc::concurrent_operation: return "concurrent WebSocket operation";
        }
        return "unknown WebSocket error";
    }
};

auto error_category() noexcept -> const std::error_category&
{
    static const websocket_category category;
    return category;
}

auto make_error_code(errc error) noexcept -> std::error_code
{
    return {static_cast<int>(error), error_category()};
}

namespace detail {

web_socket_core::web_socket_core(std::size_t maximum_message_size)
    : maximum_message_size_(maximum_message_size),
      maximum_pending_output_(maximum_message_size)
{
    constexpr std::size_t frame_and_control_overhead = 137;
    if (maximum_message_size == 0 ||
        maximum_message_size > std::numeric_limits<std::size_t>::max() -
                                   frame_and_control_overhead) {
        throw std::invalid_argument("WebSocket maximum message size is invalid");
    }
    maximum_pending_output_ += frame_and_control_overhead;
}

auto web_socket_core::prepare_next_receive() -> void
{
    if (pending_consumed_) {
        input_.erase(input_.begin(), input_.begin() +
                    static_cast<std::ptrdiff_t>(pending_consumed_));
        pending_consumed_ = 0;
        if (input_.empty()) {
            clear_buffer(input_);
        } else if (input_.capacity() > retained_buffer_size &&
                   input_.size() <= retained_buffer_size) {
            try {
                std::vector<std::byte> remaining(input_.begin(), input_.end());
                input_.swap(remaining);
            } catch (const std::bad_alloc&) {
                // Keep the valid pipelined bytes when compaction cannot allocate.
            }
        }
    }
    if (clear_fragment_on_next_receive_) {
        clear_buffer(fragmented_message_);
        clear_fragment_on_next_receive_ = false;
    }
}

auto web_socket_core::append_input(std::span<const std::byte> data) -> void
{
    input_.insert(input_.end(), data.begin(), data.end());
}

auto web_socket_core::parse_next() -> std::optional<message_view>
{
    std::size_t consumed = 0;
    while (!error_ && !close_received_) {
        const auto remaining = input_.size() - consumed;
        if (remaining < 2) break;
        const auto first = value(input_[consumed]);
        const auto second = value(input_[consumed + 1]);
        const bool final = (first & 0x80u) != 0;
        const bool masked = (second & 0x80u) != 0;
        const auto type_value = static_cast<std::uint8_t>(first & 0x0fu);
        const bool control = (type_value & 0x08u) != 0;
        if ((first & 0x70u) != 0 || !masked ||
            (type_value >= 0x03u && type_value <= 0x07u) ||
            type_value >= 0x0bu || (control && !final)) {
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
            if (payload_size < 126) { fail(errc::protocol_error, 1002); break; }
        } else if (payload_size == 127) {
            if (remaining < 10) break;
            payload_size = 0;
            for (std::size_t index = 0; index < 8; ++index)
                payload_size = (payload_size << 8) | value(input_[consumed + 2 + index]);
            header_size = 10;
            if (payload_size <= 0xffff ||
                (payload_size & (std::uint64_t {1} << 63)) != 0) {
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
        for (std::size_t index = 0; index < size; ++index)
            input_[payload_offset + index] ^= input_[key_offset + index % masking_key_size];
        const auto payload = std::span<const std::byte> {input_}.subspan(payload_offset, size);
        std::optional<message_view> event;
        switch (static_cast<opcode>(type_value)) {
        case opcode::continuation:
        case opcode::text:
        case opcode::binary:
            event = handle_data(static_cast<opcode>(type_value), final, payload);
            break;
        case opcode::ping:
            if (!enqueue(opcode::pong, payload)) fail(errc::output_full, 1002);
            else event = message_view {message_type::ping, payload, {}};
            break;
        case opcode::pong:
            event = message_view {message_type::pong, payload, {}};
            break;
        case opcode::close:
            event = handle_close(payload);
            break;
        }
        consumed += static_cast<std::size_t>(frame_size);
        if (event) {
            pending_consumed_ = consumed;
            return event;
        }
    }
    if (error_ || close_received_) {
        clear_buffer(input_);
    } else if (consumed) {
        input_.erase(input_.begin(), input_.begin() +
                     static_cast<std::ptrdiff_t>(consumed));
    }
    return {};
}

auto web_socket_core::handle_data(opcode type, bool final,
                                  std::span<const std::byte> payload)
    -> std::optional<message_view>
{
    if (type == opcode::continuation) {
        if (!fragmented_type_) { fail(errc::protocol_error, 1002); return {}; }
        if (payload.size() > maximum_message_size_ - fragmented_message_.size()) {
            fail(errc::message_too_large, 1009);
            return {};
        }
        fragmented_message_.insert(fragmented_message_.end(), payload.begin(), payload.end());
        if (!final) return {};
        type = *fragmented_type_;
        fragmented_type_.reset();
        payload = fragmented_message_;
        clear_fragment_on_next_receive_ = true;
    } else {
        if (fragmented_type_) { fail(errc::protocol_error, 1002); return {}; }
        if (!final) {
            fragmented_type_ = type;
            fragmented_message_.assign(payload.begin(), payload.end());
            return {};
        }
    }
    if (type == opcode::text && !valid_utf8(payload)) {
        fail(errc::invalid_utf8, 1007);
        return {};
    }
    return message_view {type == opcode::text ? message_type::text
                                              : message_type::binary,
                         payload, {}};
}

auto web_socket_core::handle_close(std::span<const std::byte> payload)
    -> std::optional<message_view>
{
    if (payload.size() == 1) { fail(errc::protocol_error, 1002); return {}; }
    std::optional<std::uint16_t> code;
    if (payload.size() >= 2) {
        code = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(value(payload[0])) << 8) | value(payload[1]));
        if (!valid_close_code(*code)) { fail(errc::protocol_error, 1002); return {}; }
        if (!valid_utf8(payload.subspan(2))) {
            fail(errc::invalid_utf8, 1007);
            return {};
        }
    }
    close_received_ = true;
    if (!close_sent_) {
        if (!enqueue(opcode::close, payload)) {
            fail(errc::output_full, 1002);
            return {};
        }
        close_sent_ = true;
    }
    close_after_write_ = true;
    return message_view {message_type::close, payload, code};
}

auto web_socket_core::enqueue(opcode type, std::span<const std::byte> payload)
    -> bool
{
    if (output_offset_) {
        const auto remaining = output_.size() - output_offset_;
        std::memmove(output_.data(), output_.data() + output_offset_, remaining);
        output_.resize(remaining);
        output_offset_ = 0;
    }
    const auto size = static_cast<std::uint64_t>(payload.size());
    const std::size_t header_size = size <= 125 ? 2 : size <= 0xffff ? 4 : 10;
    const auto frame_offset = output_.size();
    if (payload.size() > maximum_pending_output_ - header_size ||
        frame_offset > maximum_pending_output_ - header_size - payload.size())
        return false;
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
        for (std::size_t index = 0; index < 8; ++index)
            frame[2 + index] = static_cast<std::byte>((size >> ((7 - index) * 8)) & 0xff);
    }
    std::copy(payload.begin(), payload.end(), frame + header_size);
    return true;
}

auto web_socket_core::output_pending() const noexcept -> bool
{
    return output_offset_ < output_.size();
}

auto web_socket_core::output_chunk() noexcept -> std::span<const std::byte>
{
    const auto size = std::min(output_chunk_.size(), output_.size() - output_offset_);
    std::memcpy(output_chunk_.data(), output_.data() + output_offset_, size);
    return std::span {output_chunk_}.first(size);
}

auto web_socket_core::consume_output(std::size_t size) -> void
{
    output_offset_ += size;
    if (output_offset_ == output_.size()) {
        clear_buffer(output_);
        output_offset_ = 0;
    }
}

auto web_socket_core::fail(errc error, std::uint16_t close_code) -> void
{
    if (error_) return;
    error_ = make_error_code(error);
    fragmented_type_.reset();
    clear_buffer(fragmented_message_);
    if (!close_sent_) {
        const std::array<std::byte, 2> payload {
            static_cast<std::byte>(close_code >> 8),
            static_cast<std::byte>(close_code & 0xff),
        };
        if (!enqueue(opcode::close, payload)) {
            retire();
            return;
        }
        close_sent_ = true;
    }
    close_after_write_ = true;
}

auto web_socket_core::retire() noexcept -> void
{
    if (!error_) error_ = make_error_code(errc::closed);
    close_sent_ = true;
    close_after_write_ = false;
    fragmented_type_.reset();
    clear_buffer(input_);
    clear_buffer(fragmented_message_);
    clear_buffer(output_);
    output_offset_ = 0;
    pending_consumed_ = 0;
}

auto web_socket_core::validate_text(std::u8string_view text) const noexcept -> bool
{
    return valid_utf8(as_bytes(text));
}

auto web_socket_core::validate_close(std::uint16_t code,
                                     std::u8string_view reason) const noexcept -> bool
{
    return valid_close_code(code) && reason.size() <= 123 &&
           valid_utf8(as_bytes(reason));
}

} // namespace detail

} // namespace eventloop::ws
