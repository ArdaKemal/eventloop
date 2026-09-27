#pragma once

#include "eventloop/task.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace ws {

enum class errc {
    protocol_error = 1,
    invalid_utf8,
    message_too_large,
    output_full,
    closed,
    concurrent_operation,
};

[[nodiscard]] auto error_category() noexcept -> const std::error_category&;
[[nodiscard]] auto make_error_code(errc error) noexcept -> std::error_code;

enum class message_type { text, binary, ping, pong, close };

struct message_view {
    message_type type;
    std::span<const std::byte> payload;
    std::optional<std::uint16_t> close_code;
};

// Framing and buffers are owned by this object. It does not own the transport.
// A returned payload view remains valid until the next async_receive call or
// destruction. Framing permits one receive and one send concurrently on the
// same loop when the underlying stream permits concurrent reads and writes.
// Send buffers remain caller-owned and valid until their tasks complete.
class web_socket_core {
public:
    explicit web_socket_core(std::size_t maximum_message_size = 1024 * 1024);
    web_socket_core(const web_socket_core&) = delete;
    auto operator=(const web_socket_core&) -> web_socket_core& = delete;

protected:
    enum class opcode : std::uint8_t {
        continuation = 0, text = 1, binary = 2, close = 8, ping = 9, pong = 10,
    };

    [[nodiscard]] auto parse_next() -> std::optional<message_view>;
    auto prepare_next_receive() -> void;
    auto append_input(std::span<const std::byte> data) -> void;
    [[nodiscard]] auto enqueue(opcode type, std::span<const std::byte> payload)
        -> bool;
    auto fail(errc error, std::uint16_t close_code) -> void;
    auto retire() noexcept -> void;
    [[nodiscard]] auto validate_text(std::u8string_view text) const noexcept -> bool;
    [[nodiscard]] auto validate_close(std::uint16_t code,
                                      std::u8string_view reason) const noexcept -> bool;
    [[nodiscard]] auto output_pending() const noexcept -> bool;
    [[nodiscard]] auto output_chunk() noexcept -> std::span<const std::byte>;
    auto consume_output(std::size_t size) -> void;
    [[nodiscard]] auto receive_buffer() noexcept -> std::span<std::byte>
    {
        return receive_buffer_;
    }
    [[nodiscard]] auto error() const noexcept -> std::error_code { return error_; }
    [[nodiscard]] auto close_received() const noexcept -> bool { return close_received_; }
    [[nodiscard]] auto close_sent() const noexcept -> bool { return close_sent_; }
    auto mark_close_sent() noexcept -> void { close_sent_ = true; }
    [[nodiscard]] auto ready_to_close() const noexcept -> bool
    {
        return close_after_write_ && !output_pending();
    }
    auto request_close_after_write() noexcept -> void { close_after_write_ = true; }
    [[nodiscard]] auto maximum_message_size() const noexcept -> std::size_t
    {
        return maximum_message_size_;
    }

private:
    [[nodiscard]] auto handle_data(opcode type, bool final,
                                   std::span<const std::byte> payload)
        -> std::optional<message_view>;
    [[nodiscard]] auto handle_close(std::span<const std::byte> payload)
        -> std::optional<message_view>;

    std::size_t maximum_message_size_;
    std::size_t maximum_pending_output_;
    std::array<std::byte, 4096> receive_buffer_ {};
    std::array<std::byte, 4096> output_chunk_ {};
    std::vector<std::byte> input_;
    std::vector<std::byte> fragmented_message_;
    std::optional<opcode> fragmented_type_;
    std::vector<std::byte> output_;
    std::size_t output_offset_ {0};
    std::size_t pending_consumed_ {0};
    bool clear_fragment_on_next_receive_ {false};
    bool close_sent_ {false};
    bool close_received_ {false};
    bool close_after_write_ {false};
    std::error_code error_ {};
};

template<typename Stream>
class web_socket final : private web_socket_core {
public:
    web_socket(event_loop& loop, Stream& stream,
               std::size_t maximum_message_size = 1024 * 1024)
        : web_socket_core(maximum_message_size), loop_(loop), stream_(stream) {}

    // The returned view is invalidated by the next receive or socket destruction.
    // The caller must keep this socket and its transport alive until tasks finish.
    [[nodiscard]] auto async_receive()
        -> task<std::expected<message_view, std::error_code>>
    {
        return receive_task(loop_, *this);
    }
    [[nodiscard]] auto async_send_text(std::u8string_view message)
        -> task<std::expected<void, std::error_code>>
    {
        return send_task(loop_, *this, opcode::text,
                         {reinterpret_cast<const std::byte*>(message.data()),
                          message.size()});
    }
    [[nodiscard]] auto async_send_binary(std::span<const std::byte> message)
        -> task<std::expected<void, std::error_code>>
    {
        return send_task(loop_, *this, opcode::binary, message);
    }
    // Sends and drains the close frame. The transport stays open until a peer
    // close frame arrives; receiving that frame drains its echo, then closes.
    [[nodiscard]] auto async_close(std::optional<std::uint16_t> code = {},
                                   std::u8string_view reason = {})
        -> task<std::expected<void, std::error_code>>
    {
        return close_task(loop_, *this, code, reason);
    }

private:
    using result = std::expected<void, std::error_code>;
    using io_result = std::expected<std::size_t, std::error_code>;

    struct operation_guard {
        explicit operation_guard(bool& active) noexcept : active(active) { active = true; }
        ~operation_guard() { active = false; }
        operation_guard(const operation_guard&) = delete;
        auto operator=(const operation_guard&) -> operation_guard& = delete;
        bool& active;
    };

    [[nodiscard]] static auto normalize_io(io_result result) -> io_result
    {
        return result;
    }
    [[nodiscard]] static auto normalize_io(
        std::expected<io_result, task_result> result) -> io_result
    {
        if (result) return std::move(*result);
        return std::unexpected(std::make_error_code(
            result.error() == task_result::frame_allocation_failure
                ? std::errc::not_enough_memory : std::errc::operation_canceled));
    }

    [[nodiscard]] static auto normalize_close(
        std::expected<result, task_result> close) -> result
    {
        if (close) return std::move(*close);
        return std::unexpected(std::make_error_code(
            close.error() == task_result::frame_allocation_failure
                ? std::errc::not_enough_memory : std::errc::operation_canceled));
    }

    static auto flush_task(event_loop& loop, web_socket& self) -> task<result>
    {
        (void)loop;
        if (self.flushing_) co_return std::unexpected(make_error_code(errc::concurrent_operation));
        operation_guard flushing(self.flushing_);
        while (self.output_pending()) {
            const auto bytes = self.output_chunk();
            const auto written = normalize_io(co_await self.stream_.async_write_some(bytes));
            if (!written || *written == 0) {
                const auto error = written ? std::make_error_code(std::errc::broken_pipe)
                                           : written.error();
                self.retire_transport();
                co_return std::unexpected(error);
            }
            self.consume_output(*written);
        }
        if (self.ready_to_close()) {
            if constexpr (requires(Stream& stream) { stream.async_close(); }) {
                auto closed = normalize_close(co_await self.stream_.async_close());
                if (!closed) {
                    self.retire_transport();
                    co_return std::unexpected(closed.error());
                }
            } else {
                self.close_transport();
            }
        }
        co_return result {};
    }

    static auto receive_task(event_loop& loop, web_socket& self)
        -> task<std::expected<message_view, std::error_code>>
    {
        if (self.reading_) co_return std::unexpected(make_error_code(errc::concurrent_operation));
        operation_guard reading(self.reading_);
        self.prepare_next_receive();
        for (;;) {
            std::optional<message_view> message;
            try {
                message = self.parse_next();
            } catch (...) {
                self.retire_transport();
                co_return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
            }
            if ((self.output_pending() || self.ready_to_close()) && !self.flushing_) {
                auto flushed = co_await flush_task(loop, self);
                if (!flushed) {
                    self.retire_transport();
                    co_return std::unexpected(make_error_code(errc::closed));
                }
                if (!*flushed) co_return std::unexpected(flushed->error());
            }
            if (self.error()) {
                if (!self.output_pending()) self.close_transport();
                co_return std::unexpected(self.error());
            }
            if (message) {
                co_return *message;
            }
            if (self.close_received()) {
                co_return std::unexpected(make_error_code(errc::closed));
            }
            const auto read = normalize_io(co_await self.stream_.async_read_some(self.receive_buffer()));
            if (!read || *read == 0) {
                const auto error = read ? make_error_code(errc::closed) : read.error();
                self.retire_transport();
                co_return std::unexpected(error);
            }
            try {
                self.append_input(self.receive_buffer().first(*read));
            } catch (...) {
                self.retire_transport();
                co_return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
            }
        }
    }

    static auto send_task(event_loop& loop, web_socket& self, opcode type,
                          std::span<const std::byte> message) -> task<result>
    {
        if (self.sending_ || self.flushing_) co_return std::unexpected(make_error_code(errc::concurrent_operation));
        operation_guard sending(self.sending_);
        if (self.close_sent() || self.error()) {
            co_return std::unexpected(make_error_code(errc::closed));
        }
        if (message.size() > self.maximum_message_size()) {
            co_return std::unexpected(make_error_code(errc::message_too_large));
        }
        if (type == opcode::text &&
            !self.validate_text({reinterpret_cast<const char8_t*>(message.data()), message.size()})) {
            co_return std::unexpected(make_error_code(errc::invalid_utf8));
        }
        try {
            if (!self.enqueue(type, message)) {
                co_return std::unexpected(make_error_code(errc::output_full));
            }
        } catch (...) {
            self.retire_transport();
            co_return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
        }
        auto flushed = co_await flush_task(loop, self);
        if (!flushed) {
            self.retire_transport();
            co_return std::unexpected(make_error_code(errc::closed));
        }
        co_return std::move(*flushed);
    }

    static auto close_task(event_loop& loop, web_socket& self,
                           std::optional<std::uint16_t> code,
                           std::u8string_view reason) -> task<result>
    {
        if (self.sending_ || self.flushing_) co_return std::unexpected(make_error_code(errc::concurrent_operation));
        operation_guard sending(self.sending_);
        if (self.error()) co_return std::unexpected(make_error_code(errc::closed));
        if (self.close_sent()) co_return result {};
        if (code && !self.validate_close(*code, reason))
            co_return std::unexpected(make_error_code(errc::protocol_error));
        if (!code && !reason.empty())
            co_return std::unexpected(make_error_code(errc::protocol_error));
        std::array<std::byte, 125> payload {};
        std::size_t size = 0;
        if (code) {
            payload[0] = static_cast<std::byte>(*code >> 8);
            payload[1] = static_cast<std::byte>(*code & 0xff);
            size = 2 + reason.size();
            if (!reason.empty())
                std::memcpy(payload.data() + 2, reason.data(), reason.size());
        }
        try {
            if (!self.enqueue(opcode::close, std::span {payload}.first(size))) {
                self.retire_transport();
                co_return std::unexpected(make_error_code(errc::output_full));
            }
        } catch (...) {
            self.retire_transport();
            co_return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
        }
        self.mark_close_sent();
        auto flushed = co_await flush_task(loop, self);
        if (!flushed) {
            self.retire_transport();
            co_return std::unexpected(make_error_code(errc::closed));
        }
        co_return std::move(*flushed);
    }

    auto retire_transport() noexcept -> void
    {
        retire();
        close_transport();
    }

    auto close_transport() noexcept -> void
    {
        try { stream_.close(); } catch (...) {}
    }

    event_loop& loop_;
    Stream& stream_;
    bool reading_ {false};
    bool sending_ {false};
    bool flushing_ {false};
};

template<typename Stream>
web_socket(event_loop&, Stream&, std::size_t = 1024 * 1024) -> web_socket<Stream>;

} // namespace ws

template<>
struct std::is_error_code_enum<ws::errc> : std::true_type {};
