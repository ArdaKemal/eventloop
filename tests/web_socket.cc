#include "eventloop/ws/web_socket.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace eventloop;

namespace {

class memory_stream {
public:
    struct io_awaiter {
        std::expected<std::size_t, std::error_code> result;
        memory_stream* owner {nullptr};
        [[nodiscard]] auto await_ready() const noexcept -> bool
        {
            return owner == nullptr || !owner->block_write;
        }
        auto await_suspend(std::coroutine_handle<> handle) const noexcept -> void
        {
            owner->pending_write = handle;
        }
        [[nodiscard]] auto await_resume() const noexcept
            -> std::expected<std::size_t, std::error_code> { return result; }
    };

    [[nodiscard]] auto async_read_some(std::span<std::byte> buffer) -> io_awaiter
    {
        if (read_offset == input.size()) return {{0}};
        const auto size = std::min({buffer.size(), input.size() - read_offset,
                                    max_read_chunk});
        std::memcpy(buffer.data(), input.data() + read_offset, size);
        read_offset += size;
        return {{size}, nullptr};
    }

    [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer)
        -> io_awaiter
    {
        if (fail_write)
            return {{std::unexpected(std::make_error_code(std::errc::broken_pipe))}};
        const auto size = std::min(buffer.size(), max_write_chunk);
        if (block_write && defer_write_copy) {
            // Like a socket retrying after EAGAIN, read the bytes on completion.
            deferred_write = buffer.first(size);
            return {{size}, this};
        }
        output.insert(output.end(), buffer.begin(), buffer.begin() +
                                             static_cast<std::ptrdiff_t>(size));
        return {{size}, this};
    }

    auto close() noexcept -> void { open = false; }
    auto release_write() -> void
    {
        block_write = false;
        output.insert(output.end(), deferred_write.begin(), deferred_write.end());
        deferred_write = {};
        auto handle = std::exchange(pending_write, {});
        if (handle) handle.resume();
    }
    auto append(std::span<const std::byte> data) -> void
    {
        input.insert(input.end(), data.begin(), data.end());
    }

    std::vector<std::byte> input;
    std::vector<std::byte> output;
    std::size_t read_offset {0};
    std::size_t max_read_chunk {4096};
    std::size_t max_write_chunk {4096};
    bool open {true};
    bool fail_write {false};
    bool block_write {false};
    bool defer_write_copy {false};
    std::span<const std::byte> deferred_write {};
    std::coroutine_handle<> pending_write {};
};

class tls_like_stream : public memory_stream {
public:
    explicit tls_like_stream(event_loop& loop) : loop_(loop) {}

    [[nodiscard]] auto async_close() -> task<std::expected<void, std::error_code>>
    {
        return close_task(loop_, *this);
    }

    bool graceful_closed {false};

private:
    static auto close_task(event_loop& loop, tls_like_stream& self)
        -> task<std::expected<void, std::error_code>>
    {
        (void)loop;
        self.graceful_closed = true;
        self.open = false;
        co_return std::expected<void, std::error_code> {};
    }

    event_loop& loop_;
};

[[nodiscard]] auto bytes(std::string_view input) -> std::vector<std::byte>
{
    const auto* begin = reinterpret_cast<const std::byte*>(input.data());
    return {begin, begin + input.size()};
}

[[nodiscard]] auto masked_frame(std::uint8_t opcode, bool final,
                                std::span<const std::byte> payload)
    -> std::vector<std::byte>
{
    constexpr std::array<std::byte, 4> key {
        std::byte {0x12}, std::byte {0x34}, std::byte {0x56}, std::byte {0x78},
    };
    const auto size = static_cast<std::uint64_t>(payload.size());
    const std::size_t header_size = size <= 125 ? 2 : size <= 0xffff ? 4 : 10;
    std::vector<std::byte> frame(header_size + key.size() + payload.size());
    frame[0] = static_cast<std::byte>((final ? 0x80u : 0u) | opcode);
    if (header_size == 2) {
        frame[1] = static_cast<std::byte>(0x80u | size);
    } else if (header_size == 4) {
        frame[1] = std::byte {0xfe};
        frame[2] = static_cast<std::byte>((size >> 8) & 0xff);
        frame[3] = static_cast<std::byte>(size & 0xff);
    } else {
        frame[1] = std::byte {0xff};
        for (std::size_t index = 0; index < 8; ++index)
            frame[2 + index] = static_cast<std::byte>((size >> ((7 - index) * 8)) & 0xff);
    }
    std::copy(key.begin(), key.end(), frame.begin() +
              static_cast<std::ptrdiff_t>(header_size));
    const auto payload_offset = header_size + key.size();
    for (std::size_t index = 0; index < payload.size(); ++index)
        frame[payload_offset + index] = payload[index] ^ key[index % key.size()];
    return frame;
}

[[nodiscard]] auto byte_at(const std::vector<std::byte>& input,
                           std::size_t index) -> std::uint8_t
{
    return std::to_integer<std::uint8_t>(input[index]);
}

template<typename T>
[[nodiscard]] auto complete(task<T>& operation) -> std::optional<T>
{
    if (operation.start() != task_state::completed) return {};
    auto result = operation.result();
    if (!result) return {};
    return std::move(*result);
}

auto receive_test() -> bool
{
    event_loop loop;
    memory_stream stream;
    stream.max_read_chunk = 2;
    auto first = masked_frame(0x1, true, bytes("hello"));
    auto second = masked_frame(0x2, true, bytes("binary"));
    stream.append(first);
    stream.append(second);
    ws::web_socket socket(loop, stream);
    auto read1 = socket.async_receive();
    const auto message1 = complete(read1);
    if (!message1 || !*message1 || (*message1)->type != ws::message_type::text ||
        !std::ranges::equal((*message1)->payload, bytes("hello"))) return false;
    auto read2 = socket.async_receive();
    const auto message2 = complete(read2);
    return message2 && *message2 &&
           (*message2)->type == ws::message_type::binary &&
           std::ranges::equal((*message2)->payload, bytes("binary"));
}

auto fragmentation_and_control_test() -> bool
{
    event_loop loop;
    memory_stream stream;
    const auto part1 = masked_frame(0x1, false, bytes("hel"));
    const auto ping = masked_frame(0x9, true, bytes("p"));
    const auto part2 = masked_frame(0x0, true, bytes("lo"));
    stream.append(part1);
    stream.append(ping);
    stream.append(part2);
    ws::web_socket socket(loop, stream);
    auto read1 = socket.async_receive();
    const auto first = complete(read1);
    if (!first || !*first || (*first)->type != ws::message_type::ping ||
        !std::ranges::equal((*first)->payload, bytes("p")) ||
        stream.output.size() != 3 || byte_at(stream.output, 0) != 0x8a) return false;
    auto read2 = socket.async_receive();
    const auto second = complete(read2);
    return second && *second && (*second)->type == ws::message_type::text &&
           std::ranges::equal((*second)->payload, bytes("hello"));
}

auto send_test() -> bool
{
    event_loop loop;
    memory_stream stream;
    stream.max_write_chunk = 7;
    ws::web_socket socket(loop, stream, 128 * 1024);
    const auto payload = bytes(std::string(70 * 1024, 'x'));
    auto send = socket.async_send_binary(payload);
    const auto result = complete(send);
    if (!result || !*result || stream.output.size() != payload.size() + 10 ||
        byte_at(stream.output, 0) != 0x82 || byte_at(stream.output, 1) != 127)
        return false;
    auto invalid = socket.async_send_text(std::u8string_view {
        reinterpret_cast<const char8_t*>("\xff"), 1});
    const auto invalid_result = complete(invalid);
    return invalid_result && !*invalid_result &&
           invalid_result->error() == ws::make_error_code(ws::errc::invalid_utf8);
}

auto close_test() -> bool
{
    event_loop loop;
    memory_stream stream;
    constexpr std::array<std::byte, 3> close_payload {
        std::byte {0x03}, std::byte {0xe8}, std::byte {'a'},
    };
    const auto close = masked_frame(0x8, true, close_payload);
    stream.append(close);
    ws::web_socket socket(loop, stream);
    auto receive = socket.async_receive();
    const auto message = complete(receive);
    return message && *message && (*message)->type == ws::message_type::close &&
           (*message)->close_code == 1000 &&
           std::ranges::equal((*message)->payload, close_payload) &&
           stream.output.size() == 5 && byte_at(stream.output, 0) == 0x88 &&
           !stream.open;
}

auto active_close_test() -> bool
{
    event_loop loop;
    memory_stream tcp;
    ws::web_socket tcp_socket(loop, tcp);
    auto tcp_close = tcp_socket.async_close(1000, u8"bye");
    const auto tcp_result = complete(tcp_close);
    if (!tcp_result || !*tcp_result || !tcp.open || tcp.output.size() != 7 ||
        byte_at(tcp.output, 0) != 0x88) return false;
    const auto peer_close = masked_frame(0x8, true, bytes(""));
    tcp.append(peer_close);
    auto tcp_receive = tcp_socket.async_receive();
    const auto tcp_message = complete(tcp_receive);
    if (!tcp_message || !*tcp_message ||
        (*tcp_message)->type != ws::message_type::close || tcp.open ||
        tcp.output.size() != 7) return false;

    tls_like_stream tls(loop);
    ws::web_socket tls_socket(loop, tls);
    auto tls_close = tls_socket.async_close();
    const auto tls_result = complete(tls_close);
    if (!tls_result || !*tls_result || tls.graceful_closed || !tls.open ||
        tls.output.size() != 2 || byte_at(tls.output, 0) != 0x88) return false;
    tls.append(peer_close);
    auto tls_receive = tls_socket.async_receive();
    const auto tls_message = complete(tls_receive);
    return tls_message && *tls_message &&
           (*tls_message)->type == ws::message_type::close &&
           tls.graceful_closed && !tls.open && tls.output.size() == 2;
}

auto passive_tls_close_test() -> bool
{
    event_loop loop;
    tls_like_stream tls(loop);
    constexpr std::array<std::byte, 2> payload {
        std::byte {0x03}, std::byte {0xe8},
    };
    tls.append(masked_frame(0x8, true, payload));
    ws::web_socket socket(loop, tls);
    auto receive = socket.async_receive();
    const auto message = complete(receive);
    return message && *message &&
           (*message)->type == ws::message_type::close &&
           (*message)->close_code == 1000 &&
           tls.graceful_closed && !tls.open && tls.output.size() == 4 &&
           byte_at(tls.output, 0) == 0x88;
}

auto protocol_failure_test() -> bool
{
    event_loop loop;
    memory_stream stream;
    stream.append(bytes(std::string_view {"\x81\x00", 2})); // Client frame lacks a mask.
    ws::web_socket socket(loop, stream);
    auto receive = socket.async_receive();
    const auto result = complete(receive);
    return result && !*result &&
           result->error() == ws::make_error_code(ws::errc::protocol_error) &&
           stream.output.size() == 4 && byte_at(stream.output, 0) == 0x88 &&
           !stream.open;
}

auto bounded_and_failure_test() -> bool
{
    event_loop loop;
    memory_stream stream;
    ws::web_socket socket(loop, stream, 8);
    auto large = socket.async_send_binary(bytes("123456789"));
    const auto large_result = complete(large);
    if (!large_result || *large_result ||
        large_result->error() != ws::make_error_code(ws::errc::message_too_large))
        return false;
    stream.fail_write = true;
    auto send = socket.async_send_text(u8"small");
    const auto result = complete(send);
    return result && !*result && !stream.open;
}

auto concurrent_writer_test() -> bool
{
    event_loop loop;
    memory_stream stream;
    stream.block_write = true;
    ws::web_socket socket(loop, stream);
    auto first = socket.async_send_text(u8"first");
    if (first.start() != task_state::suspended || !stream.pending_write)
        return false;
    auto second = socket.async_send_text(u8"second");
    const auto rejected = complete(second);
    if (!rejected || *rejected ||
        rejected->error() != ws::make_error_code(ws::errc::concurrent_operation))
        return false;
    stream.release_write();
    return first.state() == task_state::completed && first.result() &&
           stream.output.size() == 7;
}

// Frames queued while a write borrows the output must not move its bytes.
auto borrowed_write_test() -> bool
{
    event_loop loop;
    memory_stream stream;
    stream.block_write = true;
    stream.defer_write_copy = true;
    stream.max_write_chunk = 1024 * 1024;
    ws::web_socket socket(loop, stream, 128 * 1024);
    std::vector<std::byte> payload(70 * 1024);
    for (std::size_t index = 0; index < payload.size(); ++index)
        payload[index] = static_cast<std::byte>(index * 7);
    auto send = socket.async_send_binary(payload);
    if (send.start() != task_state::suspended || !stream.pending_write) return false;
    // The ping's pong grows the output while the first write borrows it.
    stream.append(masked_frame(0x9, true, bytes("ping")));
    auto receive = socket.async_receive();
    const auto message = complete(receive);
    stream.release_write();
    if (!message || !*message || (*message)->type != ws::message_type::ping) return false;
    if (send.state() != task_state::completed || !send.result()) return false;
    const auto& out = stream.output;
    if (out.size() != 10 + payload.size() + 6 || byte_at(out, 0) != 0x82 ||
        !std::equal(payload.begin(), payload.end(), out.begin() + 10))
        return false;
    const auto pong = out.begin() + 10 + static_cast<std::ptrdiff_t>(payload.size());
    return pong[0] == std::byte {0x8a} && pong[1] == std::byte {4} &&
           std::ranges::equal(std::span(pong + 2, 4), bytes("ping"));
}

} // namespace

auto main() -> int
{
    if (!receive_test()) { std::cerr << "receive test failed\n"; return 1; }
    if (!fragmentation_and_control_test()) {
        std::cerr << "fragmentation/control test failed\n"; return 1;
    }
    if (!send_test()) { std::cerr << "send test failed\n"; return 1; }
    if (!close_test()) { std::cerr << "close test failed\n"; return 1; }
    if (!active_close_test()) {
        std::cerr << "active close test failed\n"; return 1;
    }
    if (!passive_tls_close_test()) {
        std::cerr << "passive TLS close test failed\n"; return 1;
    }
    if (!protocol_failure_test()) {
        std::cerr << "protocol failure test failed\n"; return 1;
    }
    if (!bounded_and_failure_test()) {
        std::cerr << "bounded/failure test failed\n"; return 1;
    }
    if (!concurrent_writer_test()) {
        std::cerr << "concurrent writer test failed\n"; return 1;
    }
    if (!borrowed_write_test()) {
        std::cerr << "borrowed write test failed\n"; return 1;
    }
    return 0;
}
