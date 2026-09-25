#include "eventloop/ws/web_socket.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
std::size_t allocations = 0;
}

auto operator new(std::size_t size) -> void*
{
    ++allocations;
    if (void* memory = std::malloc(size)) return memory;
    throw std::bad_alloc {};
}

auto operator new[](std::size_t size) -> void*
{
    ++allocations;
    if (void* memory = std::malloc(size)) return memory;
    throw std::bad_alloc {};
}

void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete[](void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }
void operator delete[](void* memory, std::size_t) noexcept { std::free(memory); }

namespace {

class memory_stream final : public byte_stream {
public:
    auto write(std::span<const std::byte> data) -> void override
    {
        if (fail_write) throw std::runtime_error("expected stream write failure");
        output.insert(output.end(), data.begin(), data.end());
        pending = block_writes;
    }

    auto close() -> void override { open = false; }
    [[nodiscard]] auto ready() const noexcept -> bool override { return open; }
    [[nodiscard]] auto write_pending() const noexcept -> bool override { return pending; }

    auto drain() -> void { pending = false; }

    std::vector<std::byte> output;
    bool open {true};
    bool block_writes {false};
    bool pending {false};
    bool fail_write {false};

private:
    auto on_data(std::span<const std::byte>) -> void override {}
};

class socket final : public ws::web_socket {
public:
    explicit socket(memory_stream& stream, std::size_t maximum = 1024 * 1024)
        : web_socket(stream, maximum)
    {
    }

    std::vector<std::u8string> texts;
    std::vector<std::vector<std::byte>> binaries;
    std::vector<std::vector<std::byte>> pings;
    std::vector<std::vector<std::byte>> pongs;
    std::optional<std::uint16_t> close_code;
    std::u8string close_reason;
    std::optional<ws::errc> error;

private:
    auto on_text(std::u8string_view message) -> void override
    {
        texts.emplace_back(message);
    }

    auto on_binary(std::span<const std::byte> message) -> void override
    {
        binaries.emplace_back(message.begin(), message.end());
    }

    auto on_ping(std::span<const std::byte> payload) -> void override
    {
        pings.emplace_back(payload.begin(), payload.end());
    }

    auto on_pong(std::span<const std::byte> payload) -> void override
    {
        pongs.emplace_back(payload.begin(), payload.end());
    }

    auto on_close(std::optional<std::uint16_t> code,
                  std::u8string_view reason) -> void override
    {
        close_code = code;
        close_reason = reason;
    }

    auto on_error(ws::errc value) -> void override { error = value; }
};

class counting_socket final : public ws::web_socket {
public:
    explicit counting_socket(memory_stream& stream) : web_socket(stream) {}

    std::size_t messages {0};

private:
    auto on_text(std::u8string_view) -> void override { ++messages; }
};

class throwing_socket final : public ws::web_socket {
public:
    explicit throwing_socket(memory_stream& stream) : web_socket(stream) {}
    int callbacks {0};

private:
    auto on_text(std::u8string_view) -> void override
    {
        ++callbacks;
        throw std::runtime_error("expected message callback failure");
    }
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
        for (std::size_t index = 0; index < 8; ++index) {
            frame[2 + index] = static_cast<std::byte>(
                (size >> ((7 - index) * 8)) & 0xff);
        }
    }
    std::copy(key.begin(), key.end(), frame.begin() +
              static_cast<std::ptrdiff_t>(header_size));
    const auto payload_offset = header_size + key.size();
    for (std::size_t index = 0; index < payload.size(); ++index) {
        frame[payload_offset + index] = payload[index] ^ key[index % key.size()];
    }
    return frame;
}

[[nodiscard]] auto byte_at(const std::vector<std::byte>& input,
                           std::size_t index) -> std::uint8_t
{
    return std::to_integer<std::uint8_t>(input[index]);
}

auto receive_and_fragmentation_tests() -> bool
{
    memory_stream stream;
    socket web_socket(stream);
    const auto hello = bytes("hello");
    const auto frame = masked_frame(0x01, true, hello);
    web_socket.receive(std::span {frame}.first(1));
    web_socket.receive(std::span {frame}.subspan(1, 3));
    web_socket.receive(std::span {frame}.subspan(4));
    if (web_socket.texts != std::vector<std::u8string> {u8"hello"}) return false;

    const auto first = masked_frame(0x01, false, bytes("hel"));
    const auto ping = masked_frame(0x09, true, bytes("p"));
    const auto last = masked_frame(0x00, true, bytes("lo"));
    std::vector<std::byte> combined;
    combined.insert(combined.end(), first.begin(), first.end());
    combined.insert(combined.end(), ping.begin(), ping.end());
    combined.insert(combined.end(), last.begin(), last.end());
    web_socket.receive(combined);

    return web_socket.texts.size() == 2 && web_socket.texts[1] == u8"hello" &&
           web_socket.pings == std::vector<std::vector<std::byte>> {bytes("p")} &&
           stream.output.size() >= 3 && byte_at(stream.output, 0) == 0x8a &&
           byte_at(stream.output, 1) == 1 && byte_at(stream.output, 2) == 'p';
}

auto length_tests() -> bool
{
    memory_stream stream;
    socket web_socket(stream, 128 * 1024);
    std::vector<std::byte> medium(126, std::byte {'m'});
    auto input = masked_frame(0x02, true, medium);
    web_socket.receive(input);
    if (web_socket.binaries.size() != 1 || web_socket.binaries[0] != medium) return false;

    web_socket.write(std::u8string(126, u8'x'));
    if (stream.output.size() != 130 || byte_at(stream.output, 0) != 0x81 ||
        byte_at(stream.output, 1) != 126 || byte_at(stream.output, 2) != 0 ||
        byte_at(stream.output, 3) != 126) return false;

    stream.output.clear();
    std::vector<std::byte> large(65536, std::byte {0x5a});
    web_socket.write_binary(large);
    return stream.output.size() == large.size() + 10 &&
           byte_at(stream.output, 0) == 0x82 && byte_at(stream.output, 1) == 127 &&
           byte_at(stream.output, 6) == 0 && byte_at(stream.output, 7) == 1 &&
           byte_at(stream.output, 8) == 0 && byte_at(stream.output, 9) == 0;
}

auto backpressure_test() -> bool
{
    memory_stream stream;
    stream.block_writes = true;
    socket web_socket(stream);
    const std::vector<std::byte> payload(40 * 1024, std::byte {0x2a});
    web_socket.write_binary(payload);
    if (stream.output.size() != 16 * 1024) return false;

    while (stream.output.size() < payload.size() + 4) {
        stream.drain();
        web_socket.write_drained();
    }
    stream.drain();
    web_socket.write_drained();
    return stream.output.size() == payload.size() + 4 &&
           byte_at(stream.output, 0) == 0x82 && byte_at(stream.output, 1) == 126;
}

auto allocation_reuse_test() -> bool
{
    memory_stream output_stream;
    output_stream.output.reserve(4096);
    const auto before_construction = allocations;
    socket web_socket(output_stream);
    if (allocations != before_construction) return false;
    web_socket.write(u8"message");
    output_stream.output.clear();

    const auto before = allocations;
    for (int index = 0; index < 100; ++index) web_socket.write(u8"message");
    const auto after = allocations;
    if (before != after) return false;

    memory_stream input_stream;
    counting_socket reader(input_stream);
    const auto frame = masked_frame(0x01, true, bytes("message"));
    reader.receive(frame);
    const auto before_reads = allocations;
    for (int index = 0; index < 100; ++index) reader.receive(frame);
    return allocations == before_reads && reader.messages == 101;
}

auto exception_cleanup_test() -> bool
{
    memory_stream input_stream;
    throwing_socket reader(input_stream);
    const auto frame = masked_frame(0x01, true, bytes("hello"));
    try {
        reader.receive(frame);
        return false;
    } catch (const std::runtime_error&) {
    }
    reader.receive(frame);
    if (input_stream.open || reader.callbacks != 1) return false;

    memory_stream output_stream;
    output_stream.fail_write = true;
    socket writer(output_stream);
    try {
        writer.write(u8"hello");
        return false;
    } catch (const std::runtime_error&) {
    }
    if (output_stream.open) return false;
    try {
        writer.write(u8"again");
    } catch (const std::logic_error&) {
        return true;
    }
    return false;
}

auto control_and_error_tests() -> bool
{
    memory_stream close_stream;
    socket closing(close_stream);
    std::vector<std::byte> close_payload {std::byte {0x03}, std::byte {0xe8}};
    const auto reason = bytes("bye");
    close_payload.insert(close_payload.end(), reason.begin(), reason.end());
    const auto close_frame = masked_frame(0x08, true, close_payload);
    closing.receive(close_frame);
    if (closing.close_code != 1000 || closing.close_reason != u8"bye" ||
        close_stream.open || close_stream.output.size() != close_payload.size() + 2 ||
        byte_at(close_stream.output, 0) != 0x88) return false;

    memory_stream mask_stream;
    socket unmasked(mask_stream);
    const std::array<std::byte, 3> invalid {
        std::byte {0x81}, std::byte {0x01}, std::byte {'x'},
    };
    unmasked.receive(invalid);
    if (unmasked.error != ws::errc::protocol_error || mask_stream.open ||
        mask_stream.output.size() != 4 || byte_at(mask_stream.output, 0) != 0x88 ||
        byte_at(mask_stream.output, 2) != 0x03 ||
        byte_at(mask_stream.output, 3) != 0xea) return false;

    memory_stream utf8_stream;
    socket invalid_utf8(utf8_stream);
    const std::array<std::byte, 2> bad_utf8 {std::byte {0xc0}, std::byte {0x80}};
    const auto utf8_frame = masked_frame(0x01, true, bad_utf8);
    invalid_utf8.receive(utf8_frame);
    if (invalid_utf8.error != ws::errc::invalid_utf8 || utf8_stream.open ||
        utf8_stream.output.size() != 4 || byte_at(utf8_stream.output, 2) != 0x03 ||
        byte_at(utf8_stream.output, 3) != 0xef) return false;

    memory_stream size_stream;
    socket oversized(size_stream, 16);
    const auto oversized_frame = masked_frame(0x02, true,
                                               std::vector<std::byte>(17));
    oversized.receive(oversized_frame);
    return oversized.error == ws::errc::message_too_large && !size_stream.open &&
           size_stream.output.size() == 4 && byte_at(size_stream.output, 2) == 0x03 &&
           byte_at(size_stream.output, 3) == 0xf1;
}

} // namespace

auto main() -> int
{
    if (!receive_and_fragmentation_tests()) {
        std::cerr << "WebSocket receive/fragmentation tests failed\n";
        return 1;
    }
    if (!length_tests()) {
        std::cerr << "WebSocket length tests failed\n";
        return 1;
    }
    if (!backpressure_test()) {
        std::cerr << "WebSocket backpressure test failed\n";
        return 1;
    }
    if (!allocation_reuse_test()) {
        std::cerr << "WebSocket allocation reuse test failed\n";
        return 1;
    }
    if (!exception_cleanup_test()) {
        std::cerr << "WebSocket exception cleanup test failed\n";
        return 1;
    }
    if (!control_and_error_tests()) {
        std::cerr << "WebSocket control/error tests failed\n";
        return 1;
    }
    return 0;
}
