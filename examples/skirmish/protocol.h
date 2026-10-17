// Wire constants and byte helpers for the Skirmish protocol (PROTOCOL.md).
// Every integer is little-endian; q8 values are round(v * 256).
#pragma once

#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace skirmish::proto {

// Datagram types.
inline constexpr std::uint8_t kClientInput = 1;
inline constexpr std::uint8_t kClientPing = 2;
inline constexpr std::uint8_t kServerPong = 2;
inline constexpr std::uint8_t kServerSnapshot = 3;
inline constexpr std::size_t kPingSize = 9;
inline constexpr std::size_t kMaxInputsPerPacket = 4;

// Control stream message types.
inline constexpr std::uint8_t kHello = 1;
inline constexpr std::uint8_t kWelcome = 1;
inline constexpr std::uint8_t kJoin = 2;
inline constexpr std::uint8_t kLeave = 3;
inline constexpr std::uint8_t kKill = 4;
inline constexpr std::uint8_t kChat = 5;
inline constexpr std::uint8_t kNotice = 6;

inline constexpr std::uint8_t kRpcScoreboard = 1;
inline constexpr std::uint8_t kKillcamKind = 1;

inline constexpr std::uint16_t kTickRate = 60;
inline constexpr std::uint16_t kSnapshotRate = 30;
inline constexpr std::size_t kMaxName = 16;
inline constexpr std::size_t kMaxChat = 200;
inline constexpr std::size_t kMaxControlPayload = 1024;

// WebTransport session close codes.
inline constexpr std::uint32_t kCloseServerFull = 1;
inline constexpr std::uint32_t kCloseTooSlow = 2;
inline constexpr std::uint32_t kCloseProtocol = 3;
inline constexpr std::uint32_t kCloseShutdown = 4;
inline constexpr std::uint32_t kCloseBadName = 5;
inline constexpr std::size_t kCloseCodeCount = 6;

// Stream error codes.
inline constexpr std::uint32_t kResetKillcamRespawn = 0x10;
inline constexpr std::uint32_t kStopChatTooLong = 0x11;
inline constexpr std::uint32_t kBusy = 0x12;

// Appends little-endian values to a byte vector. The caller bounds the size.
class byte_writer {
public:
    explicit byte_writer(std::vector<std::byte>& out) noexcept : out_(out) {}

    auto u8(std::uint8_t value) -> void { out_.push_back(std::byte {value}); }
    auto u16(std::uint16_t value) -> void
    {
        u8(static_cast<std::uint8_t>(value & 0xff));
        u8(static_cast<std::uint8_t>(value >> 8));
    }
    auto u32(std::uint32_t value) -> void
    {
        u16(static_cast<std::uint16_t>(value & 0xffff));
        u16(static_cast<std::uint16_t>(value >> 16));
    }
    auto f64(double value) -> void
    {
        const auto bits = std::bit_cast<std::uint64_t>(value);
        u32(static_cast<std::uint32_t>(bits & 0xffffffffu));
        u32(static_cast<std::uint32_t>(bits >> 32));
    }
    // Map coordinates are below 256, so q8 fits an unsigned 16-bit value.
    auto q8(double value) -> void
    {
        auto scaled = std::lround(value * 256.0);
        if (scaled < 0) scaled = 0;
        if (scaled > 65535) scaled = 65535;
        u16(static_cast<std::uint16_t>(scaled));
    }
    auto bytes(std::span<const std::byte> data) -> void
    {
        out_.insert(out_.end(), data.begin(), data.end());
    }
    auto text(std::string_view data) -> void
    {
        for (const char c : data) u8(static_cast<std::uint8_t>(c));
    }
    [[nodiscard]] auto size() const noexcept -> std::size_t { return out_.size(); }

private:
    std::vector<std::byte>& out_;
};

// Reads little-endian values with bounds checks. Any overrun clears ok() and
// yields zeros, so callers check ok() (and done()) once after parsing.
class byte_reader {
public:
    explicit byte_reader(std::span<const std::byte> data) noexcept : data_(data) {}

    auto u8() noexcept -> std::uint8_t
    {
        if (pos_ + 1 > data_.size()) return fail();
        return std::to_integer<std::uint8_t>(data_[pos_++]);
    }
    auto u16() noexcept -> std::uint16_t
    {
        const auto low = u8();
        const auto high = u8();
        return static_cast<std::uint16_t>(low | (high << 8));
    }
    auto u32() noexcept -> std::uint32_t
    {
        const auto low = u16();
        const auto high = u16();
        return static_cast<std::uint32_t>(low) | (static_cast<std::uint32_t>(high) << 16);
    }
    auto bytes(std::size_t count) noexcept -> std::span<const std::byte>
    {
        if (pos_ + count > data_.size() || pos_ + count < pos_) {
            (void)fail();
            return {};
        }
        auto result = data_.subspan(pos_, count);
        pos_ += count;
        return result;
    }
    [[nodiscard]] auto ok() const noexcept -> bool { return ok_; }
    [[nodiscard]] auto done() const noexcept -> bool { return ok_ && pos_ == data_.size(); }

private:
    auto fail() noexcept -> std::uint8_t
    {
        ok_ = false;
        return 0;
    }

    std::span<const std::byte> data_;
    std::size_t pos_ {0};
    bool ok_ {true};
};

// Frames a control stream message: u16 length of (type + payload), then both.
[[nodiscard]] inline auto frame_message(std::uint8_t type, std::span<const std::byte> payload)
    -> std::vector<std::byte>
{
    std::vector<std::byte> out;
    out.reserve(3 + payload.size());
    byte_writer writer(out);
    writer.u16(static_cast<std::uint16_t>(1 + payload.size()));
    writer.u8(type);
    writer.bytes(payload);
    return out;
}

// Strict enough for names and chat: rejects malformed lead and continuation bytes.
[[nodiscard]] inline auto valid_utf8(std::span<const std::byte> text) noexcept -> bool
{
    for (std::size_t i = 0; i < text.size();) {
        const auto lead = std::to_integer<unsigned>(text[i]);
        std::size_t count = 0;
        if (lead < 0x80) count = 1;
        else if ((lead >> 5) == 0x6) count = 2;
        else if ((lead >> 4) == 0xe) count = 3;
        else if ((lead >> 3) == 0x1e) count = 4;
        if (count == 0 || i + count > text.size()) return false;
        for (std::size_t k = 1; k < count; ++k) {
            if ((std::to_integer<unsigned>(text[i + k]) & 0xc0) != 0x80) return false;
        }
        i += count;
    }
    return true;
}

} // namespace skirmish::proto
