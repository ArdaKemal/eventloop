#pragma once

#include "eventloop/byte_stream.h"
#include "eventloop/event_loop.h"

#include <array>
#include <cstddef>
#include <span>
#include <system_error>

class tcp_stream : public byte_stream, public notifiable {
public:
    tcp_stream(event_loop& loop, int descriptor);
    ~tcp_stream() override;

    tcp_stream(const tcp_stream&) = delete;
    auto operator=(const tcp_stream&) -> tcp_stream& = delete;

    [[nodiscard]] auto descriptor() const noexcept -> int override;
    auto write(std::span<const std::byte> data) -> void override;
    auto close() -> void override;
    [[nodiscard]] auto ready() const noexcept -> bool override;
    [[nodiscard]] auto write_pending() const noexcept -> bool override;

protected:
    virtual auto on_transport_data(std::span<const std::byte> data) -> void;
    virtual auto on_transport_close() -> void;
    virtual auto on_transport_error(std::error_code error) -> void;
    virtual auto on_write_drained() -> void {}
    auto abort() -> void;

private:
    auto on_read() -> void override;
    auto on_write() -> void override;
    auto on_error() -> void override;
    auto flush() -> void;
    auto watch_writes(bool enabled) -> void;

    event_loop& loop_;
    int descriptor_;
    std::array<std::byte, 64 * 1024> output_ {};
    std::size_t output_size_ {0};
    std::size_t written_ {0};
    bool watching_writes_ {false};
    bool peer_closed_ {false};
    bool closing_ {false};
    bool closed_ {false};
    bool notifying_write_drained_ {false};
    bool write_drained_deferred_ {false};
};
