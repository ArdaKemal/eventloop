#pragma once

#include "eventloop/event_loop.h"

#include <cstdint>
#include <string_view>

class tcp_acceptor : public notifiable {
public:
    tcp_acceptor(event_loop& loop, std::uint16_t port,
                 std::string_view address = "127.0.0.1");
    ~tcp_acceptor() override;

    tcp_acceptor(const tcp_acceptor&) = delete;
    auto operator=(const tcp_acceptor&) -> tcp_acceptor& = delete;

    [[nodiscard]] auto descriptor() const noexcept -> int override;

protected:
    [[nodiscard]] auto owner() noexcept -> event_loop&;
    virtual auto on_accept(int descriptor) -> void = 0;

private:
    auto on_read() -> void override;
    auto on_write() -> void override {}
    auto on_error() -> void override;

    event_loop& loop_;
    int descriptor_ {-1};
};
