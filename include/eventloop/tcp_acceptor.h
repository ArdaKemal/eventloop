#pragma once

#include "eventloop/event_loop.h"
#include "eventloop/unique_fd.h"

#include <cstdint>
#include <string_view>

class tcp_acceptor : public notifiable {
public:
    tcp_acceptor(event_loop& loop, std::uint16_t port,
                 std::string_view address = "127.0.0.1",
                 bool reuse_port = false);
    ~tcp_acceptor() override;

    tcp_acceptor(const tcp_acceptor&) = delete;
    auto operator=(const tcp_acceptor&) -> tcp_acceptor& = delete;

    [[nodiscard]] auto descriptor() const noexcept -> int override;

protected:
    [[nodiscard]] auto owner() noexcept -> event_loop&;
    // The owning callback keeps the accepted descriptor safe if construction
    // of a session throws. The int callback is retained for existing users.
    virtual auto on_accept_owned(unique_fd descriptor) -> void;
    virtual auto on_accept(int descriptor) -> void = 0;

private:
    auto on_read() -> void override;
    auto on_write() -> void override {}
    auto on_error() -> void override;
    auto on_shutdown() -> void override;

    event_loop& loop_;
    unique_fd descriptor_;
};
