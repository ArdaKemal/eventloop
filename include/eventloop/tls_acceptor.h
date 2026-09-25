#pragma once

#include "eventloop/tcp_acceptor.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"

#include <memory>

class tls_acceptor : public tcp_acceptor {
public:
    tls_acceptor(event_loop& loop, std::uint16_t port,
                 std::shared_ptr<tls_context> context,
                 std::string_view address = "127.0.0.1");

protected:
    [[nodiscard]] auto context() const noexcept -> const std::shared_ptr<tls_context>&;
    [[nodiscard]] virtual auto make_stream(int descriptor)
        -> std::unique_ptr<tls_stream> = 0;
    [[nodiscard]] virtual auto make_owned_stream(unique_fd descriptor)
        -> std::unique_ptr<tls_stream>;

private:
    auto on_accept(int descriptor) -> void final;
    auto on_accept_owned(unique_fd descriptor) -> void final;

    std::shared_ptr<tls_context> context_;
};
