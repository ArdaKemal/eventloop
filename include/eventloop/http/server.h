#pragma once

#include "eventloop/tcp_acceptor.h"

#include <cstdint>
#include <string_view>

namespace http {

class server final : public tcp_acceptor {
public:
    server(event_loop& loop, std::uint16_t port, std::string_view root,
           std::string_view address = "127.0.0.1");
    ~server() override;

private:
    auto on_accept(int descriptor) -> void override;

    int root_descriptor_ {-1};
};

} // namespace http
