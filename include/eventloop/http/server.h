#pragma once

#include "eventloop/tcp_acceptor.h"
#include "eventloop/tls_acceptor.h"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace http {

struct server_options {
    bool directory_listing {false};
    bool reuse_port {false};
};

class server final : public tcp_acceptor {
public:
    server(event_loop& loop, std::uint16_t port, std::string_view root,
           std::string_view address = "127.0.0.1",
           server_options options = {});
    ~server() override;

private:
    auto on_accept(int descriptor) -> void override;
    auto on_accept_owned(unique_fd descriptor) -> void override;

    std::shared_ptr<unique_fd> root_descriptor_;
    server_options options_;
};

class https_server final : public tls_acceptor {
public:
    https_server(event_loop& loop, std::uint16_t port,
                 std::shared_ptr<tls_context> context, std::string_view root,
                 std::string_view address = "127.0.0.1",
                 server_options options = {});
    ~https_server() override;

private:
    auto make_stream(int descriptor) -> std::unique_ptr<tls_stream> override;
    auto make_owned_stream(unique_fd descriptor)
        -> std::unique_ptr<tls_stream> override;

    std::shared_ptr<unique_fd> root_descriptor_;
    server_options options_;
};

class redirect_server final : public tcp_acceptor {
public:
    redirect_server(event_loop& loop, std::uint16_t port,
                    std::string_view hostname, std::uint16_t https_port,
                    std::string_view address = "127.0.0.1");

private:
    auto on_accept(int descriptor) -> void override;
    auto on_accept_owned(unique_fd descriptor) -> void override;

    std::shared_ptr<const std::string> hostname_;
    std::uint16_t https_port_;
};

} // namespace http
