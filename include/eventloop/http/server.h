#pragma once

#include "eventloop/task.h"
#include "eventloop/tcp_acceptor.h"
#include "eventloop/tls_context.h"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace eventloop::http {

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

    [[nodiscard]] auto run() -> task<void>;

private:
    static auto accept_loop(event_loop& loop, server& listener,
                            std::shared_ptr<unique_fd> root,
                            server_options options) -> task<void>;

    std::shared_ptr<unique_fd> root_descriptor_;
    server_options options_;
};

class https_server final : public tcp_acceptor {
public:
    https_server(event_loop& loop, std::uint16_t port,
                 std::shared_ptr<tls_context> context, std::string_view root,
                 std::string_view address = "127.0.0.1",
                 server_options options = {});
    ~https_server() override;

    [[nodiscard]] auto run() -> task<void>;

private:
    static auto accept_loop(event_loop& loop, https_server& listener,
                            std::shared_ptr<unique_fd> root,
                            std::shared_ptr<tls_context> context,
                            server_options options) -> task<void>;

    std::shared_ptr<unique_fd> root_descriptor_;
    std::shared_ptr<tls_context> context_;
    server_options options_;
};

class redirect_server final : public tcp_acceptor {
public:
    redirect_server(event_loop& loop, std::uint16_t port,
                    std::string_view hostname, std::uint16_t https_port,
                    std::string_view address = "127.0.0.1");

    [[nodiscard]] auto run() -> task<void>;

private:
    static auto accept_loop(event_loop& loop, redirect_server& listener,
                            std::shared_ptr<const std::string> hostname,
                            std::uint16_t https_port) -> task<void>;

    std::shared_ptr<const std::string> hostname_;
    std::uint16_t https_port_;
};

} // namespace eventloop::http
