#pragma once

#include "eventloop/http/server_options.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/task.h"
#include "eventloop/tcp_acceptor.h"
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
#include "eventloop/tls_context.h"
#endif

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace eventloop { class tls_context; }

namespace eventloop::http {
namespace detail { struct document_root; }

// Cleartext HTTP/1.1 server. It owns its listening socket and document-root
// descriptor; run() accepts until the listener closes.
class server final : public tcp_acceptor {
public:
    server(event_loop& loop, ip_endpoint local, server_options options);
    ~server() override;

    [[nodiscard]] auto run() -> task<void>;

private:
    static auto accept_loop(event_loop& loop, server& listener,
                            std::shared_ptr<detail::document_root> root,
                            server_options options) -> task<void>;

    std::shared_ptr<detail::document_root> root_descriptor_;
    server_options options_;
};

#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
class https_server final : public tcp_acceptor {
public:
    // Advertises h2 and http/1.1 with ALPN unless enable_http2 is false.
    https_server(event_loop& loop, ip_endpoint local,
                 std::shared_ptr<tls_context> context, server_options options);
    ~https_server() override;

    [[nodiscard]] auto run() -> task<void>;

private:
    static auto accept_loop(event_loop& loop, https_server& listener,
                            std::shared_ptr<detail::document_root> root,
                            std::shared_ptr<tls_context> context,
                            server_options options) -> task<void>;

    std::shared_ptr<detail::document_root> root_descriptor_;
    std::shared_ptr<tls_context> context_;
    server_options options_;
};
#endif

class redirect_server final : public tcp_acceptor {
public:
    // Answers every request with 308 to https://hostname[:https_port].
    redirect_server(event_loop& loop, ip_endpoint local,
                    std::string_view hostname, std::uint16_t https_port);

    [[nodiscard]] auto run() -> task<void>;

private:
    static auto accept_loop(event_loop& loop, redirect_server& listener,
                            std::shared_ptr<const std::string> hostname,
                            std::uint16_t https_port) -> task<void>;

    std::shared_ptr<const std::string> hostname_;
    std::uint16_t https_port_;
};

} // namespace eventloop::http
