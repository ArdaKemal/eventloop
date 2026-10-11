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
#include <vector>

namespace eventloop { class tls_context; }

namespace eventloop::http {
namespace detail {
struct serving_loop;
using serving_set = std::vector<std::shared_ptr<const serving_loop>>;
}

// Cleartext HTTP/1.1 server. It owns its listening socket and document-root
// descriptor; run() accepts until the listener closes.
class server final : public tcp_acceptor {
public:
    server(event_loop& loop, ip_endpoint local, server_options options);
    ~server() override;

    [[nodiscard]] auto run() -> task<void>;

private:
    detail::serving_set serving_;
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
    detail::serving_set serving_;
};
#endif

class redirect_server final : public tcp_acceptor {
public:
    // Answers every request with 308 to https://hostname[:https_port], then
    // closes. Only reuse_port, header_timeout, and serving_loops apply from
    // options.
    redirect_server(event_loop& loop, ip_endpoint local,
                    std::string_view hostname, std::uint16_t https_port,
                    server_options options = {});
    ~redirect_server() override;

    [[nodiscard]] auto run() -> task<void>;

private:
    detail::serving_set serving_;
};

} // namespace eventloop::http
