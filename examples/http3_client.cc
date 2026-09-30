#include "http3_client_session.h"
#include "http_client_resolve.h"
#include "http_client_url.h"

#include "eventloop/event_loop.h"
#include "eventloop/quic.h"
#include "eventloop/task.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#endif

#include <array>
#include <cerrno>
#include <chrono>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

namespace {

using namespace eventloop;

auto fetch(event_loop& loop, http_client_example::url_parts url,
           quic_version version, bool& success) -> task<void>
{
    try {
        const auto addresses = co_await run_blocking(
            loop, [hostname = url.hostname, port = url.port]() noexcept {
                return http_client_example::resolve_addresses(hostname, port);
            });
        if (!addresses) {
            std::cerr << "DNS worker unavailable or cancelled\n";
            loop.stop();
            co_return;
        }
        if (addresses->error != 0 || addresses->count == 0) {
            std::cerr << "DNS lookup failed: "
                      << (addresses->error != 0
                              ? ::gai_strerror(addresses->error)
                              : "no supported addresses")
                      << '\n';
            loop.stop();
            co_return;
        }

        // ALPN is the protocol name, without a TLS length prefix. An empty
        // trusted_ca selects the system store; async_connect verifies hostname.
        constexpr std::array<std::uint8_t, 2> alpn {'h', '3'};
        for (std::size_t index = 0; index < addresses->count; ++index) {
            const auto remote = addresses->endpoints[index];
            const auto local = remote.address_family == ip_endpoint::family::ipv4
                                   ? ip_endpoint::any_v4()
                                   : ip_endpoint::any_v6();
            quic_client_options options;
            options.alpn = alpn;
            options.version = version;
            quic_endpoint endpoint(loop, local, options);
            auto connected = co_await endpoint.async_connect(remote, url.hostname);
            if (!connected || !*connected) {
                std::cerr << "QUIC connect/TLS handshake failed (address "
                          << index + 1 << "): "
                          << (connected ? connected->error().message()
                                        : "coroutine unavailable or cancelled")
                          << '\n';
                const auto closed = co_await endpoint.async_close();
                if (closed != task_result::success) {
                    std::cerr << "QUIC endpoint close cancelled\n";
                    break;
                }
                continue;
            }

            auto connection = std::move(**connected);
            const auto response = co_await http3_client_example::perform_get(
                loop, connection, url.host_header, url.target);
            success = response && response->has_value();
            if (!success) {
                std::cerr << "HTTP/3 exchange failed: "
                          << (response ? response->error().message()
                                       : "coroutine unavailable or cancelled")
                          << '\n';
            }
            connection.close();
            const auto closed = co_await endpoint.async_close();
            if (closed != task_result::success) {
                std::cerr << "QUIC endpoint close cancelled\n";
                success = false;
            }
            break;
        }
    } catch (const std::exception& error) {
        std::cerr << "HTTP/3 client setup failed: " << error.what() << '\n';
    }
    loop.stop();
}

} // namespace

auto main(int argc, char* argv[]) -> int
{
    if (argc != 2 && argc != 4) {
        std::cerr << "usage: http3_client [--version v1|v2] <https:// URL>\n";
        return 2;
    }
    auto version = quic_version::v1;
    const char* input = argv[1];
    if (argc == 4) {
        if (std::string_view(argv[1]) != "--version" ||
            (std::string_view(argv[2]) != "v1" &&
             std::string_view(argv[2]) != "v2")) {
            std::cerr << "usage: http3_client [--version v1|v2] <https:// URL>\n";
            return 2;
        }
        version = std::string_view(argv[2]) == "v2" ? quic_version::v2
                                                   : quic_version::v1;
        input = argv[3];
    }
    try {
#ifdef _WIN32
        if (::_setmode(::_fileno(stdout), _O_BINARY) == -1)
            throw std::system_error(errno, std::generic_category(),
                                    "set stdout binary mode");
#endif
        auto url = http_client_example::parse_url(input);
        if (!url.secure) {
            std::cerr << "HTTP/3 requires an https:// URL\n";
            return 2;
        }
        event_loop_options options;
        options.worker_count = 1;
        event_loop loop(options);
        bool success = false;
        if (loop.spawn(fetch(loop, std::move(url), version, success)) !=
            task_spawn_result::accepted)
            throw std::runtime_error("cannot start HTTP/3 client task");
        if (loop.run() == event_loop_result::interrupted) {
            loop.shutdown(std::chrono::seconds {0});
            (void)loop.run();
        }
        return success ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "HTTP/3 client setup failed: " << error.what() << '\n';
        return 1;
    }
}
