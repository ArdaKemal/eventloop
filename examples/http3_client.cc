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
#include <charconv>
#include <chrono>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

namespace {

using namespace eventloop;

struct request_state {
    quic_endpoint* endpoint {};
    bool expired {};
};

auto deadline(event_loop& loop, request_state& state,
              std::chrono::milliseconds duration) -> task<void>
{
    if (co_await sleep_for(loop, duration) == timer_wait_result::expired) {
        state.expired = true;
        std::cerr << "HTTP/3 overall timeout\n";
        // Close the transport to wake I/O without cancelling the cleanup task.
        if (state.endpoint) state.endpoint->close();
    }
}

auto fetch(event_loop& loop, http_client_example::url_parts url,
           quic_version version, const std::filesystem::path& ca_file,
           request_state& state, bool& success) -> task<void>
{
    try {
        const auto addresses = co_await run_blocking(
            loop, [hostname = url.hostname, port = url.port]() noexcept {
                return http_client_example::resolve_addresses(hostname, port);
            });
        if (!addresses) {
            std::cerr << "DNS worker unavailable or cancelled\n";
            co_return;
        }
        if (addresses->error != 0 || addresses->count == 0) {
            std::cerr << "DNS lookup failed: "
                      << (addresses->error != 0
                              ? ::gai_strerror(addresses->error)
                              : "no supported addresses")
                      << '\n';
            co_return;
        }
        if (state.expired) co_return;

        // ALPN is the protocol name, without a TLS length prefix. An empty
        // trusted_ca selects the system store; async_connect verifies hostname.
        constexpr std::array<std::uint8_t, 2> alpn {'h', '3'};
        for (std::size_t index = 0; index < addresses->count; ++index) {
            if (state.expired) break;
            const auto remote = addresses->endpoints[index];
            const auto local = remote.address_family == ip_endpoint::family::ipv4
                                   ? ip_endpoint::any_v4()
                                   : ip_endpoint::any_v6();
            quic_client_options options;
            options.alpn = alpn;
            options.version = version;
            options.trusted_ca = ca_file;
            quic_endpoint endpoint(loop, local, options);
            state.endpoint = &endpoint;
            struct active_endpoint_guard {
                request_state& state;
                ~active_endpoint_guard() { state.endpoint = nullptr; }
            } active {state};
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
}

auto run_request(event_loop& loop, http_client_example::url_parts url,
                 quic_version version, std::filesystem::path ca_file,
                 std::chrono::milliseconds duration, bool& success) -> task<void>
{
    request_state state;
    task_handle<void> operation, timer;
    const auto timer_started = loop.spawn(deadline(loop, state, duration), timer) ==
                              task_spawn_result::accepted;
    const auto operation_started = timer_started &&
        loop.spawn(fetch(loop, std::move(url), version, ca_file, state, success), operation) ==
            task_spawn_result::accepted;
    if (operation_started) (void)co_await operation;
    if (timer_started) {
        (void)timer.cancel();
        (void)co_await timer;
    }
    if (!operation_started || state.expired) success = false;
    loop.stop();
}

} // namespace

auto main(int argc, char* argv[]) -> int
{
    auto version = quic_version::v1;
    std::filesystem::path ca_file;
    std::chrono::milliseconds duration {30000};
    const char* input = nullptr;
    const auto usage = [] {
        std::cerr << "usage: http3_client [--version v1|v2] [--ca-file PEM] "
                     "[--timeout-ms 1..3600000] <https:// URL>\n";
    };
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--version" && index + 1 < argc) {
            const std::string_view value(argv[++index]);
            if (value != "v1" && value != "v2") { usage(); return 2; }
            version = value == "v2" ? quic_version::v2 : quic_version::v1;
        } else if (argument == "--ca-file" && index + 1 < argc) {
            ca_file = argv[++index];
            if (ca_file.empty()) { usage(); return 2; }
        } else if (argument == "--timeout-ms" && index + 1 < argc) {
            const std::string_view value(argv[++index]);
            unsigned milliseconds {};
            const auto result = std::from_chars(value.data(), value.data() + value.size(), milliseconds);
            if (result.ec != std::errc{} || result.ptr != value.data() + value.size() ||
                milliseconds == 0 || milliseconds > 3600000) { usage(); return 2; }
            duration = std::chrono::milliseconds(milliseconds);
        } else if (argument.starts_with("--") || input) {
            usage();
            return 2;
        } else input = argv[index];
    }
    if (!input) { usage(); return 2; }
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
        if (loop.spawn(run_request(loop, std::move(url), version,
                                  std::move(ca_file), duration, success)) !=
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
