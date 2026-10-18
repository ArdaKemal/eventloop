// HTTP/3 GET client for the HTTP/3 server and interop tests, built on the
// public http3::client_connection. Status lines and fields go to stderr. One
// request writes its body to stdout; with --request-path, request i writes
// <output-dir>/<i>.body. All requests share one connection, in order.
#include "client_support/resolve.h"
#include "client_support/url.h"

#include "eventloop/event_loop.h"
#include "eventloop/http3/client.h"
#include "eventloop/task.h"
#include "eventloop/task_composition.h"
#include "eventloop/util/arg_parser.h"

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
#include <cstdio>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using namespace eventloop;
using namespace std::chrono_literals;

constexpr std::size_t max_requests = 32;

struct get_request {
    std::string path;
    std::FILE* output {};
};

struct request_state {
    http3::client_connection* connection {};
    bool expired {};
};

auto deadline(event_loop& loop, request_state& state,
              std::chrono::milliseconds duration) -> task<void>
{
    if (co_await sleep_for(loop, duration) == timer_wait_result::expired) {
        state.expired = true;
        std::cerr << "HTTP/3 overall timeout\n";
        // Close the connection to wake I/O without cancelling the cleanup.
        if (state.connection) state.connection->close();
    }
}

auto print_fields(unsigned status, std::span<const http3::header> fields) -> std::error_code
{
    if (status == 0) std::fputs("HTTP/3 trailers\n", stderr);
    else std::fprintf(stderr, "HTTP/3 %u\n", status);
    for (const auto& field : fields)
        std::fprintf(stderr, "%s: %s\n", field.name.c_str(), field.value.c_str());
    std::fputc('\n', stderr);
    return {};
}

auto exchange(event_loop& loop, http3::client_connection& connection,
              std::string_view authority, std::span<const get_request> requests)
    -> task<std::expected<void, std::error_code>>
{
    (void)loop;
    for (const auto& request : requests) {
        http3::client_request message;
        message.target = request.path;
        message.authority = authority;
        message.headers.push_back({"user-agent", "eventloop-http3-example"});
        auto* output = request.output;
        const auto response = flatten_result(co_await connection.async_request(
            std::move(message),
            [output](std::span<const std::byte> chunk) -> std::error_code {
                if (std::fwrite(chunk.data(), 1, chunk.size(), output) != chunk.size())
                    return std::make_error_code(std::errc::io_error);
                return {};
            },
            print_fields));
        if (!response) co_return std::unexpected(response.error());
        if (std::fflush(output) != 0)
            co_return std::unexpected(std::make_error_code(std::errc::io_error));
    }
    co_return std::expected<void, std::error_code> {};
}

// A silent address (nothing listening, so UDP goes unanswered) holds a
// handshake until the QUIC idle timeout. Bounded attempts let localhost's ::1
// fall through to 127.0.0.1.
auto connect(event_loop& loop, http3::client_connection& connection, bool bounded)
    -> task<std::expected<void, std::error_code>>
{
    if (!bounded) co_return flatten_result(co_await connection.async_connect());
    auto attempt = co_await with_timeout(loop, connection.async_connect(), 3s);
    if (attempt && attempt->result) co_return flatten_result(std::move(*attempt->result));
    co_return std::unexpected(std::make_error_code(
        attempt && attempt->state ==
            timeout_result<std::expected<void, std::error_code>>::outcome::timed_out
        ? std::errc::timed_out : std::errc::operation_canceled));
}

auto fetch(event_loop& loop, client_support::url_parts url, http3::client_options options,
           request_state& state, bool& success, std::span<const get_request> requests)
    -> task<void>
{
    const auto addresses = co_await run_blocking(
        loop, [hostname = url.hostname, port = url.port]() noexcept {
            return client_support::resolve_addresses(hostname, port);
        });
    if (!addresses) {
        std::cerr << "DNS worker unavailable or cancelled\n";
        co_return;
    }
    if (addresses->error != 0 || addresses->count == 0) {
        std::cerr << "DNS lookup failed: "
                  << (addresses->error != 0 ? ::gai_strerror(addresses->error)
                                            : "no supported addresses")
                  << '\n';
        co_return;
    }
    for (std::size_t index = 0; index < addresses->count && !state.expired; ++index) {
        http3::client_connection connection(loop, addresses->endpoints[index], url.hostname,
                                            options);
        state.connection = &connection;
        const auto connected =
            flatten_result(co_await connect(loop, connection, index + 1 < addresses->count));
        if (connected) {
            const auto exchanged = flatten_result(
                co_await exchange(loop, connection, url.host_header, requests));
            success = exchanged.has_value();
            if (!success)
                std::cerr << "HTTP/3 exchange failed: " << exchanged.error().message() << '\n';
        } else {
            std::cerr << "QUIC connect/TLS handshake failed (address " << index + 1
                      << "): " << connected.error().message() << '\n';
        }
        (void)co_await connection.async_close();
        state.connection = nullptr;
        if (connected) break;
    }
}

auto run_request(event_loop& loop, client_support::url_parts url, http3::client_options options,
                 std::chrono::milliseconds duration, bool& success,
                 std::span<const get_request> requests) -> task<void>
{
    request_state state;
    task_handle<void> operation, timer;
    const auto timer_started =
        loop.spawn(deadline(loop, state, duration), timer) == task_spawn_result::accepted;
    const auto operation_started = timer_started &&
        loop.spawn(fetch(loop, std::move(url), std::move(options), state, success, requests),
                   operation) == task_spawn_result::accepted;
    if (operation_started) (void)co_await operation;
    if (timer_started) {
        (void)timer.cancel();
        (void)co_await timer;
    }
    if (!operation_started || state.expired) success = false;
    loop.stop();
}

constexpr std::string_view usage =
    "usage: http3_client [--version v1|v2] [--ca-file PEM] [--timeout-ms 1..3600000] "
    "[--request-path PATH ... --output-dir DIR] <https:// URL>\n";

} // namespace

auto main(int argc, char* argv[]) -> int
{
    http3::client_options options;
    std::chrono::milliseconds duration {30000};
    std::string input;
    std::vector<get_request> requests;
    std::string output_directory;
    using option = arg_parser::option;
    using value = arg_parser::value_handler;
    const std::array parsers {
        option {'\0', "version", value([&options](std::string_view version) {
            if (version != "v1" && version != "v2") throw std::invalid_argument("--version is v1 or v2");
            options.version = version == "v2" ? quic_version::v2 : quic_version::v1;
        }), false},
        option {'\0', "ca-file", value([&options](std::string_view path) {
            if (path.empty()) throw std::invalid_argument("--ca-file is empty");
            options.trusted_ca = path;
        }), false},
        option {'\0', "timeout-ms", value([&duration](std::string_view text) {
            unsigned milliseconds {};
            const auto result = std::from_chars(text.data(), text.data() + text.size(), milliseconds);
            if (result.ec != std::errc {} || result.ptr != text.data() + text.size() ||
                milliseconds == 0 || milliseconds > 3600000)
                throw std::invalid_argument("--timeout-ms is 1..3600000");
            duration = std::chrono::milliseconds(milliseconds);
        }), false},
        option {'\0', "request-path", value([&requests](std::string_view path) {
            if (requests.size() == max_requests)
                throw std::invalid_argument("at most 32 --request-path values");
            requests.push_back({std::string(path)});
        }), false},
        option {'\0', "output-dir", &output_directory, false},
    };
    const std::array positionals {arg_parser::positional {"URL", &input, true}};
    arg_parser arguments(parsers, positionals);
    arguments.set_usage(usage);
    try {
        arguments.parse(argc, argv);
        if (!requests.empty() && output_directory.empty())
            throw std::invalid_argument("--request-path needs --output-dir");
    } catch (const std::invalid_argument& error) {
        std::cerr << "http3_client: " << error.what() << '\n' << usage;
        return 2;
    }
    try {
#ifdef _WIN32
        if (::_setmode(::_fileno(stdout), _O_BINARY) == -1)
            throw std::system_error(errno, std::generic_category(), "set stdout binary mode");
#endif
        auto url = client_support::parse_url(input);
        if (!url.secure) {
            std::cerr << "HTTP/3 requires an https:// URL\n";
            return 2;
        }
        struct outputs {
            std::vector<std::FILE*> files;
            ~outputs() { for (auto* file : files) std::fclose(file); }
        } owned_outputs;
        if (requests.empty()) {
            requests.push_back({url.target, stdout});
        } else {
            std::filesystem::create_directories(output_directory);
            for (std::size_t i = 0; i < requests.size(); ++i) {
                const auto filename =
                    std::filesystem::path(output_directory) / (std::to_string(i) + ".body");
#ifdef _WIN32
                auto* file = ::_wfopen(filename.c_str(), L"wb");
#else
                auto* file = std::fopen(filename.c_str(), "wb");
#endif
                if (!file) throw std::system_error(errno, std::generic_category(), "open response output");
                owned_outputs.files.push_back(file);
                requests[i].output = file;
            }
        }
        event_loop_options loop_options;
        loop_options.worker_count = 1;
        event_loop loop(loop_options);
        bool success = false;
        if (loop.spawn(run_request(loop, std::move(url), std::move(options), duration, success,
                                   requests)) != task_spawn_result::accepted)
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
