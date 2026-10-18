#include "http_client_resolve.h"
#include "http_client_url.h"

#include "eventloop/event_loop.h"
#include "eventloop/task.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "eventloop/util/arg_parser.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <netdb.h>
#endif

namespace {
using http_client_example::parse_url;
using http_client_example::resolve_addresses;
using http_client_example::url_parts;

[[nodiscard]] auto io(std::expected<std::size_t, std::error_code> result)
    -> std::expected<std::size_t, std::error_code> { return result; }
[[nodiscard]] auto io(std::expected<std::expected<std::size_t, std::error_code>,
                                    eventloop::task_result> result)
    -> std::expected<std::size_t, std::error_code>
{
    if (result) return std::move(*result);
    return std::unexpected(std::make_error_code(
        result.error() == eventloop::task_result::frame_allocation_failure
            ? std::errc::not_enough_memory : std::errc::operation_canceled));
}

template<typename Stream>
auto write_all(eventloop::event_loop& loop, Stream& stream,
               std::span<const std::byte> bytes) -> eventloop::task<bool>
{
    (void)loop;
    while (!bytes.empty()) {
        auto written = io(co_await stream.async_write_some(bytes));
        if (!written || *written == 0) co_return false;
        bytes = bytes.subspan(*written);
    }
    co_return true;
}

template<typename Stream>
auto fill(eventloop::event_loop& loop, Stream& stream,
          std::vector<std::byte>& input, std::size_t needed)
    -> eventloop::task<bool>
{
    (void)loop;
    while (input.size() < needed) {
        std::array<std::byte, 512> buffer {};
        auto read = io(co_await stream.async_read_some(buffer));
        if (!read || *read == 0) co_return false;
        input.insert(input.end(), buffer.begin(), buffer.begin() +
                     static_cast<std::ptrdiff_t>(*read));
        if (input.size() > 65536) co_return false;
    }
    co_return true;
}

[[nodiscard]] auto bytes(std::string_view text) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(text.data(), text.size()));
}

[[nodiscard]] auto base64(std::span<const unsigned char> data) -> std::string
{
    std::string result((data.size() + 2) / 3 * 4, '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(result.data()),
                    data.data(), static_cast<int>(data.size()));
    return result;
}

[[nodiscard]] auto trim(std::string_view text) -> std::string_view
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    return text;
}

[[nodiscard]] auto ascii_equal(std::string_view left,
                               std::string_view right) noexcept -> bool
{
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        auto lower = [](unsigned char value) -> unsigned char {
            return value >= 'A' && value <= 'Z'
                ? static_cast<unsigned char>(value - 'A' + 'a') : value;
        };
        if (lower(static_cast<unsigned char>(left[index])) !=
            lower(static_cast<unsigned char>(right[index]))) return false;
    }
    return true;
}

[[nodiscard]] auto has_token(std::string_view list,
                             std::string_view token) noexcept -> bool
{
    while (!list.empty()) {
        const auto separator = list.find(',');
        if (ascii_equal(trim(list.substr(0, separator)), token)) return true;
        if (separator == std::string_view::npos) break;
        list.remove_prefix(separator + 1);
    }
    return false;
}

[[nodiscard]] auto header(std::string_view response, std::string_view name)
    -> std::string_view
{
    auto start = response.find("\r\n");
    if (start == std::string_view::npos) return {};
    start += 2;
    while (start < response.size()) {
        auto end = response.find("\r\n", start);
        if (end == std::string_view::npos || end == start) break;
        auto line = response.substr(start, end - start);
        auto colon = line.find(':');
        if (colon != std::string_view::npos &&
            ascii_equal(line.substr(0, colon), name))
            return trim(line.substr(colon + 1));
        start = end + 2;
    }
    return {};
}

[[nodiscard]] auto frame(std::uint8_t opcode, std::span<const std::byte> payload)
    -> std::vector<std::byte>
{
    if (payload.size() > 4096) throw std::invalid_argument("message exceeds 4096 bytes");
    std::array<unsigned char, 4> mask {};
    if (RAND_bytes(mask.data(), static_cast<int>(mask.size())) != 1)
        throw std::runtime_error("random mask generation failed");
    std::vector<std::byte> result;
    result.reserve(payload.size() + 8);
    result.push_back(static_cast<std::byte>(0x80 | opcode));
    if (payload.size() < 126) {
        result.push_back(static_cast<std::byte>(0x80 | payload.size()));
    } else {
        result.push_back(std::byte {0xfe});
        result.push_back(static_cast<std::byte>((payload.size() >> 8) & 0xff));
        result.push_back(static_cast<std::byte>(payload.size() & 0xff));
    }
    for (auto octet : mask) result.push_back(static_cast<std::byte>(octet));
    for (std::size_t i = 0; i < payload.size(); ++i)
        result.push_back(payload[i] ^ static_cast<std::byte>(mask[i % 4]));
    return result;
}

template<typename Stream>
auto exchange(eventloop::event_loop& loop, Stream& stream,
              const url_parts& url, std::string_view message)
    -> eventloop::task<bool>
{
    std::array<unsigned char, 16> nonce {};
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1)
        throw std::runtime_error("random key generation failed");
    auto key = base64(nonce);
    const std::string request = "GET " + url.target + " HTTP/1.1\r\nHost: " +
        url.host_header + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n\r\n";
    auto sent = co_await write_all(loop, stream, bytes(request));
    if (!sent || !*sent) {
        std::cerr << "upgrade write failed\n"; co_return false;
    }
    std::vector<std::byte> input;
    std::size_t end = std::string::npos;
    while (end == std::string::npos && input.size() <= 16384) {
        auto received = co_await fill(loop, stream, input, input.size() + 1);
        if (!received || !*received) {
            std::cerr << "upgrade read failed\n"; co_return false;
        }
        std::string_view view(reinterpret_cast<const char*>(input.data()), input.size());
        end = view.find("\r\n\r\n");
    }
    if (end == std::string::npos) { std::cerr << "upgrade headers too large\n"; co_return false; }
    std::string_view response(reinterpret_cast<const char*>(input.data()), end + 4);
    if (!response.starts_with("HTTP/1.1 101 ")) {
        std::cerr << "upgrade rejected: " << response.substr(0, response.find("\r\n")) << '\n';
        co_return false;
    }
    std::string challenge = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int digest_size = 0;
    if (EVP_Digest(challenge.data(), challenge.size(), digest.data(),
                   &digest_size, EVP_sha1(), nullptr) != 1 ||
        header(response, "Sec-WebSocket-Accept") !=
            base64(std::span<const unsigned char>(digest.data(), digest_size)) ||
        !has_token(header(response, "Upgrade"), "websocket")) {
        std::cerr << "invalid upgrade response\n"; co_return false;
    }
    input.erase(input.begin(), input.begin() + static_cast<std::ptrdiff_t>(end + 4));
    auto outgoing = frame(1, bytes(message));
    sent = co_await write_all(loop, stream, outgoing);
    if (!sent || !*sent) {
        std::cerr << "message write failed\n"; co_return false;
    }
    for (unsigned count = 0; count < 16; ++count) {
        auto received = co_await fill(loop, stream, input, 2);
        if (!received || !*received) {
            std::cerr << "frame read failed\n"; co_return false;
        }
        auto first = std::to_integer<unsigned>(input[0]);
        auto second = std::to_integer<unsigned>(input[1]);
        if ((first & 0x70) != 0 || (second & 0x80) != 0 || (first & 0x80) == 0) {
            std::cerr << "unsupported or invalid frame\n"; co_return false;
        }
        std::size_t length = second & 0x7f;
        std::size_t offset = 2;
        if (length == 126) {
            received = co_await fill(loop, stream, input, 4);
            if (!received || !*received) co_return false;
            length = (std::to_integer<unsigned>(input[2]) << 8) |
                     std::to_integer<unsigned>(input[3]);
            offset = 4;
        } else if (length == 127) {
            std::cerr << "frame exceeds example limit\n"; co_return false;
        }
        received = co_await fill(loop, stream, input, offset + length);
        if (length > 4096 || !received || !*received) {
            std::cerr << "frame exceeds example limit or read failed\n"; co_return false;
        }
        auto payload = std::span<const std::byte>(input).subspan(offset, length);
        auto opcode = first & 0x0f;
        if (opcode == 1) {
            bool match = payload.size() == message.size() &&
                std::equal(payload.begin(), payload.end(), bytes(message).begin());
            if (match) {
                std::cout << "echo: " << message << '\n';
                co_return true;
            }
        }
        if (opcode == 8) { std::cerr << "server closed before echo\n"; co_return false; }
        if (opcode == 9) {
            auto pong = frame(10, payload);
            sent = co_await write_all(loop, stream, pong);
            if (!sent || !*sent) co_return false;
        }
        input.erase(input.begin(), input.begin() + static_cast<std::ptrdiff_t>(offset + length));
    }
    std::cerr << "too many control frames\n";
    co_return false;
}

auto run(eventloop::event_loop& loop, url_parts url, std::string message,
         bool& success) -> eventloop::task<void>
{
    try {
        auto resolved = co_await eventloop::run_blocking(
            loop, [host = url.hostname, port = url.port]() noexcept {
                return resolve_addresses(host, port);
            });
        if (!resolved || resolved->error || resolved->count == 0) {
            std::cerr << "DNS failed: " << (resolved && resolved->error
                ? ::gai_strerror(resolved->error) : "no addresses") << '\n';
            loop.stop(); co_return;
        }
        std::shared_ptr<eventloop::tls_context> context;
        if (url.secure) context = eventloop::tls_context::make_system_client();
        for (std::size_t i = 0; i < resolved->count; ++i) {
            if (url.secure) {
                auto owned = std::make_unique<eventloop::tls_stream>(
                    loop, resolved->endpoints[i], context,
                    eventloop::tls_client_options {.hostname = url.hostname,
                                                   .application_protocols = {"http/1.1"}});
                auto* stream = owned.get();
                loop.add(std::move(owned));
                auto connected = co_await stream->async_connect();
                if (!connected) { stream->close(); continue; }
                auto handshake = co_await stream->async_handshake();
                if (!handshake || !*handshake) {
                    std::cerr << "TLS handshake failed\n"; stream->close(); continue;
                }
                auto result = co_await exchange(loop, *stream, url, message);
                success = result && *result;
                stream->close(); break;
            }
            auto owned = std::make_unique<eventloop::tcp_stream>(loop, resolved->endpoints[i]);
            auto* stream = owned.get();
            loop.add(std::move(owned));
            auto connected = co_await stream->async_connect();
            if (!connected) { stream->close(); continue; }
            auto result = co_await exchange(loop, *stream, url, message);
            success = result && *result;
            stream->close(); break;
        }
        if (!success) std::cerr << "WebSocket exchange failed\n";
    } catch (const std::exception& error) {
        std::cerr << "WebSocket client failed: " << error.what() << '\n';
    }
    loop.stop();
}
} // namespace

auto main(int argc, char* argv[]) -> int
{
    std::string address, message = "eventloop echo";
    const std::array positionals {
        eventloop::arg_parser::positional {"URL", &address, true},
        eventloop::arg_parser::positional {"MESSAGE", &message, false},
    };
    eventloop::arg_parser arguments({}, positionals);
    arguments.set_usage("usage: websocket_client <ws:// or wss:// URL> [message]\n");
    arguments.parse(argc, argv);
    try {
        if (address.starts_with("wss://")) address.replace(0, 6, "https://");
        else if (address.starts_with("ws://")) address.replace(0, 5, "http://");
        else throw std::invalid_argument("URL must start with ws:// or wss://");
        auto url = parse_url(address);
        eventloop::event_loop_options options;
        options.worker_count = 1;
        eventloop::event_loop loop(options);
        bool success = false;
        if (loop.spawn(run(loop, std::move(url), message, success)) !=
            eventloop::task_spawn_result::accepted)
            throw std::runtime_error("cannot start WebSocket client task");
        if (loop.run() == eventloop::event_loop_result::interrupted) {
            loop.shutdown(std::chrono::seconds {0}); (void)loop.run();
        }
        return success ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
