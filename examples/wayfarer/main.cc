#include "http3.h"
#include "options.h"
#include "http_client_resolve.h"
#include "http_client_url.h"

#include "eventloop/event_loop.h"
#include "eventloop/task.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"
#include "eventloop/http2/client.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <netdb.h>
#endif

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace {
using namespace eventloop;
using http_client_example::url_parts;

auto fail(std::string_view message) -> void { std::cerr << "wayfarer: " << message << '\n'; }

auto safe_header(std::string_view value) -> bool
{
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return c >= 0x20 && c != 0x7f;
    });
}

auto read_bounded_body_file(const std::filesystem::path& path) -> std::string
{
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::invalid_argument("cannot open request body file");
    std::string body;
    std::array<char, 4096> chunk {};
    while (input) {
        input.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const auto count = static_cast<std::size_t>(input.gcount());
        if (count > 4 * 1024 * 1024 - body.size())
            throw std::invalid_argument("HTTP/1.1 request body file exceeds 4 MiB");
        body.append(chunk.data(), count);
    }
    if (!input.eof()) throw std::invalid_argument("cannot read request body file");
    return body;
}

auto percent_decode(std::string_view text) -> std::string
{
    std::string decoded;
    decoded.reserve(text.size());
    for (std::size_t index = 0; index < text.size(); ++index) {
        if (text[index] == '%' && index + 2 < text.size() &&
            std::isxdigit(static_cast<unsigned char>(text[index + 1])) &&
            std::isxdigit(static_cast<unsigned char>(text[index + 2]))) {
            const auto digit = [](char value) {
                return value <= '9' ? value - '0'
                    : std::tolower(static_cast<unsigned char>(value)) - 'a' + 10;
            };
            decoded.push_back(static_cast<char>(
                (digit(text[index + 1]) << 4) | digit(text[index + 2])));
            index += 2;
        } else {
            decoded.push_back(text[index]);
        }
    }
    return decoded;
}

// Derive the -O/--remote-name target from the request target. Percent escapes
// are decoded, the query and fragment are dropped, and only the final path
// component is used. Empty and dot components fall back to "index.html" so a
// directory request lands on a predictable name. Components that still carry a
// path separator or control byte are rejected rather than silently rewritten.
auto remote_output_name(std::string_view target) -> std::filesystem::path
{
    const auto separator = target.find_first_of("?#");
    const std::string path = percent_decode(target.substr(0, separator));
    const auto slash = path.rfind('/');
    std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
    if (name.empty() || name == "." || name == "..") name = "index.html";
    for (unsigned char character : name) {
        if (character < 0x20 || character == 0x7f ||
            character == '/' || character == '\\')
            throw std::invalid_argument("cannot derive a safe output name from the URL");
    }
#ifdef _WIN32
    const std::string stem = name.substr(0, name.find('.'));
    std::string upper(stem);
    std::transform(upper.begin(), upper.end(), upper.begin(),
        [](unsigned char character) { return static_cast<char>(std::toupper(character)); });
    constexpr std::array<std::string_view, 22> reserved {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"};
    if (name.find_first_of("<>:\"|?*") != std::string::npos ||
        std::find(reserved.begin(), reserved.end(), upper) != reserved.end() ||
        name.ends_with('.') || name.ends_with(' '))
        throw std::invalid_argument("cannot derive a safe output name from the URL");
#endif
    return std::filesystem::path(name);
}

auto parse_options(int argc, char** argv) -> request_options
{
    request_options options;
    bool explicit_method = false;
    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        auto value = [&]() -> std::string {
            if (++i == argc) throw std::invalid_argument("missing value for " + std::string(arg));
            return argv[i];
        };
        if (arg == "--http1.1") options.protocol = 1;
        else if (arg == "--http2") options.protocol = 2;
        else if (arg == "--http3") options.protocol = 3;
        else if (arg == "--http3-v2") { options.protocol = 3; options.quic_version = quic_version::v2; }
        else if (arg == "-X" || arg == "--request") { options.method = value(); explicit_method = true; }
        else if (arg == "-H" || arg == "--header") {
            const auto header = value();
            const auto pos = header.find(':');
            if (pos == std::string::npos || pos == 0) throw std::invalid_argument("header needs Name: value");
            std::string name = header.substr(0, pos);
            std::string val = header.substr(pos + 1);
            if (!val.empty() && val.front() == ' ') val.erase(0, 1);
            if (!safe_header(val) || !std::all_of(name.begin(), name.end(), [](unsigned char c) {
                    return std::isalnum(c) || std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) != std::string_view::npos;
                })) throw std::invalid_argument("invalid header");
            std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (name == "host" || name == "connection" || name == "content-length" || name == "transfer-encoding")
                throw std::invalid_argument("Host, Connection, Content-Length and Transfer-Encoding are managed by wayfarer");
            options.headers.emplace_back(std::move(name), std::move(val));
        } else if (arg == "-d" || arg == "--data") {
            options.body = value();
            options.body_file.clear();
            options.body_supplied = true;
        }
        else if (arg == "--data-binary") {
            const auto data = value();
            if (data.starts_with('@')) {
                if (data.size() == 1) throw std::invalid_argument("--data-binary @ requires a file path");
                options.body_file = data.substr(1);
                options.body.clear();
            } else {
                options.body = data;
                options.body_file.clear();
            }
            options.body_supplied = true;
        }
        else if (arg == "-o" || arg == "--output") options.output = value();
        else if (arg == "-O" || arg == "--remote-name") options.remote_name = true;
        else if (arg == "-I" || arg == "--head") options.head_request = true;
        else if (arg == "-i" || arg == "--include") options.show_headers = true;
        else if (arg == "-L" || arg == "--location") options.follow_redirects = true;
        else if (arg == "--fail") options.fail_http_errors = true;
        else if (arg == "--ca-file") options.ca_file = value();
        else if (arg == "--timeout-ms") {
            const auto input = value();
            unsigned duration {};
            const auto result = std::from_chars(input.data(), input.data() + input.size(), duration);
            if (result.ec != std::errc{} || result.ptr != input.data() + input.size() ||
                duration == 0 || duration > 3600000) throw std::invalid_argument("timeout must be 1..3600000 ms");
            options.timeout = std::chrono::milliseconds(duration);
        } else if (arg.starts_with('-')) throw std::invalid_argument("unknown option " + std::string(arg));
        else if (!options.url.empty()) throw std::invalid_argument("only one URL is supported per invocation");
        else options.url = arg;
    }
    if (options.url.empty()) throw std::invalid_argument("URL required");
    if (options.head_request) {
        if (explicit_method && options.method != "HEAD")
            throw std::invalid_argument("-I/--head conflicts with -X " + options.method);
        options.method = "HEAD";
        options.show_headers = true;
    }
    if (options.method.empty() || !std::all_of(options.method.begin(), options.method.end(), [](unsigned char c) {
            return std::isupper(c) || std::isdigit(c) || std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) != std::string_view::npos;
        })) throw std::invalid_argument("invalid request method");
    if (options.body_supplied && options.method == "GET") options.method = "POST";
    if (options.head_request && options.body_supplied)
        throw std::invalid_argument("-I/--head cannot send a request body");
    if (options.body.size() > 4 * 1024 * 1024)
        throw std::invalid_argument("request body exceeds 4 MiB");
    if (options.protocol == 3 && (options.method != "GET" && options.method != "HEAD"))
        throw std::invalid_argument("HTTP/3 supports GET and HEAD only");
    if (options.protocol == 3 && (options.body_supplied || !options.headers.empty()))
        throw std::invalid_argument("HTTP/3 request bodies and custom headers are unsupported");
    if (options.remote_name && !options.output.empty())
        throw std::invalid_argument("-O/--remote-name and -o/--output are mutually exclusive");
    if (options.protocol == 1 && !options.body_file.empty()) {
        options.body = read_bounded_body_file(options.body_file);
        options.body_file.clear();
    }
    return options;
}

template<class T>
auto io_result(std::expected<T, std::error_code> result) -> std::expected<T, std::error_code> { return result; }
template<class T>
auto io_result(std::expected<std::expected<T, std::error_code>, task_result> result) -> std::expected<T, std::error_code>
{
    if (result) return std::move(*result);
    return std::unexpected(std::make_error_code(result.error() == task_result::frame_allocation_failure
        ? std::errc::not_enough_memory : std::errc::operation_canceled));
}

auto redirect_status(unsigned status) -> bool;
auto redirect_url(const url_parts& current, std::string_view location) -> url_parts;
auto same_origin(const url_parts& left, const url_parts& right) -> bool;

struct response_reader {
    enum class phase { headers, body, chunk_size, chunk_data, chunk_end, trailers, done } current {phase::headers};
    std::string pending;
    std::optional<std::uint64_t> remaining;
    std::uint64_t chunk_remaining {};
    unsigned status {};
    bool chunked {}, saw_final {}, follow_redirects {}, redirect_response {};
    std::string location;
    std::FILE* output {};
    bool show_headers {}, head_request {};

    auto write(std::string_view bytes) -> bool
    {
        return bytes.empty() || std::fwrite(bytes.data(), 1, bytes.size(), output) == bytes.size();
    }
    auto fail_response(std::string_view reason) -> bool { fail(reason); return false; }
    auto consume(std::string_view bytes) -> bool
    {
        pending.append(bytes);
        for (;;) {
            if (current == phase::headers) {
                const auto end = pending.find("\r\n\r\n");
                if (end == std::string::npos) return pending.size() <= 65536 || fail_response("response headers exceed 64 KiB");
                const std::string block = pending.substr(0, end + 4);
                pending.erase(0, end + 4);
                const auto line_end = block.find("\r\n");
                if (line_end == std::string::npos || !std::string_view(block).starts_with("HTTP/1.")) return fail_response("invalid HTTP response");
                const auto first = std::string_view(block).substr(0, line_end);
                if (first.size() < 12 || first[8] != ' ' ||
                    std::from_chars(first.data() + 9, first.data() + 12, status).ec != std::errc{}) return fail_response("invalid HTTP status");
                if (status >= 100 && status < 200) {
                    if (status == 101) return fail_response("protocol upgrade is unsupported");
                    if (show_headers && !write(block)) return fail_response("output write failed");
                    continue;
                }
                saw_final = true;
                chunked = false; remaining.reset();
                std::size_t start = line_end + 2;
                while (start < end) {
                    const auto finish = block.find("\r\n", start);
                    if (finish == std::string::npos || finish > end) return fail_response("invalid response field");
                    const auto line = std::string_view(block).substr(start, finish - start);
                    const auto colon = line.find(':');
                    if (colon == std::string_view::npos) return fail_response("invalid response field");
                    std::string name(line.substr(0, colon));
                    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    auto value = line.substr(colon + 1);
                    while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
                    if (name == "content-length") {
                        std::uint64_t count {};
                        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), count);
                        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || remaining)
                            return fail_response("invalid Content-Length");
                        remaining = count;
                    } else if (name == "transfer-encoding") {
                        std::string transfer(value);
                        std::transform(transfer.begin(), transfer.end(), transfer.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                        if (transfer != "chunked") return fail_response("unsupported Transfer-Encoding");
                        chunked = true;
                    } else if (name == "location" && location.empty()) {
                        location = value;
                    }
                    start = finish + 2;
                }
                redirect_response = follow_redirects &&
                    (status == 301 || status == 302 || status == 303 || status == 307 || status == 308);
                if (show_headers && !write(block)) return fail_response("output write failed");
                std::cerr << "HTTP/1.1 " << status << '\n';
                if (redirect_response) { current = phase::done; return true; }
                if (head_request || status == 204 || status == 304) current = phase::done;
                else if (chunked) current = phase::chunk_size;
                else if (remaining && *remaining == 0) current = phase::done;
                else current = phase::body;
            } else if (current == phase::body) {
                const auto n = remaining ? static_cast<std::size_t>(std::min<std::uint64_t>(*remaining, pending.size())) : pending.size();
                if (!write(std::string_view(pending).substr(0, n))) return fail_response("output write failed");
                pending.erase(0, n);
                if (remaining) {
                    *remaining -= n;
                    if (*remaining == 0) current = phase::done;
                }
                return true;
            } else if (current == phase::chunk_size) {
                const auto end = pending.find("\r\n");
                if (end == std::string::npos) return pending.size() <= 128 || fail_response("chunk size line too long");
                const auto line = std::string_view(pending).substr(0, end);
                const auto extension = line.find(';');
                const auto size_text = line.substr(0, extension);
                const auto parsed = std::from_chars(size_text.data(), size_text.data() + size_text.size(), chunk_remaining, 16);
                if (size_text.empty() || parsed.ec != std::errc{} || parsed.ptr != size_text.data() + size_text.size())
                    return fail_response("invalid chunk size");
                pending.erase(0, end + 2);
                current = chunk_remaining ? phase::chunk_data : phase::trailers;
            } else if (current == phase::chunk_data) {
                const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(chunk_remaining, pending.size()));
                if (!write(std::string_view(pending).substr(0, n))) return fail_response("output write failed");
                pending.erase(0, n); chunk_remaining -= n;
                if (chunk_remaining) return true;
                current = phase::chunk_end;
            } else if (current == phase::chunk_end) {
                if (pending.size() < 2) return true;
                if (!pending.starts_with("\r\n")) return fail_response("invalid chunk terminator");
                pending.erase(0, 2); current = phase::chunk_size;
            } else if (current == phase::trailers) {
                if (pending.starts_with("\r\n")) { pending.erase(0, 2); current = phase::done; continue; }
                const auto end = pending.find("\r\n\r\n");
                if (end == std::string::npos) return pending.size() <= 65536 || fail_response("trailers exceed 64 KiB");
                pending.erase(0, end + 4); current = phase::done;
            } else return true;
        }
    }
    auto complete() const -> bool { return saw_final && (current == phase::done || (current == phase::body && !remaining)); }
};

template<class Stream>
auto exchange(event_loop& loop, Stream& stream, const url_parts& url, const request_options& options,
              std::FILE* output, unsigned& final_status, std::string& location) -> task<bool>
{
    (void)loop;
    std::string request = options.method + " " + url.target + " HTTP/1.1\r\nHost: " + url.host_header + "\r\nConnection: close\r\n";
    for (const auto& [name, value] : options.headers) request += name + ": " + value + "\r\n";
    if (options.body_supplied) request += "Content-Length: " + std::to_string(options.body.size()) + "\r\n";
    request += "\r\n";
    request += options.body;
    auto bytes = std::as_bytes(std::span(request.data(), request.size()));
    while (!bytes.empty()) {
        const auto written = io_result(co_await stream.async_write_some(bytes));
        if (!written || *written == 0) { fail("request write failed"); co_return false; }
        bytes = bytes.subspan(*written);
    }
    response_reader reader;
    reader.output = output; reader.show_headers = options.show_headers;
    reader.follow_redirects = options.follow_redirects;
    reader.head_request = options.method == "HEAD";
    std::array<std::byte, 1024> buffer {};
    for (;;) {
        const auto received = io_result(co_await stream.async_read_some(buffer));
        if (!received) { fail("response read failed: " + received.error().message()); co_return false; }
        if (*received == 0) break;
        if (!reader.consume(std::string_view(reinterpret_cast<const char*>(buffer.data()), *received))) co_return false;
        if (reader.current == response_reader::phase::done) break;
    }
    if (!reader.complete()) { fail("truncated HTTP response"); co_return false; }
    if (!reader.redirect_response && std::fflush(output) != 0) { fail("output flush failed"); co_return false; }
    final_status = reader.status;
    location = std::move(reader.location);
    co_return true;
}

auto fetch_http1(event_loop& loop, const url_parts& url, const request_options& options,
                 std::FILE* output, request_state& state, bool& success, unsigned& final_status) -> task<void>
{
    url_parts current = url;
    request_options request = options;
    std::unordered_set<std::string> visited;
    for (unsigned hop = 0; hop <= 10 && !state.expired; ++hop) {
        std::string host = current.hostname;
        std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        const std::string identity = (current.secure ? "https://" : "http://") + host +
            ':' + std::to_string(current.port) + current.target + '\n' + request.method;
        if (!visited.insert(identity).second) { fail("redirect loop detected"); co_return; }
        auto addresses = co_await run_blocking(loop, [host = current.hostname, port = current.port]() noexcept {
            return http_client_example::resolve_addresses(host, port);
        });
        if (!addresses || addresses->error || addresses->count == 0) { fail("DNS lookup failed"); co_return; }
        std::shared_ptr<tls_context> tls;
        if (current.secure) tls = options.ca_file.empty() ? tls_context::make_system_client() : tls_context::make_client(options.ca_file);
        bool connected_and_exchanged = false;
        std::string location;
        for (std::size_t i = 0; i < addresses->count && !state.expired; ++i) {
            if (current.secure) {
                auto socket = std::make_unique<tls_stream>(loop, addresses->endpoints[i], tls,
                    tls_client_options {.hostname = current.hostname, .application_protocols = {"http/1.1"}});
                auto* stream = socket.get(); loop.add(std::move(socket)); state.socket = stream;
                const auto connected = co_await stream->async_connect();
                if (!connected) { stream->close(); state.socket = nullptr; continue; }
                const auto handshake = io_result(co_await stream->async_handshake());
                if (!handshake) { fail("TLS handshake failed: " + handshake.error().message()); stream->close(); state.socket = nullptr; co_return; }
                const auto result = co_await exchange(loop, *stream, current, request, output, final_status, location);
                connected_and_exchanged = result && *result;
                stream->close(); state.socket = nullptr;
            } else {
                auto socket = std::make_unique<tcp_stream>(loop, addresses->endpoints[i]);
                auto* stream = socket.get(); loop.add(std::move(socket)); state.socket = stream;
                const auto connected = co_await stream->async_connect();
                if (!connected) { stream->close(); state.socket = nullptr; continue; }
                const auto result = co_await exchange(loop, *stream, current, request, output, final_status, location);
                connected_and_exchanged = result && *result;
                stream->close(); state.socket = nullptr;
            }
            if (!connected_and_exchanged) co_return;
            break;
        }
        if (!connected_and_exchanged) { if (!state.expired) fail("all connection attempts failed"); co_return; }
        if (!options.follow_redirects || !redirect_status(final_status)) { success = true; co_return; }
        if (location.empty()) { fail("redirect response has no Location"); co_return; }
        if (hop == 10) { fail("redirect limit of 10 reached"); co_return; }
        url_parts next;
        try { next = redirect_url(current, location); }
        catch (const std::exception& error) { fail(error.what()); co_return; }
        if (current.secure && !next.secure) { fail("HTTPS to HTTP redirect is unsupported"); co_return; }
        if (!same_origin(current, next)) {
            std::erase_if(request.headers, [](const auto& field) {
                return field.first == "authorization" || field.first == "cookie" || field.first == "proxy-authorization";
            });
        }
        if ((final_status == 303 && request.method != "HEAD") ||
            ((final_status == 301 || final_status == 302) && request.method == "POST")) {
            request.method = "GET"; request.body.clear(); request.body_file.clear();
            request.body_supplied = false;
            std::erase_if(request.headers, [](const auto& field) {
                return field.first == "content-type" || field.first == "content-encoding" ||
                    field.first == "content-length" || field.first == "transfer-encoding";
            });
        }
        current = std::move(next);
    }
}

auto redirect_status(unsigned status) -> bool
{
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

auto redirect_url(const url_parts& current, std::string_view location) -> url_parts
{
    if (location.empty()) throw std::invalid_argument("empty redirect Location");
    const std::string scheme = current.secure ? "https:" : "http:";
    const std::string origin = scheme + "//" + current.host_header;
    const auto separator = location.find(':');
    const auto path_start = location.find_first_of("/?#");
    if (separator != std::string_view::npos &&
        (path_start == std::string_view::npos || separator < path_start)) {
        std::string absolute(location);
        std::transform(absolute.begin(), absolute.begin() + separator, absolute.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return http_client_example::parse_url(absolute);
    }
    if (location.starts_with("//"))
        return http_client_example::parse_url(scheme + std::string(location));
    if (location.starts_with('/'))
        return http_client_example::parse_url(origin + std::string(location));
    if (location.starts_with('#'))
        return http_client_example::parse_url(origin + current.target + std::string(location));
    if (location.starts_with('?')) {
        const auto question = current.target.find('?');
        return http_client_example::parse_url(origin + current.target.substr(0, question) + std::string(location));
    }
    const auto question = current.target.find('?');
    const auto path = current.target.substr(0, question);
    const auto slash = path.rfind('/');
    std::string combined = path.substr(0, slash + 1) + std::string(location);
    const auto suffix = combined.find_first_of("?#");
    const std::string path_only = combined.substr(0, suffix);
    std::vector<std::string_view> segments;
    std::string_view remainder(path_only);
    while (!remainder.empty()) {
        const auto separator = remainder.find('/', 1);
        const auto segment = remainder.substr(1, separator == std::string_view::npos
            ? std::string_view::npos : separator - 1);
        if (segment == "..") { if (!segments.empty()) segments.pop_back(); }
        else if (segment != "." && !segment.empty()) segments.push_back(segment);
        if (separator == std::string_view::npos) break;
        remainder.remove_prefix(separator);
    }
    std::string normalized = "/";
    for (const auto segment : segments) {
        if (normalized.size() > 1) normalized += '/';
        normalized += segment;
    }
    if (path_only.ends_with('/') || path_only.ends_with("/.") || path_only.ends_with("/..")) {
        if (!normalized.ends_with('/')) normalized += '/';
    }
    if (suffix != std::string::npos) normalized += combined.substr(suffix);
    return http_client_example::parse_url(origin + normalized);
}

auto same_origin(const url_parts& left, const url_parts& right) -> bool
{
    if (left.secure != right.secure || left.port != right.port || left.hostname.size() != right.hostname.size())
        return false;
    return std::equal(left.hostname.begin(), left.hostname.end(), right.hostname.begin(),
        [](unsigned char a, unsigned char b) { return std::tolower(a) == std::tolower(b); });
}

auto fetch_http2(event_loop& loop, const url_parts& url, const request_options& options,
                 std::FILE* output, request_state& state, bool& success, unsigned& final_status) -> task<void>
{
    auto tls = options.ca_file.empty() ? tls_context::make_system_client() : tls_context::make_client(options.ca_file);
    url_parts current = url;
    std::string method = options.method;
    std::string body = options.body;
    std::filesystem::path body_file = options.body_file;
    auto custom_headers = options.headers;
    std::optional<http2::client_connection> connection;
    for (unsigned hop = 0; hop <= 10 && !state.expired; ++hop) {
        auto addresses = co_await run_blocking(loop, [host = current.hostname, port = current.port]() noexcept {
            return http_client_example::resolve_addresses(host, port);
        });
        if (!addresses || addresses->error || addresses->count == 0) { fail("DNS lookup failed"); co_return; }
        // RFC 9113 9.1.1: a redirect to a host the open connection is
        // authoritative for, at one of the host's addresses, reuses it.
        const auto endpoints = std::span(addresses->endpoints).first(addresses->count);
        const bool reused = connection && std::any_of(endpoints.begin(), endpoints.end(),
            [&](const ip_endpoint& endpoint) { return connection->can_reuse_for(current.hostname, endpoint); });
        if (connection && !reused) { (void)co_await connection->async_close(); connection.reset(); }
        bool redirected = false;
        // Attempt 0 uses the reused connection; attempt i connects to address i - 1.
        for (std::size_t attempt = reused ? 0 : 1; attempt <= addresses->count && !state.expired; ++attempt) {
            if (attempt != 0) {
                connection.reset();
                connection.emplace(loop, endpoints[attempt - 1], tls, current.hostname);
                auto connected = io_result(co_await connection->async_connect());
                if (!connected) {
                    if (!state.expired) fail("HTTP/2 request failed: " + connected.error().message());
                    continue;
                }
            }
            http2::client_request request;
            request.method = method;
            request.target = current.target;
            request.authority = current.host_header;
            for (const auto& [name, value] : custom_headers) request.headers.push_back({name, value});
            const auto body_bytes = std::as_bytes(std::span(body.data(), body.size()));
            request.body.assign(body_bytes.begin(), body_bytes.end());
            if (!body_file.empty()) {
                auto file = std::make_unique<std::ifstream>(body_file, std::ios::binary);
                if (!file->is_open()) { fail("cannot open request body file"); co_return; }
                request.body_source = [file = std::move(file)](std::span<std::byte> buffer)
                    -> std::expected<std::size_t, std::error_code> {
                    file->read(reinterpret_cast<char*>(buffer.data()),
                        static_cast<std::streamsize>(buffer.size()));
                    if (file->bad() || (!*file && !file->eof()))
                        return std::unexpected(std::make_error_code(std::errc::io_error));
                    return static_cast<std::size_t>(file->gcount());
                };
            }
            // 421 on a reused connection: the server is not authoritative for
            // this host there, so retry on a new connection (RFC 9110 15.5.20).
            bool wrote_output = false, redirect_response = false, misdirected = false;
            std::string location;
            http2::response_sink sink = [&](std::span<const std::byte> chunk) -> std::error_code {
                if (chunk.empty() || redirect_response || misdirected) return {};
                wrote_output = true;
                if (std::fwrite(chunk.data(), 1, chunk.size(), output) != chunk.size())
                    return std::make_error_code(std::errc::io_error);
                return {};
            };
            http2::response_header_sink headers_sink = [&](unsigned status,
                std::span<const http2::header> fields) -> std::error_code {
                if (status == 421 && attempt == 0) misdirected = true;
                if (misdirected) return {};
                if (options.follow_redirects && redirect_status(status)) {
                    for (const auto& field : fields)
                        if (field.name == "location") { location = field.value; break; }
                    redirect_response = !location.empty();
                }
                if (!options.show_headers) return {};
                wrote_output = true;
                if (status != 0) {
                    const auto line = "HTTP/2 " + std::to_string(status) + "\r\n";
                    if (std::fwrite(line.data(), 1, line.size(), output) != line.size())
                        return std::make_error_code(std::errc::io_error);
                }
                for (const auto& field : fields) {
                    const auto line = field.name + ": " + field.value + "\r\n";
                    if (std::fwrite(line.data(), 1, line.size(), output) != line.size())
                        return std::make_error_code(std::errc::io_error);
                }
                if (std::fwrite("\r\n", 1, 2, output) != 2)
                    return std::make_error_code(std::errc::io_error);
                return {};
            };
            auto response = io_result(co_await connection->async_request(
                std::move(request), std::move(sink), std::move(headers_sink)));
            if (!response) {
                if (!state.expired && (attempt != 0 || wrote_output))
                    fail("HTTP/2 request failed: " + response.error().message());
                if (wrote_output) co_return;
                continue;
            }
            if (misdirected) continue;
            std::cerr << "HTTP/2 " << response->status << '\n';
            if (!redirect_response) {
                if (std::fflush(output) != 0) { fail("output flush failed"); co_return; }
                final_status = response->status;
                success = true;
                (void)co_await connection->async_close();
                co_return;
            }
            if (hop == 10) { fail("redirect limit of 10 reached"); co_return; }
            url_parts next;
            try { next = redirect_url(current, location); }
            catch (const std::exception& error) { fail(error.what()); co_return; }
            if (!next.secure) { fail("HTTP/2 redirect to non-HTTPS URL is unsupported"); co_return; }
            if (!same_origin(current, next)) {
                std::erase_if(custom_headers, [](const auto& field) {
                    return field.first == "authorization" || field.first == "cookie" || field.first == "proxy-authorization";
                });
            }
            if ((response->status == 303 && method != "HEAD") ||
                ((response->status == 301 || response->status == 302) && method == "POST")) {
                method = "GET"; body.clear(); body_file.clear();
                std::erase_if(custom_headers, [](const auto& field) {
                    return field.first == "content-type" || field.first == "content-encoding";
                });
            }
            current = std::move(next);
            redirected = true;
            break;
        }
        if (!redirected) { if (!state.expired) fail("all HTTP/2 connection attempts failed"); co_return; }
    }
}

auto deadline(event_loop& loop, request_state& state, std::chrono::milliseconds duration) -> task<void>
{
    if (co_await sleep_for(loop, duration) == timer_wait_result::expired) {
        state.expired = true;
        fail("overall timeout");
        if (state.socket) state.socket->close();
        if (state.endpoint) state.endpoint->close();
        if (!state.socket && !state.endpoint && state.operation)
            (void)state.operation->cancel();
    }
}

auto run_request(event_loop& loop, url_parts url, const request_options& options,
                 std::FILE* output, bool& success, unsigned& final_status) -> task<void>
{
    request_state state;
    task_handle<void> timer, operation;
    state.operation = &operation;
    const bool timer_started = loop.spawn(deadline(loop, state, options.timeout), timer) == task_spawn_result::accepted;
    const bool operation_started = timer_started && loop.spawn(
        options.protocol == 3 ? fetch_http3(loop, url, options, output, state, success, final_status)
        : options.protocol == 2 ? fetch_http2(loop, url, options, output, state, success, final_status)
                                : fetch_http1(loop, url, options, output, state, success, final_status), operation) == task_spawn_result::accepted;
    if (operation_started) (void)co_await operation;
    if (timer_started) { (void)timer.cancel(); (void)co_await timer; }
    if (!operation_started) fail("request task capacity exhausted");
    if (!operation_started || state.expired) success = false;
    loop.stop();
}

struct temporary_output {
    struct file_closer {
        auto operator()(std::FILE* file) const -> void { if (file) (void)std::fclose(file); }
    };
    std::filesystem::path target, temporary;
    std::unique_ptr<std::FILE, file_closer> file;

    explicit temporary_output(const std::filesystem::path& path) : target(path)
    {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        for (unsigned attempt = 0; attempt < 100; ++attempt) {
            temporary = target;
            temporary += ".wayfarer-" + std::to_string(nonce) + "-" + std::to_string(attempt) + ".tmp";
#ifdef _WIN32
            file.reset(::_wfopen(temporary.c_str(), L"wbx"));
#else
            file.reset(std::fopen(temporary.c_str(), "wbx"));
#endif
            if (file) return;
            if (errno != EEXIST) break;
        }
        throw std::runtime_error("cannot create temporary output file");
    }

    ~temporary_output()
    {
        file.reset();
        if (!temporary.empty()) {
            std::error_code ignored;
            std::filesystem::remove(temporary, ignored);
        }
    }

    auto commit() -> void
    {
        if (std::fclose(file.release()) != 0) throw std::runtime_error("output close failed");
#ifdef _WIN32
        if (!::MoveFileExW(temporary.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING))
            throw std::runtime_error("cannot replace output file");
#else
        std::error_code error;
        std::filesystem::rename(temporary, target, error);
        if (error) throw std::runtime_error("cannot replace output file: " + error.message());
#endif
        temporary.clear();
    }
};
} // namespace

auto main(int argc, char** argv) -> int
{
    try {
        if (argc == 2 && std::string_view(argv[1]) == "--help") {
            std::cout << "usage: wayfarer [--http1.1|--http2|--http3|--http3-v2] "
                         "[-X METHOD] [-H 'Name: value']... [-d BODY|--data-binary @FILE] "
                         "[-o FILE|-O|--remote-name] [-I|--head] [-i] [-L] [--fail] "
                         "[--ca-file PEM] [--timeout-ms N] URL\n";
            return 0;
        }
        auto options = parse_options(argc, argv);
        const auto url = http_client_example::parse_url(options.url);
        if (options.remote_name) options.output = remote_output_name(url.target);
        if (options.protocol == 3 && !url.secure) throw std::invalid_argument("HTTP/3 requires https://");
        if (options.protocol == 2 && !url.secure) throw std::invalid_argument("HTTP/2 requires https://");
        if (options.remote_name)
            std::cerr << "wayfarer: saving to " << options.output.string() << '\n';
#ifdef _WIN32
        if (options.output.empty()) (void)::_setmode(::_fileno(stdout), _O_BINARY);
#endif
        std::unique_ptr<temporary_output> owned;
        std::FILE* output = stdout;
        if (!options.output.empty()) {
            owned = std::make_unique<temporary_output>(options.output);
            output = owned->file.get();
        }
        event_loop_options settings; settings.worker_count = 1;
        event_loop loop(settings);
        bool success = false;
        unsigned final_status = 0;
        if (loop.spawn(run_request(loop, url, options, output, success, final_status)) != task_spawn_result::accepted)
            throw std::runtime_error("cannot start request task");
        if (loop.run() == event_loop_result::interrupted) {
            loop.shutdown(std::chrono::seconds{0});
            (void)loop.run();
        }
        if (!success) return 1;
        if (options.fail_http_errors && final_status >= 400 && final_status <= 599) {
            fail("HTTP status " + std::to_string(final_status));
            return 22;
        }
        if (owned) owned->commit();
        return 0;
    } catch (const std::runtime_error& error) {
        std::cerr << "wayfarer: " << error.what() << '\n';
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "wayfarer: " << error.what() << '\n';
        return 2;
    }
}
