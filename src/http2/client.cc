#include "eventloop/http2/client.h"

#include "eventloop/tls_stream.h"
#include "hpack.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>

namespace eventloop::http2 {
namespace detail {
class client_access {
public:
    static auto remove(event_loop& loop, native_socket descriptor) -> void
    {
        loop.remove(descriptor);
    }
    static auto certificate_matches(const tls_stream& stream, std::string_view hostname)
        -> bool
    {
        return stream.certificate_matches(hostname);
    }
};
} // namespace detail
namespace {

constexpr std::size_t max_body = 4 * 1024 * 1024;
constexpr std::size_t max_frame = 16 * 1024;
constexpr std::uint64_t max_streamed_body = std::uint64_t{1} << 40;
constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

[[nodiscard]] auto failure(std::errc code) -> std::error_code
{
    return std::make_error_code(code);
}

[[nodiscard]] auto task_failure(task_result result) -> std::error_code
{
    return failure(result == task_result::frame_allocation_failure
        ? std::errc::not_enough_memory : std::errc::operation_canceled);
}

template<class T>
[[nodiscard]] auto unwrap(std::expected<std::expected<T, std::error_code>,
                                        task_result> result)
    -> std::expected<T, std::error_code>
{
    if (!result) return std::unexpected(task_failure(result.error()));
    return std::move(*result);
}

[[nodiscard]] auto write_all(event_loop& loop, tls_stream& stream,
                             std::span<const std::byte> bytes)
    -> task<std::expected<void, std::error_code>>
{
    (void)loop;
    while (!bytes.empty()) {
        auto sent = unwrap(co_await stream.async_write_some(bytes));
        if (!sent) co_return std::unexpected(sent.error());
        if (*sent == 0) co_return std::unexpected(failure(std::errc::broken_pipe));
        bytes = bytes.subspan(*sent);
    }
    co_return std::expected<void, std::error_code>{};
}

[[nodiscard]] auto read_exact(event_loop& loop, tls_stream& stream,
                              std::span<std::byte> bytes)
    -> task<std::expected<void, std::error_code>>
{
    (void)loop;
    while (!bytes.empty()) {
        auto received = unwrap(co_await stream.async_read_some(bytes));
        if (!received) co_return std::unexpected(received.error());
        if (*received == 0) co_return std::unexpected(failure(std::errc::connection_reset));
        bytes = bytes.subspan(*received);
    }
    co_return std::expected<void, std::error_code>{};
}

[[nodiscard]] auto u32(const std::byte* p) -> std::uint32_t
{
    return (std::uint32_t(std::to_integer<unsigned char>(p[0])) << 24) |
           (std::uint32_t(std::to_integer<unsigned char>(p[1])) << 16) |
           (std::uint32_t(std::to_integer<unsigned char>(p[2])) << 8) |
            std::uint32_t(std::to_integer<unsigned char>(p[3]));
}

auto put_u32(std::byte* p, std::uint32_t value) -> void
{
    p[0] = std::byte((value >> 24) & 255);
    p[1] = std::byte((value >> 16) & 255);
    p[2] = std::byte((value >> 8) & 255);
    p[3] = std::byte(value & 255);
}

auto frame_header(std::byte* p, std::size_t length, unsigned type,
                  unsigned flags, std::uint32_t stream_id) -> void
{
    p[0] = std::byte((length >> 16) & 255);
    p[1] = std::byte((length >> 8) & 255);
    p[2] = std::byte(length & 255);
    p[3] = std::byte(type);
    p[4] = std::byte(flags);
    put_u32(p + 5, stream_id);
}

[[nodiscard]] auto valid_name(std::string_view name) -> bool
{
    if (name.empty() || name.front() == ':') return false;
    for (unsigned char c : name) {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            std::string_view("!#$%&'*+-.^_`|~").find(char(c)) != std::string_view::npos)
            continue;
        return false;
    }
    return true;
}

[[nodiscard]] auto valid_method(std::string_view method) -> bool
{
    if (method.empty()) return false;
    for (unsigned char c : method) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            std::string_view("!#$%&'*+-.^_`|~").find(char(c)) != std::string_view::npos)
            continue;
        return false;
    }
    return true;
}

[[nodiscard]] auto valid_value(std::string_view value) -> bool
{
    if (!value.empty() && (value.front() == ' ' || value.front() == '\t' ||
                           value.back() == ' ' || value.back() == '\t'))
        return false;
    for (unsigned char c : value)
        if (c == 0x7f || (c < 0x20 && c != '\t')) return false;
    return true;
}

[[nodiscard]] auto valid_target(std::string_view value) -> bool
{
    if (value.empty() || value.front() != '/' || value.find('#') != std::string_view::npos)
        return false;
    for (unsigned char c : value) if (c <= 0x20 || c == 0x7f) return false;
    return true;
}

// RFC 9113 section 8.2.2. TE is allowed only in requests, as "trailers".
[[nodiscard]] auto connection_specific(const std::string_view name) -> bool
{
    return name == "connection" || name == "upgrade" || name == "keep-alive" ||
           name == "proxy-connection" || name == "transfer-encoding";
}

// Every content-length field must hold the same decimal value. Absent returns
// an empty optional; a malformed or conflicting value returns an error.
[[nodiscard]] auto content_length(std::span<const header> headers)
    -> std::expected<std::optional<std::uint64_t>, std::error_code>
{
    std::optional<std::uint64_t> length;
    for (const auto& item : headers) {
        if (item.name != "content-length") continue;
        std::uint64_t value = 0;
        const auto* end = item.value.data() + item.value.size();
        const auto parsed = std::from_chars(item.value.data(), end, value);
        if (parsed.ec != std::errc{} || parsed.ptr != end || (length && *length != value))
            return std::unexpected(failure(std::errc::protocol_error));
        length = value;
    }
    return length;
}

[[nodiscard]] auto parse_headers(std::span<const std::byte> block,
                                 detail::hpack_decoder& decoder,
                                 client_response& response, bool initial)
    -> std::error_code
{
    std::vector<detail::field> fields;
    const auto decoded = decoder.decode(block, fields);
    if (decoded == detail::hpack_error::limit_exceeded)
        return failure(std::errc::message_size);
    if (decoded != detail::hpack_error::none)
        return failure(std::errc::protocol_error);
    bool status_seen = false;
    bool regular_seen = false;
    if (response.headers.size() + fields.size() > detail::hpack_max_fields)
        return failure(std::errc::message_size);
    for (auto& field : fields) {
        if (field.name == ":status" && initial && !status_seen && response.status == 0) {
            if (regular_seen) return failure(std::errc::protocol_error);
            if (field.value.size() != 3) return failure(std::errc::protocol_error);
            unsigned value = 0;
            const auto parsed = std::from_chars(field.value.data(),
                field.value.data() + field.value.size(), value);
            if (parsed.ec != std::errc{} || parsed.ptr != field.value.data() + 3 ||
                value < 100 || value > 599) return failure(std::errc::protocol_error);
            response.status = value;
            status_seen = true;
        } else if (!field.name.empty() && field.name.front() == ':') {
            return failure(std::errc::protocol_error);
        } else if (!valid_name(field.name) || !valid_value(field.value) ||
                   connection_specific(field.name) || field.name == "te") {
            return failure(std::errc::protocol_error);
        } else {
            regular_seen = true;
            response.headers.push_back({std::move(field.name), std::move(field.value)});
        }
    }
    if (initial && !status_seen) return failure(std::errc::protocol_error);
    return {};
}

struct prepared_request {
    std::vector<std::byte> block;
    std::optional<std::uint64_t> length;
};

// Validates the request and encodes its header block; request headers are
// moved into the block's fields.
[[nodiscard]] auto prepare(client_request& request, std::string_view hostname)
    -> std::expected<prepared_request, std::error_code>
{
    if (!valid_target(request.target) ||
        (!request.authority.empty() && !valid_value(request.authority)) ||
        !valid_method(request.method) ||
        (request.body_source && !request.body.empty()))
        return std::unexpected(failure(std::errc::invalid_argument));
    // A CONNECT tunnel (RFC 9113 section 8.5) does not fit one buffered exchange.
    if (request.method == "CONNECT")
        return std::unexpected(failure(std::errc::operation_not_supported));
    if (request.body.size() > max_body ||
        request.headers.size() > detail::hpack_max_fields - 4)
        return std::unexpected(failure(std::errc::message_size));
    std::vector<detail::field> fields;
    fields.reserve(request.headers.size() + 4);
    fields.push_back({":method", request.method});
    fields.push_back({":scheme", "https"});
    fields.push_back({":authority", request.authority.empty() ? std::string(hostname)
                                                               : request.authority});
    fields.push_back({":path", request.target});
    for (auto& item : request.headers) {
        // A Host field must repeat :authority (RFC 9113 8.3.1).
        if (!valid_name(item.name) || !valid_value(item.value) ||
            connection_specific(item.name) || (item.name == "te" && item.value != "trailers") ||
            (item.name == "host" && item.value != fields[2].value))
            return std::unexpected(failure(std::errc::invalid_argument));
    }
    // A declared request length must match the owned body, or the source total.
    const auto request_length = content_length(request.headers);
    if (!request_length ||
        (*request_length && !request.body_source && **request_length != request.body.size()))
        return std::unexpected(failure(std::errc::invalid_argument));
    for (auto& item : request.headers)
        fields.push_back({std::move(item.name), std::move(item.value)});
    request.headers.clear();
    prepared_request prepared {.block = {}, .length = *request_length};
    const auto encoded = detail::hpack_encode(fields, prepared.block);
    if (encoded != detail::hpack_error::none)
        return std::unexpected(failure(encoded == detail::hpack_error::limit_exceeded
            ? std::errc::message_size : std::errc::invalid_argument));
    return prepared;
}

[[nodiscard]] auto equal_hostnames(std::string_view left, std::string_view right) -> bool
{
    return std::ranges::equal(left, right, [](unsigned char a, unsigned char b) {
        return (a >= 'A' && a <= 'Z' ? a + 32 : a) == (b >= 'A' && b <= 'Z' ? b + 32 : b);
    });
}

constexpr std::uint32_t max_stream_id = 0x7fffffff;

} // namespace

struct client_connection::state {
    state(event_loop& owner, ip_endpoint peer, std::shared_ptr<tls_context> tls,
          std::string name)
        : loop(owner), endpoint(peer), context(std::move(tls)), hostname(std::move(name)) {}

    struct operation_guard {
        explicit operation_guard(bool& active) noexcept : active(active) { active = true; }
        ~operation_guard() { active = false; }
        operation_guard(const operation_guard&) = delete;
        auto operator=(const operation_guard&) -> operation_guard& = delete;
        bool& active;
    };

    event_loop& loop;
    ip_endpoint endpoint;
    std::shared_ptr<tls_context> context;
    std::string hostname;
    tls_stream* stream {nullptr};
    native_socket socket_id {};
    bool started {false};
    bool busy {false};
    bool preface_sent {false};
    bool settings_received {false};
    bool goaway {false};
    // Client streams are odd; each request takes the next one.
    std::uint32_t next_stream {1};
    // Connection-level state persists across requests.
    std::int64_t connection_send_window {65535};
    std::uint32_t peer_initial_window {65535};
    detail::hpack_decoder decoder;
    std::unique_ptr<std::array<std::byte, max_frame>> payload;

    [[nodiscard]] auto usable() const noexcept -> bool
    {
        return stream != nullptr && !goaway && next_stream <= max_stream_id;
    }

    auto retire() -> void
    {
        if (stream == nullptr) return;
        detail::client_access::remove(loop, socket_id);
        stream = nullptr;
    }

    [[nodiscard]] static auto connect(event_loop& loop, state& self)
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] static auto request(event_loop& loop, state& self, client_request request,
                                      response_sink sink, response_header_sink header_sink)
        -> task<std::expected<client_response, std::error_code>>;
    [[nodiscard]] static auto exchange(event_loop& loop, state& self,
                                       prepared_request prepared, client_request request,
                                       response_sink sink, response_header_sink header_sink)
        -> task<std::expected<client_response, std::error_code>>;
    [[nodiscard]] static auto close(event_loop& loop, state& self)
        -> task<std::expected<void, std::error_code>>;
    // Ends with GOAWAY when the preface was sent (RFC 9113 6.8, 9.1). No pushed
    // stream was accepted, so the last stream is 0. A dead transport just fails
    // this write.
    [[nodiscard]] static auto close_transport(event_loop& loop, state& self,
                                              bool protocol_error)
        -> task<std::expected<void, std::error_code>>;
};

auto client_connection::state::connect(event_loop& loop, state& self)
    -> task<std::expected<void, std::error_code>>
{
    if (self.busy) co_return std::unexpected(failure(std::errc::device_or_resource_busy));
    if (self.started) co_return std::unexpected(failure(std::errc::already_connected));
    if (!self.context || self.hostname.empty())
        co_return std::unexpected(failure(std::errc::invalid_argument));
    self.started = true;
    operation_guard guard(self.busy);
    auto owned = std::make_unique<tls_stream>(loop, self.endpoint, self.context,
        tls_client_options{.hostname = self.hostname, .application_protocols = {"h2"}});
    self.stream = owned.get();
    self.socket_id = self.stream->descriptor();
    loop.add(std::move(owned));
    auto connected = co_await self.stream->async_connect();
    if (!connected) {
        self.retire();
        co_return std::unexpected(connected.error());
    }
    auto handshaken = unwrap(co_await self.stream->async_handshake());
    if (!handshaken) {
        self.retire();
        co_return std::unexpected(handshaken.error());
    }
    if (self.stream->application_protocol() != "h2") {
        self.retire();
        co_return std::unexpected(failure(std::errc::protocol_not_supported));
    }
    self.payload = std::make_unique<std::array<std::byte, max_frame>>();
    co_return std::expected<void, std::error_code>{};
}

auto client_connection::state::request(event_loop& loop, state& self,
                                       client_request request, response_sink sink,
                                       response_header_sink header_sink)
    -> task<std::expected<client_response, std::error_code>>
{
    if (self.busy) co_return std::unexpected(failure(std::errc::device_or_resource_busy));
    if (!self.usable()) co_return std::unexpected(failure(std::errc::not_connected));
    auto prepared = prepare(request, self.hostname);
    if (!prepared) co_return std::unexpected(prepared.error());
    co_return unwrap(co_await exchange(loop, self, std::move(*prepared), std::move(request),
                                       std::move(sink), std::move(header_sink)));
}

auto client_connection::state::close(event_loop& loop, state& self)
    -> task<std::expected<void, std::error_code>>
{
    if (self.busy) co_return std::unexpected(failure(std::errc::device_or_resource_busy));
    if (self.stream == nullptr) co_return std::expected<void, std::error_code>{};
    operation_guard guard(self.busy);
    co_return unwrap(co_await close_transport(loop, self, false));
}

auto client_connection::state::close_transport(event_loop& loop, state& self,
                                               bool protocol_error)
    -> task<std::expected<void, std::error_code>>
{
    std::expected<void, std::error_code> result;
    if (self.preface_sent && self.stream != nullptr) {
        std::array<std::byte, 17> goaway {};
        frame_header(goaway.data(), 8, 7, 0, 0);
        if (protocol_error) goaway[16] = std::byte {1};
        result = unwrap(co_await write_all(loop, *self.stream, goaway));
    }
    self.retire();
    co_return result;
}

auto client_connection::state::exchange(event_loop& loop, state& self,
                                        prepared_request prepared, client_request request,
                                        response_sink sink, response_header_sink header_sink)
    -> task<std::expected<client_response, std::error_code>>
{
    operation_guard guard(self.busy);
    auto* stream = self.stream;
    const auto stream_id = self.next_stream;
    self.next_stream += 2;
    const auto& block = prepared.block;
    const auto& request_length = prepared.length;

    std::vector<std::byte> outgoing;
    if (!self.preface_sent) {
        outgoing.resize(preface.size() + 15);
        std::memcpy(outgoing.data(), preface.data(), preface.size());
        auto* p = outgoing.data() + preface.size();
        frame_header(p, 6, 4, 0, 0);
        p[9] = std::byte{0};
        p[10] = std::byte{2}; // SETTINGS_ENABLE_PUSH = 0
        put_u32(p + 11, 0);
        self.preface_sent = true;
    }
    for (std::size_t offset = 0; offset < block.size() || offset == 0;) {
        const auto count = std::min(max_frame, block.size() - offset);
        const auto first = offset == 0;
        const auto last = offset + count == block.size();
        const auto old_size = outgoing.size();
        outgoing.resize(old_size + 9 + count);
        frame_header(outgoing.data() + old_size, count, first ? 1 : 9,
                     (first && request.body.empty() && !request.body_source ? 1u : 0u) |
                         (last ? 4u : 0u), stream_id);
        std::copy_n(block.begin() + static_cast<std::ptrdiff_t>(offset), count,
                    outgoing.begin() + static_cast<std::ptrdiff_t>(old_size + 9));
        offset += count;
    }
    auto written = unwrap(co_await write_all(loop, *stream, outgoing));
    if (!written) {
        const auto error = written.error();
        (void)co_await close_transport(loop, self, false);
        co_return std::unexpected(error);
    }

    client_response response;
    auto& decoder = self.decoder;
    std::array<std::byte, 9> header_bytes{};
    auto& payload = self.payload;
    std::vector<std::byte> header_block;
    bool initial_headers = false;
    bool continuation = false;
    bool end_stream_on_headers = false;
    std::size_t header_start = 0;
    bool finished = false;
    std::uint64_t response_bytes = 0;
    // Set from the final response headers. HEAD, 204, and 304 carry no content.
    std::optional<std::uint64_t> response_length;
    bool bodyless = false;
    std::size_t body_offset = 0;
    std::uint64_t sourced_bytes = 0;
    bool upload_finished = request.body.empty() && !request.body_source;
    auto& connection_send_window = self.connection_send_window;
    std::int64_t stream_send_window = self.peer_initial_window;
    std::vector<std::byte> upload_frame;
    std::error_code error;
    while (!finished && !error) {
        // A request body is sent only while both peer flow-control windows
        // have room. Reading peer frames below replenishes those windows.
        while (!upload_finished &&
               connection_send_window > 0 && stream_send_window > 0) {
            const auto capacity = std::min({max_frame,
                static_cast<std::size_t>(connection_send_window),
                static_cast<std::size_t>(stream_send_window)});
            upload_frame.resize(9 + capacity);
            std::size_t count = 0;
            bool last = false;
            if (request.body_source) {
                std::expected<std::size_t, std::error_code> produced;
                try {
                    produced = request.body_source(
                        std::span(upload_frame).subspan(9, capacity));
                } catch (const std::system_error& source_error) {
                    error = source_error.code(); break;
                } catch (...) {
                    error = failure(std::errc::io_error); break;
                }
                if (!produced) { error = produced.error(); break; }
                count = *produced;
                if (count > capacity) {
                    error = failure(std::errc::invalid_argument); break;
                }
                if (count > max_streamed_body - sourced_bytes) {
                    error = failure(std::errc::message_size); break;
                }
                if (request_length && (count > *request_length - sourced_bytes ||
                                       (count == 0 && sourced_bytes != *request_length))) {
                    error = failure(std::errc::invalid_argument); break;
                }
                sourced_bytes += count;
                last = count == 0;
            } else {
                count = std::min(capacity, request.body.size() - body_offset);
                last = body_offset + count == request.body.size();
                std::copy_n(request.body.data() + body_offset, count,
                            upload_frame.data() + 9);
                body_offset += count;
            }
            frame_header(upload_frame.data(), count, 0, last ? 1 : 0, stream_id);
            written = unwrap(co_await write_all(loop, *stream,
                std::span(upload_frame).first(9 + count)));
            if (!written) { error = written.error(); break; }
            connection_send_window -= static_cast<std::int64_t>(count);
            stream_send_window -= static_cast<std::int64_t>(count);
            upload_finished = last;
        }
        if (error) break;
        auto read = unwrap(co_await read_exact(loop, *stream, header_bytes));
        if (!read) { error = read.error(); break; }
        const auto length = (std::size_t(std::to_integer<unsigned char>(header_bytes[0])) << 16) |
            (std::size_t(std::to_integer<unsigned char>(header_bytes[1])) << 8) |
             std::size_t(std::to_integer<unsigned char>(header_bytes[2]));
        const auto type = std::to_integer<unsigned char>(header_bytes[3]);
        const auto flags = std::to_integer<unsigned char>(header_bytes[4]);
        // RFC 9113 section 4.1: the reserved bit and undefined flags are ignored.
        const auto id = u32(header_bytes.data() + 5) & 0x7fffffffu;
        if (length > max_frame) {
            error = failure(std::errc::message_size); break;
        }
        if (!self.settings_received && (type != 4 || id != 0 || (flags & 1) != 0)) {
            error = failure(std::errc::protocol_error); break;
        }
        if (continuation && (type != 9 || id != stream_id)) {
            error = failure(std::errc::protocol_error); break;
        }
        read = unwrap(co_await read_exact(loop, *stream,
            std::span(*payload).first(length)));
        if (!read) { error = read.error(); break; }
        auto data = std::span(*payload).first(length);
        if (type == 4) {
            if (id != 0 || ((flags & 1u) ? length != 0 : length % 6 != 0)) {
                error = failure(std::errc::protocol_error); break;
            }
            self.settings_received = true;
            if (!(flags & 1u)) {
                for (std::size_t i = 0; i < length; i += 6) {
                    const auto key = (unsigned(std::to_integer<unsigned char>(data[i])) << 8) |
                        unsigned(std::to_integer<unsigned char>(data[i + 1]));
                    const auto value = u32(data.data() + i + 2);
                    // RFC 9113 section 6.5.2: a server must not enable push.
                    if ((key == 2 && value != 0) ||
                        (key == 4 && value > 0x7fffffffu) ||
                        (key == 5 && (value < 16384 || value > 16777215))) {
                        error = failure(std::errc::protocol_error); break;
                    }
                    if (key == 4) {
                        stream_send_window += static_cast<std::int64_t>(value) -
                            static_cast<std::int64_t>(self.peer_initial_window);
                        self.peer_initial_window = value;
                        if (stream_send_window > 0x7fffffff) {
                            error = failure(std::errc::protocol_error); break;
                        }
                    }
                }
                if (error) break;
                frame_header(header_bytes.data(), 0, 4, 1, 0);
                written = unwrap(co_await write_all(loop, *stream, header_bytes));
                if (!written) error = written.error();
            }
        } else if (type == 1 || type == 9) {
            if (id != stream_id || (type == 9 && !continuation) ||
                (type == 1 && initial_headers && !(flags & 1u))) {
                error = failure(std::errc::protocol_error); break;
            }
            std::size_t start = 0;
            std::size_t pad = 0;
            if (type == 1) {
                if (flags & 8u) {
                    if (length == 0) { error = failure(std::errc::protocol_error); break; }
                    pad = std::to_integer<unsigned char>(data[0]);
                    start = 1;
                }
                if (flags & 0x20u) start += 5;
                if (start + pad > length) {
                    error = failure(std::errc::protocol_error); break;
                }
            }
            const auto fragment = data.subspan(start, length - start - pad);
            if (header_block.size() + fragment.size() > detail::hpack_max_block_size) {
                error = failure(std::errc::message_size); break;
            }
            header_block.insert(header_block.end(), fragment.begin(), fragment.end());
            if (type == 1) {
                end_stream_on_headers = (flags & 1u) != 0;
                header_start = response.headers.size();
            }
            continuation = (flags & 4u) == 0;
            if (!continuation) {
                error = parse_headers(header_block, decoder, response, !initial_headers);
                header_block.clear();
                if (error) break;
                if (!initial_headers && response.status >= 200) {
                    bodyless = request.method == "HEAD" || response.status == 204 ||
                               response.status == 304;
                    const auto length = content_length(response.headers);
                    if (!length) { error = length.error(); break; }
                    if (!bodyless) response_length = *length;
                }
                if (header_sink) {
                    try {
                        error = header_sink(initial_headers ? 0 : response.status,
                            std::span<const header>(response.headers).subspan(header_start));
                    } catch (const std::system_error& failure) {
                        error = failure.code();
                    } catch (...) {
                        error = failure(std::errc::io_error);
                    }
                    if (error) break;
                }
                if (response.status >= 100 && response.status < 200) {
                    if (end_stream_on_headers || response.status == 101) {
                        error = failure(std::errc::protocol_error); break;
                    }
                    response.status = 0;
                    response.headers.clear();
                    continue;
                }
                initial_headers = true;
                if (end_stream_on_headers) finished = true;
            }
        } else if (type == 0) {
            if (id != stream_id || !initial_headers) {
                error = failure(std::errc::protocol_error); break;
            }
            std::size_t padding = 0;
            if (flags & 8u) {
                if (length == 0) { error = failure(std::errc::protocol_error); break; }
                padding = 1 + std::to_integer<unsigned char>(data[0]);
                if (padding > length) { error = failure(std::errc::protocol_error); break; }
            }
            const auto size = length - padding;
            if ((bodyless && size != 0) ||
                (response_length && size > *response_length - response_bytes)) {
                error = failure(std::errc::protocol_error); break;
            }
            const auto limit = sink ? max_streamed_body : max_body;
            if (size > limit - response_bytes) {
                error = failure(std::errc::message_size); break;
            }
            response_bytes += size;
            const auto chunk = data.subspan(padding == 0 ? 0 : 1, size);
            if (sink && !chunk.empty()) {
                try {
                    error = sink(chunk);
                } catch (const std::system_error& failure) {
                    error = failure.code();
                } catch (...) {
                    error = failure(std::errc::io_error);
                }
                if (error) break;
            } else {
                response.body.insert(response.body.end(), chunk.begin(), chunk.end());
            }
            // Connection credit survives END_STREAM and is needed by later requests.
            if (length != 0) {
                std::array<std::byte, 26> updates{};
                frame_header(updates.data(), 4, 8, 0, 0);
                put_u32(updates.data() + 9, static_cast<std::uint32_t>(length));
                frame_header(updates.data() + 13, 4, 8, 0, stream_id);
                put_u32(updates.data() + 22, static_cast<std::uint32_t>(length));
                written = unwrap(co_await write_all(loop, *stream,
                    std::span(updates).first((flags & 1u) ? 13 : 26)));
                if (!written) { error = written.error(); break; }
            }
            if (flags & 1u) finished = true;
        } else if (type == 6) {
            if (id != 0 || length != 8) { error = failure(std::errc::protocol_error); break; }
            if (!(flags & 1u)) {
                frame_header(header_bytes.data(), 8, 6, 1, 0);
                std::array<std::byte, 17> pong{};
                std::copy(header_bytes.begin(), header_bytes.end(), pong.begin());
                std::copy_n(data.begin(), 8, pong.begin() + 9);
                written = unwrap(co_await write_all(loop, *stream, pong));
                if (!written) error = written.error();
            }
        } else if (type == 8) {
            // RFC 9113 section 5.1: an earlier closed stream may still see
            // WINDOW_UPDATE; ignore it. Later streams are idle.
            if (length != 4 || (id != 0 && (id > stream_id || id % 2 == 0))) {
                error = failure(std::errc::protocol_error); break;
            }
            if (id != 0 && id != stream_id) continue;
            const auto increment = u32(data.data()) & 0x7fffffffu;
            if (increment == 0) {
                error = failure(std::errc::protocol_error); break;
            }
            auto& window = id == 0 ? connection_send_window : stream_send_window;
            window += increment;
            if (window > 0x7fffffff) error = failure(std::errc::protocol_error);
        } else if (type == 3) {
            // RFC 9113 section 6.4. Earlier streams are closed, so a late
            // RST_STREAM is ignored; even and later streams are idle.
            if (id == 0 || id > stream_id || id % 2 == 0 || length != 4) {
                error = failure(std::errc::protocol_error); break;
            }
            if (id == stream_id) error = failure(std::errc::connection_reset);
        } else if (type == 7) {
            // RFC 9113 section 6.8. The request still completes if the peer
            // processed its stream; otherwise it was not handled. No new
            // request may use this connection.
            if (id != 0) { error = failure(std::errc::protocol_error); break; }
            if (length < 8) { error = failure(std::errc::protocol_error); break; }
            self.goaway = true;
            if ((u32(data.data()) & 0x7fffffffu) < stream_id)
                error = failure(std::errc::connection_reset);
        } else if (type == 5) {
            error = failure(std::errc::protocol_error);
        }
    }
    if (!error && (!initial_headers || continuation || response.status == 0 ||
                   (response_length && response_bytes != *response_length)))
        error = failure(std::errc::protocol_error);
    if (error) {
        (void)co_await close_transport(loop, self, error == failure(std::errc::protocol_error));
        co_return std::unexpected(error);
    }
    // A complete response can precede the whole request (RFC 9113 8.1); end
    // the unfinished upload so the stream closes and the connection stays usable.
    if (!upload_finished) {
        std::array<std::byte, 13> cancel {};
        frame_header(cancel.data(), 4, 3, 0, stream_id);
        put_u32(cancel.data() + 9, 8); // CANCEL
        if (!unwrap(co_await write_all(loop, *stream, cancel))) self.retire();
    }
    if (self.goaway && self.stream != nullptr)
        (void)co_await close_transport(loop, self, false);
    co_return response;
}

client_connection::client_connection(event_loop& loop, ip_endpoint endpoint,
                                     std::shared_ptr<tls_context> context,
                                     std::string hostname)
    : state_(std::make_unique<state>(loop, endpoint, std::move(context), std::move(hostname)))
{
}

client_connection::~client_connection()
{
    state_->retire();
}

auto client_connection::async_connect() -> task<std::expected<void, std::error_code>>
{
    return state::connect(state_->loop, *state_);
}

auto client_connection::async_request(client_request request, response_sink sink,
                                      response_header_sink header_sink)
    -> task<std::expected<client_response, std::error_code>>
{
    return state::request(state_->loop, *state_, std::move(request), std::move(sink),
                          std::move(header_sink));
}

auto client_connection::can_reuse_for(std::string_view hostname,
                                      const ip_endpoint& endpoint) const -> bool
{
    const auto& self = *state_;
    if (!self.usable() || endpoint != self.endpoint) return false;
    return equal_hostnames(hostname, self.hostname) ||
           detail::client_access::certificate_matches(*self.stream, hostname);
}

auto client_connection::async_close() -> task<std::expected<void, std::error_code>>
{
    return state::close(state_->loop, *state_);
}

auto async_request(event_loop& loop, ip_endpoint endpoint,
                   std::shared_ptr<tls_context> context,
                   std::string hostname, client_request request,
                   response_sink sink, response_header_sink header_sink)
    -> task<std::expected<client_response, std::error_code>>
{
    if (!context || hostname.empty())
        co_return std::unexpected(failure(std::errc::invalid_argument));
    // Validation fails before connecting.
    auto prepared = prepare(request, hostname);
    if (!prepared) co_return std::unexpected(prepared.error());
    client_connection connection(loop, endpoint, std::move(context), std::move(hostname));
    auto& self = *connection.state_;
    auto connected = unwrap(co_await client_connection::state::connect(loop, self));
    if (!connected) co_return std::unexpected(connected.error());
    auto response = unwrap(co_await client_connection::state::exchange(loop, self,
        std::move(*prepared), std::move(request), std::move(sink), std::move(header_sink)));
    if (self.stream != nullptr) (void)co_await client_connection::state::close_transport(
        loop, self, false);
    co_return response;
}

} // namespace eventloop::http2
