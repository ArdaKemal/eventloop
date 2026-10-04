#include "eventloop/http/http3_server.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/mime_types.h"
#include "eventloop/unique_fd.h"
#include "../http/file_operations.h"
#include "../http/resource.h"
#include "../http/file_response.h"
#include "frames.h"
#include "peer_streams.h"
#include "request_stream.h"
#include "qpack.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace eventloop::http {
namespace {
namespace h3 = eventloop::http3::detail;
constexpr std::size_t max_streams = 40;
constexpr std::size_t header_limit = 16 * 1024;
using stream_handlers = std::array<std::optional<task_handle<void>>, max_streams>;

struct stream_storage {
    std::array<std::byte, header_limit> headers {};
    std::array<char, header_limit> strings {};
    std::array<h3::field, h3::qpack_max_fields> fields {};
    std::array<std::byte, 4096> io {};
    bool in_use {false};
};

struct storage_pool {
    explicit storage_pool(std::size_t capacity) : slots(checked_capacity(capacity)) {}
    [[nodiscard]] static auto checked_capacity(std::size_t capacity) -> std::size_t
    {
        if (capacity == 0 || capacity > 8192)
            throw std::invalid_argument("HTTP/3 request capacity must be 1..8192");
        return capacity;
    }
    [[nodiscard]] auto acquire() noexcept -> stream_storage*
    {
        for (auto& slot : slots) if (!slot.in_use) {
            slot.in_use = true;
            return &slot;
        }
        return nullptr;
    }
    std::vector<stream_storage> slots;
};

auto write_all(event_loop& loop, quic_connection& connection, std::uint64_t id,
               std::span<const std::byte> bytes, bool fin) -> task<bool>
{
    (void)loop;
    while (!bytes.empty()) {
        auto result = flatten_result(co_await connection.async_write(id, bytes, false));
        if (!result || *result == 0 || *result > bytes.size()) co_return false;
        bytes = bytes.subspan(*result);
    }
    if (fin) {
        auto result = flatten_result(co_await connection.async_write(id, {}, true));
        if (!result) co_return false;
    }
    co_return true;
}

// Header encoding uses a caller-owned scratch buffer so the 512-byte encode
// area does not enlarge this coroutine's frame. Keeping the frame within the
// 1 KiB size class matters because each active request holds one.
auto send_headers(event_loop& loop, quic_connection& connection, std::uint64_t id,
                  unsigned status, std::uint64_t length, std::string_view mime,
                  bool fin, std::span<std::byte> buffer,
                  const detail::file_response* selected = nullptr) -> task<bool>
{
    std::array<char, 32> status_text {}, length_text {};
    auto status_end = std::to_chars(status_text.data(), status_text.data() + status_text.size(), status);
    auto length_end = std::to_chars(length_text.data(), length_text.data() + length_text.size(), length);
    if (status_end.ec != std::errc{} || length_end.ec != std::errc{}) co_return false;
    std::array<h3::field, 8> fields {};
    std::size_t field_count = 0;
    fields[field_count++] = {":status", {status_text.data(), status_end.ptr}};
    if (status != 204) {
        fields[field_count++] = {"content-length", {length_text.data(), length_end.ptr}};
        fields[field_count++] = {"content-type", mime};
    }
    if (status == 204 || status == 405)
        fields[field_count++] = {"allow", "GET, HEAD, OPTIONS"};
    if (selected != nullptr) {
        fields[field_count++] = {"etag", {selected->etag.data(), selected->etag_size}};
        fields[field_count++] = {"last-modified", {selected->modified.data(), selected->modified_size}};
        fields[field_count++] = {"accept-ranges", "bytes"};
        if (selected->content_range_size != 0)
            fields[field_count++] = {"content-range", {selected->content_range.data(), selected->content_range_size}};
    }
    auto encoded = h3::qpack_encode(std::span(fields).first(field_count),
                                    buffer.subspan(16));
    if (!encoded) co_return false;
    auto framed = h3::encode_frame(h3::headers_frame,
        buffer.subspan(16, *encoded), buffer);
    if (!framed) co_return false;
    co_return (co_await write_all(loop, connection, id, buffer.first(*framed), fin)).value_or(false);
}

// Stream-scoped HTTP/3 errors reset the response and stop the request body;
// the transport absorbs the rest so the stream retires. Every other code is a
// connection error sent in CONNECTION_CLOSE.
auto fail(quic_connection& connection, std::uint64_t id, h3::h3_error error) noexcept -> void
{
    const auto code = static_cast<std::uint64_t>(error);
    if (!h3::stream_scoped(error)) {
        connection.close_application(code);
        return;
    }
    (void)connection.stop_sending(id, code);
    (void)connection.reset_stream(id, code);
}

// io holds the encoded response HEADERS in its first part and request input
// in the rest, so bytes read past the request HEADERS survive the response.
constexpr std::size_t response_header_area = 1024;
// Request DATA read after a complete response. Beyond it the server stops
// reading with H3_NO_ERROR, as RFC 9114 4.1 permits for unneeded bodies.
constexpr std::uint64_t request_body_limit = 1024 * 1024;

enum class read_outcome { block, end, body_limit, failure, transport_failure };

// Reads request frames until a complete HEADERS block, a clean FIN, or an
// error. pending carries unparsed input in input_area between calls.
auto read_request_frames(event_loop& loop, quic_connection& connection, std::uint64_t id,
                         h3::request_frames& frames, std::span<std::byte> input_area,
                         std::span<const std::byte>& pending, h3::h3_error& error)
    -> task<read_outcome>
{
    (void)loop;
    for (;;) {
        if (!pending.empty()) {
            const auto parsed = frames.receive(pending);
            if (!parsed) { error = parsed.error(); co_return read_outcome::failure; }
            if (*parsed == h3::request_frames::event::header_block) co_return read_outcome::block;
            if (frames.data_received() > request_body_limit) co_return read_outcome::body_limit;
            continue;
        }
        const auto got = flatten_result(co_await connection.async_read(id, input_area));
        if (!got) co_return read_outcome::transport_failure;
        if (*got == 0) {
            if (const auto finished = frames.finish(); !finished) {
                error = finished.error();
                co_return read_outcome::failure;
            }
            co_return read_outcome::end;
        }
        pending = std::span<const std::byte>(input_area).first(*got);
    }
}

// After the response: validate the remaining request frames, DATA length
// against Content-Length, and any trailers, until FIN or the body limit.
auto finish_request(event_loop& loop, quic_connection& connection, std::uint64_t id,
                    stream_storage& s, h3::request_frames& frames,
                    std::span<const std::byte> pending) -> task<void>
{
    const auto input_area = std::span(s.io).subspan(response_header_area);
    h3::h3_error error {};
    for (;;) {
        const auto outcome = (co_await read_request_frames(loop, connection, id, frames,
            input_area, pending, error)).value_or(read_outcome::transport_failure);
        switch (outcome) {
        case read_outcome::block: {
            const auto decoded = h3::qpack_decode(frames.block(), s.fields, s.strings);
            if (!decoded) { fail(connection, id, h3::qpack_failure(decoded.error())); co_return; }
            if (const auto valid = h3::validate_trailers(std::span(s.fields).first(*decoded)); !valid) {
                fail(connection, id, valid.error());
                co_return;
            }
            continue;
        }
        case read_outcome::body_limit:
            (void)connection.stop_sending(id, static_cast<std::uint64_t>(h3::h3_error::no_error));
            co_return;
        case read_outcome::failure: fail(connection, id, error); co_return;
        case read_outcome::end:
        case read_outcome::transport_failure: co_return;
        }
    }
}

auto serve_request(event_loop& loop, quic_connection& connection, std::uint64_t id,
                   native_socket root, stream_storage* storage,
                   bool directory_listing)
    -> task<void>
{
    struct release_storage {
        stream_storage* storage;
        ~release_storage() { storage->in_use = false; }
    } release {storage};
    auto& s = *storage;
    // The parser copies HEADERS payloads into s.headers. Once the request
    // section is decoded (strings live in s.strings), s.headers is reused for
    // If-None-Match and response DATA, and later for any trailers.
    h3::request_frames frames(s.headers);
    std::span<const std::byte> pending;
    h3::h3_error error {};
    const auto input_area = std::span(s.io).subspan(response_header_area);
    const auto outcome = (co_await read_request_frames(loop, connection, id, frames,
        input_area, pending, error)).value_or(read_outcome::transport_failure);
    if (outcome == read_outcome::failure) fail(connection, id, error);
    if (outcome != read_outcome::block) co_return;
    const auto decoded = h3::qpack_decode(frames.block(), s.fields, s.strings);
    if (!decoded) {
        fail(connection, id, h3::qpack_failure(decoded.error()));
        co_return;
    }
    const auto request_fields = std::span<const h3::field>(s.fields).first(*decoded);
    const auto head = h3::validate_request(request_fields);
    if (!head) {
        fail(connection, id, head.error());
        co_return;
    }
    frames.set_content_length(head->content_length);
    const auto method = head->method;
    const auto path = head->path;
    std::size_t match_size = 0;
    std::string_view if_modified_since, range;
    bool duplicate_range = false;
    for (const auto& field : request_fields) {
        if (field.name == "if-none-match") {
            const auto extra = field.value.size() + (match_size != 0 ? 1 : 0);
            if (extra > s.headers.size() - match_size) {
                fail(connection, id, h3::h3_error::excessive_load);
                co_return;
            }
            auto* output = reinterpret_cast<char*>(s.headers.data());
            if (match_size != 0) output[match_size++] = ',';
            if (!field.value.empty())
                std::memcpy(output + match_size, field.value.data(), field.value.size());
            match_size += field.value.size();
        }
        else if (field.name == "if-modified-since") if_modified_since = field.value;
        else if (field.name == "range") {
            if (!range.empty()) duplicate_range = true;
            else range = field.value;
        }
    }
    const std::string_view if_none_match {
        reinterpret_cast<const char*>(s.headers.data()), match_size};
    unsigned status = 200;
    unique_fd file;
    std::uint64_t size = 0;
    std::uint64_t offset = 0;
    detail::file_response selected;
    bool have_file = false;
    bool have_listing = false;
    std::vector<char> listing;
    std::string_view mime = "text/plain";
    // Plain CONNECT has no :scheme and is answered 405 below.
    if (method != "CONNECT" && head->scheme != "https") status = 400;
    else if (method == "OPTIONS") status = 204;
    else if (method != "GET" && method != "HEAD") status = 405;
    else {
        auto opened = http::detail::open_resource(root, path);
        if (!opened) status = opened.error() == http::detail::resource_error::invalid_target ? 400
            : opened.error() == http::detail::resource_error::target_too_long ? 414 : 404;
        else {
            file = std::move(*opened);
            auto info = http::detail::get_file_info(file.get());
            if (!info) status = 404;
            else if (info->kind == http::detail::file_info::type::directory) {
                auto index = http::detail::open_child(file.get(), "index.html", false);
                auto index_info = index ? http::detail::get_file_info(index.get()) : std::nullopt;
                if (index_info && index_info->kind == http::detail::file_info::type::regular) {
                    file = std::move(index);
                    selected = detail::choose_file_response(*index_info,
                        {if_none_match, if_modified_since, duplicate_range ? std::string_view {} : range});
                    size = selected.length; offset = selected.offset; status = selected.status;
                    have_file = true; mime = http::mime_type_from_path("index.html");
                } else if (!directory_listing) {
                    status = 403;
                } else {
                    auto rendered = http::detail::render_directory_listing(std::move(file));
                    if (!rendered) {
                        status = 500;
                        mime = "text/plain";
                        listing.assign(directory_listing_error_body.begin(),
                                       directory_listing_error_body.end());
                    } else {
                        listing = std::move(*rendered);
                        mime = "text/html; charset=utf-8";
                    }
                    size = listing.size();
                    have_listing = true;
                }
            } else if (info->kind == http::detail::file_info::type::regular) {
                selected = detail::choose_file_response(*info,
                    {if_none_match, if_modified_since, duplicate_range ? std::string_view {} : range});
                size = selected.length; offset = selected.offset; status = selected.status;
                have_file = true; mime = http::mime_type_from_path(path);
            } else status = 404;
        }
    }
    const bool body_expected = have_listing || (have_file && (status == 200 || status == 206));
    const bool finish = !body_expected || method == "HEAD";
    // A failed write means the peer stopped or reset the stream, or the
    // connection is ending; abandon only this request.
    const auto cancelled = h3::h3_error::request_cancelled;
    if (!(co_await send_headers(loop, connection, id, status, size, mime, finish,
            std::span(s.io).first(response_header_area),
            have_file ? &selected : nullptr)).value_or(false)) {
        fail(connection, id, cancelled);
        co_return;
    }
    if (have_listing) {
        std::array<std::byte, 16> frame_header {};
        const auto header_size = h3::encode_frame_header(h3::data_frame, listing.size(), frame_header);
        if (!header_size ||
            !(co_await write_all(loop, connection, id,
                    std::span(frame_header).first(*header_size), false)).value_or(false) ||
            !(co_await write_all(loop, connection, id,
                    std::span(reinterpret_cast<const std::byte*>(listing.data()),
                              listing.size()), true)).value_or(false)) {
            fail(connection, id, cancelled);
            co_return;
        }
    } else if (!finish) {
        if (size == 0 && !(co_await write_all(loop, connection, id, {}, true)).value_or(false)) {
            fail(connection, id, cancelled);
            co_return;
        }
        std::uint64_t sent = 0;
        while (sent < size) {
            // Request headers and conditional fields have already been
            // consumed. Reuse their bounded scratch area for a contiguous DATA
            // frame: larger reads and one stream write per chunk need no
            // additional request memory.
            constexpr std::size_t frame_header_limit = 16;
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
                s.headers.size() - frame_header_limit, size - sent));
            const auto header_size = h3::encode_frame_header(h3::data_frame, count,
                std::span(s.headers).first(frame_header_limit));
            if (!header_size ||
                !http::detail::read_file_at(file.get(), offset + sent,
                    std::span(s.headers).subspan(*header_size, count))) {
                fail(connection, id, h3::h3_error::internal_error);
                co_return;
            }
            if (!(co_await write_all(loop, connection, id,
                    std::span<const std::byte>(s.headers).first(*header_size + count),
                    sent + count == size)).value_or(false)) {
                fail(connection, id, cancelled);
                co_return;
            }
            sent += count;
        }
    }
    (void)co_await finish_request(loop, connection, id, s, frames, pending);
}

// Client unidirectional streams: control, QPACK encoder/decoder, rejected
// push streams, and refused unknown types. Validation state lives in this
// frame; a reset or FIN of a critical stream closes the connection.
auto read_peer_uni(event_loop& loop, quic_connection& connection, std::uint64_t id,
                   h3::peer_critical_streams& critical) -> task<void>
{
    (void)loop;
    h3::peer_uni_stream stream;
    std::array<std::byte, 256> input {};
    while (connection.valid()) {
        const auto got = flatten_result(co_await connection.async_read(id, input));
        if (!got && got.error() != make_error_code(quic_errc::stream_reset)) co_return;
        const bool ended = !got || *got == 0;
        const auto checked = ended ? stream.finish()
                                   : stream.receive(std::span(input).first(*got), critical);
        if (!checked) {
            fail(connection, id, checked.error());
            co_return;
        }
        if (ended) co_return;
        // Unknown and reserved types are refused rather than drained
        // (RFC 9114 6.2); the transport discards anything still arriving.
        if (stream.stream_kind() == h3::peer_uni_stream::kind::unknown) {
            (void)connection.stop_sending(id,
                static_cast<std::uint64_t>(h3::h3_error::stream_creation_error));
            co_return;
        }
    }
}

auto serve_connection(event_loop& loop, quic_connection connection,
                      std::shared_ptr<unique_fd> root,
                      stream_handlers& handlers, storage_pool& pool,
                      bool directory_listing) -> task<void>
{
    h3::peer_critical_streams critical;
    auto control = flatten_result(co_await connection.async_open_stream(quic_stream_direction::unidirectional));
    // RFC 9114 6.2 requires room for the three server critical streams.
    const auto general = static_cast<std::uint64_t>(h3::h3_error::general_protocol_error);
    if (!control) { connection.close_application(general); co_return; }
    // Server control stream: stream type 0, SETTINGS with zero QPACK dynamic table.
    const std::array<std::byte, 6> settings {std::byte{0}, std::byte{4}, std::byte{4},
        std::byte{1}, std::byte{0}, std::byte{7}};
    const std::array<std::byte, 1> last {std::byte{0}};
    if (!(co_await write_all(loop, connection, *control, settings, false)).value_or(false) ||
        !(co_await write_all(loop, connection, *control, last, false)).value_or(false)) {
        connection.close(); co_return;
    }
    // Required QPACK encoder and decoder streams. No dynamic entries are sent.
    for (std::byte type : {std::byte{2}, std::byte{3}}) {
        auto id = flatten_result(co_await connection.async_open_stream(quic_stream_direction::unidirectional));
        if (!id) { connection.close_application(general); co_return; }
        if (!(co_await write_all(loop, connection, *id, std::span(&type, 1), false)).value_or(false)) {
            connection.close(); co_return;
        }
    }
    while (connection.valid()) {
        auto accepted = flatten_result(co_await connection.async_accept_stream());
        if (!accepted) break;
        const auto id = *accepted;
        const bool request = (id & 3u) == 0u;
        // Handler slots cover every stream QUIC admits (32 bidirectional and
        // 8 unidirectional), so exhaustion here is a capacity bug.
        auto slot = std::find_if(handlers.begin(), handlers.end(),
            [](const auto& handler) { return !handler || handler->done(); });
        stream_storage* storage = request ? pool.acquire() : nullptr;
        auto spawned = task_spawn_result::invalid_task;
        if (slot != handlers.end() && (!request || storage)) {
            slot->reset();
            slot->emplace();
            spawned = request
                ? loop.spawn(serve_request(loop, connection, id, root->get(),
                      storage, directory_listing), **slot)
                : loop.spawn(read_peer_uni(loop, connection, id, critical), **slot);
            if (spawned != task_spawn_result::accepted) slot->reset();
        }
        if (spawned == task_spawn_result::accepted) continue;
        if (storage) storage->in_use = false;
        // Without request storage or a frame, refuse only this request; it
        // was not processed and may be retried (RFC 9114 8.1). A peer
        // unidirectional stream may be critical, so the connection ends.
        if (request) fail(connection, id, h3::h3_error::request_rejected);
        else {
            connection.close_application(static_cast<std::uint64_t>(h3::h3_error::internal_error));
            break;
        }
    }
    connection.close_application(static_cast<std::uint64_t>(h3::h3_error::no_error));
    for (auto& handler : handlers) {
        if (!handler) continue;
        (void)handler->cancel();
        (void)co_await *handler;
        handler.reset();
    }
}
} // namespace

class http3_server::implementation {
public:
    struct connection_slot {
        stream_handlers handlers;
        std::optional<task_handle<void>> handle;
    };

    static auto make_limits(std::size_t max_udp_payload_size) -> quic_transport_limits
    {
        quic_transport_limits limits;
        limits.max_udp_payload_size = max_udp_payload_size;
        return limits;
    }

    // An empty document root means routes only; static requests answer 404.
    static auto open_document_root(const server_options& options) -> std::shared_ptr<unique_fd>
    {
        if (!options.routes && options.document_root.empty())
            throw std::invalid_argument("server needs routes or a document root");
        if (options.document_root.empty()) return std::make_shared<unique_fd>();
        return std::make_shared<unique_fd>(
            http::detail::open_root(options.document_root.string()));
    }

    implementation(event_loop& loop, ip_endpoint local, std::filesystem::path cert,
                   std::filesystem::path key, const server_options& options)
        : loop_(loop), root_(open_document_root(options)),
          endpoint_(loop, local, quic_server_options{std::move(cert), std::move(key),
              std::span(alpn_), make_limits(options.max_udp_payload_size),
              options.connection_capacity}),
          directory_listing_(options.directory_listing),
          connections_(options.connection_capacity),
          request_storage_(options.request_capacity == 0 ? options.connection_capacity * 4
                                                         : options.request_capacity) {}

    event_loop& loop_;
    std::shared_ptr<unique_fd> root_;
    const std::array<std::uint8_t, 2> alpn_ {'h', '3'};
    quic_endpoint endpoint_;
    bool directory_listing_ {false};
    std::vector<connection_slot> connections_;
    storage_pool request_storage_;
};

http3_server::http3_server(event_loop& loop, ip_endpoint local,
                           std::filesystem::path certificate_chain,
                           std::filesystem::path private_key, server_options options)
    : implementation_(std::make_unique<implementation>(loop, local,
          std::move(certificate_chain), std::move(private_key), options)) {}
http3_server::~http3_server() = default;
auto http3_server::local_endpoint() const noexcept -> ip_endpoint
{ return implementation_->endpoint_.local_endpoint(); }
auto http3_server::run() -> task<void>
{ return run_loop(implementation_->loop_, *this); }
auto http3_server::run_loop(event_loop& loop, http3_server& server) -> task<void>
{
    auto& impl = *server.implementation_;
    while (true) {
        auto accepted = flatten_result(co_await impl.endpoint_.async_accept());
        if (!accepted) {
            if (accepted.error() == make_error_code(quic_errc::peer_closed) ||
                accepted.error() == std::make_error_code(std::errc::operation_canceled))
                break;
            continue;
        }
        auto slot = std::find_if(impl.connections_.begin(), impl.connections_.end(),
            [](const auto& entry) { return !entry.handle || entry.handle->done(); });
        if (slot == impl.connections_.end()) { accepted->close(); continue; }
        slot->handle.emplace();
        const auto spawned = loop.spawn(serve_connection(loop, std::move(*accepted), impl.root_,
                slot->handlers, impl.request_storage_, impl.directory_listing_), *slot->handle);
        if (spawned != task_spawn_result::accepted) {
            slot->handle.reset();
            if (spawned == task_spawn_result::frame_allocation_failure) {
                // The connection task frame was never created, so the accepted
                // connection is untouched. Reject only this connection instead
                // of tearing down the listener and every live connection.
                accepted->close();
                continue;
            }
            break;
        }
    }
    impl.endpoint_.close();
    for (auto& slot : impl.connections_) {
        if (!slot.handle) continue;
        (void)slot.handle->cancel();
        (void)co_await *slot.handle;
        slot.handle.reset();
    }
    (void)co_await impl.endpoint_.async_close();
}
auto http3_server::async_close() -> task<void>
{ return close_loop(implementation_->loop_, *this); }
auto http3_server::close_loop(event_loop& loop, http3_server& server) -> task<void>
{
    (void)loop;
    server.implementation_->endpoint_.close();
    (void)co_await server.implementation_->endpoint_.async_close();
}
auto http3_server::close() noexcept -> void { implementation_->endpoint_.close(); }

} // namespace eventloop::http
