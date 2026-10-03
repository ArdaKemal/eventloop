#include "eventloop/http/http3_server.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/mime_types.h"
#include "eventloop/unique_fd.h"
#include "../http/file_operations.h"
#include "../http/resource.h"
#include "../http/file_response.h"
#include "frames.h"
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
namespace wire = eventloop::quic::detail;
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

auto read_exact(event_loop& loop, quic_connection& connection, std::uint64_t id,
                std::span<std::byte> bytes) -> task<bool>
{
    (void)loop;
    while (!bytes.empty()) {
        auto result = flatten_result(co_await connection.async_read(id, bytes));
        if (!result || *result == 0 || *result > bytes.size()) co_return false;
        bytes = bytes.subspan(*result);
    }
    co_return true;
}

auto read_varint(event_loop& loop, quic_connection& connection, std::uint64_t id,
                 std::size_t* remaining = nullptr)
    -> task<std::expected<std::uint64_t, std::error_code>>
{
    std::array<std::byte, 8> input {};
    if (remaining && *remaining == 0)
        co_return std::unexpected(std::make_error_code(std::errc::protocol_error));
    if (!(co_await read_exact(loop, connection, id, std::span(input).first(1))).value_or(false))
        co_return std::unexpected(std::make_error_code(std::errc::protocol_error));
    const auto size = std::size_t{1} << (std::to_integer<unsigned>(input[0]) >> 6);
    if (remaining && size > *remaining)
        co_return std::unexpected(std::make_error_code(std::errc::protocol_error));
    if (size > 1 && !(co_await read_exact(loop, connection, id, std::span(input).subspan(1, size - 1))).value_or(false))
        co_return std::unexpected(std::make_error_code(std::errc::protocol_error));
    auto decoded = wire::decode_varint(std::span(input).first(size));
    if (!decoded) co_return std::unexpected(std::make_error_code(std::errc::protocol_error));
    if (remaining) *remaining -= size;
    co_return decoded->value;
}

auto read_control_settings(event_loop& loop, quic_connection& connection,
                           std::uint64_t id, std::size_t remaining) -> task<bool>
{
    // Keep the 64 identifiers in a short-lived frame. The peer SETTINGS
    // payload is consumed incrementally, so no 1 KiB receive buffer remains
    // pinned while the long-lived unidirectional stream waits for input.
    std::array<std::uint64_t, 64> identifiers {};
    std::size_t count = 0;
    while (remaining != 0) {
        if (count == identifiers.size()) co_return false;
        const auto identifier = flatten_result(co_await read_varint(loop, connection, id, &remaining));
        if (!identifier || h3::forbidden_setting(*identifier)) co_return false;
        const auto value = flatten_result(co_await read_varint(loop, connection, id, &remaining));
        if (!value || std::find(identifiers.begin(), identifiers.begin() +
                static_cast<std::ptrdiff_t>(count), *identifier) !=
                identifiers.begin() + static_cast<std::ptrdiff_t>(count)) co_return false;
        identifiers[count++] = *identifier;
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

auto discard_request_remainder(event_loop& loop, quic_connection& connection,
                               std::uint64_t id, std::span<std::byte> scratch)
    -> task<void>
{
    (void)loop;
    constexpr std::size_t discard_limit = 1024 * 1024;
    std::size_t discarded = 0;
    while (connection.valid()) {
        const auto got = flatten_result(co_await connection.async_read(id, scratch));
        if (!got || *got == 0) co_return;
        if (*got > discard_limit - discarded) {
            connection.close(std::make_error_code(std::errc::message_size));
            co_return;
        }
        discarded += *got;
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
    const auto type = flatten_result(co_await read_varint(loop, connection, id));
    const auto length = flatten_result(co_await read_varint(loop, connection, id));
    if (!type || !length || *type != h3::headers_frame || *length > s.headers.size()) {
        connection.close(std::make_error_code(std::errc::protocol_error));
        co_return;
    }
    if (!(co_await read_exact(loop, connection, id, std::span(s.headers).first(*length))).value_or(false))
        co_return;
    const auto decoded = h3::qpack_decode(std::span(s.headers).first(*length), s.fields, s.strings);
    if (!decoded) {
        connection.close(std::make_error_code(std::errc::protocol_error));
        co_return;
    }
    std::string_view method, path, scheme, authority;
    std::size_t match_size = 0;
    bool match_overflow = false;
    std::string_view if_modified_since, range;
    bool duplicate_range = false;
    bool regular = false;
    for (const auto& field : std::span(s.fields).first(*decoded)) {
        bool invalid = field.name.empty() || field.name == "connection" ||
            field.name == "transfer-encoding" || field.name == "upgrade";
        for (unsigned char c : field.name)
            invalid |= c <= 0x20 || c >= 0x7f || (c >= 'A' && c <= 'Z');
        for (unsigned char c : field.value)
            invalid |= c == 0 || c == '\r' || c == '\n' || c == 0x7f;
        if (invalid) {
            connection.close(std::make_error_code(std::errc::protocol_error));
            co_return;
        }
        if (field.name.front() == ':') {
            if (regular) { connection.close(std::make_error_code(std::errc::protocol_error)); co_return; }
            if (field.name == ":method" && method.empty()) method = field.value;
            else if (field.name == ":path" && path.empty()) path = field.value;
            else if (field.name == ":scheme" && scheme.empty()) scheme = field.value;
            else if (field.name == ":authority" && authority.empty()) authority = field.value;
            else { connection.close(std::make_error_code(std::errc::protocol_error)); co_return; }
        } else {
            regular = true;
            if (field.name == "if-none-match") {
                const auto extra = field.value.size() + (match_size != 0 ? 1 : 0);
                if (extra > s.headers.size() - match_size) match_overflow = true;
                else {
                    auto* output = reinterpret_cast<char*>(s.headers.data());
                    if (match_size != 0) output[match_size++] = ',';
                    if (!field.value.empty())
                        std::memcpy(output + match_size, field.value.data(), field.value.size());
                    match_size += field.value.size();
                }
            }
            else if (field.name == "if-modified-since") if_modified_since = field.value;
            else if (field.name == "range") {
                if (!range.empty()) duplicate_range = true;
                else range = field.value;
            }
        }
    }
    if (match_overflow) {
        connection.close(std::make_error_code(std::errc::message_size));
        co_return;
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
    if (method.empty() || path.empty() || scheme != "https" || authority.empty()) status = 400;
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
    if (!(co_await send_headers(loop, connection, id, status, size, mime, finish,
                               s.io, have_file ? &selected : nullptr)).value_or(false)) {
        connection.close(std::make_error_code(std::errc::io_error));
        co_return;
    }
    if (finish) {
        (void)co_await discard_request_remainder(loop, connection, id, s.io);
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
                              listing.size()), false)).value_or(false))
            co_return;
        (void)co_await write_all(loop, connection, id, {}, true);
        (void)co_await discard_request_remainder(loop, connection, id, s.io);
        co_return;
    }
    std::uint64_t sent = 0;
    while (sent < size) {
        // Request headers and conditional fields have already been consumed.
        // Reuse their bounded scratch area for a contiguous DATA frame: larger
        // reads and one stream write per chunk need no additional request memory.
        constexpr std::size_t frame_header_limit = 16;
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
            s.headers.size() - frame_header_limit, size - sent));
        const auto header_size = h3::encode_frame_header(h3::data_frame, count,
            std::span(s.headers).first(frame_header_limit));
        if (!header_size) co_return;
        if (!http::detail::read_file_at(file.get(), offset + sent,
                std::span(s.headers).subspan(*header_size, count))) {
            connection.close(std::make_error_code(std::errc::io_error)); co_return;
        }
        if (!(co_await write_all(loop, connection, id,
                std::span<const std::byte>(s.headers).first(*header_size + count), false))
                .value_or(false)) co_return;
        sent += count;
    }
    (void)co_await write_all(loop, connection, id, {}, true);
    (void)co_await discard_request_remainder(loop, connection, id, s.io);
}

auto drain_peer_uni(event_loop& loop, quic_connection& connection, std::uint64_t id,
                    bool& have_control) -> task<void>
{
    const auto stream_type = flatten_result(co_await read_varint(loop, connection, id));
    if (!stream_type) co_return;
    if (*stream_type == 0) {
        if (have_control) { connection.close(std::make_error_code(std::errc::protocol_error)); co_return; }
        have_control = true;
        const auto frame_type = flatten_result(co_await read_varint(loop, connection, id));
        const auto length = flatten_result(co_await read_varint(loop, connection, id));
        if (!frame_type || !length || *frame_type != h3::settings_frame || *length > 1024) {
            connection.close(std::make_error_code(std::errc::protocol_error)); co_return;
        }
        if (!(co_await read_control_settings(loop, connection, id,
                static_cast<std::size_t>(*length))).value_or(false)) {
            connection.close(std::make_error_code(std::errc::protocol_error)); co_return;
        }
    }
    std::array<std::byte, 256> discard {};
    while (connection.valid()) {
        auto got = flatten_result(co_await connection.async_read(id, discard));
        if (!got || *got == 0) break;
    }
    if (*stream_type == 0 && connection.valid())
        connection.close(std::make_error_code(std::errc::protocol_error));
}

auto serve_connection(event_loop& loop, quic_connection connection,
                      std::shared_ptr<unique_fd> root,
                      stream_handlers& handlers, storage_pool& pool,
                      bool directory_listing) -> task<void>
{
    bool have_control = false;
    auto control = flatten_result(co_await connection.async_open_stream(quic_stream_direction::unidirectional));
    if (!control) { connection.close(control.error()); co_return; }
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
        if (!id || !(co_await write_all(loop, connection, *id, std::span(&type, 1), false)).value_or(false)) {
            connection.close(); co_return;
        }
    }
    while (connection.valid()) {
        auto accepted = flatten_result(co_await connection.async_accept_stream());
        if (!accepted) break;
        const auto id = *accepted;
        task_spawn_result spawned = task_spawn_result::invalid_task;
        auto slot = std::find_if(handlers.begin(), handlers.end(),
            [](const auto& handler) { return !handler || handler->done(); });
        if (slot == handlers.end()) { connection.close(); break; }
        slot->reset();
        slot->emplace();
        if ((id & 3u) == 2u) {
            spawned = loop.spawn(drain_peer_uni(loop, connection, id, have_control), **slot);
        } else if ((id & 3u) == 0u) {
            auto* storage = pool.acquire();
            if (!storage) { slot->reset(); connection.close(); break; }
            spawned = loop.spawn(serve_request(loop, connection, id, root->get(),
                storage, directory_listing), **slot);
            if (spawned != task_spawn_result::accepted) storage->in_use = false;
        }
        if (spawned != task_spawn_result::accepted) {
            slot->reset();
            connection.close();
            break;
        }
    }
    connection.close();
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

    implementation(event_loop& loop, ip_endpoint local, std::string_view root,
                   std::filesystem::path cert, std::filesystem::path key,
                   bool directory_listing, std::size_t connection_capacity,
                   std::size_t request_capacity, std::size_t max_udp_payload_size)
        : loop_(loop), root_(std::make_shared<unique_fd>(http::detail::open_root(root))),
          endpoint_(loop, local, quic_server_options{std::move(cert), std::move(key),
              std::span(alpn_), make_limits(max_udp_payload_size), connection_capacity}),
          directory_listing_(directory_listing), connections_(connection_capacity),
          request_storage_(request_capacity == 0 ? connection_capacity * 4
                                                 : request_capacity) {}

    event_loop& loop_;
    std::shared_ptr<unique_fd> root_;
    const std::array<std::uint8_t, 2> alpn_ {'h', '3'};
    quic_endpoint endpoint_;
    bool directory_listing_ {false};
    std::vector<connection_slot> connections_;
    storage_pool request_storage_;
};

http3_server::http3_server(event_loop& loop, ip_endpoint local, std::string_view root,
                           std::filesystem::path certificate_chain,
                           std::filesystem::path private_key,
                           bool directory_listing,
                           std::size_t connection_capacity,
                           std::size_t request_capacity,
                           std::size_t max_udp_payload_size)
    : implementation_(std::make_unique<implementation>(loop, local, root,
          std::move(certificate_chain), std::move(private_key), directory_listing,
          connection_capacity, request_capacity, max_udp_payload_size)) {}
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
