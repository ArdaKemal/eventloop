#include "eventloop/http/http3_server.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/mime_types.h"
#include "eventloop/unique_fd.h"
#include "../http/exchange.h"
#include "../http/file_operations.h"
#include "../http/open_file_cache.h"
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
#include <functional>
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

// Per-request scratch reserved at startup. A routed request decodes its
// section into fields and strings and copies the regular fields into
// request_headers; headers then holds trailer blocks (first half) and their
// decoded strings (second half), and body holds encoded response HEADERS,
// trailers and file DATA.
struct stream_storage {
    std::array<std::byte, header_limit> headers {};
    std::array<char, header_limit> strings {};
    std::array<h3::field, h3::qpack_max_fields> fields {};
    std::array<std::byte, 4096> io {};
    std::array<http::header, h3::qpack_max_fields> request_headers {};
    std::array<std::byte, 8 * 1024> body {};
    // Kept here, not in serve_request's frame, so that frame stays in its
    // size class; its views point into strings.
    h3::request_head head {};
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
                  const detail::file_response* selected = nullptr,
                  std::string_view allow = "GET, HEAD, OPTIONS") -> task<bool>
{
    std::array<char, 32> status_text {}, length_text {};
    auto status_end = std::to_chars(status_text.data(), status_text.data() + status_text.size(), status);
    auto length_end = std::to_chars(length_text.data(), length_text.data() + length_text.size(), length);
    if (status_end.ec != std::errc{} || length_end.ec != std::errc{}) co_return false;
    if (buffer.size() < 80) co_return false;
    const auto date_buffer = buffer.last(64);
    const auto date_text = reinterpret_cast<char*>(date_buffer.data());
    std::array<h3::field, 8> fields {};
    std::size_t field_count = 0;
    fields[field_count++] = {":status", {status_text.data(), status_end.ptr}};
    if (status != 204) {
        fields[field_count++] = {"content-length", {length_text.data(), length_end.ptr}};
        fields[field_count++] = {"content-type", mime};
    }
    if (status == 204 || status == 405)
        fields[field_count++] = {"allow", allow};
    if (selected != nullptr) {
        fields[field_count++] = {"etag", {selected->etag.data(), selected->etag_size}};
        fields[field_count++] = {"last-modified", {selected->modified.data(), selected->modified_size}};
        fields[field_count++] = {"accept-ranges", "bytes"};
        if (selected->content_range_size != 0)
            fields[field_count++] = {"content-range", {selected->content_range.data(), selected->content_range_size}};
    }
    const auto date_size = detail::format_http_time(std::time(nullptr),
                                                     {date_text, date_buffer.size()});
    fields[field_count++] = {"date", {date_text, date_size}};
    auto encoded = h3::qpack_encode(std::span(fields).first(field_count),
                                    buffer.subspan(16, buffer.size() - 80));
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

using void_result = detail::void_result;
using size_result = detail::size_result;

[[nodiscard]] auto failure(std::errc code) -> std::error_code
{
    return std::make_error_code(code);
}

// Response field encoding uses the first half of stream_storage::fields and
// trailer decoding the second, so a body read can run beside a response write.
constexpr std::size_t response_fields = h3::qpack_max_fields / 2;
constexpr std::size_t trailer_block = header_limit / 2;

[[nodiscard]] auto expects_continue(std::span<const header> headers) noexcept -> bool
{
    for (const auto& field : headers) {
        if (field.name != "expect") continue;
        auto value = field.value;
        while (!value.empty()) {
            std::size_t end = 0;
            bool quoted = false;
            for (; end < value.size(); ++end) {
                const char c = value[end];
                if (quoted && c == '\\' && end + 1 < value.size()) ++end;
                else if (c == '"') quoted = !quoted;
                else if (!quoted && c == ',') break;
            }
            auto member = value.substr(0, end);
            while (!member.empty() && (member.front() == ' ' || member.front() == '\t'))
                member.remove_prefix(1);
            while (!member.empty() && (member.back() == ' ' || member.back() == '\t'))
                member.remove_suffix(1);
            if (h3::ascii_equal(member, "100-continue")) return true;
            value.remove_prefix(end + (end < value.size()));
        }
    }
    return false;
}

// One routed request on a request stream. Lives in serve_route's frame; the
// connection, storage and parser outlive it.
class http3_exchange final : public detail::exchange {
public:
    http3_exchange(event_loop& loop, quic_connection& connection, std::uint64_t id,
                   stream_storage& storage, h3::request_frames& frames,
                   std::span<const std::byte>& pending, std::uint64_t max_request_body,
                   bool head_only) noexcept
        : loop_(loop), connection_(connection), storage_(storage), frames_(frames),
          pending_(pending), id_(id), max_request_body_(max_request_body),
          head_only_(head_only)
    {
        frames_.set_block_storage(std::span(storage_.headers).first(trailer_block));
    }

    auto read_body(std::span<std::byte> buffer) -> task<size_result> override
    {
        return read_task(loop_, *this, buffer);
    }
    auto start(unsigned status, std::span<const header> headers,
               std::optional<std::uint64_t> length) -> task<void_result> override
    {
        return start_task(loop_, *this, status, headers, length);
    }
    auto write(std::span<const std::byte> data) -> task<void_result> override
    {
        return write_task(loop_, *this, data);
    }
    auto finish(std::span<const header> trailers) -> task<void_result> override
    {
        return finish_task(loop_, *this, trailers);
    }
    auto send_file(unsigned status, std::span<const header> headers, unique_fd file,
                   std::uint64_t offset, std::uint64_t size) -> task<void_result> override
    {
        return send_file_task(loop_, *this, status, headers, std::move(file), offset, size);
    }
    [[nodiscard]] auto loop() noexcept -> event_loop& override { return loop_; }
    auto accept_websocket(std::span<const header> headers) -> task<void_result> override
    { return start_task(loop_, *this, 200, headers, std::nullopt, true); }
    auto abort_websocket() noexcept -> void override
    {
        if (websocket_aborted || (finished_ && body_ended_)) return;
        websocket_aborted = true;
        broken_ = true;
        fail(connection_, id_, h3::h3_error::request_cancelled);
    }

    http::request request_ = detail::request_access::make_request();
    http::response response_ = detail::request_access::make_response();
    bool started_ {false};
    bool finished_ {false};
    bool broken_ {false};
    bool body_ended_ {false};
    bool too_large_ {false};

    static auto start_task(event_loop& loop, http3_exchange& self, unsigned status,
                           std::span<const header> headers, std::optional<std::uint64_t> length,
                           bool websocket = false)
        -> task<void_result>
    {
        if (self.writing_) co_return std::unexpected(failure(std::errc::operation_in_progress));
        if (self.broken_) co_return std::unexpected(failure(std::errc::connection_reset));
        if (self.started_ || (websocket && self.reading_))
            co_return std::unexpected(failure(std::errc::invalid_argument));
        const auto checked = detail::check_response_start(status, headers, length);
        if (!checked) co_return std::unexpected(checked.error());
        if (self.request_.method() == method_type::connect && status < 300 &&
            (length || checked->declared))
            co_return std::unexpected(failure(std::errc::invalid_argument));
        if (headers.size() + 3 > response_fields)
            co_return std::unexpected(failure(std::errc::message_size));
        busy writing(self.writing_);
        std::array<char, 4> status_text {};
        const auto status_end = std::to_chars(status_text.data(), status_text.data() + 3, status).ptr;
        std::array<char, 24> length_text {};
        std::array<char, 64> date {};
        auto fields = std::span(self.storage_.fields).first(response_fields);
        std::size_t count = 0;
        fields[count++] = {":status", {status_text.data(), status_end}};
        for (const auto& field : headers) fields[count++] = {field.name, field.value};
        if (checked->emit_length) {
            const auto end = std::to_chars(length_text.data(),
                length_text.data() + length_text.size(), *length).ptr;
            fields[count++] = {"content-length", {length_text.data(), end}};
        }
        if (!checked->has_date) {
            const auto size = detail::format_http_time(std::time(nullptr), date);
            fields[count++] = {"date", {date.data(), size}};
        }
        if (!(co_await write_section(loop, self, fields.first(count), false)).value_or(false)) {
            self.broken_ = true;
            if (websocket) self.abort_websocket();
            co_return std::unexpected(failure(std::errc::connection_reset));
        }
        self.started_ = true;
        self.websocket_accepted = websocket;
        if (websocket) self.frames_.accept_connect();
        self.bodyless_ = checked->bodyless;
        self.declared_ = checked->declared;
        co_return void_result {};
    }

private:
    struct busy {
        explicit busy(bool& flag) noexcept : flag(flag) { flag = true; }
        ~busy() { flag = false; }
        busy(const busy&) = delete;
        auto operator=(const busy&) -> busy& = delete;
        bool& flag;
    };

    // Encodes fields as one HEADERS frame in storage.body and writes it.
    static auto write_section(event_loop& loop, http3_exchange& self,
                              std::span<const h3::field> fields, bool fin) -> task<bool>
    {
        const auto buffer = std::span(self.storage_.body);
        const auto encoded = h3::qpack_encode(fields, buffer.subspan(16));
        if (!encoded) co_return false;
        const auto framed = h3::encode_frame(h3::headers_frame,
            buffer.subspan(16, *encoded), buffer);
        if (!framed) co_return false;
        co_return (co_await write_all(loop, self.connection_, self.id_,
                                      buffer.first(*framed), fin)).value_or(false);
    }

    // Validates a trailer section against the trailer rules (RFC 9114 4.1.2).
    auto check_trailers() noexcept -> std::expected<void, h3::h3_error>
    {
        auto strings = std::span(reinterpret_cast<char*>(storage_.headers.data()) + trailer_block,
                                 header_limit - trailer_block);
        auto fields = std::span(storage_.fields).subspan(response_fields);
        const auto decoded = h3::qpack_decode(frames_.block(), fields, strings);
        if (!decoded) return std::unexpected(h3::qpack_failure(decoded.error()));
        return h3::validate_trailers(fields.first(*decoded));
    }

    static auto read_task(event_loop& loop, http3_exchange& self, std::span<std::byte> buffer)
        -> task<size_result>
    {
        (void)loop;
        if (self.reading_) co_return std::unexpected(failure(std::errc::operation_in_progress));
        if (self.too_large_) co_return std::unexpected(failure(std::errc::message_size));
        busy reading(self.reading_);
        const auto input_area = std::span(self.storage_.io).subspan(response_header_area);
        for (;;) {
            if (self.websocket_aborted)
                co_return std::unexpected(failure(std::errc::operation_canceled));
            if (self.broken_) co_return std::unexpected(failure(std::errc::connection_reset));
            if (!self.data_.empty()) {
                if (buffer.empty()) co_return std::unexpected(failure(std::errc::invalid_argument));
                self.continue_checked_ = true;
                const auto count = std::min(buffer.size(), self.data_.size());
                std::memcpy(buffer.data(), self.data_.data(), count);
                self.data_ = self.data_.subspan(count);
                co_return count;
            }
            if (self.body_ended_) co_return 0;
            if (!self.pending_.empty()) {
                const auto parsed = self.frames_.receive(self.pending_);
                std::expected<void, h3::h3_error> valid {};
                if (!parsed) valid = std::unexpected(parsed.error());
                else if (*parsed == h3::request_frames::event::header_block)
                    valid = self.check_trailers();
                if (!valid) {
                    fail(self.connection_, self.id_, valid.error());
                    self.broken_ = true;
                    co_return std::unexpected(failure(std::errc::bad_message));
                }
                if (*parsed == h3::request_frames::event::data) {
                    if (!self.websocket_accepted &&
                        self.frames_.data_received() > self.max_request_body_) {
                        self.too_large_ = true;
                        co_return std::unexpected(failure(std::errc::message_size));
                    }
                    self.data_ = self.frames_.data();
                }
                continue;
            }
            // RFC 9110 10.1.1: send Continue before waiting for content,
            // unless content or a final response has already started.
            if (!self.continue_checked_) {
                self.continue_checked_ = true;
                if (!self.started_ && !self.writing_ && self.request_.content_length() != 0 &&
                    expects_continue(self.request_.headers())) {
                    busy writing(self.writing_);
                    const std::array<h3::field, 1> fields {{{":status", "100"}}};
                    if (!(co_await write_section(loop, self, fields, false)).value_or(false)) {
                        self.broken_ = true;
                        co_return std::unexpected(failure(std::errc::connection_reset));
                    }
                }
            }
            const auto got = flatten_result(co_await self.connection_.async_read(self.id_, input_area));
            if (!got) {
                if (self.websocket_aborted)
                    co_return std::unexpected(failure(std::errc::operation_canceled));
                if (self.websocket_accepted && got.error() == failure(std::errc::operation_canceled))
                    co_return std::unexpected(got.error());
                self.broken_ = true;
                co_return std::unexpected(failure(std::errc::connection_reset));
            }
            if (*got == 0) {
                if (const auto finished = self.frames_.finish(); !finished) {
                    fail(self.connection_, self.id_, finished.error());
                    self.broken_ = true;
                    co_return std::unexpected(failure(std::errc::bad_message));
                }
                self.body_ended_ = true;
                co_return 0;
            }
            self.pending_ = std::span<const std::byte>(input_area).first(*got);
        }
    }

    static auto write_task(event_loop& loop, http3_exchange& self, std::span<const std::byte> data)
        -> task<void_result>
    {
        (void)loop;
        if (self.writing_) co_return std::unexpected(failure(std::errc::operation_in_progress));
        if (self.websocket_aborted)
            co_return std::unexpected(failure(std::errc::operation_canceled));
        if (self.broken_) co_return std::unexpected(failure(std::errc::connection_reset));
        if (!self.started_ || self.finished_ || (self.bodyless_ && !data.empty()) ||
            (self.declared_ && data.size() > *self.declared_ - self.sent_))
            co_return std::unexpected(failure(std::errc::invalid_argument));
        busy writing(self.writing_);
        self.sent_ += data.size();
        if (self.head_only_ || data.empty()) co_return void_result {};
        const auto buffer = std::span(self.storage_.body);
        const auto header_size = h3::encode_frame_header(h3::data_frame, data.size(),
                                                         buffer.first(16));
        if (!header_size) co_return std::unexpected(failure(std::errc::message_size));
        const bool contiguous = data.size() <= buffer.size() - *header_size;
        if (contiguous) {
            // Small writes go out as one contiguous frame.
            std::memcpy(buffer.data() + *header_size, data.data(), data.size());
        }
        std::span<const std::byte> pending = buffer.first(
            *header_size + (contiguous ? data.size() : 0));
        bool payload_pending = !contiguous;
        std::expected<std::size_t, std::error_code> written;
        for (;;) {
            written = flatten_result(co_await self.connection_.async_write(self.id_, pending, false));
            if (!written) break;
            if (*written == 0 || *written > pending.size()) {
                written = std::unexpected(failure(std::errc::connection_reset));
                break;
            }
            pending = pending.subspan(*written);
            if (!pending.empty()) continue;
            if (!payload_pending) break;
            pending = data;
            payload_pending = false;
        }
        if (!written) {
            if (self.websocket_aborted)
                co_return std::unexpected(failure(std::errc::operation_canceled));
            self.broken_ = true;
            if (self.websocket_accepted) {
                fail(self.connection_, self.id_, h3::h3_error::request_cancelled);
                co_return std::unexpected(written.error() == failure(std::errc::operation_canceled)
                    ? written.error() : failure(std::errc::connection_reset));
            }
            co_return std::unexpected(failure(std::errc::connection_reset));
        }
        co_return void_result {};
    }

    static auto finish_task(event_loop& loop, http3_exchange& self, std::span<const header> trailers)
        -> task<void_result>
    {
        if (self.writing_) co_return std::unexpected(failure(std::errc::operation_in_progress));
        if (self.websocket_aborted)
            co_return std::unexpected(failure(std::errc::operation_canceled));
        if (self.broken_) co_return std::unexpected(failure(std::errc::connection_reset));
        if (!self.started_ || self.finished_)
            co_return std::unexpected(failure(std::errc::invalid_argument));
        if (self.declared_ && self.sent_ != *self.declared_ && !self.head_only_) {
            self.broken_ = true;
            fail(self.connection_, self.id_, h3::h3_error::internal_error);
            co_return std::unexpected(failure(std::errc::invalid_argument));
        }
        if (trailers.size() > response_fields)
            co_return std::unexpected(failure(std::errc::message_size));
        for (const auto& field : trailers)
            if (!detail::valid_response_field(field.name, field.value) ||
                field.name == "content-length")
                co_return std::unexpected(failure(std::errc::invalid_argument));
        busy writing(self.writing_);
        bool written = false;
        if (!trailers.empty() && !self.head_only_) {
            auto fields = std::span(self.storage_.fields).first(response_fields);
            for (std::size_t index = 0; index < trailers.size(); ++index)
                fields[index] = {trailers[index].name, trailers[index].value};
            written = (co_await write_section(loop, self, fields.first(trailers.size()), true))
                .value_or(false);
        } else {
            written = (co_await write_all(loop, self.connection_, self.id_, {}, true))
                .value_or(false);
        }
        if (!written) {
            self.broken_ = true;
            co_return std::unexpected(failure(std::errc::connection_reset));
        }
        self.finished_ = true;
        co_return void_result {};
    }

    static auto send_file_task(event_loop& loop, http3_exchange& self, unsigned status,
                               std::span<const header> headers, unique_fd file,
                               std::uint64_t offset, std::uint64_t size) -> task<void_result>
    {
        auto started = co_await start_task(loop, self, status, headers, size);
        if (!started) co_return std::unexpected(failure(std::errc::operation_canceled));
        if (!*started) co_return std::unexpected(started->error());
        if (self.bodyless_ || self.head_only_ || size == 0)
            co_return (co_await finish_task(loop, self, {}))
                .value_or(std::unexpected(failure(std::errc::operation_canceled)));
        busy writing(self.writing_);
        const auto buffer = std::span(self.storage_.body);
        constexpr std::size_t frame_header_limit = 16;
        std::uint64_t sent = 0;
        while (sent < size) {
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
                buffer.size() - frame_header_limit, size - sent));
            const auto header_size = h3::encode_frame_header(h3::data_frame, count,
                                                             buffer.first(frame_header_limit));
            if (!header_size ||
                !detail::read_file_at(file.get(), offset + sent,
                                      buffer.subspan(*header_size, count))) {
                self.broken_ = true;
                fail(self.connection_, self.id_, h3::h3_error::internal_error);
                co_return std::unexpected(failure(std::errc::io_error));
            }
            sent += count;
            if (!(co_await write_all(loop, self.connection_, self.id_,
                    buffer.first(*header_size + count), sent == size)).value_or(false)) {
                self.broken_ = true;
                co_return std::unexpected(failure(std::errc::connection_reset));
            }
        }
        self.sent_ = size;
        self.finished_ = true;
        co_return void_result {};
    }

    event_loop& loop_;
    quic_connection& connection_;
    stream_storage& storage_;
    h3::request_frames& frames_;
    std::span<const std::byte>& pending_;
    std::span<const std::byte> data_;
    std::uint64_t id_;
    std::uint64_t max_request_body_;
    std::uint64_t sent_ {0};
    std::optional<std::uint64_t> declared_;
    bool head_only_;
    bool bodyless_ {false};
    bool continue_checked_ {false};
    bool reading_ {false};
    bool writing_ {false};
};

// Join split Cookie lines for the generic HTTP application (RFC 9114 4.2.1).
// The unused decoded-string tail keeps the joined view alive through body
// reads and response writes without using either operation's scratch area.
auto prepare_request_headers(stream_storage& s, std::span<const h3::field> fields,
                             std::size_t& count) -> bool
{
    std::size_t cookies = 0, cookie_size = 0;
    for (const auto& field : fields)
        if (field.name == "cookie") { ++cookies; cookie_size += field.value.size(); }
    std::string_view joined;
    if (cookies > 1) {
        std::size_t used = 0;
        const std::less<const char*> less;
        for (const auto& field : fields)
            for (const auto value : {field.name, field.value})
                if (!less(value.data(), s.strings.data()) &&
                    less(value.data(), s.strings.data() + s.strings.size()))
                    used = std::max(used, static_cast<std::size_t>(value.data() - s.strings.data()) +
                                         value.size());
        cookie_size += 2 * (cookies - 1);
        if (cookie_size > s.strings.size() - used)
            return false;
        char* output = s.strings.data() + used;
        std::size_t written = 0;
        bool first = true;
        for (const auto& field : fields) {
            if (field.name != "cookie") continue;
            if (!first) { output[written++] = ';'; output[written++] = ' '; }
            if (!field.value.empty())
                std::memcpy(output + written, field.value.data(), field.value.size());
            written += field.value.size();
            first = false;
        }
        joined = {output, written};
    }
    count = 0;
    bool copied_cookie = false;
    for (const auto& field : fields) {
        if (!field.name.empty() && field.name.front() == ':') continue;
        if (field.name == "cookie" && cookies > 1) {
            if (copied_cookie) continue;
            copied_cookie = true;
            s.request_headers[count++] = {field.name, joined};
        } else s.request_headers[count++] = {field.name, field.value};
    }
    return true;
}

// Runs a route handler for a decoded, validated request.
auto serve_route(event_loop& loop, quic_connection& connection, std::uint64_t id,
                 stream_storage& s, h3::request_frames& frames,
                 std::span<const std::byte>& pending, const h3::request_head& head,
                 std::span<const h3::field> fields, detail::route_match match,
                 std::uint64_t max_request_body) -> task<void>
{
    std::size_t count = 0;
    if (!prepare_request_headers(s, fields, count)) {
        fail(connection, id, h3::h3_error::excessive_load);
        co_return;
    }
    http3_exchange exchange(loop, connection, id, s, frames, pending, max_request_body,
                            head.method == "HEAD");
    const detail::request_fields request {
        .headers = std::span<const header>(s.request_headers).first(count),
        .method_name = head.method,
        .target = head.path,
        .authority = head.authority,
        .connect_protocol = head.connect_protocol,
        .content_length = head.content_length,
        .method = detail::method_from_name(head.method),
        .protocol = http::protocol::http3,
    };
    detail::request_access::bind(exchange.request_, exchange, request, match.context);
    detail::request_access::bind(exchange.response_, exchange);
    const auto handled = co_await match.function(loop, exchange.request_, exchange.response_);
    if (handled == task_result::cancelled) co_return;
    if (!exchange.started_ && !exchange.broken_) {
        const unsigned status = exchange.too_large_ ? 413
            : handled == task_result::frame_allocation_failure ? 503 : 500;
        const auto started = co_await http3_exchange::start_task(loop, exchange, status, {}, 0);
        if (started && *started)
            (void)co_await exchange.finish(std::span<const header> {});
    }
    if (exchange.broken_) co_return;
    if (!exchange.finished_) {
        fail(connection, id, h3::h3_error::internal_error);
        co_return;
    }
    // RFC 9114 4.1: the rest of the body is not needed.
    if (!exchange.body_ended_)
        (void)connection.stop_sending(id, static_cast<std::uint64_t>(h3::h3_error::no_error));
}

// The server-wide request settings, shared by every connection.
struct request_settings {
    const router* routes {nullptr};
    std::uint64_t max_request_body {0};
    bool directory_listing {false};
};

// Answers a request whose path has routes. Returns false when no route
// matches, so the caller serves static files.
auto route_request(event_loop& loop, quic_connection& connection, std::uint64_t id,
                   stream_storage& s, h3::request_frames& frames,
                   std::span<const std::byte>& pending, const h3::request_head& head,
                   std::span<const h3::field> fields, const request_settings& settings)
    -> task<bool>
{
    const auto match = detail::router_access::match(*settings.routes,
        detail::method_from_name(head.method), head.path.substr(0, head.path.find('?')));
    const bool extended = !head.connect_protocol.empty();
    const bool unsupported = extended && head.connect_protocol != "websocket";
    if (match.allowed == 0 && !extended) co_return false;
    const bool too_large = match.function != nullptr && (head.content_length_too_large ||
        (head.connect_protocol.empty() && head.content_length &&
         *head.content_length > settings.max_request_body));
    if (match.function != nullptr && !too_large && !unsupported) {
        (void)co_await serve_route(loop, connection, id, s, frames, pending, head, fields,
                                   match, settings.max_request_body);
        co_return true;
    }
    std::array<char, 96> allow {};
    const auto allow_size = detail::format_allow(match.allowed, allow);
    const unsigned status = too_large ? 413 : unsupported ? 501 : match.allowed == 0 ? 404
        : head.method == "OPTIONS" ? 204 : 405;
    if (!(co_await send_headers(loop, connection, id, status, 0, "text/plain", true,
            std::span(s.io).first(response_header_area), nullptr,
            {allow.data(), allow_size})).value_or(false)) {
        fail(connection, id, h3::h3_error::request_cancelled);
        co_return true;
    }
    if (too_large || !head.connect_protocol.empty())
        (void)connection.stop_sending(id, static_cast<std::uint64_t>(h3::h3_error::no_error));
    else
        (void)co_await finish_request(loop, connection, id, s, frames, pending);
    co_return true;
}

// Validates outside serve_request, whose frame would otherwise hold the result.
[[nodiscard]] auto store_request_head(stream_storage& s, std::span<const h3::field> fields,
                                      bool extended_connect) noexcept
    -> std::optional<h3::h3_error>
{
    const auto head = h3::validate_request(fields, extended_connect);
    if (!head) return head.error();
    s.head = *head;
    return std::nullopt;
}

auto serve_request(event_loop& loop, quic_connection& connection, std::uint64_t id,
                   native_socket root, http::detail::open_file_cache* files,
                   stream_storage* storage,
                   const request_settings& settings)
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
    if (const auto invalid = store_request_head(s, request_fields, settings.routes != nullptr)) {
        fail(connection, id, *invalid);
        co_return;
    }
    frames.set_content_length(s.head.content_length, s.head.content_length_too_large);
    const auto method = s.head.method;
    const auto path = s.head.path;
    const bool https = h3::ascii_equal(s.head.scheme, "https");
    if (s.head.connect_protocol == "websocket" && !https) {
        fail(connection, id, h3::h3_error::message_error);
        co_return;
    }
    // Routes see https requests; others keep the static answers below. The
    // routed path runs in its own frame so this one stays in its size class.
    if (settings.routes != nullptr && (https || !s.head.connect_protocol.empty()) &&
        (co_await route_request(loop, connection, id, s, frames, pending, s.head,
                                request_fields, settings)).value_or(true))
        co_return;
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
    http::detail::static_file file;
    std::uint64_t size = 0;
    std::uint64_t offset = 0;
    detail::file_response selected;
    bool have_file = false;
    bool have_listing = false;
    std::vector<char> listing;
    std::string_view mime = "text/plain";
    // Plain CONNECT has no :scheme and is answered 405 below.
    if (method != "CONNECT" && !https) status = 400;
    else if (method == "OPTIONS") status = 204;
    else if (method != "GET" && method != "HEAD") status = 405;
    else {
        auto opened = http::detail::open_static(root, files, path);
        if (!opened) status = opened.error() == http::detail::resource_error::invalid_target ? 400
            : opened.error() == http::detail::resource_error::target_too_long ? 414 : 404;
        else {
            file = std::move(opened->file);
            const std::optional<http::detail::file_info> info = opened->info;
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
                } else if (!settings.directory_listing) {
                    status = 403;
                } else {
                    auto rendered = http::detail::render_directory_listing(file.take_owned());
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
    if (have_listing && method != "HEAD") {
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
                      std::shared_ptr<http::detail::document_root> root,
                      stream_handlers& handlers, storage_pool& pool,
                      const request_settings& settings) -> task<void>
{
    h3::peer_critical_streams critical;
    auto control = flatten_result(co_await connection.async_open_stream(quic_stream_direction::unidirectional));
    // RFC 9114 6.2 requires room for the three server critical streams.
    const auto general = static_cast<std::uint64_t>(h3::h3_error::general_protocol_error);
    if (!control) { connection.close_application(general); co_return; }
    // Server control stream: stream type 0, SETTINGS with zero QPACK dynamic table.
    const bool extended = settings.routes != nullptr;
    const std::array<std::byte, 9> control_settings {std::byte{0}, std::byte{4},
        extended ? std::byte{6} : std::byte{4}, std::byte{1}, std::byte{0}, std::byte{7},
        std::byte{0}, std::byte{8}, std::byte{1}};
    if (!(co_await write_all(loop, connection, *control,
            std::span(control_settings).first(extended ? 9 : 7), false)).value_or(false)) {
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
                ? loop.spawn(serve_request(loop, connection, id, root->descriptor.get(),
                      root->cache.get(), storage, settings), **slot)
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
    static auto open_document_root(const server_options& options)
        -> std::shared_ptr<http::detail::document_root>
    {
        if (!options.routes && options.document_root.empty())
            throw std::invalid_argument("server needs routes or a document root");
        auto root = std::make_shared<http::detail::document_root>();
        if (options.document_root.empty()) return root;
        root->descriptor = http::detail::open_root(options.document_root.string());
        if (options.open_file_cache_capacity != 0)
            root->cache = std::make_unique<http::detail::open_file_cache>(
                options.open_file_cache_capacity);
        return root;
    }

    implementation(event_loop& loop, ip_endpoint local, std::filesystem::path cert,
                   std::filesystem::path key, const server_options& options)
        : loop_(loop), root_(open_document_root(options)),
          endpoint_(loop, local, quic_server_options{std::move(cert), std::move(key),
              std::span(alpn_), make_limits(options.max_udp_payload_size),
              options.connection_capacity}),
          routes_(options.routes),
          settings_ {routes_.get(), options.max_request_body, options.directory_listing},
          connections_(options.connection_capacity),
          request_storage_(options.request_capacity == 0 ? options.connection_capacity * 4
                                                         : options.request_capacity) {}

    event_loop& loop_;
    std::shared_ptr<http::detail::document_root> root_;
    const std::array<std::uint8_t, 2> alpn_ {'h', '3'};
    quic_endpoint endpoint_;
    std::shared_ptr<const router> routes_;
    request_settings settings_;
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
            // Other errors, such as a peer that closed before acceptance,
            // fail only that connection.
            if (accepted.error() == std::make_error_code(std::errc::operation_canceled)) break;
            continue;
        }
        auto slot = std::find_if(impl.connections_.begin(), impl.connections_.end(),
            [](const auto& entry) { return !entry.handle || entry.handle->done(); });
        if (slot == impl.connections_.end()) { accepted->close(); continue; }
        slot->handle.emplace();
        const auto spawned = loop.spawn(serve_connection(loop, std::move(*accepted), impl.root_,
                slot->handlers, impl.request_storage_, impl.settings_), *slot->handle);
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
