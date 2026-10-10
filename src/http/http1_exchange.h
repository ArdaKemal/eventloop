#pragma once

#include "exchange.h"
#include "file_operations.h"
#include "session.h"

#include "eventloop/tcp_stream.h"
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
#include "eventloop/tls_stream.h"
#endif

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <optional>
#include <string_view>
#include <type_traits>

namespace eventloop::http::detail {

template<typename T>
[[nodiscard]] auto io_value(std::expected<T, std::error_code> result) noexcept
    -> std::expected<T, std::error_code>
{
    return result;
}

template<typename T>
[[nodiscard]] auto io_value(std::expected<std::expected<T, std::error_code>, task_result> result)
    noexcept -> std::expected<T, std::error_code>
{
    if (!result) {
        return std::unexpected(std::make_error_code(
            result.error() == task_result::frame_allocation_failure
                ? std::errc::not_enough_memory : std::errc::operation_canceled));
    }
    return std::move(*result);
}

[[nodiscard]] constexpr auto reason_phrase(unsigned status) noexcept -> std::string_view
{
    switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Content Too Large";
    case 415: return "Unsupported Media Type";
    case 422: return "Unprocessable Content";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    default: return {};
    }
}

// Runs routed HTTP/1.1 requests on one connection. Allocated once per
// connection when the server has routes; every per-request byte lives here,
// in the session input, or in the handler's frame.
template<typename Stream>
class http1_exchange final : public exchange {
public:
    http1_exchange(event_loop& loop, Stream& peer, session& state, route_state& routing) noexcept
        : loop_(loop), peer_(peer), session_(state), routing_(routing)
    {
    }

    // Runs the handler for the session's routed request. Returns whether the
    // connection can carry another request.
    static auto serve(event_loop& loop, http1_exchange& self) -> task<bool>
    {
        self.reset();
        const auto& head = self.routing_.request;
        request_fields fields {
            .headers = std::span<const header>(head.headers.data(), head.header_count),
            .method_name = head.method_name,
            .target = head.target,
            .authority = head.host,
            .content_length = head.content_length_seen
                ? std::optional<std::uint64_t>(head.content_length) : std::nullopt,
            .method = head.method,
            .protocol = http::protocol::http1_1,
        };
        request_access::bind(self.request_, self, fields, self.routing_.match.context);
        request_access::bind(self.response_, self);
        // A handler that throws is treated as one that returned.
        auto handled = task_result::success;
        try {
            handled = co_await self.routing_.match.function(loop, self.request_, self.response_);
        } catch (...) {}
        const bool rejected = handled == task_result::frame_allocation_failure;
        if (handled == task_result::cancelled) co_return false;
        if (!self.started_ && !self.broken_) {
            const unsigned status = self.malformed_ ? 400 : self.too_large_ ? 413
                : rejected ? 503 : 500;
            auto started = co_await start_task(loop, self, status, {}, 0);
            if (started && *started) (void)co_await finish_task(loop, self, {});
        }
        // After a malformed or oversized body, the next request cannot be found.
        if (self.broken_ || !self.finished_ || self.malformed_ || self.too_large_) co_return false;
        if (head.chunked) {
            // A client waiting for 100 Continue may never send the body.
            if (head.expect_continue && !self.continued_ && !self.decoder_.done()) co_return false;
            // Discard the rest of the body within the body limit; the
            // response buffer is free once the response has finished.
            while (!self.decoder_.done()) {
                const auto read = co_await read_chunked_task(loop, self, self.buffer_);
                if (!read || !*read) co_return false;
            }
            co_return !head.close_after_response;
        }
        // A client waiting for 100 Continue may never send the body.
        if (head.expect_continue && !self.continued_ && self.body_read_ < self.body_length_)
            co_return false;
        // Discard the unread body so the next request starts at its head.
        while (self.body_read_ < self.body_length_) {
            const auto buffered = self.session_.buffered_body();
            if (!buffered.empty()) {
                self.body_read_ += buffered.size();
                self.session_.consume_buffered_body(buffered.size());
                continue;
            }
            const auto want = std::min<std::uint64_t>(self.buffer_.size(),
                                                      self.body_length_ - self.body_read_);
            const auto received = io_value(co_await self.peer_.async_read_some(
                std::span(self.buffer_).first(static_cast<std::size_t>(want))));
            if (!received || *received == 0) co_return false;
            self.body_read_ += *received;
        }
        co_return !head.close_after_response;
    }

    auto read_body(std::span<std::byte> buffer) -> task<size_result> override
    {
        return routing_.request.chunked ? read_chunked_task(loop_, *this, buffer)
                                        : read_task(loop_, *this, buffer);
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

private:
    struct busy {
        explicit busy(bool& flag) noexcept : flag(flag) { flag = true; }
        ~busy() { flag = false; }
        busy(const busy&) = delete;
        auto operator=(const busy&) -> busy& = delete;
        bool& flag;
    };

    [[nodiscard]] static auto failure(std::errc code) -> std::error_code
    {
        return std::make_error_code(code);
    }

    [[nodiscard]] static auto unwrap(std::expected<void_result, task_result> result) noexcept
        -> void_result
    {
        if (!result) return std::unexpected(failure(std::errc::operation_canceled));
        return *result;
    }

    auto reset() noexcept -> void
    {
        const auto& head = routing_.request;
        body_length_ = head.content_length;
        body_read_ = 0;
        sent_ = 0;
        declared_.reset();
        output_size_ = 0;
        head_only_ = head.method == method_type::head;
        reading_ = writing_ = false;
        continued_ = false;
        started_ = finished_ = broken_ = false;
        decoder_ = chunked_decoder {};
        staging_begin_ = staging_end_ = 0;
        malformed_ = too_large_ = false;
        chunked_ = bodyless_ = false;
    }

    // Copies as much of text as fits into the output buffer and returns the rest.
    [[nodiscard]] auto append(std::string_view text) noexcept -> std::string_view
    {
        const auto count = std::min(text.size(), buffer_.size() - output_size_);
        std::memcpy(buffer_.data() + output_size_, text.data(), count);
        output_size_ += count;
        return text.substr(count);
    }

    static auto write_all(event_loop& loop, http1_exchange& self, std::span<const std::byte> data)
        -> task<void_result>
    {
        (void)loop;
        while (!data.empty()) {
            const auto written = io_value(co_await self.peer_.async_write_some(data));
            if (!written || *written == 0) {
                self.broken_ = true;
                co_return std::unexpected(written ? failure(std::errc::broken_pipe)
                                                  : written.error());
            }
            data = data.subspan(*written);
        }
        co_return void_result {};
    }

    static auto flush(event_loop& loop, http1_exchange& self) -> task<void_result>
    {
        const auto size = self.output_size_;
        self.output_size_ = 0;
        auto written = co_await write_all(loop, self, std::span(self.buffer_).first(size));
        if (!written) {
            self.broken_ = true;
            co_return std::unexpected(failure(std::errc::operation_canceled));
        }
        co_return *written;
    }

    static auto read_task(event_loop& loop, http1_exchange& self, std::span<std::byte> buffer)
        -> task<size_result>
    {
        (void)loop;
        if (self.reading_) co_return std::unexpected(failure(std::errc::operation_in_progress));
        if (self.broken_) co_return std::unexpected(failure(std::errc::connection_reset));
        busy reading(self.reading_);
        const auto remaining = self.body_length_ - self.body_read_;
        if (remaining == 0) co_return 0;
        if (buffer.empty()) co_return std::unexpected(failure(std::errc::invalid_argument));
        const auto want = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), remaining));
        const auto buffered = self.session_.buffered_body();
        if (!buffered.empty()) {
            const auto count = std::min(want, buffered.size());
            std::memcpy(buffer.data(), buffered.data(), count);
            self.session_.consume_buffered_body(count);
            self.body_read_ += count;
            co_return count;
        }
        const auto proceeded = co_await send_continue(loop, self);
        if (!proceeded || !*proceeded)
            co_return std::unexpected(failure(std::errc::connection_reset));
        const auto received = io_value(co_await self.peer_.async_read_some(buffer.first(want)));
        if (!received || *received == 0) {
            self.broken_ = true;
            co_return std::unexpected(received ? failure(std::errc::connection_reset)
                                               : received.error());
        }
        self.body_read_ += *received;
        co_return *received;
    }

    // RFC 9110 section 10.1.1: ask for the body only once it is read.
    static auto send_continue(event_loop& loop, http1_exchange& self) -> task<bool>
    {
        if (!self.routing_.request.expect_continue || self.continued_ || self.started_ ||
            self.writing_) co_return true;
        constexpr std::string_view proceed = "HTTP/1.1 100 Continue\r\n\r\n";
        self.continued_ = true;
        busy writing(self.writing_);
        auto sent = co_await write_all(loop, self, std::as_bytes(std::span(proceed)));
        co_return sent && *sent;
    }

    // Decodes a chunked body: buffered session input first, then socket reads
    // through the staging buffer. Bytes read past the body go back to the
    // session for the next request.
    static auto read_chunked_task(event_loop& loop, http1_exchange& self,
                                  std::span<std::byte> buffer) -> task<size_result>
    {
        if (self.reading_) co_return std::unexpected(failure(std::errc::operation_in_progress));
        if (self.broken_) co_return std::unexpected(failure(std::errc::connection_reset));
        if (self.malformed_) co_return std::unexpected(failure(std::errc::bad_message));
        if (self.too_large_) co_return std::unexpected(failure(std::errc::message_size));
        if (buffer.empty()) co_return std::unexpected(failure(std::errc::invalid_argument));
        busy reading(self.reading_);
        for (;;) {
            if (self.decoder_.done()) co_return 0;
            const auto buffered = self.session_.buffered_body();
            std::span<const std::byte> input = !buffered.empty() ? buffered
                : std::span<const std::byte>(self.staging_)
                      .subspan(self.staging_begin_, self.staging_end_ - self.staging_begin_);
            if (input.empty()) {
                const auto proceeded = co_await send_continue(loop, self);
                if (!proceeded || !*proceeded)
                    co_return std::unexpected(failure(std::errc::connection_reset));
                const auto received = io_value(co_await self.peer_.async_read_some(self.staging_));
                if (!received || *received == 0) {
                    self.broken_ = true;
                    co_return std::unexpected(received ? failure(std::errc::connection_reset)
                                                       : received.error());
                }
                self.staging_begin_ = 0;
                self.staging_end_ = *received;
                continue;
            }
            const auto available = input.size();
            std::span<const std::byte> data;
            const auto status = self.decoder_.feed(input, buffer.size(), data);
            const auto consumed = available - input.size();
            const auto count = data.size();
            if (count != 0) std::memcpy(buffer.data(), data.data(), count);
            if (!buffered.empty()) self.session_.consume_buffered_body(consumed);
            else self.staging_begin_ += consumed;
            if (status == chunked_decoder::status::error) {
                self.malformed_ = true;
                co_return std::unexpected(failure(std::errc::bad_message));
            }
            self.body_read_ += count;
            if (self.body_read_ > self.routing_.max_request_body) {
                self.too_large_ = true;
                co_return std::unexpected(failure(std::errc::message_size));
            }
            if (status == chunked_decoder::status::done &&
                self.staging_begin_ != self.staging_end_) {
                self.session_.receive(std::span<const std::byte>(self.staging_)
                    .subspan(self.staging_begin_, self.staging_end_ - self.staging_begin_));
                self.staging_begin_ = self.staging_end_ = 0;
            }
            if (count != 0) co_return count;
        }
    }

    static auto start_task(event_loop& loop, http1_exchange& self, unsigned status,
                           std::span<const header> headers, std::optional<std::uint64_t> length)
        -> task<void_result>
    {
        if (self.writing_) co_return std::unexpected(failure(std::errc::operation_in_progress));
        if (self.broken_) co_return std::unexpected(failure(std::errc::connection_reset));
        if (self.started_) co_return std::unexpected(failure(std::errc::invalid_argument));
        const auto checked = check_response_start(status, headers, length);
        if (!checked) co_return std::unexpected(checked.error());
        busy writing(self.writing_);
        self.started_ = true;
        self.bodyless_ = checked->bodyless;
        self.declared_ = checked->declared;
        self.chunked_ = !checked->bodyless && !checked->declared;

        std::array<char, 64> status_line {};
        const auto reason = reason_phrase(status);
        const int status_size = std::snprintf(status_line.data(), status_line.size(),
            "HTTP/1.1 %u %.*s\r\n", status, static_cast<int>(reason.size()), reason.data());
        std::array<char, 192> trailer_lines {};
        std::size_t extra = 0;
        const auto add = [&](std::string_view text) {
            std::memcpy(trailer_lines.data() + extra, text.data(), text.size());
            extra += text.size();
        };
        if (!checked->has_date) {
            std::array<char, 64> date {};
            add("date: ");
            add({date.data(), format_http_time(std::time(nullptr), date)});
            add("\r\n");
        }
        if (checked->emit_length) {
            std::array<char, 24> digits {};
            const auto end = std::to_chars(digits.data(), digits.data() + digits.size(),
                                           *length).ptr;
            add("content-length: ");
            add({digits.data(), static_cast<std::size_t>(end - digits.data())});
            add("\r\n");
        }
        if (self.chunked_) add("transfer-encoding: chunked\r\n");
        auto& parsed = self.routing_.request;
        if (self.routing_.draining != nullptr && *self.routing_.draining)
            parsed.close_after_response = true;
        if (parsed.close_after_response) add("connection: close\r\n");
        add("\r\n");

        const auto pieces = 2 + headers.size() * 4;
        for (std::size_t index = 0; index < pieces; ++index) {
            std::string_view piece;
            if (index == 0) piece = {status_line.data(), static_cast<std::size_t>(status_size)};
            else if (index == pieces - 1) piece = {trailer_lines.data(), extra};
            else {
                const auto& field = headers[(index - 1) / 4];
                const std::array<std::string_view, 4> parts {field.name, ": ", field.value, "\r\n"};
                piece = parts[(index - 1) % 4];
            }
            while (!piece.empty()) {
                piece = self.append(piece);
                if (self.output_size_ == self.buffer_.size()) {
                    auto flushed = unwrap(co_await flush(loop, self));
                    if (!flushed) co_return std::unexpected(flushed.error());
                }
            }
        }
        // A declared body follows through write(), which sends these headers
        // with a body that fits the buffer. Streamed responses send them now.
        if (length && *length != 0 && !self.bodyless_ && !self.head_only_)
            co_return void_result {};
        co_return unwrap(co_await flush(loop, self));
    }

    static auto write_task(event_loop& loop, http1_exchange& self, std::span<const std::byte> data)
        -> task<void_result>
    {
        if (self.writing_) co_return std::unexpected(failure(std::errc::operation_in_progress));
        if (self.broken_) co_return std::unexpected(failure(std::errc::connection_reset));
        if (!self.started_ || self.finished_ || (self.bodyless_ && !data.empty()) ||
            (self.declared_ && data.size() > *self.declared_ - self.sent_))
            co_return std::unexpected(failure(std::errc::invalid_argument));
        busy writing(self.writing_);
        self.sent_ += data.size();
        if (self.head_only_ || data.empty()) co_return void_result {};
        if (self.chunked_) {
            std::array<char, 20> size_line {};
            const auto end = std::to_chars(size_line.data(), size_line.data() + 16,
                                           data.size(), 16).ptr;
            *end = '\r';
            *(end + 1) = '\n';
            (void)self.append({size_line.data(), static_cast<std::size_t>(end + 2 - size_line.data())});
        }
        const auto tail = self.chunked_ ? std::size_t {2} : std::size_t {0};
        if (data.size() + tail <= self.buffer_.size() - self.output_size_) {
            (void)self.append({reinterpret_cast<const char*>(data.data()), data.size()});
            if (self.chunked_) (void)self.append("\r\n");
            co_return unwrap(co_await flush(loop, self));
        }
        auto flushed = unwrap(co_await flush(loop, self));
        if (!flushed) co_return std::unexpected(flushed.error());
        auto written = co_await write_all(loop, self, data);
        if (!written) co_return std::unexpected(failure(std::errc::operation_canceled));
        if (!*written) co_return std::unexpected(written->error());
        if (self.chunked_) {
            (void)self.append("\r\n");
            co_return unwrap(co_await flush(loop, self));
        }
        co_return void_result {};
    }

    static auto finish_task(event_loop& loop, http1_exchange& self, std::span<const header> trailers)
        -> task<void_result>
    {
        if (self.writing_) co_return std::unexpected(failure(std::errc::operation_in_progress));
        if (self.broken_) co_return std::unexpected(failure(std::errc::connection_reset));
        if (!self.started_ || self.finished_)
            co_return std::unexpected(failure(std::errc::invalid_argument));
        if (self.declared_ && self.sent_ != *self.declared_ && !self.head_only_) {
            self.broken_ = true;
            co_return std::unexpected(failure(std::errc::invalid_argument));
        }
        for (const auto& field : trailers)
            if (!valid_response_field(field.name, field.value) || field.name == "content-length")
                co_return std::unexpected(failure(std::errc::invalid_argument));
        busy writing(self.writing_);
        if (self.chunked_ && !self.head_only_) {
            (void)self.append("0\r\n");
            if (self.routing_.request.trailers_accepted) {
                for (const auto& field : trailers) {
                    const std::array<std::string_view, 4> parts {field.name, ": ", field.value, "\r\n"};
                    for (auto piece : parts) {
                        while (!piece.empty()) {
                            piece = self.append(piece);
                            if (self.output_size_ == self.buffer_.size()) {
                                auto flushed = unwrap(co_await flush(loop, self));
                                if (!flushed) co_return std::unexpected(flushed.error());
                            }
                        }
                    }
                }
            }
            (void)self.append("\r\n");
        }
        if (self.output_size_ != 0) {
            auto flushed = unwrap(co_await flush(loop, self));
            if (!flushed) co_return std::unexpected(flushed.error());
        }
        self.finished_ = true;
        co_return void_result {};
    }

    static auto send_file_task(event_loop& loop, http1_exchange& self, unsigned status,
                               std::span<const header> headers, unique_fd file,
                               std::uint64_t offset, std::uint64_t size) -> task<void_result>
    {
        auto started = co_await start_task(loop, self, status, headers, size);
        if (!started) co_return std::unexpected(failure(std::errc::operation_canceled));
        if (!*started) co_return std::unexpected(started->error());
        // start() keeps the headers buffered for a declared body; the file
        // goes out separately and reuses the buffer, so send them first.
        if (self.output_size_ != 0) {
            busy writing(self.writing_);
            auto flushed = unwrap(co_await flush(loop, self));
            if (!flushed) co_return std::unexpected(flushed.error());
        }
        if (!self.bodyless_ && !self.head_only_ && size != 0) {
            busy writing(self.writing_);
            bool sent = false;
            if constexpr (std::is_same_v<Stream, tcp_stream>) {
                auto result = io_value(co_await self.peer_.async_send_file(
                    {}, std::move(file), offset, static_cast<std::size_t>(size)));
                if (!result) {
                    self.broken_ = true;
                    co_return std::unexpected(result.error());
                }
                sent = true;
            }
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
            if constexpr (std::is_same_v<Stream, tls_stream>) {
                if (self.peer_.kernel_sendfile_available()) {
                    auto result = io_value(co_await self.peer_.async_send_file(
                        std::move(file), offset, static_cast<std::size_t>(size)));
                    if (!result) {
                        self.broken_ = true;
                        co_return std::unexpected(result.error());
                    }
                    sent = true;
                }
            }
#endif
            while (!sent && self.sent_ < size) {
                const auto count = static_cast<std::size_t>(
                    std::min<std::uint64_t>(self.buffer_.size(), size - self.sent_));
                const auto chunk = std::span(self.buffer_).first(count);
                if (!read_file_at(file.get(), offset + self.sent_, chunk)) {
                    self.broken_ = true;
                    co_return std::unexpected(failure(std::errc::io_error));
                }
                auto written = co_await write_all(loop, self, chunk);
                if (!written) co_return std::unexpected(failure(std::errc::operation_canceled));
                if (!*written) co_return std::unexpected(written->error());
                self.sent_ += count;
            }
            self.sent_ = size;
        }
        self.finished_ = true;
        co_return void_result {};
    }

    event_loop& loop_;
    Stream& peer_;
    session& session_;
    route_state& routing_;
    request request_ = request_access::make_request();
    response response_ = request_access::make_response();
    std::array<std::byte, 4096> buffer_ {};
    std::size_t output_size_ {0};
    std::uint64_t body_length_ {0};
    std::uint64_t body_read_ {0};
    std::uint64_t sent_ {0};
    std::optional<std::uint64_t> declared_;
    bool head_only_ {false};
    bool reading_ {false};
    bool writing_ {false};
    bool started_ {false};
    bool finished_ {false};
    bool broken_ {false};
    bool chunked_ {false};
    bool bodyless_ {false};
    bool continued_ {false};
    // Chunked request bodies.
    chunked_decoder decoder_;
    std::array<std::byte, 1024> staging_ {};
    std::size_t staging_begin_ {0};
    std::size_t staging_end_ {0};
    bool malformed_ {false};
    bool too_large_ {false};
};

} // namespace eventloop::http::detail
