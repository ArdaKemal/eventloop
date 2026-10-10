#include "connection.h"

#include "../http/directory_listing.h"
#include "eventloop/http/mime_types.h"
#include "../http/resource.h"
#include "../http/file_operations.h"
#include "../http/file_response.h"
#include "session.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <optional>
#include <ctime>
#include <coroutine>
#include <expected>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace eventloop::http2::detail {
namespace {

// Decimal text for content-length; the fields borrow digits.
struct length_text {
    explicit length_text(std::uint64_t value) noexcept
        : size(static_cast<std::size_t>(
              std::to_chars(digits.data(), digits.data() + digits.size(), value).ptr -
              digits.data())) {}
    [[nodiscard]] auto view() const noexcept -> std::string_view { return {digits.data(), size}; }
    std::array<char, 24> digits {};
    std::size_t size;
};

auto respond_empty(session& state, std::uint32_t stream_id,
                   unsigned status) -> void
{
    if (status == 405) {
        const std::array<http::header, 2> headers {{
            {"content-length", "0"}, {"allow", "GET, HEAD, OPTIONS"}}};
        (void)state.respond(stream_id, status, headers, {});
    } else {
        const std::array<http::header, 1> headers {{{"content-length", "0"}}};
        (void)state.respond(stream_id, status, headers, {});
    }
}

auto respond_static_file(session& state, const request& incoming,
                         http::detail::static_file descriptor,
                         const http::detail::file_info& info, std::string_view path) -> void
{
    const auto selected = http::detail::choose_file_response(info, {
        incoming.if_none_match, incoming.if_modified_since, incoming.range});
    const length_text length(selected.length);
    const std::array<http::header, 6> headers {{
        {"content-length", length.view()},
        {"content-type", http::mime_type_from_path(path)},
        {"etag", {selected.etag.data(), selected.etag_size}},
        {"last-modified", {selected.modified.data(), selected.modified_size}},
        {"accept-ranges", "bytes"},
        {"content-range", {selected.content_range.data(), selected.content_range_size}},
    }};
    const auto count = selected.content_range_size == 0 ? 5 : 6;
    (void)state.respond_file(incoming.stream_id, selected.status,
        std::span(headers).first(count), std::move(descriptor), selected.length,
        !incoming.method.empty() && incoming.method == "GET" &&
            (selected.status == 200 || selected.status == 206), selected.offset);
}

[[nodiscard]] auto path_without_suffix(std::string_view target) noexcept
    -> std::string_view
{
    return target.substr(0, target.find_first_of("?#"));
}

[[nodiscard]] auto make_redirect(std::string_view target) -> std::string
{
    const auto path = path_without_suffix(target);
    const auto suffix = target.substr(path.size());
    std::string location;
    location.reserve(target.size() + 1);
    location.append(path);
    location.push_back('/');
    location.append(suffix);
    return location;
}

auto serve_request(session& state, const request& incoming, native_socket root,
                   http::detail::open_file_cache* files, bool directory_listing,
                   const http::router* routes) -> void
{
    // A routed path reaches here only without a handler for the method.
    if (routes != nullptr) {
        const std::string_view target = incoming.target;
        const auto match = http::detail::router_access::match(*routes,
            http::detail::method_from_name(incoming.method), target.substr(0, target.find('?')));
        if (match.allowed != 0) {
            std::array<char, 96> allow {};
            const auto size = http::detail::format_allow(match.allowed, allow);
            const std::array<http::header, 2> headers {{
                {"content-length", "0"}, {"allow", {allow.data(), size}}}};
            (void)state.respond(incoming.stream_id, incoming.method == "OPTIONS" ? 204 : 405,
                                std::span(headers).subspan(incoming.method == "OPTIONS" ? 1 : 0),
                                {});
            return;
        }
    }
    if (incoming.method == "OPTIONS") {
        const std::array<http::header, 1> headers {{{"allow", "GET, HEAD, OPTIONS"}}};
        (void)state.respond(incoming.stream_id, 204, headers, {});
        return;
    }
    if (incoming.method != "GET" && incoming.method != "HEAD") {
        respond_empty(state, incoming.stream_id, 405);
        return;
    }

    const bool headers_only = incoming.method == "HEAD";
    auto opened = http::detail::open_static(root, files, incoming.target);
    if (!opened) {
        const auto status = opened.error() == http::detail::resource_error::invalid_target
            ? 400u : opened.error() == http::detail::resource_error::target_too_long
                ? 414u : 404u;
        respond_empty(state, incoming.stream_id, status);
        return;
    }
    auto descriptor = std::move(opened->file);
    const auto info = opened->info;
    if (info.kind != http::detail::file_info::type::regular &&
        info.kind != http::detail::file_info::type::directory) {
        respond_empty(state, incoming.stream_id, 404);
        return;
    }

    if (info.kind == http::detail::file_info::type::regular) {
        respond_static_file(state, incoming, std::move(descriptor), info, incoming.target);
        return;
    }

    const auto raw_path = path_without_suffix(incoming.target);
    if (raw_path.empty() || raw_path.back() != '/') {
        const auto location = make_redirect(incoming.target);
        const std::array<http::header, 2> headers {{
            {"content-length", "0"}, {"location", location}}};
        (void)state.respond(incoming.stream_id, 308, headers, {});
        return;
    }

    unique_fd index = http::detail::open_child(descriptor.get(), "index.html", false);
    auto index_info = index ? http::detail::get_file_info(index.get()) : std::nullopt;
    if (index_info && index_info->kind == http::detail::file_info::type::regular) {
        respond_static_file(state, incoming, std::move(index), *index_info, "index.html");
        return;
    }

    if (!directory_listing) {
        respond_empty(state, incoming.stream_id, 403);
        return;
    }
    try {
        auto listing = http::make_directory_listing(descriptor.take_owned().release());
        if (!listing) {
            if (listing.error() == http::directory_listing_error::list_failed) {
                respond_empty(state, incoming.stream_id, 500);
                return;
            }
            std::vector<std::byte> body(http::directory_listing_error_body.size());
            if (!body.empty()) {
                std::memcpy(body.data(), http::directory_listing_error_body.data(),
                            body.size());
            }
            const length_text length(body.size());
            const std::array<http::header, 2> fields {{
                {"content-length", length.view()}, {"content-type", "text/plain"}}};
            (void)state.respond(incoming.stream_id, 500, fields, std::move(body));
            return;
        }
        const length_text length(listing->size());
        const std::array<http::header, 2> fields {{
            {"content-length", length.view()}, {"content-type", "text/html; charset=utf-8"}}};
        if (headers_only) {
            (void)state.respond(incoming.stream_id, 200, fields, {});
            return;
        }
        std::vector<std::byte> body(listing->size());
        if (!body.empty()) {
            std::memcpy(body.data(), listing->data(), listing->size());
        }
        if (!state.respond(incoming.stream_id, 200, fields, std::move(body))) {
            respond_empty(state, incoming.stream_id, 503);
        }
    } catch (...) {
        respond_empty(state, incoming.stream_id, 500);
    }
}

template<typename T>
[[nodiscard]] auto operation_result(
    std::expected<std::expected<T, std::error_code>, task_result> result)
    noexcept -> std::expected<T, std::error_code>
{
    if (!result) {
        return std::unexpected(std::make_error_code(
            result.error() == task_result::frame_allocation_failure
                ? std::errc::not_enough_memory
                : std::errc::operation_canceled));
    }
    return std::move(*result);
}

// --- Routed connections ----------------------------------------------------
//
// With routes, a connection runs as one writer task (this coordinator), one
// reader task, and up to max_concurrent_streams handler tasks, all on the
// connection's loop. They share the session. A task that must wait for the
// session parks a coroutine handle; drain() resumes parked handles whose
// condition holds, at points where the session is not mid-update.

struct connection_state;

// RFC 9113 section 7 error codes used by routed streams.
constexpr std::uint32_t internal_error = 2;
constexpr std::uint32_t refused_stream_error = 7;
constexpr std::uint32_t cancel_error = 8;

using void_result = http::detail::void_result;
using size_result = http::detail::size_result;

[[nodiscard]] auto failure(std::errc code) -> std::error_code
{
    return std::make_error_code(code);
}

// Parks the awaiting coroutine in slot unless ready already holds. drain()
// resumes it through the slot; cancelling the awaiting task resumes it at
// once. await_resume() is false after cancellation.
class park {
public:
    park(std::coroutine_handle<>& slot, bool ready) noexcept : slot_(slot), ready_(ready)
    {
        node_.operation = this;
        node_.cancel = &cancel;
    }
    park(const park&) = delete;
    auto operator=(const park&) -> park& = delete;
    ~park() { eventloop::detail::coroutine_frame_access::detach_cancellation(node_); }

    [[nodiscard]] auto await_ready() const noexcept -> bool { return ready_; }
    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
    {
        auto& state = *handle.promise().cancellation_state();
        if (!eventloop::detail::coroutine_frame_access::attach_cancellation(state, node_)) {
            cancelled_ = true;
            return false;
        }
        handle_ = handle;
        slot_ = handle;
        return true;
    }
    [[nodiscard]] auto await_resume() noexcept -> bool
    {
        eventloop::detail::coroutine_frame_access::detach_cancellation(node_);
        return !cancelled_;
    }

private:
    static auto cancel(eventloop::detail::coroutine_cancellation_node& node) noexcept -> void
    {
        auto& self = *static_cast<park*>(node.operation);
        eventloop::detail::coroutine_frame_access::detach_cancellation(node);
        self.cancelled_ = true;
        self.slot_ = {};
        self.handle_.resume();
    }

    std::coroutine_handle<>& slot_;
    std::coroutine_handle<> handle_;
    eventloop::detail::coroutine_cancellation_node node_ {};
    bool ready_;
    bool cancelled_ {false};
};

class http2_exchange final : public http::detail::exchange {
public:
    auto read_body(std::span<std::byte> buffer) -> task<size_result> override;
    auto start(unsigned status, std::span<const http::header> headers,
               std::optional<std::uint64_t> length) -> task<void_result> override;
    auto write(std::span<const std::byte> data) -> task<void_result> override;
    auto finish(std::span<const http::header> trailers) -> task<void_result> override;
    auto send_file(unsigned status, std::span<const http::header> headers, unique_fd file,
                   std::uint64_t offset, std::uint64_t size) -> task<void_result> override;
    auto loop() noexcept -> event_loop& override;
    auto accept_websocket(std::span<const http::header> headers) -> task<void_result> override;
    auto abort_websocket() noexcept -> void override;

    // Read-side and write-side waits resume when these hold.
    [[nodiscard]] auto read_ready() const noexcept -> bool;
    [[nodiscard]] auto write_ready() const noexcept -> bool;
    // Starts and finishes a response synchronously with an empty body.
    auto respond_status(unsigned status) -> void;
    // Prepares the slot for a new stream; headers keeps its capacity.
    auto reset(std::uint32_t stream_id) noexcept -> void
    {
        id = stream_id;
        in_use = true;
        headers.clear();
        read_waiter = write_waiter = {};
        declared.reset();
        sent = 0;
        head_only = bodyless = reading = writing = false;
        started = finished = broken = released = completed = false;
        waiting_file = too_large = false;
        websocket_accepted = websocket_aborted = body_read = false;
    }

    connection_state* owner {nullptr};
    std::uint32_t id {0};
    bool in_use {false};
    routed_request routed {};
    std::vector<http::header> headers;
    http::request request_ = http::detail::request_access::make_request();
    http::response response_ = http::detail::request_access::make_response();
    std::coroutine_handle<> read_waiter;
    std::coroutine_handle<> write_waiter;
    std::optional<std::uint64_t> declared;
    std::uint64_t sent {0};
    bool head_only {false};
    bool bodyless {false};
    bool reading {false};
    bool writing {false};
    bool started {false};
    bool finished {false};
    bool broken {false};
    bool released {false};
    bool completed {false};
    bool waiting_file {false};
    bool too_large {false};
};

// Stops the connection deadline while a request is in progress and restarts
// it with the idle timeout after the last one; until the first request, the
// deadline from accept keeps running.
class idle_deadline {
public:
    idle_deadline(http::detail::connection_deadline& deadline,
                  std::chrono::milliseconds timeout) noexcept
        : deadline_(deadline), timeout_(timeout) {}

    auto update(const session& state) -> void
    {
        if (!state.idle()) {
            if (!busy_) deadline_.stop();
            busy_ = true;
        } else if (busy_) {
            busy_ = false;
            deadline_.start(timeout_);
        }
    }

    [[nodiscard]] auto deadline() noexcept -> http::detail::connection_deadline&
    {
        return deadline_;
    }

private:
    http::detail::connection_deadline& deadline_;
    std::chrono::milliseconds timeout_;
    bool busy_ {false};
};

struct connection_state {
    connection_state(event_loop& loop, tls_stream& peer, session& state,
                     const http::router& routes, native_socket root,
                     http::detail::open_file_cache* files, bool directory_listing,
                     idle_deadline deadline)
        : loop(loop), peer(peer), state(state), routes(routes), root(root), files(files),
          directory_listing(directory_listing), deadline(deadline)
    {
        for (auto& exchange : exchanges) exchange.owner = this;
    }

    // Resumes parked tasks whose condition holds; reentrant calls repeat the
    // pass instead of nesting.
    auto drain() -> void
    {
        if (waking) {
            wake_again = true;
            return;
        }
        waking = true;
        do {
            wake_again = false;
            state.resume_input();
            const auto wake = [](std::coroutine_handle<>& slot) {
                auto handle = std::exchange(slot, {});
                if (handle && !handle.done()) handle.resume();
            };
            if (reader_waiter && (broken || !state.input_paused())) wake(reader_waiter);
            for (auto& exchange : exchanges) {
                if (exchange.read_waiter && exchange.read_ready()) wake(exchange.read_waiter);
                if (exchange.write_waiter && exchange.write_ready()) wake(exchange.write_waiter);
            }
            // While the reader dispatches one input batch, responses
            // accumulate so the writer sends them together.
            if (writer_waiter && (broken || (!batching && (state.has_output() ||
                                                           state.closed()))))
                wake(writer_waiter);
        } while (wake_again);
        waking = false;
    }

    static auto released(void* context, std::uint32_t stream_id, bool completed) noexcept
        -> void
    {
        auto& self = *static_cast<connection_state*>(context);
        for (auto& exchange : self.exchanges) {
            if (!exchange.in_use || exchange.id != stream_id) continue;
            exchange.released = true;
            exchange.completed = completed;
        }
    }

    event_loop& loop;
    tls_stream& peer;
    session& state;
    const http::router& routes;
    native_socket root;
    http::detail::open_file_cache* files;
    bool directory_listing;
    idle_deadline deadline;
    std::array<http2_exchange, max_concurrent_streams> exchanges {};
    std::array<std::optional<task_handle<void>>, max_concurrent_streams> handlers {};
    std::coroutine_handle<> reader_waiter;
    std::coroutine_handle<> writer_waiter;
    bool broken {false};
    bool waking {false};
    bool wake_again {false};
    bool batching {false};
};

auto http2_exchange::loop() noexcept -> event_loop& { return owner->loop; }

auto http2_exchange::read_ready() const noexcept -> bool
{
    return owner->broken || owner->state.body_ready(id);
}

auto http2_exchange::write_ready() const noexcept -> bool
{
    if (owner->broken) return true;
    if (waiting_file) return released;
    return !owner->state.chunk_pending(id);
}

// Fields the server adds after the handler's: content-length and date. The
// views borrow this object, which lives on the caller's stack.
struct generated_fields {
    generated_fields(bool emit_length, std::uint64_t length, bool add_date) noexcept
        : length_digits(length)
    {
        if (emit_length) fields[count++] = {"content-length", length_digits.view()};
        if (add_date) {
            const auto size = http::detail::format_http_time(std::time(nullptr), date);
            fields[count++] = {"date", {date.data(), size}};
        }
    }
    generated_fields(const generated_fields&) = delete;
    auto operator=(const generated_fields&) -> generated_fields& = delete;
    [[nodiscard]] auto view() const noexcept -> std::span<const http::header>
    {
        return std::span(fields).first(count);
    }

    length_text length_digits;
    std::array<char, 64> date {};
    std::array<http::header, 2> fields {};
    std::size_t count {0};
};

auto http2_exchange::respond_status(unsigned status) -> void
{
    const generated_fields extra(true, 0, true);
    if (owner->state.start_streamed(id, status, {}, extra.view())) {
        started = true;
        if (owner->state.finish_streamed(id, {})) finished = true;
    }
}

auto read_task(event_loop& loop, http2_exchange& self, std::span<std::byte> buffer)
    -> task<size_result>
{
    (void)loop;
    if (self.reading) co_return std::unexpected(failure(std::errc::operation_in_progress));
    if (buffer.empty()) co_return std::unexpected(failure(std::errc::invalid_argument));
    self.reading = true;
    struct done { bool& flag; ~done() { flag = false; } } guard {self.reading};
    for (;;) {
        if (self.websocket_aborted) co_return std::unexpected(failure(std::errc::operation_canceled));
        if (self.owner->broken) co_return std::unexpected(failure(std::errc::connection_reset));
        if (self.websocket_accepted && self.released && self.completed) co_return 0;
        std::size_t count = 0;
        switch (self.owner->state.read_body(self.id, buffer, count)) {
        case session::body_state::data:
            self.owner->drain();
            co_return count;
        case session::body_state::ended: co_return 0;
        case session::body_state::too_large:
            self.too_large = true;
            co_return std::unexpected(failure(std::errc::message_size));
        case session::body_state::failed:
            co_return std::unexpected(failure(std::errc::connection_reset));
        case session::body_state::waiting:
            if (!co_await park(self.read_waiter, self.read_ready()))
                co_return std::unexpected(failure(std::errc::operation_canceled));
            break;
        }
    }
}

auto start_task(event_loop& loop, http2_exchange& self, unsigned status,
                std::span<const http::header> headers, std::optional<std::uint64_t> length,
                bool websocket = false)
    -> task<void_result>
{
    (void)loop;
    if (self.writing) co_return std::unexpected(failure(std::errc::operation_in_progress));
    if (self.broken || self.owner->broken)
        co_return std::unexpected(failure(std::errc::connection_reset));
    if (self.started || (websocket && self.reading))
        co_return std::unexpected(failure(std::errc::invalid_argument));
    const auto checked = http::detail::check_response_start(status, headers, length);
    if (!checked) co_return std::unexpected(checked.error());
    if (self.request_.method() == http::method_type::connect && status < 300 &&
        (length || checked->declared))
        co_return std::unexpected(failure(std::errc::invalid_argument));
    const generated_fields extra(checked->emit_length, length.value_or(0), !checked->has_date);
    if (!self.owner->state.start_streamed(self.id, status, headers, extra.view(), websocket)) {
        self.broken = true;
        if (websocket) self.abort_websocket();
        co_return std::unexpected(failure(std::errc::connection_reset));
    }
    self.started = true;
    self.websocket_accepted = websocket;
    self.bodyless = checked->bodyless;
    self.declared = checked->declared;
    self.owner->drain();
    co_return void_result {};
}

auto write_task(event_loop& loop, http2_exchange& self, std::span<const std::byte> data)
    -> task<void_result>
{
    (void)loop;
    if (self.writing) co_return std::unexpected(failure(std::errc::operation_in_progress));
    if (self.websocket_aborted) co_return std::unexpected(failure(std::errc::operation_canceled));
    if (self.broken || self.owner->broken)
        co_return std::unexpected(failure(std::errc::connection_reset));
    if (!self.started || self.finished || (self.bodyless && !data.empty()) ||
        (self.declared && data.size() > *self.declared - self.sent))
        co_return std::unexpected(failure(std::errc::invalid_argument));
    self.sent += data.size();
    if (self.head_only || data.empty()) co_return void_result {};
    self.writing = true;
    struct done { bool& flag; ~done() { flag = false; } } guard {self.writing};
    if (!self.owner->state.queue_chunk(self.id, data)) {
        self.broken = true;
        co_return std::unexpected(failure(std::errc::connection_reset));
    }
    self.owner->drain();
    while (!self.write_ready()) {
        if (!co_await park(self.write_waiter, self.write_ready())) {
            // The session must not keep borrowing the caller's span.
            self.broken = true;
            self.owner->state.abandon(self.id, cancel_error);
            self.owner->drain();
            co_return std::unexpected(failure(std::errc::operation_canceled));
        }
    }
    // The chunk is accepted once it has left the borrowed span.
    if (self.websocket_aborted) co_return std::unexpected(failure(std::errc::operation_canceled));
    if (self.owner->broken || !self.owner->state.stream_open(self.id)) {
        self.broken = true;
        co_return std::unexpected(failure(std::errc::connection_reset));
    }
    co_return void_result {};
}

auto finish_task(event_loop& loop, http2_exchange& self, std::span<const http::header> trailers)
    -> task<void_result>
{
    (void)loop;
    if (self.writing) co_return std::unexpected(failure(std::errc::operation_in_progress));
    if (self.websocket_aborted) co_return std::unexpected(failure(std::errc::operation_canceled));
    if (self.broken || self.owner->broken)
        co_return std::unexpected(failure(std::errc::connection_reset));
    if (!self.started || self.finished)
        co_return std::unexpected(failure(std::errc::invalid_argument));
    if (self.declared && self.sent != *self.declared && !self.head_only) {
        self.broken = true;
        self.owner->state.abandon(self.id, internal_error);
        self.owner->drain();
        co_return std::unexpected(failure(std::errc::invalid_argument));
    }
    for (const auto& entry : trailers)
        if (!http::detail::valid_response_field(entry.name, entry.value) ||
            entry.name == "content-length")
            co_return std::unexpected(failure(std::errc::invalid_argument));
    if (!self.owner->state.finish_streamed(self.id,
            self.head_only ? std::span<const http::header> {} : trailers)) {
        self.broken = true;
        co_return std::unexpected(failure(std::errc::connection_reset));
    }
    self.finished = true;
    self.owner->drain();
    co_return void_result {};
}

auto http2_exchange::accept_websocket(std::span<const http::header> headers) -> task<void_result>
{
    return start_task(owner->loop, *this, 200, headers, std::nullopt, true);
}

auto http2_exchange::abort_websocket() noexcept -> void
{
    if (released) return;
    websocket_aborted = true;
    broken = true;
    owner->state.abandon(id, cancel_error);
    owner->drain();
}

auto send_file_task(event_loop& loop, http2_exchange& self, unsigned status,
                    std::span<const http::header> headers, unique_fd file,
                    std::uint64_t offset, std::uint64_t size) -> task<void_result>
{
    auto started = co_await start_task(loop, self, status, headers, size);
    if (!started) co_return std::unexpected(failure(std::errc::operation_canceled));
    if (!*started) co_return std::unexpected(started->error());
    if (self.bodyless || self.head_only || size == 0)
        co_return (co_await finish_task(loop, self, {}))
            .value_or(std::unexpected(failure(std::errc::operation_canceled)));
    self.writing = true;
    struct done { bool& flag; ~done() { flag = false; } } guard {self.writing};
    self.waiting_file = true;
    if (!self.owner->state.send_streamed_file(self.id, std::move(file), offset, size)) {
        self.broken = true;
        co_return std::unexpected(failure(std::errc::connection_reset));
    }
    self.owner->drain();
    while (!self.write_ready()) {
        if (!co_await park(self.write_waiter, self.write_ready())) {
            self.waiting_file = false;
            self.broken = true;
            self.owner->state.abandon(self.id, cancel_error);
            self.owner->drain();
            co_return std::unexpected(failure(std::errc::operation_canceled));
        }
    }
    self.waiting_file = false;
    if (!self.completed) {
        self.broken = true;
        co_return std::unexpected(failure(std::errc::connection_reset));
    }
    self.sent = size;
    self.finished = true;
    co_return void_result {};
}

auto http2_exchange::read_body(std::span<std::byte> buffer) -> task<size_result>
{
    return read_task(owner->loop, *this, buffer);
}
auto http2_exchange::start(unsigned status, std::span<const http::header> headers,
                           std::optional<std::uint64_t> length) -> task<void_result>
{
    return start_task(owner->loop, *this, status, headers, length);
}
auto http2_exchange::write(std::span<const std::byte> data) -> task<void_result>
{
    return write_task(owner->loop, *this, data);
}
auto http2_exchange::finish(std::span<const http::header> trailers) -> task<void_result>
{
    return finish_task(owner->loop, *this, trailers);
}
auto http2_exchange::send_file(unsigned status, std::span<const http::header> headers,
                               unique_fd file, std::uint64_t offset, std::uint64_t size)
    -> task<void_result>
{
    return send_file_task(owner->loop, *this, status, headers, std::move(file), offset, size);
}

// Runs one handler, then settles a response it did not finish.
auto run_route(event_loop& loop, http2_exchange& self, http::handler function) -> task<void>
{
    const auto handled = co_await function(loop, self.request_, self.response_);
    auto& state = self.owner->state;
    if (!self.owner->broken && !self.released) {
        if (handled == task_result::cancelled) {
            state.abandon(self.id, cancel_error);
        } else if (!self.started && !self.broken) {
            self.respond_status(self.too_large ? 413
                : handled == task_result::frame_allocation_failure ? 503 : 500);
        } else if (!self.finished) {
            state.abandon(self.id, internal_error);
        }
    }
    self.in_use = false;
    self.owner->drain();
}

auto dispatch_routed(connection_state& connection, routed_request routed) -> void
{
    auto& state = connection.state;
    std::size_t index = 0;
    for (; index < connection.exchanges.size(); ++index) {
        const auto& handle = connection.handlers[index];
        if (!connection.exchanges[index].in_use && (!handle || handle->done())) break;
    }
    if (index == connection.exchanges.size()) {
        state.abandon(routed.stream_id, refused_stream_error);
        return;
    }
    auto& exchange = connection.exchanges[index];
    exchange.reset(routed.stream_id);
    // The slot's previous fields go back to the decoder with their strings.
    auto previous = std::move(exchange.routed.fields);
    exchange.routed = std::move(routed);
    state.recycle_fields(std::move(previous));
    if (exchange.routed.too_large) {
        exchange.respond_status(413);
        exchange.in_use = false;
        return;
    }
    std::string_view method, target, authority, host, connect_protocol;
    exchange.headers.reserve(hpack_max_fields);
    for (const auto& entry : exchange.routed.fields) {
        if (entry.name == ":method") method = entry.value;
        else if (entry.name == ":path") target = entry.value;
        else if (entry.name == ":authority") authority = entry.value;
        else if (entry.name == ":protocol") connect_protocol = entry.value;
        else if (!entry.name.empty() && entry.name.front() != ':') {
            if (entry.name == "host") host = entry.value;
            exchange.headers.push_back({entry.name, entry.value});
        }
    }
    exchange.head_only = method == "HEAD";
    const http::detail::request_fields fields {
        .headers = exchange.headers,
        .method_name = method,
        .target = target,
        .authority = authority.empty() ? host : authority,
        .connect_protocol = connect_protocol,
        .content_length = exchange.routed.content_length,
        .method = http::detail::method_from_name(method),
        .protocol = http::protocol::http2,
    };
    http::detail::request_access::bind(exchange.request_, exchange, fields,
                                       exchange.routed.match.context);
    http::detail::request_access::bind(exchange.response_, exchange);
    auto& slot = connection.handlers[index];
    slot.reset();
    slot.emplace();
    if (connection.loop.spawn(run_route(connection.loop, exchange, exchange.routed.match.function),
                              *slot) != task_spawn_result::accepted) {
        slot.reset();
        exchange.respond_status(503);
        exchange.in_use = false;
    }
}

auto read_loop(event_loop& loop, connection_state& connection) -> task<void>
{
    (void)loop;
    auto& state = connection.state;
    // Reused so request strings keep their capacity across requests.
    request incoming;
    for (;;) {
        // Handlers spawned here usually finish before they suspend; their
        // responses are written together once the batch is dispatched.
        connection.batching = true;
        while (state.pop_request(incoming))
            serve_request(state, incoming, connection.root, connection.files,
                          connection.directory_listing, &connection.routes);
        routed_request routed;
        while (state.pop_routed(routed)) dispatch_routed(connection, std::move(routed));
        connection.batching = false;
        connection.drain();
        if (connection.broken || state.closed()) co_return;
        connection.deadline.update(state);
        const auto buffer = state.read_buffer();
        if (buffer.empty()) {
            if (!co_await park(connection.reader_waiter,
                               connection.broken || !state.input_paused())) co_return;
            continue;
        }
        const auto received = operation_result(co_await connection.peer.async_read_some(buffer));
        if (!received || *received == 0) {
            connection.broken = true;
            connection.drain();
            co_return;
        }
        state.commit_read(*received);
    }
}

auto serve_routed(event_loop& loop, tls_stream& peer, native_socket root,
                  http::detail::open_file_cache* files, bool directory_listing,
                  const http::router& routes,
                  std::uint64_t max_request_body, idle_deadline deadline) -> task<bool>
{
    // Session, task slots and exchanges are allocated once per connection.
    auto state = std::make_unique<session>(peer.kernel_sendfile_available(), &routes,
                                           max_request_body);
    auto connection = std::make_unique<connection_state>(loop, peer, *state, routes, root,
                                                         files, directory_listing, deadline);
    state->set_release_hook(&connection_state::released, connection.get());
    task_handle<void> reader;
    if (loop.spawn(read_loop(loop, *connection), reader) != task_spawn_result::accepted)
        co_return false;
    bool clean = false;
    for (;;) {
        if (auto file = state->take_file_send(true)) {
            auto sent = operation_result(co_await peer.async_send_file(
                file->file.get(), file->offset, file->size, file->prefix));
            if (!sent) break;
            state->consume_output(file->prefix.size());
            state->complete_file_send(std::move(file->file));
            connection->drain();
            continue;
        }
        if (!state->output().empty()) {
            auto written = operation_result(co_await peer.async_write_some(state->output()));
            if (!written || *written == 0) break;
            state->consume_output(*written);
            connection->drain();
            continue;
        }
        if (state->closed()) {
            clean = true;
            break;
        }
        if (connection->broken) break;
        connection->deadline.update(*state);
        // Cancellation (server close, loop shutdown, or the connection
        // deadline) ends the connection.
        if (!co_await park(connection->writer_waiter,
                           connection->broken || state->has_output() || state->closed()))
            break;
    }
    // Wake every parked task with the connection marked broken, then wait for
    // the reader and handlers before releasing the shared state they borrow.
    connection->broken = true;
    connection->drain();
    if (!reader.done()) (void)reader.cancel();
    (void)co_await reader;
    for (auto& handler : connection->handlers) {
        if (!handler) continue;
        if (!handler->done()) (void)handler->cancel();
        connection->drain();
        (void)co_await *handler;
        handler.reset();
    }
    co_return clean;
}

} // namespace

auto serve([[maybe_unused]] event_loop& loop, tls_stream& peer,
           std::shared_ptr<http::detail::document_root> document_root,
           bool directory_listing, std::shared_ptr<const http::router> routes,
           std::uint64_t max_request_body, http::detail::connection_deadline& deadline,
           std::chrono::milliseconds idle_timeout) -> task<bool>
{
    if (routes) {
        try {
            co_return (co_await serve_routed(loop, peer, document_root->descriptor.get(),
                                             document_root->cache.get(), directory_listing,
                                             *routes, max_request_body,
                                             idle_deadline {deadline, idle_timeout}))
                .value_or(false);
        } catch (...) {
            co_return false;
        }
    }
    try {
        auto state = std::make_unique<session>(peer.kernel_sendfile_available());
        idle_deadline idle {deadline, idle_timeout};
        request incoming;
        for (;;) {
            while (state->pop_request(incoming)) {
                serve_request(*state, incoming, document_root->descriptor.get(),
                              document_root->cache.get(), directory_listing, nullptr);
            }

            for (;;) {
                if (auto file = state->take_file_send(true)) {
                    auto sent = operation_result(co_await peer.async_send_file(
                        file->file.get(), file->offset, file->size, file->prefix));
                    if (!sent) co_return false;
                    state->consume_output(file->prefix.size());
                    state->complete_file_send(std::move(file->file));
                    continue;
                }
                if (state->output().empty()) break;
                auto written = operation_result(
                    co_await peer.async_write_some(state->output()));
                if (!written || *written == 0) co_return false;
                state->consume_output(*written);
                if (state->closed()) co_return true;
            }
            if (state->closed()) co_return true;

            idle.update(*state);
            auto received = operation_result(
                co_await peer.async_read_some(state->read_buffer()));
            if (!received || *received == 0) co_return false;
            state->commit_read(*received);
        }
    } catch (...) {
        // A failed bounded-state allocation retires only this connection.
        co_return false;
    }
}

} // namespace eventloop::http2::detail
