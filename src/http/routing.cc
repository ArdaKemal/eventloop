#include "exchange.h"
#include "parser.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>

namespace eventloop::http {
namespace detail {
namespace {

[[nodiscard]] auto failure(std::errc code) -> std::error_code
{
    return std::make_error_code(code);
}

template<typename T>
auto rejected(event_loop& loop, std::errc code) -> task<std::expected<T, std::error_code>>
{
    (void)loop;
    co_return std::unexpected(failure(code));
}

[[nodiscard]] auto token(std::string_view value) noexcept -> bool
{
    if (value.empty()) return false;
    for (const unsigned char c : value)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) !=
                  std::string_view::npos)) return false;
    return true;
}

auto accept_websocket_task(event_loop& loop, exchange& owner, const request& incoming,
                           std::string_view selected)
    -> task<std::expected<websocket_stream, std::error_code>>
{
    (void)loop;
    if (incoming.protocol() == http::protocol::http1_1)
        co_return std::unexpected(failure(std::errc::operation_not_supported));
    if (owner.websocket_accepted || owner.body_read || incoming.method() != method_type::connect ||
        incoming.connect_protocol() != "websocket" || incoming.content_length() ||
        (!selected.empty() && !token(selected)))
        co_return std::unexpected(failure(std::errc::invalid_argument));
    unsigned versions = 0;
    bool offered = selected.empty();
    for (const auto& field : incoming.headers()) {
        if (field.name == "sec-websocket-version") {
            if (++versions != 1 || field.value != "13")
                co_return std::unexpected(failure(std::errc::invalid_argument));
        }
        if (field.name != "sec-websocket-protocol") continue;
        auto rest = field.value;
        for (;;) {
            const auto comma = rest.find(',');
            auto item = rest.substr(0, comma);
            while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.remove_prefix(1);
            while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) item.remove_suffix(1);
            if (!token(item)) co_return std::unexpected(failure(std::errc::invalid_argument));
            if (item == selected) offered = true;
            if (comma == std::string_view::npos) break;
            rest.remove_prefix(comma + 1);
        }
    }
    if (versions != 1 || !offered)
        co_return std::unexpected(failure(std::errc::invalid_argument));
    const std::array<header, 1> fields {{{"sec-websocket-protocol", selected}}};
    auto accepted = flatten_result(co_await owner.accept_websocket(
        selected.empty() ? std::span<const header> {} : std::span<const header>(fields)));
    if (!accepted) co_return std::unexpected(accepted.error());
    co_return request_access::make_websocket(owner);
}

auto websocket_write_task(event_loop& loop, exchange* owner, std::span<const std::byte> data)
    -> task<size_result>
{
    (void)loop;
    if (owner == nullptr) co_return std::unexpected(failure(std::errc::operation_canceled));
    auto written = flatten_result(co_await owner->write(data));
    if (!written) co_return std::unexpected(written.error());
    co_return data.size();
}

auto websocket_close_task(event_loop& loop, exchange*& slot) -> task<void_result>
{
    (void)loop;
    auto* owner = slot;
    if (owner == nullptr) co_return void_result {};
    auto finished = flatten_result(co_await owner->finish({}));
    if (!finished) { owner->abort_websocket(); slot = nullptr; co_return finished; }
    std::array<std::byte, 256> discard {};
    for (;;) {
        auto read = flatten_result(co_await owner->read_body(discard));
        if (!read) { owner->abort_websocket(); slot = nullptr; co_return std::unexpected(read.error()); }
        if (*read == 0) { slot = nullptr; co_return void_result {}; }
    }
}

auto send_task(event_loop& loop, exchange& owner, unsigned status,
               std::span<const header> headers, std::span<const std::byte> body)
    -> task<void_result>
{
    (void)loop;
    for (const auto& field : headers)
        if (field.name == "content-length")
            co_return std::unexpected(failure(std::errc::invalid_argument));
    auto started = co_await owner.start(status, headers, body.size());
    if (!started) co_return std::unexpected(failure(std::errc::operation_canceled));
    if (!*started) co_return std::unexpected(started->error());
    if (!body.empty()) {
        auto written = co_await owner.write(body);
        if (!written) co_return std::unexpected(failure(std::errc::operation_canceled));
        if (!*written) co_return std::unexpected(written->error());
    }
    auto finished = co_await owner.finish({});
    if (!finished) co_return std::unexpected(failure(std::errc::operation_canceled));
    co_return *finished;
}

[[nodiscard]] auto valid_path(std::string_view path) noexcept -> bool
{
    if (path.empty() || path.front() != '/') return false;
    for (const unsigned char value : path)
        if (value <= 0x20 || value == 0x7f || value == '?' || value == '#') return false;
    return true;
}

constexpr std::array<std::string_view, 9> method_names {
    "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PATCH"};

} // namespace

auto request_access::bind(request& value, exchange& owner, const request_fields& fields,
                          void* context) noexcept -> void
{
    const auto query = fields.target.find('?');
    value.exchange_ = &owner;
    value.headers_ = fields.headers;
    value.method_name_ = fields.method_name;
    value.path_ = fields.target.substr(0, query);
    value.query_ = query == std::string_view::npos ? std::string_view {}
                                                   : fields.target.substr(query + 1);
    value.authority_ = fields.authority;
    value.connect_protocol_ = fields.connect_protocol;
    value.content_length_ = fields.content_length;
    value.route_context_ = context;
    value.method_ = fields.method;
    value.protocol_ = fields.protocol;
}

auto request_access::bind(response& value, exchange& owner) noexcept -> void
{
    value.exchange_ = &owner;
}

auto router_access::match(const router& routes, method_type method,
                          std::string_view path) noexcept -> route_match
{
    // Candidates are ranked exact first, then by prefix length; ties keep
    // registration order.
    const router::route* best = nullptr;
    const router::route* fallback_get = nullptr;
    route_match result;
    const auto better = [](const router::route* current, const router::route& candidate) {
        if (current == nullptr) return true;
        if (current->prefix != candidate.prefix) return !candidate.prefix;
        return candidate.path.size() > current->path.size();
    };
    for (std::size_t index = 0; index < routes.size_; ++index) {
        const auto& route = routes.routes_[index];
        if (route.prefix ? !path.starts_with(route.path) : path != route.path) continue;
        result.allowed |= method_bit(route.method);
        if (route.method == method && better(best, route)) best = &route;
        if (method == method_type::head && route.method == method_type::get &&
            better(fallback_get, route)) fallback_get = &route;
    }
    if (result.allowed == 0) return result;
    if ((result.allowed & method_bit(method_type::get)) != 0)
        result.allowed |= method_bit(method_type::head);
    result.allowed |= method_bit(method_type::options);
    if (best == nullptr) best = fallback_get;
    if (best != nullptr) {
        result.function = best->function;
        result.context = best->context;
    }
    return result;
}

auto format_allow(method_set allowed, std::span<char> output) noexcept -> std::size_t
{
    std::size_t size = 0;
    for (std::size_t index = 0; index < method_names.size(); ++index) {
        if ((allowed & (1u << index)) == 0) continue;
        const auto name = method_names[index];
        const auto separator = size == 0 ? 0 : 2;
        if (output.size() - size < name.size() + separator) break;
        if (separator != 0) {
            output[size++] = ',';
            output[size++] = ' ';
        }
        std::memcpy(output.data() + size, name.data(), name.size());
        size += name.size();
    }
    return size;
}

auto valid_response_field(std::string_view name, std::string_view value) noexcept -> bool
{
    if (name.empty()) return false;
    for (const unsigned char c : name) {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) !=
                std::string_view::npos) continue;
        return false;
    }
    if (name == "connection" || name == "keep-alive" || name == "proxy-connection" ||
        name == "transfer-encoding" || name == "upgrade" || name == "te") return false;
    if (!value.empty() && (value.front() == ' ' || value.front() == '\t' ||
                           value.back() == ' ' || value.back() == '\t')) return false;
    for (const unsigned char c : value)
        if ((c < 0x20 && c != '\t') || c == 0x7f) return false;
    return true;
}

auto check_response_start(unsigned status, std::span<const header> headers,
                          std::optional<std::uint64_t> length) noexcept
    -> std::expected<response_start, std::error_code>
{
    if (status < 200 || status > 599) return std::unexpected(failure(std::errc::invalid_argument));
    response_start result;
    result.bodyless = status == 204 || status == 304;
    std::optional<std::uint64_t> declared;
    for (const auto& field : headers) {
        if (!valid_response_field(field.name, field.value))
            return std::unexpected(failure(std::errc::invalid_argument));
        if (field.name == "date") result.has_date = true;
        if (field.name != "content-length") continue;
        const auto value = parse_length(field.value);
        if (!value || (declared && *declared != *value) || status == 204 ||
            (length && *length != *value))
            return std::unexpected(failure(std::errc::invalid_argument));
        declared = value;
    }
    result.emit_length = length && !declared && !result.bodyless;
    if (!declared) declared = length;
    if (!result.bodyless) result.declared = declared;
    return result;
}

auto method_from_name(std::string_view name) noexcept -> method_type
{
    for (std::size_t index = 0; index < method_names.size(); ++index)
        if (name == method_names[index]) return static_cast<method_type>(index);
    return method_type::unknown;
}

auto parse_length(std::string_view value) noexcept -> std::optional<std::uint64_t>
{
    std::uint64_t parsed = 0;
    const auto* end = value.data() + value.size();
    const auto result = std::from_chars(value.data(), end, parsed);
    if (value.empty() || result.ec != std::errc {} || result.ptr != end) return std::nullopt;
    return parsed;
}

auto exchange::accept_websocket(std::span<const header>) -> task<void_result>
{
    return rejected<void>(loop(), std::errc::operation_not_supported);
}

} // namespace detail

auto request::header_value(std::string_view name) const noexcept
    -> std::optional<std::string_view>
{
    for (const auto& field : headers_)
        if (detail::ascii_equal(field.name, name)) return field.value;
    return std::nullopt;
}

auto request::async_read_body(std::span<std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
    if (exchange_->websocket_accepted)
        return detail::rejected<std::size_t>(exchange_->loop(), std::errc::invalid_argument);
    exchange_->body_read = true;
    return exchange_->read_body(buffer);
}

auto request::async_accept_websocket(std::string_view subprotocol)
    -> task<std::expected<websocket_stream, std::error_code>>
{
    return detail::accept_websocket_task(exchange_->loop(), *exchange_, *this, subprotocol);
}

auto response::async_start(unsigned status, std::span<const header> headers)
    -> task<std::expected<void, std::error_code>>
{
    if (exchange_->websocket_accepted)
        return detail::rejected<void>(exchange_->loop(), std::errc::invalid_argument);
    return exchange_->start(status, headers, std::nullopt);
}

auto response::async_write(std::span<const std::byte> data)
    -> task<std::expected<void, std::error_code>>
{
    if (exchange_->websocket_accepted)
        return detail::rejected<void>(exchange_->loop(), std::errc::invalid_argument);
    return exchange_->write(data);
}

auto response::async_finish(std::span<const header> trailers)
    -> task<std::expected<void, std::error_code>>
{
    if (exchange_->websocket_accepted)
        return detail::rejected<void>(exchange_->loop(), std::errc::invalid_argument);
    return exchange_->finish(trailers);
}

auto response::async_send(unsigned status, std::span<const header> headers,
                          std::span<const std::byte> body)
    -> task<std::expected<void, std::error_code>>
{
    if (exchange_->websocket_accepted)
        return detail::rejected<void>(exchange_->loop(), std::errc::invalid_argument);
    return detail::send_task(exchange_->loop(), *exchange_, status, headers, body);
}

auto response::async_send_file(unsigned status, std::span<const header> headers,
                               unique_fd file, std::uint64_t offset, std::uint64_t size)
    -> task<std::expected<void, std::error_code>>
{
    if (exchange_->websocket_accepted)
        return detail::rejected<void>(exchange_->loop(), std::errc::invalid_argument);
    return exchange_->send_file(status, headers, std::move(file), offset, size);
}

websocket_stream::websocket_stream(detail::exchange& owner) noexcept
    : exchange_(&owner), loop_(&owner.loop()) {}

websocket_stream::websocket_stream(websocket_stream&& other) noexcept
    : exchange_(std::exchange(other.exchange_, nullptr)), loop_(other.loop_) {}

auto websocket_stream::operator=(websocket_stream&& other) noexcept -> websocket_stream&
{
    if (this != &other) {
        close();
        exchange_ = std::exchange(other.exchange_, nullptr);
        loop_ = other.loop_;
    }
    return *this;
}

websocket_stream::~websocket_stream() { close(); }

auto websocket_stream::close() noexcept -> void
{
    if (auto* owner = std::exchange(exchange_, nullptr)) owner->abort_websocket();
}

auto websocket_stream::async_read_some(std::span<std::byte> buffer) -> task<detail::size_result>
{
    if (exchange_ == nullptr)
        return detail::rejected<std::size_t>(*loop_, std::errc::operation_canceled);
    return exchange_->read_body(buffer);
}

auto websocket_stream::async_write_some(std::span<const std::byte> buffer) -> task<detail::size_result>
{
    return detail::websocket_write_task(*loop_, exchange_, buffer);
}

auto websocket_stream::async_close() -> task<detail::void_result>
{
    return detail::websocket_close_task(*loop_, exchange_);
}

auto router::add(method_type method, std::string_view path, handler function, void* context)
    -> std::expected<void, std::error_code>
{
    return insert(method, path, function, context, false);
}

auto router::add_prefix(method_type method, std::string_view prefix, handler function,
                        void* context) -> std::expected<void, std::error_code>
{
    return insert(method, prefix, function, context, true);
}

auto router::insert(method_type method, std::string_view path, handler function,
                    void* context, bool prefix) -> std::expected<void, std::error_code>
{
    if (function == nullptr || method == method_type::unknown || !detail::valid_path(path))
        return std::unexpected(detail::failure(std::errc::invalid_argument));
    for (std::size_t index = 0; index < size_; ++index) {
        const auto& route = routes_[index];
        if (route.method == method && route.prefix == prefix && route.path == path)
            return std::unexpected(detail::failure(std::errc::file_exists));
    }
    if (size_ == routes_.size())
        return std::unexpected(detail::failure(std::errc::no_buffer_space));
    routes_[size_++] = {std::string(path), function, context, method, prefix};
    return {};
}

} // namespace eventloop::http
