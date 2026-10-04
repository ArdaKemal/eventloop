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
    return exchange_->read_body(buffer);
}

auto response::async_start(unsigned status, std::span<const header> headers)
    -> task<std::expected<void, std::error_code>>
{
    return exchange_->start(status, headers, std::nullopt);
}

auto response::async_write(std::span<const std::byte> data)
    -> task<std::expected<void, std::error_code>>
{
    return exchange_->write(data);
}

auto response::async_finish(std::span<const header> trailers)
    -> task<std::expected<void, std::error_code>>
{
    return exchange_->finish(trailers);
}

auto response::async_send(unsigned status, std::span<const header> headers,
                          std::span<const std::byte> body)
    -> task<std::expected<void, std::error_code>>
{
    return detail::send_task(exchange_->loop(), *exchange_, status, headers, body);
}

auto response::async_send_file(unsigned status, std::span<const header> headers,
                               unique_fd file, std::uint64_t offset, std::uint64_t size)
    -> task<std::expected<void, std::error_code>>
{
    return exchange_->send_file(status, headers, std::move(file), offset, size);
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
