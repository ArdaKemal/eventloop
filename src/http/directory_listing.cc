#include "eventloop/http/directory_listing.h"
#include "file_operations.h"

#include <string_view>

namespace eventloop::http {
namespace {

auto append(std::vector<char>& output, std::string_view value) -> void
{
    output.insert(output.end(), value.begin(), value.end());
}

auto append(std::vector<char>& output, char value) -> void
{
    output.push_back(value);
}

[[nodiscard]] constexpr auto url_safe(unsigned char value) noexcept -> bool
{
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') || value == '-' || value == '.' ||
           value == '_' || value == '~';
}

auto append_url_encoded(std::vector<char>& output,
                        std::string_view value) -> void
{
    constexpr char hex[] = "0123456789ABCDEF";
    for (const unsigned char byte : value) {
        if (url_safe(byte)) {
            append(output, static_cast<char>(byte));
        } else {
            append(output, '%');
            append(output, hex[byte >> 4]);
            append(output, hex[byte & 0x0f]);
        }
    }
}

auto append_html_escaped(std::vector<char>& output,
                         std::string_view value) -> void
{
    for (const char byte : value) {
        switch (byte) {
        case '&': append(output, "&amp;"); break;
        case '<': append(output, "&lt;"); break;
        case '>': append(output, "&gt;"); break;
        case '"': append(output, "&quot;"); break;
        case '\'': append(output, "&#39;"); break;
        default: append(output, byte); break;
        }
    }
}

} // namespace

auto detail::render_directory_listing(unique_fd descriptor)
    -> std::optional<std::vector<char>>
{
    auto entries = list_directory(descriptor.get());
    if (!entries) return std::nullopt;

    std::vector<char> output;
    output.reserve(4096);
    append(output,
           "<!doctype html><html><head><meta charset=\"utf-8\">"
           "<title>Index</title></head><body><h1>Index</h1><ul>\n");

    for (const auto& entry : *entries) {
        const bool is_directory = entry.is_directory;
        const std::string_view name {entry.name};
        append(output, "<li><a href=\"");
        append_url_encoded(output, name);
        if (is_directory) append(output, '/');
        append(output, "\">");
        append_html_escaped(output, name);
        if (is_directory) append(output, '/');
        append(output, "</a></li>\n");
    }

    append(output, "</ul></body></html>\n");
    return output;
}

auto make_directory_listing(native_socket descriptor)
    -> std::optional<std::vector<char>>
{
#ifdef _WIN32
    return detail::render_directory_listing(
        unique_fd(descriptor, unique_fd::kind::native_file));
#else
    return detail::render_directory_listing(unique_fd(descriptor));
#endif
}

} // namespace eventloop::http
