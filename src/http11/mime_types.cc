#include "eventloop/http/mime_types.h"

namespace http {
namespace {
[[nodiscard]] constexpr auto ascii_lower(char value) noexcept -> char
{
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
}

[[nodiscard]] auto extension_is(std::string_view extension,
                                std::string_view expected) noexcept -> bool
{
    if (extension.size() != expected.size()) {
        return false;
    }
    for (std::size_t index = 0; index < extension.size(); ++index) {
        if (ascii_lower(extension[index]) != expected[index]) {
            return false;
        }
    }
    return true;
}
} // namespace

auto mime_type_from_path(std::string_view path) noexcept -> std::string_view
{
    path = path.substr(0, path.find_first_of("?#"));
    const auto slash = path.find_last_of('/');
    const auto dot = path.find_last_of('.');
    if (dot == std::string_view::npos ||
        (slash != std::string_view::npos && dot < slash)) {
        return "application/octet-stream";
    }
    const auto extension = path.substr(dot + 1);
    if (extension_is(extension, "html") || extension_is(extension, "htm")) return "text/html; charset=utf-8";
    if (extension_is(extension, "css")) return "text/css; charset=utf-8";
    if (extension_is(extension, "js") || extension_is(extension, "mjs")) return "text/javascript; charset=utf-8";
    if (extension_is(extension, "txt")) return "text/plain; charset=utf-8";
    if (extension_is(extension, "json")) return "application/json";
    if (extension_is(extension, "xml")) return "application/xml";
    if (extension_is(extension, "svg")) return "image/svg+xml";
    if (extension_is(extension, "png")) return "image/png";
    if (extension_is(extension, "gif")) return "image/gif";
    if (extension_is(extension, "webp")) return "image/webp";
    if (extension_is(extension, "ico")) return "image/x-icon";
    if (extension_is(extension, "jpg") || extension_is(extension, "jpeg")) return "image/jpeg";
    if (extension_is(extension, "avif")) return "image/avif";
    if (extension_is(extension, "pdf")) return "application/pdf";
    if (extension_is(extension, "wasm")) return "application/wasm";
    if (extension_is(extension, "woff")) return "font/woff";
    if (extension_is(extension, "woff2")) return "font/woff2";
    if (extension_is(extension, "ttf")) return "font/ttf";
    if (extension_is(extension, "otf")) return "font/otf";
    if (extension_is(extension, "mp4")) return "video/mp4";
    if (extension_is(extension, "webm")) return "video/webm";
    if (extension_is(extension, "mp3")) return "audio/mpeg";
    if (extension_is(extension, "wav")) return "audio/wav";
    if (extension_is(extension, "ogg")) return "audio/ogg";
    return "application/octet-stream";
}

} // namespace http
