#include "eventloop/http/directory_listing.h"

#include <cerrno>
#include <cstring>
#include <memory>
#include <string_view>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace eventloop::http {
namespace {

struct directory_closer {
    auto operator()(DIR* directory) const noexcept -> void
    {
        (void)closedir(directory);
    }
};

using directory_ptr = std::unique_ptr<DIR, directory_closer>;

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

auto make_directory_listing(int descriptor)
    -> std::optional<std::vector<char>>
{
    directory_ptr directory(fdopendir(descriptor));
    if (!directory) {
        ::close(descriptor);
        return std::nullopt;
    }

    std::vector<char> output;
    output.reserve(4096);
    append(output,
           "<!doctype html><html><head><meta charset=\"utf-8\">"
           "<title>Index</title></head><body><h1>Index</h1><ul>\n");

    for (;;) {
        errno = 0;
        dirent* entry = readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) return std::nullopt;
            break;
        }
        if (std::strcmp(entry->d_name, ".") == 0 ||
            std::strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        bool is_directory = entry->d_type == DT_DIR;
        if (entry->d_type == DT_UNKNOWN) {
            struct stat info {};
            is_directory = fstatat(descriptor, entry->d_name, &info,
                                   AT_SYMLINK_NOFOLLOW) == 0 &&
                           S_ISDIR(info.st_mode);
        }

        const std::string_view name {entry->d_name};
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

} // namespace eventloop::http
