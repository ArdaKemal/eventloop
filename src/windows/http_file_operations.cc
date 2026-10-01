#include "../http/file_operations.h"

#include <algorithm>
#include <climits>
#include <ctime>
#include <cwchar>
#include <limits>
#include <stdexcept>
#include <system_error>

#include <windows.h>

namespace eventloop::http::detail {
namespace {

[[nodiscard]] auto as_handle(native_socket value) noexcept -> HANDLE
{
    return reinterpret_cast<HANDLE>(value);
}

[[nodiscard]] auto utf16(std::string_view value) -> std::wstring
{
    if (value.size() > INT_MAX) return {};
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (length == 0) return {};
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), length) == 0) return {};
    return result;
}

[[nodiscard]] auto utf8(std::wstring_view value) -> std::string
{
    if (value.size() > INT_MAX) return {};
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (length == 0) return {};
    std::string result(static_cast<std::size_t>(length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), length, nullptr, nullptr) == 0)
        return {};
    return result;
}

[[nodiscard]] auto final_path(HANDLE handle) -> std::wstring
{
    const DWORD size = GetFinalPathNameByHandleW(handle, nullptr, 0,
                                                 FILE_NAME_NORMALIZED);
    if (size == 0 || size > 32767) return {};
    std::wstring path(size, L'\0');
    const DWORD written = GetFinalPathNameByHandleW(handle, path.data(), size,
                                                    FILE_NAME_NORMALIZED);
    if (written == 0 || written >= size) return {};
    path.resize(written);
    return path;
}

[[nodiscard]] auto is_direct_child(std::wstring_view parent,
                                   std::wstring_view child) noexcept -> bool
{
    if (parent.empty() || child.size() <= parent.size()) return false;
    if (child.substr(0, parent.size()) != parent) return false;
    const auto name_start = parent.size() + (parent.back() == L'\\' ? 0 : 1);
    return (parent.back() == L'\\' || child[parent.size()] == L'\\') &&
           name_start < child.size() &&
           child.find(L'\\', name_start) == std::wstring_view::npos;
}

[[nodiscard]] auto native_file(HANDLE handle) noexcept -> unique_fd
{
    return unique_fd(reinterpret_cast<native_socket>(handle),
                     unique_fd::kind::native_file);
}

} // namespace

auto open_root(std::string_view root) -> unique_fd
{
    if (root.empty() || root.size() >= 4096 ||
        root.find('\0') != std::string_view::npos)
        throw std::invalid_argument("HTTP root path is invalid or too long");
    auto path = utf16(root);
    if (path.empty()) throw std::invalid_argument("HTTP root path is invalid UTF-8");
    unique_fd result = native_file(CreateFileW(path.c_str(), FILE_READ_DATA |
        FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY, FILE_SHARE_READ |
        FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!result || !final_path(as_handle(result.get())).size())
        throw std::system_error(GetLastError(), std::system_category(),
                                "open HTTP root");
    auto info = get_file_info(result.get());
    if (!info || info->kind != file_info::type::directory)
        throw std::invalid_argument("HTTP root is not a directory");
    return result;
}

auto open_child(native_socket parent, std::string_view name,
                bool directory_required) noexcept -> unique_fd
{
    try {
        if (name == ".") {
            HANDLE duplicate = INVALID_HANDLE_VALUE;
            if (DuplicateHandle(GetCurrentProcess(), as_handle(parent),
                    GetCurrentProcess(), &duplicate, 0, FALSE,
                    DUPLICATE_SAME_ACCESS)) return native_file(duplicate);
            return {};
        }
        if (name.empty() || name == ".." || name.size() >= 4096 ||
            name.find_first_of("/\\:\0", 0, 3) != std::string_view::npos ||
            name.back() == '.' || name.back() == ' ') return {};
        auto wide = utf16(name);
        auto base = final_path(as_handle(parent));
        if (wide.empty() || base.empty()) return {};
        if (base.back() != L'\\') base.push_back(L'\\');
        base += wide;
        unique_fd child = native_file(CreateFileW(base.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
            FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!child) return {};
        FILE_ATTRIBUTE_TAG_INFO tag {};
        if (!GetFileInformationByHandleEx(as_handle(child.get()), FileAttributeTagInfo,
                &tag, sizeof(tag)) || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            return {};
        auto actual = final_path(as_handle(child.get()));
        const auto parent_path = final_path(as_handle(parent));
        if (!is_direct_child(parent_path, actual)) return {};
        auto info = get_file_info(child.get());
        if (!info || (directory_required &&
                      info->kind != file_info::type::directory)) return {};
        return child;
    } catch (...) {
        return {};
    }
}

auto get_file_info(native_socket file) noexcept -> std::optional<file_info>
{
    FILE_ATTRIBUTE_TAG_INFO attributes {};
    FILE_STANDARD_INFO standard {};
    FILE_BASIC_INFO basic {};
    HANDLE handle = as_handle(file);
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo,
            &attributes, sizeof(attributes)) ||
        !GetFileInformationByHandleEx(handle, FileStandardInfo,
            &standard, sizeof(standard)) ||
        !GetFileInformationByHandleEx(handle, FileBasicInfo,
            &basic, sizeof(basic))) return std::nullopt;
    if (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) return std::nullopt;
    constexpr std::int64_t epoch_offset = 116444736000000000LL;
    BY_HANDLE_FILE_INFORMATION identity {};
    const bool have_identity = GetFileInformationByHandle(handle, &identity) != 0;
    const auto modified_ticks = basic.LastWriteTime.QuadPart - epoch_offset;
    const auto changed_ticks = basic.ChangeTime.QuadPart - epoch_offset;
    return file_info {
        standard.Directory ? file_info::type::directory : file_info::type::regular,
        standard.EndOfFile.QuadPart < 0 ? 0U :
            static_cast<std::uint64_t>(standard.EndOfFile.QuadPart),
        modified_ticks / 10000000LL,
        static_cast<std::uint32_t>((modified_ticks % 10000000LL + 10000000LL) % 10000000LL * 100),
        changed_ticks / 10000000LL,
        static_cast<std::uint32_t>((changed_ticks % 10000000LL + 10000000LL) % 10000000LL * 100),
        have_identity ? identity.dwVolumeSerialNumber : 0,
        have_identity ? (static_cast<std::uint64_t>(identity.nFileIndexHigh) << 32 |
                         identity.nFileIndexLow) : 0};
}

auto read_file(native_socket file, std::span<std::byte> output) noexcept -> bool
{
    std::size_t offset = 0;
    while (offset < output.size()) {
        DWORD received = 0;
        const DWORD amount = static_cast<DWORD>(std::min<std::size_t>(
            output.size() - offset, 1U << 20));
        if (!ReadFile(as_handle(file), output.data() + offset, amount,
                      &received, nullptr) || received == 0) return false;
        offset += received;
    }
    return true;
}

auto read_file_at(native_socket file, std::uint64_t offset,
                  std::span<std::byte> output) noexcept -> bool
{
    constexpr auto max_offset = static_cast<std::uint64_t>(
        std::numeric_limits<std::int64_t>::max());
    if (offset > max_offset || output.size() > max_offset - offset)
        return false;
    LARGE_INTEGER position {};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(as_handle(file), position, nullptr, FILE_BEGIN))
        return false;
    std::size_t read_size = 0;
    while (read_size < output.size()) {
        DWORD received = 0;
        const DWORD amount = static_cast<DWORD>(std::min<std::size_t>(
            output.size() - read_size, 1U << 20));
        if (!ReadFile(as_handle(file), output.data() + read_size, amount,
                      &received, nullptr) || received == 0) return false;
        read_size += received;
    }
    return true;
}

auto list_directory(native_socket directory)
    -> std::optional<std::vector<directory_entry>>
{
    auto path = final_path(as_handle(directory));
    if (path.empty()) return std::nullopt;
    if (path.back() != L'\\') path.push_back(L'\\');
    path.push_back(L'*');
    WIN32_FIND_DATAW data {};
    HANDLE search = FindFirstFileW(path.c_str(), &data);
    if (search == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) return std::vector<directory_entry> {};
        return std::nullopt;
    }
    struct search_guard {
        HANDLE value;
        ~search_guard() { FindClose(value); }
    } guard {search};
    std::vector<directory_entry> entries;
    do {
        if (wcscmp(data.cFileName, L".") == 0 ||
            wcscmp(data.cFileName, L"..") == 0) continue;
        auto name = utf8(data.cFileName);
        if (name.empty()) continue;
        entries.push_back({std::move(name),
            (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0});
    } while (FindNextFileW(search, &data));
    return GetLastError() == ERROR_NO_MORE_FILES ?
        std::optional {std::move(entries)} : std::nullopt;
}

auto format_http_time(std::int64_t value, std::span<char> output) noexcept
    -> std::size_t
{
    const auto seconds = static_cast<std::time_t>(value);
    std::tm time {};
    if (gmtime_s(&time, &seconds) != 0) return 0;
    return std::strftime(output.data(), output.size(),
                         "%a, %d %b %Y %H:%M:%S GMT", &time);
}

} // namespace eventloop::http::detail
