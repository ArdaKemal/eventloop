#include "file_operation.h"
#include "eventloop/file_io.h"

#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <io.h>
#include <stdlib.h>
#include <system_error>
#include <winternl.h>

namespace eventloop {

namespace {
[[nodiscard]] auto file_errno(DWORD error) noexcept -> int
{
    const auto condition = std::error_code(static_cast<int>(error),
                                           std::system_category())
                               .default_error_condition();
    return condition.category() == std::generic_category() &&
                   condition.value() > 0
               ? condition.value()
               : EIO;
}

// The CRT invokes its invalid-parameter handler for closed descriptors.
// File operations report EBADF through the awaiter instead of terminating.
[[nodiscard]] auto windows_file_handle(int descriptor) noexcept -> intptr_t
{
    if (descriptor < 0) return -1;
    const auto previous = _set_thread_local_invalid_parameter_handler(
        [](const wchar_t*, const wchar_t*, const wchar_t*, unsigned,
           uintptr_t) noexcept {});
    const intptr_t native = _get_osfhandle(descriptor);
    _set_thread_local_invalid_parameter_handler(previous);
    return native;
}

[[nodiscard]] auto windows_file_open(
    const detail::file_io_operation& operation) noexcept -> int
{
    wchar_t path[256] {};
    const int path_size = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, operation.path, -1, path,
        static_cast<int>(std::size(path)));
    if (path_size == 0) return -EINVAL;

    const int access_mode = operation.flags & (O_WRONLY | O_RDWR);
    if (access_mode != O_RDONLY && access_mode != O_WRONLY &&
        access_mode != O_RDWR) return -EINVAL;
    constexpr int supported_flags = O_WRONLY | O_RDWR | O_CREAT | O_EXCL |
        O_TRUNC | O_APPEND | O_BINARY | O_NOINHERIT
#ifdef O_DIRECTORY
        | O_DIRECTORY
#endif
#ifdef O_NOFOLLOW
        | O_NOFOLLOW
#endif
        ;
    if ((operation.flags & ~supported_flags) != 0) return -EINVAL;
    const bool append = (operation.flags & O_APPEND) != 0;
    if (append && access_mode == O_RDONLY) return -EINVAL;
    DWORD access = SYNCHRONIZE;
    if (access_mode != O_WRONLY) access |= GENERIC_READ;
    if (access_mode != O_RDONLY) {
        access |= append ? FILE_APPEND_DATA : GENERIC_WRITE;
    }
    const bool create = (operation.flags & O_CREAT) != 0;
    const bool exclusive = (operation.flags & O_EXCL) != 0;
    const bool truncate = (operation.flags & O_TRUNC) != 0;
    if (truncate && access_mode == O_RDONLY) return -EINVAL;
    if (truncate && append) return -EINVAL;

    DWORD create_options = FILE_FLAG_BACKUP_SEMANTICS;
    ULONG nt_options = FILE_SYNCHRONOUS_IO_NONALERT |
                       FILE_OPEN_FOR_BACKUP_INTENT;
#ifdef O_NOFOLLOW
    if (operation.flags & O_NOFOLLOW) {
        create_options |= FILE_FLAG_OPEN_REPARSE_POINT;
        nt_options |= FILE_OPEN_REPARSE_POINT;
    }
#endif
#ifdef O_DIRECTORY
    if (operation.flags & O_DIRECTORY) nt_options |= FILE_DIRECTORY_FILE;
#endif

    DWORD disposition = OPEN_EXISTING;
    ULONG nt_disposition = FILE_OPEN;
    if (create && exclusive) {
        disposition = CREATE_NEW;
        nt_disposition = FILE_CREATE;
    } else if (create && truncate) {
        disposition = CREATE_ALWAYS;
        nt_disposition = FILE_OVERWRITE_IF;
    } else if (create) {
        disposition = OPEN_ALWAYS;
        nt_disposition = FILE_OPEN_IF;
    } else if (truncate) {
        disposition = TRUNCATE_EXISTING;
        nt_disposition = FILE_OVERWRITE;
    }

    const bool absolute = path[0] == L'\\' || path[0] == L'/' ||
                          (path_size > 2 && path[1] == L':');
    HANDLE handle = INVALID_HANDLE_VALUE;
    if (operation.descriptor == AT_FDCWD || absolute) {
        handle = CreateFileW(path, access,
                             FILE_SHARE_READ | FILE_SHARE_WRITE |
                                 FILE_SHARE_DELETE,
                             nullptr, disposition, create_options,
                             nullptr);
        if (handle == INVALID_HANDLE_VALUE) return -file_errno(GetLastError());
    } else {
        const intptr_t parent = windows_file_handle(operation.descriptor);
        if (parent == -1) return -EBADF;
        for (int index = 0; index < path_size - 1; ++index) {
            if (path[index] == L'/') path[index] = L'\\';
        }
        const auto module = GetModuleHandleW(L"ntdll.dll");
        if (module == nullptr) return -EIO;
        const auto create_file = reinterpret_cast<decltype(&NtCreateFile)>(
            GetProcAddress(module, "NtCreateFile"));
        const auto status_error = reinterpret_cast<
            decltype(&RtlNtStatusToDosError)>(
            GetProcAddress(module, "RtlNtStatusToDosError"));
        if (create_file == nullptr || status_error == nullptr) return -EIO;
        UNICODE_STRING name {};
        name.Buffer = path;
        name.Length = static_cast<USHORT>((path_size - 1) * sizeof(wchar_t));
        name.MaximumLength = static_cast<USHORT>(path_size * sizeof(wchar_t));
        OBJECT_ATTRIBUTES attributes {};
        attributes.Length = sizeof(attributes);
        attributes.RootDirectory = reinterpret_cast<HANDLE>(parent);
        attributes.ObjectName = &name;
        attributes.Attributes = OBJ_CASE_INSENSITIVE;
        IO_STATUS_BLOCK status_block {};
        const NTSTATUS status = create_file(
            &handle, access, &attributes, &status_block, nullptr,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nt_disposition,
            nt_options,
            nullptr, 0);
        if (!NT_SUCCESS(status)) return -file_errno(status_error(status));
    }

#if defined(O_NOFOLLOW) || defined(O_DIRECTORY)
    FILE_ATTRIBUTE_TAG_INFO file_tag {};
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo,
                                      &file_tag, sizeof(file_tag))) {
        const int error = file_errno(GetLastError());
        CloseHandle(handle);
        return -error;
    }
#ifdef O_NOFOLLOW
    if ((operation.flags & O_NOFOLLOW) &&
        (file_tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        CloseHandle(handle);
        return -ELOOP;
    }
#endif
#ifdef O_DIRECTORY
    if ((operation.flags & O_DIRECTORY) &&
        !(file_tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        CloseHandle(handle);
        return -ENOTDIR;
    }
#endif
#endif

    const int descriptor = _open_osfhandle(
        reinterpret_cast<intptr_t>(handle),
        (access_mode == O_RDONLY ? _O_RDONLY :
         access_mode == O_WRONLY ? _O_WRONLY : _O_RDWR) |
            (append ? _O_APPEND : 0) | _O_BINARY | _O_NOINHERIT);
    if (descriptor < 0) {
        const int error = errno;
        CloseHandle(handle);
        return -error;
    }
    return descriptor;
}

[[nodiscard]] auto windows_file_transfer(
    const detail::file_io_operation& operation) noexcept -> int
{
    const intptr_t native = windows_file_handle(operation.descriptor);
    if (native == -1) return -EBADF;
    if (operation.length == 0) return 0;
    OVERLAPPED overlapped {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (overlapped.hEvent == nullptr) return -file_errno(GetLastError());
    const auto offset = static_cast<std::uint64_t>(operation.offset);
    overlapped.Offset = static_cast<DWORD>(offset);
    overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32);
    DWORD transferred = 0;
    const BOOL ok = operation.opcode == detail::file_opcode::read_at
        ? ReadFile(reinterpret_cast<HANDLE>(native), operation.buffer,
                   static_cast<DWORD>(operation.length), &transferred,
                   &overlapped)
        : WriteFile(reinterpret_cast<HANDLE>(native), operation.buffer,
                    static_cast<DWORD>(operation.length), &transferred,
                    &overlapped);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && error == ERROR_IO_PENDING) {
        if (GetOverlappedResult(reinterpret_cast<HANDLE>(native), &overlapped,
                                &transferred, TRUE)) {
            error = ERROR_SUCCESS;
        } else {
            error = GetLastError();
        }
    }
    CloseHandle(overlapped.hEvent);
    if (error == ERROR_SUCCESS) return static_cast<int>(transferred);
    if (operation.opcode == detail::file_opcode::read_at &&
        error == ERROR_HANDLE_EOF) return 0;
    return -file_errno(error);
}

} // namespace

auto detail::perform_file_operation(detail::file_io_operation& operation) noexcept
    -> int
{
    if (operation.cancelled.load(std::memory_order_acquire)) {
        return -ECANCELED;
    }
    return operation.opcode == detail::file_opcode::openat
        ? windows_file_open(operation)
        : windows_file_transfer(operation);
}

} // namespace eventloop
