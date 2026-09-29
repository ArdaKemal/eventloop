#pragma once

#include "eventloop/native_socket.h"

#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

namespace eventloop {

// Owns one descriptor. Moving transfers ownership without allocating.
class unique_fd {
public:
    enum class kind { socket, file, native_file };
    unique_fd() noexcept = default;
    explicit unique_fd(native_socket descriptor, kind handle_kind = kind::socket) noexcept
        : descriptor_(descriptor), kind_(handle_kind) {}
    ~unique_fd() { reset(); }

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept
        : descriptor_(other.release()), kind_(other.kind_) {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd&
    {
        if (this != &other) {
            reset();
            descriptor_ = other.release();
            kind_ = other.kind_;
        }
        return *this;
    }

    [[nodiscard]] auto get() const noexcept -> native_socket { return descriptor_; }
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return descriptor_ != invalid;
    }

    [[nodiscard]] auto release() noexcept -> native_socket
    {
        return std::exchange(descriptor_, invalid);
    }

    auto reset(native_socket descriptor = invalid,
               kind handle_kind = kind::socket) noexcept -> void
    {
        if (descriptor_ == descriptor) return;
        if (descriptor_ != invalid) {
#ifdef _WIN32
            if (kind_ == kind::socket)
                (void)::closesocket(static_cast<SOCKET>(descriptor_));
            else if (kind_ == kind::native_file)
                (void)::CloseHandle(reinterpret_cast<HANDLE>(descriptor_));
            else
                (void)::_close(static_cast<int>(descriptor_));
#else
            (void)::close(descriptor_);
#endif
        }
        descriptor_ = descriptor;
        kind_ = handle_kind;
    }

private:
    static constexpr native_socket invalid = static_cast<native_socket>(-1);
    native_socket descriptor_ {invalid};
    kind kind_ {kind::socket};
};

} // namespace eventloop
