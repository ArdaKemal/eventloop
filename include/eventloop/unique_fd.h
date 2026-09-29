#pragma once

#ifdef _WIN32
#include "eventloop/native_socket.h"
#endif

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
#ifdef _WIN32
    enum class kind { socket, file, native_file };
    unique_fd() noexcept = default;
    explicit unique_fd(native_socket descriptor, kind handle_kind = kind::socket) noexcept
        : descriptor_(descriptor), kind_(handle_kind) {}
#else
    unique_fd() noexcept = default;
    explicit unique_fd(int descriptor) noexcept : descriptor_(descriptor) {}
#endif
    ~unique_fd() { reset(); }

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept
#ifdef _WIN32
        : descriptor_(other.release()), kind_(other.kind_) {}
#else
        : descriptor_(other.release()) {}
#endif

    auto operator=(unique_fd&& other) noexcept -> unique_fd&
    {
        if (this != &other) {
#ifdef _WIN32
            reset();
            descriptor_ = other.release();
            kind_ = other.kind_;
#else
            reset(other.release());
#endif
        }
        return *this;
    }

#ifdef _WIN32
    [[nodiscard]] auto get() const noexcept -> native_socket { return descriptor_; }
#else
    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }
#endif
    [[nodiscard]] explicit operator bool() const noexcept
    {
#ifdef _WIN32
        return descriptor_ != invalid;
#else
        return descriptor_ != -1;
#endif
    }

#ifdef _WIN32
    [[nodiscard]] auto release() noexcept -> native_socket
    {
        return std::exchange(descriptor_, invalid);
    }
#else
    [[nodiscard]] auto release() noexcept -> int
    {
        return std::exchange(descriptor_, -1);
    }
#endif

#ifdef _WIN32
    auto reset(native_socket descriptor = invalid,
               kind handle_kind = kind::socket) noexcept -> void
#else
    auto reset(int descriptor = -1) noexcept -> void
#endif
    {
        if (descriptor_ == descriptor) return;
#ifdef _WIN32
        if (descriptor_ != invalid) {
            if (kind_ == kind::socket)
                (void)::closesocket(static_cast<SOCKET>(descriptor_));
            else if (kind_ == kind::native_file)
                (void)::CloseHandle(reinterpret_cast<HANDLE>(descriptor_));
            else
                (void)::_close(static_cast<int>(descriptor_));
#else
        if (descriptor_ != -1) (void)::close(descriptor_);
#endif
#ifdef _WIN32
        }
#endif
        descriptor_ = descriptor;
#ifdef _WIN32
        kind_ = handle_kind;
#endif
    }

private:
#ifdef _WIN32
    static constexpr native_socket invalid = static_cast<native_socket>(-1);
    native_socket descriptor_ {invalid};
    kind kind_ {kind::socket};
#else
    int descriptor_ {-1};
#endif
};

} // namespace eventloop
