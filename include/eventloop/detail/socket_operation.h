#pragma once

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif
#include <cstddef>
#include <cstdint>
#include "eventloop/native_socket.h"
#include "eventloop/ip_endpoint.h"
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#endif

namespace eventloop::detail {

struct socket_operation {
#ifdef _WIN32
    OVERLAPPED overlapped {};
    WSABUF buffer {};
    sockaddr_storage address {};
    int address_length {sizeof(sockaddr_storage)};
    DWORD flags {0};
#endif
    void* context {nullptr};
    void (*complete)(socket_operation&, std::size_t, int) noexcept {nullptr};
    bool pending_completion {false};
};

struct socket_result {
    bool pending {false};
    std::size_t transferred {0};
    native_socket accepted {static_cast<native_socket>(-1)};
    ip_endpoint source {};
    std::error_code error {};
};

} // namespace eventloop::detail
