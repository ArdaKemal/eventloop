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
#include "eventloop/unique_fd.h"
#include <array>
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
    void* context {nullptr};
    void (*complete)(socket_operation&, std::size_t, int) noexcept {nullptr};
    bool pending_completion {false};
    bool cancelled {false};
    std::size_t file_requested {0};
    bool file_reopened {false};
#endif
};

// Empty on readiness backends, so embedding it does not enlarge a stream.
struct socket_stream_state {
#ifdef _WIN32
    native_socket registered_descriptor {static_cast<native_socket>(-1)};
    std::size_t pending_operations {0};
#endif
};

struct socket_accept_state {
#ifdef _WIN32
    native_socket registered_descriptor {static_cast<native_socket>(-1)};
    int family {0};
#endif
};

struct socket_accept_awaiter_state {
#ifdef _WIN32
    unique_fd accepted;
    std::array<std::byte, 288> addresses {};
#endif
};

struct socket_datagram_state {
#ifdef _WIN32
    native_socket registered_descriptor {static_cast<native_socket>(-1)};
    std::size_t pending_operations {0};
#endif
};

struct socket_result {
    bool pending {false};
    std::size_t transferred {0};
    native_socket accepted {static_cast<native_socket>(-1)};
    ip_endpoint source {};
    std::error_code error {};
    // UDP_GRO: when nonzero, `transferred` bytes hold whole datagrams of this
    // size (the final datagram may be shorter). Zero means one datagram.
    std::size_t segment_size {0};
};

} // namespace eventloop::detail
