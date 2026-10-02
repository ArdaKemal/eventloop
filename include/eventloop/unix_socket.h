#pragma once

#ifdef _WIN32
#error "eventloop Unix domain sockets are supported on Linux and macOS only"
#endif

#include "eventloop/tcp_acceptor.h"
#include "eventloop/tcp_stream.h"

#include <cstdint>
#include <array>
#include <string_view>

namespace eventloop {

// A filesystem-path Unix stream listener. Existing paths are never removed
// during bind. close() removes the path only if it still names this socket.
// Accepted descriptors are owned by the caller, like tcp_acceptor.
class unix_acceptor final : public tcp_acceptor {
public:
    unix_acceptor(event_loop& loop, std::string_view path);
    ~unix_acceptor() override;

    auto close() -> void override;

private:
    std::array<char, 108> path_ {};
    std::uint64_t device_ {0};
    std::uint64_t inode_ {0};
    bool path_closed_ {false};
};

// Uses the same bounded direct awaiters and cancellation rules as tcp_stream.
// One pending read and one pending write are allowed; buffers remain borrowed
// until completion. The accepted-descriptor constructor takes ownership.
class unix_stream final : public tcp_stream {
public:
    unix_stream(event_loop& loop, unique_fd descriptor)
        : tcp_stream(loop, std::move(descriptor)) {}
    unix_stream(event_loop& loop, std::string_view path)
        : tcp_stream(loop, path) {}
};

} // namespace eventloop
