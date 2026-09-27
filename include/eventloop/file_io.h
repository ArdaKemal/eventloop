#pragma once

#include "eventloop/task.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <expected>
#include <limits>
#include <span>
#include <string_view>
#include <system_error>
#include <type_traits>

#include <fcntl.h>
#include <unistd.h>

namespace eventloop_detail {

enum class file_opcode { openat, read_at, write_at };

// The worker may access the path/buffer until the completion is delivered,
// including after cancellation has been requested.
struct file_io_operation {
    explicit file_io_operation(file_opcode kind) noexcept : opcode(kind) {}

    file_opcode opcode;
    int descriptor {-1};
    const char* path {nullptr};
    void* buffer {nullptr};
    std::size_t length {0};
    std::int64_t offset {0};
    int flags {0};
    unsigned mode {0};
    std::coroutine_handle<> continuation {};
    coroutine_cancellation_node cancellation;
    std::atomic<bool> cancelled {false};
    void* context {nullptr};
    void (*finish)(file_io_operation&, int) noexcept {nullptr};
};

} // namespace eventloop_detail

template<eventloop_detail::file_opcode Kind>
class file_io_awaiter {
public:
    using value_type = std::conditional_t<
        Kind == eventloop_detail::file_opcode::openat, int, std::size_t>;
    using result_type = std::expected<value_type, std::error_code>;

    file_io_awaiter(event_loop& loop, int directory, std::string_view path,
                    int flags, unsigned mode) noexcept
        requires (Kind == eventloop_detail::file_opcode::openat)
        : loop_(loop), operation_(Kind)
    {
        operation_.descriptor = directory;
        operation_.flags = flags | O_CLOEXEC;
        operation_.mode = mode;
        if (path.empty() || path.size() >= path_.size()) {
            result_ = -ENAMETOOLONG;
        } else if (path.find('\0') != std::string_view::npos) {
            result_ = -EINVAL;
        } else {
            std::memcpy(path_.data(), path.data(), path.size());
            path_[path.size()] = '\0';
            operation_.path = path_.data();
        }
        initialize();
    }

    file_io_awaiter(event_loop& loop, int descriptor, void* buffer,
                    std::size_t length, std::int64_t offset) noexcept
        requires (Kind != eventloop_detail::file_opcode::openat)
        : loop_(loop), operation_(Kind)
    {
        operation_.descriptor = descriptor;
        operation_.buffer = buffer;
        operation_.length = length;
        operation_.offset = offset;
        if (length > static_cast<std::size_t>(
                         std::numeric_limits<int>::max()) || offset < 0 ||
            (buffer == nullptr && length != 0)) {
            result_ = -EINVAL;
        }
        initialize();
    }

    file_io_awaiter(const file_io_awaiter&) = delete;
    auto operator=(const file_io_awaiter&) -> file_io_awaiter& = delete;

    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }

    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
    {
        if (handle.promise().loop_ != &loop_) {
            std::terminate();
        }
        if (result_ < 0) return false;
        auto& cancellation = *handle.promise().cancellation_;
        if (cancellation.requested) {
            result_ = -ECANCELED;
            return false;
        }
        operation_.continuation = handle;
        if (!eventloop_detail::coroutine_frame_access::attach_cancellation(
                cancellation, operation_.cancellation)) {
            result_ = -ECANCELED;
            return false;
        }
        const int submitted =
            eventloop_detail::coroutine_frame_access::submit_file(loop_, operation_);
        if (submitted < 0) {
            eventloop_detail::coroutine_frame_access::detach_cancellation(
                operation_.cancellation);
            result_ = submitted;
            return false;
        }
        return true;
    }

    [[nodiscard]] auto await_resume() const noexcept -> result_type
    {
        if (result_ < 0) {
            return std::unexpected(std::error_code(-result_,
                                                    std::generic_category()));
        }
        return static_cast<value_type>(result_);
    }

private:
    template<typename> friend class task;

    static auto cancel(eventloop_detail::coroutine_cancellation_node& node)
        noexcept -> void
    {
        auto& operation = *static_cast<eventloop_detail::file_io_operation*>(
            node.operation);
        operation.cancelled.store(true, std::memory_order_release);
        eventloop_detail::coroutine_frame_access::detach_cancellation(node);
    }

    static auto complete(eventloop_detail::file_io_operation& operation,
                         int result) noexcept -> void
    {
        auto& self = *static_cast<file_io_awaiter*>(operation.context);
        eventloop_detail::coroutine_frame_access::detach_cancellation(
            operation.cancellation);
        if (operation.cancelled.load(std::memory_order_acquire)) {
            if constexpr (Kind == eventloop_detail::file_opcode::openat) {
                if (result >= 0) (void)::close(result);
            }
            result = -ECANCELED;
        }
        self.result_ = result;
        const auto continuation = operation.continuation;
        continuation.resume();
    }

    auto initialize() noexcept -> void
    {
        operation_.context = this;
        operation_.finish = &complete;
        operation_.cancellation.operation = &operation_;
        operation_.cancellation.cancel = &cancel;
    }

    event_loop& loop_;
    eventloop_detail::file_io_operation operation_;
    std::array<char, Kind == eventloop_detail::file_opcode::openat ? 256 : 1>
        path_ {};
    int result_ {0};
};

// Paths are copied into the awaiter and limited to 255 bytes. Read and write
// buffers belong to the caller and must remain valid until completion.
[[nodiscard]] inline auto async_openat(event_loop& loop, int directory,
                                       std::string_view path, int flags,
                                       unsigned mode = 0) noexcept
    -> file_io_awaiter<eventloop_detail::file_opcode::openat>
{
    return {loop, directory, path, flags, mode};
}

[[nodiscard]] inline auto async_read_at(event_loop& loop, int descriptor,
                                        std::span<std::byte> buffer,
                                        std::int64_t offset) noexcept
    -> file_io_awaiter<eventloop_detail::file_opcode::read_at>
{
    return {loop, descriptor, buffer.data(), buffer.size(), offset};
}

[[nodiscard]] inline auto async_write_at(event_loop& loop, int descriptor,
                                         std::span<const std::byte> buffer,
                                         std::int64_t offset) noexcept
    -> file_io_awaiter<eventloop_detail::file_opcode::write_at>
{
    return {loop, descriptor, const_cast<std::byte*>(buffer.data()),
            buffer.size(), offset};
}
