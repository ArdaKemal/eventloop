#pragma once
#include "eventloop/native_socket.h"

#include <cstdint>
#include <memory>

namespace eventloop {

namespace detail {

class notifiable {
public:
    virtual ~notifiable() = default;
    [[nodiscard]] virtual auto descriptor() const noexcept -> native_socket = 0;
    virtual auto on_read() -> void = 0;
    virtual auto on_write() -> void = 0;
    virtual auto on_error() -> void = 0;
    virtual auto on_shutdown() -> void {}
    [[nodiscard]] virtual auto initial_read_interest() const noexcept -> bool
    {
        return true;
    }

    // An internal owner that keeps calling a loop-owned handler across loop
    // iterations pins it. Removal then leaves a pinned handler alive, closed
    // and deregistered, until the last unpin destroys it.
    auto pin() noexcept -> void { ++pins_; }
    auto unpin() noexcept -> void
    {
        if (--pins_ == 0 && orphaned_) delete this;
    }
    // Destroys a handler the loop removed, unless it is pinned.
    static auto retire(std::unique_ptr<notifiable> handler) noexcept -> void
    {
        if (!handler || handler->pins_ == 0) return;
        handler->orphaned_ = true;
        (void)handler.release();
    }

private:
    std::uint32_t pins_ {0};
    bool orphaned_ {false};
};

} // namespace detail

} // namespace eventloop
