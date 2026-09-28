#pragma once

namespace eventloop {

namespace detail {

class notifiable {
public:
    virtual ~notifiable() = default;
    [[nodiscard]] virtual auto descriptor() const noexcept -> int = 0;
    virtual auto on_read() -> void = 0;
    virtual auto on_write() -> void = 0;
    virtual auto on_error() -> void = 0;
    virtual auto on_shutdown() -> void {}
    [[nodiscard]] virtual auto initial_read_interest() const noexcept -> bool
    {
        return true;
    }
};

} // namespace detail

} // namespace eventloop
