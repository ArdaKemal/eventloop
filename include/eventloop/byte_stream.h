#pragma once

#include <cstddef>
#include <span>
#include <system_error>

class byte_stream {
public:
    virtual ~byte_stream() = default;

    virtual auto write(std::span<const std::byte> data) -> void = 0;
    virtual auto close() -> void = 0;
    [[nodiscard]] virtual auto ready() const noexcept -> bool = 0;
    [[nodiscard]] virtual auto write_pending() const noexcept -> bool = 0;

protected:
    auto emit_ready() -> void { on_ready(); }
    auto emit_data(std::span<const std::byte> data) -> void { on_data(data); }
    auto emit_close() -> void { on_close(); }
    auto emit_error(std::error_code error) -> void { on_error(error); }

    virtual auto on_ready() -> void {}
    virtual auto on_data(std::span<const std::byte> data) -> void = 0;
    virtual auto on_close() -> void {}
    virtual auto on_error(std::error_code) -> void {}
};
