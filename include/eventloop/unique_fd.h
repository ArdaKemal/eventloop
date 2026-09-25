#pragma once

#include <utility>

#include <unistd.h>

// Owns one descriptor. Moving transfers ownership without allocating.
class unique_fd {
public:
    unique_fd() noexcept = default;
    explicit unique_fd(int descriptor) noexcept : descriptor_(descriptor) {}
    ~unique_fd() { reset(); }

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept
        : descriptor_(other.release()) {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd&
    {
        if (this != &other) reset(other.release());
        return *this;
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return descriptor_ != -1;
    }

    [[nodiscard]] auto release() noexcept -> int
    {
        return std::exchange(descriptor_, -1);
    }

    auto reset(int descriptor = -1) noexcept -> void
    {
        if (descriptor_ == descriptor) return;
        if (descriptor_ != -1) (void)::close(descriptor_);
        descriptor_ = descriptor;
    }

private:
    int descriptor_ {-1};
};
