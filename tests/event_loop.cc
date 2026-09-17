#include "eventloop/event_loop.h"

#include <cerrno>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <system_error>

#include <sys/eventfd.h>
#include <unistd.h>

namespace {

[[nodiscard]] auto make_event() -> int
{
    const int descriptor = eventfd(1, EFD_CLOEXEC | EFD_NONBLOCK);
    if (descriptor == -1) {
        throw std::system_error(errno, std::system_category(), "eventfd");
    }
    return descriptor;
}

class throwing_handler final : public notifiable {
public:
    explicit throwing_handler(event_loop& loop)
        : loop_(loop), descriptor_(make_event())
    {
    }

    ~throwing_handler() override { ::close(descriptor_); }

    [[nodiscard]] auto descriptor() const noexcept -> int override
    {
        return descriptor_;
    }

private:
    auto on_read() -> void override
    {
        loop_.remove(descriptor_);
        throw std::runtime_error("expected handler failure");
    }

    auto on_write() -> void override {}
    auto on_error() -> void override {}

    event_loop& loop_;
    int descriptor_;
};

class stopping_handler final : public notifiable {
public:
    explicit stopping_handler(event_loop& loop)
        : loop_(loop), descriptor_(make_event())
    {
    }

    ~stopping_handler() override { ::close(descriptor_); }

    [[nodiscard]] auto descriptor() const noexcept -> int override
    {
        return descriptor_;
    }

private:
    auto on_read() -> void override { loop_.stop(); }
    auto on_write() -> void override {}
    auto on_error() -> void override {}

    event_loop& loop_;
    int descriptor_;
};

} // namespace

auto main() -> int
{
    event_loop loop;
    auto throwing = std::make_unique<throwing_handler>(loop);
    const int released_descriptor = throwing->descriptor();
    loop.add(std::move(throwing));

    try {
        loop.run();
        return 1;
    } catch (const std::runtime_error&) {
    }

    auto stopping = std::make_unique<stopping_handler>(loop);
    if (stopping->descriptor() != released_descriptor) return 1;
    loop.add(std::move(stopping));
    loop.run();
}
