#pragma once

#include <memory>

class notifiable {
public:
    virtual ~notifiable() = default;
    [[nodiscard]] virtual auto descriptor() const noexcept -> int = 0;
    virtual auto on_read() -> void = 0;
    virtual auto on_write() -> void = 0;
    virtual auto on_error() -> void = 0;
};

class event_loop {
public:
    event_loop();
    ~event_loop();

    event_loop(const event_loop&) = delete;
    auto operator=(const event_loop&) -> event_loop& = delete;

    auto run() -> void;
    auto stop() -> void;
    auto add(std::unique_ptr<notifiable> handler) -> void;
    auto remove(int descriptor) -> void;
    auto set_write_interest(int descriptor, bool enabled) -> void;

private:
    class implementation;
    std::unique_ptr<implementation> implementation_;
};
