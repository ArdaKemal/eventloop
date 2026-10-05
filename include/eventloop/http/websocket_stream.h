#pragma once

#include "eventloop/task.h"

#include <cstddef>
#include <expected>
#include <span>
#include <system_error>

namespace eventloop::http {
namespace detail { class exchange; struct request_access; }

// One accepted Extended CONNECT stream, borrowed from its route handler's
// exchange. Keep it and pending operations inside that handler. It owns no
// socket. Destruction aborts this stream unless async_close() completed.
// One read and one write may run concurrently; spans are borrowed through
// completion, including cancellation. Move only with no pending operations.
class websocket_stream {
public:
    websocket_stream(const websocket_stream&) = delete;
    auto operator=(const websocket_stream&) -> websocket_stream& = delete;
    websocket_stream(websocket_stream&& other) noexcept;
    auto operator=(websocket_stream&& other) noexcept -> websocket_stream&;
    ~websocket_stream();

    [[nodiscard]] auto owning_loop() const noexcept -> event_loop& { return *loop_; }
    [[nodiscard]] auto async_read_some(std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Ends sending, then waits for peer END_STREAM/FIN. Cancellation aborts.
    [[nodiscard]] auto async_close() -> task<std::expected<void, std::error_code>>;
    // Abort only this stream; pending operations must still retire.
    auto close() noexcept -> void;

private:
    friend struct detail::request_access;
    explicit websocket_stream(detail::exchange& exchange) noexcept;
    detail::exchange* exchange_;
    event_loop* loop_;
};

} // namespace eventloop::http
