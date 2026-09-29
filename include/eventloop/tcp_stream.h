#pragma once

#include "eventloop/event_loop.h"
#include "eventloop/detail/notifiable.h"
#include "eventloop/ip_endpoint.h"
#include "eventloop/task.h"
#include "eventloop/unique_fd.h"
#include "eventloop/detail/socket_operation.h"

#include <cstddef>
#include <coroutine>
#include <cstdint>
#include <exception>
#include <expected>
#include <span>
#include <system_error>

namespace eventloop {
namespace detail { class socket_operations; }

class tcp_stream : private detail::notifiable {
public:
    // Takes ownership of the accepted descriptor, including on failure.
    tcp_stream(event_loop& loop, unique_fd descriptor);
    tcp_stream(event_loop& loop, ip_endpoint endpoint);
    ~tcp_stream() override;

    tcp_stream(const tcp_stream&) = delete;
    auto operator=(const tcp_stream&) -> tcp_stream& = delete;

    [[nodiscard]] auto descriptor() const noexcept -> native_socket override;
    [[nodiscard]] auto owning_loop() const noexcept -> event_loop& { return loop_; }
    class connect_awaiter {
    public:
        explicit connect_awaiter(tcp_stream& owner) noexcept;
        ~connect_awaiter();
        connect_awaiter(const connect_awaiter&) = delete;
        auto operator=(const connect_awaiter&) -> connect_awaiter& = delete;
        connect_awaiter(connect_awaiter&&) = delete;
        [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }
        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> handle) -> bool
        {
            if (handle.promise().owner_loop() != &owner_.loop_) std::terminate();
            return suspend(handle, *handle.promise().cancellation_state());
        }
        [[nodiscard]] auto await_resume() const noexcept
            -> std::expected<void, std::error_code>;
    private:
        friend class tcp_stream;
        friend class detail::socket_operations;
        static auto cancel(detail::coroutine_cancellation_node& node)
            noexcept -> void;
        auto suspend(std::coroutine_handle<> handle,
                     detail::coroutine_cancellation_state& state) -> bool;
        auto finish(std::error_code error) noexcept -> void;
        tcp_stream& owner_;
        detail::coroutine_cancellation_node cancellation_ {};
        std::coroutine_handle<> continuation_ {};
        std::error_code error_ {};
        [[no_unique_address]] detail::socket_operation operation_ {};
    };
    [[nodiscard]] auto async_connect() noexcept -> connect_awaiter
    {
        return connect_awaiter(*this);
    }

    template<bool Read>
    class io_awaiter {
    public:
        io_awaiter(tcp_stream& owner, void* data, std::size_t size) noexcept;
        ~io_awaiter();
        io_awaiter(const io_awaiter&) = delete;
        auto operator=(const io_awaiter&) -> io_awaiter& = delete;
        io_awaiter(io_awaiter&&) = delete;
        [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }
        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> handle) -> bool
        {
            if (handle.promise().owner_loop() != &owner_.loop_) std::terminate();
            return suspend(handle, *handle.promise().cancellation_state());
        }
        [[nodiscard]] auto await_resume() const noexcept
            -> std::expected<std::size_t, std::error_code>;
    private:
        friend class tcp_stream;
        friend class detail::socket_operations;
        static auto cancel(detail::coroutine_cancellation_node& node)
            noexcept -> void;
        auto suspend(std::coroutine_handle<> handle,
                     detail::coroutine_cancellation_state& state) -> bool;
        auto finish(std::size_t size, std::error_code error) noexcept -> void;
        tcp_stream& owner_;
        void* data_;
        std::size_t size_;
        detail::coroutine_cancellation_node cancellation_ {};
        std::coroutine_handle<> continuation_ {};
        std::size_t transferred_ {0};
        std::error_code error_ {};
        [[no_unique_address]] detail::socket_operation operation_ {};
    };
    // Buffers remain caller-owned until completion, including cancellation.
    // One read and one write may be pending at a time. Operations return
    // partial byte counts; zero from read means EOF. A duplicate operation in
    // the same direction returns EBUSY. Cancellation or close of a pending
    // operation returns ECANCELED.
    // These direct awaiters store state in the caller's coroutine frame.
    [[nodiscard]] auto async_read_some(std::span<std::byte> buffer) noexcept
        -> io_awaiter<true>
    {
        return {*this, buffer.data(), buffer.size()};
    }
    [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer) noexcept
        -> io_awaiter<false>
    {
        return {*this, const_cast<std::byte*>(buffer.data()), buffer.size()};
    }
private:
    class file_awaiter {
    public:
        file_awaiter(tcp_stream& owner, unique_fd file,
                     std::size_t size) noexcept;
        ~file_awaiter();
        file_awaiter(const file_awaiter&) = delete;
        auto operator=(const file_awaiter&) -> file_awaiter& = delete;
        file_awaiter(file_awaiter&&) = delete;
        [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }
        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> handle) -> bool
        {
            if (handle.promise().owner_loop() != &owner_.loop_) std::terminate();
            return suspend(handle, *handle.promise().cancellation_state());
        }
        [[nodiscard]] auto await_resume() const noexcept
            -> std::expected<void, std::error_code>;
    private:
        friend class tcp_stream;
        friend class detail::socket_operations;
        static auto cancel(detail::coroutine_cancellation_node& node)
            noexcept -> void;
        auto suspend(std::coroutine_handle<> handle,
                     detail::coroutine_cancellation_state& state) -> bool;
        auto advance() noexcept -> std::error_code;
        auto finish(std::error_code error) noexcept -> void;
        tcp_stream& owner_;
        unique_fd file_;
        std::size_t remaining_;
        detail::coroutine_cancellation_node cancellation_ {};
        std::coroutine_handle<> continuation_ {};
        std::error_code error_ {};
        [[no_unique_address]] detail::socket_operation operation_ {};
    };
    [[nodiscard]] static auto send_file_task(
        event_loop& loop, tcp_stream& socket, std::span<const std::byte> header,
        unique_fd file, std::size_t size)
        -> task<std::expected<void, std::error_code>>;
public:
    // Owns file through completion, including cancellation. This task wraps
    // the internal sendfile awaiter and requires a coroutine frame.
    [[nodiscard]] auto async_send_file(std::span<const std::byte> header,
                                       unique_fd file, std::size_t size)
        -> task<std::expected<void, std::error_code>>;
    virtual auto close() -> void;

protected:
    [[nodiscard]] auto owner_loop() noexcept -> event_loop& { return loop_; }
    // TLS activates its raw socket awaiters before driving encrypted records.
    [[nodiscard]] auto activate_async_transport() noexcept
        -> std::expected<void, std::error_code>;
    [[nodiscard]] auto transport_closed() const noexcept -> bool { return closed_; }

private:
    friend class event_loop;
    friend class detail::socket_operations;

    [[nodiscard]] auto initial_read_interest() const noexcept -> bool override
    {
        return false;
    }

    auto on_read() -> void override;
    auto on_write() -> void override;
    auto on_error() -> void override;
    auto on_shutdown() -> void override;
    auto set_async_interest(bool read_enabled, bool write_enabled) -> void;
    auto update_async_interest() noexcept -> void;
    auto complete_connect(std::error_code error) noexcept -> void;
    auto complete_read(std::size_t size, std::error_code error) noexcept -> void;
    auto complete_write(std::size_t size, std::error_code error) noexcept -> void;
    auto complete_file(std::error_code error) noexcept -> void;
    auto fail_and_close(std::error_code error) -> void;

    event_loop& loop_;
    unique_fd descriptor_;
    bool closed_ {false};
    ip_endpoint remote_ {};
    connect_awaiter* connector_ {nullptr};
    io_awaiter<true>* reader_ {nullptr};
    io_awaiter<false>* writer_ {nullptr};
    file_awaiter* file_writer_ {nullptr};
    bool connected_ {true};
    bool connect_started_ {false};
    bool transport_activated_ {false};
    bool read_interest_enabled_ {false};
    bool write_interest_enabled_ {false};
    [[no_unique_address]] detail::socket_stream_state socket_state_ {};
};

} // namespace eventloop
