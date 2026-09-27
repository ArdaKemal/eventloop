#pragma once

#include "eventloop/tcp_stream.h"
#include "eventloop/task.h"
#include "eventloop/tls_context.h"

#include <expected>
#include <memory>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

enum class tls_errc {
    truncated = 1000,
    handshake_failed,
    protocol_error,
};

[[nodiscard]] auto tls_error_category() noexcept -> const std::error_category&;
[[nodiscard]] auto make_error_code(tls_errc error) noexcept -> std::error_code;

struct tls_client_options {
    std::string hostname;
    std::vector<std::string> application_protocols;
};

struct tls_server_options {
    std::vector<std::string> application_protocols;
};

class tls_stream : public tcp_stream {
public:
    tls_stream(event_loop& loop, int descriptor, std::shared_ptr<tls_context> context,
               tls_client_options options);
    tls_stream(event_loop& loop, unique_fd descriptor,
               std::shared_ptr<tls_context> context,
               tls_client_options options);
    tls_stream(event_loop& loop, int descriptor, std::shared_ptr<tls_context> context,
               tls_server_options options = {});
    tls_stream(event_loop& loop, unique_fd descriptor,
               std::shared_ptr<tls_context> context,
               tls_server_options options = {});
    ~tls_stream() override;

    auto close() -> void override;
    [[nodiscard]] auto application_protocol() const -> std::string;

    // One read and one write may be pending together. A second operation in
    // either direction returns EBUSY. Handshake and close require an idle stream.
    [[nodiscard]] auto async_handshake()
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] auto async_read_some(std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Flushes close_notify. Close the transport after this task completes.
    [[nodiscard]] auto async_close()
        -> task<std::expected<void, std::error_code>>;

private:
    class flush_waiter;
    auto release_flush() noexcept -> void;
    [[nodiscard]] static auto handshake_task(event_loop& loop, tls_stream& self)
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] static auto read_task(event_loop& loop, tls_stream& self,
                                        std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    [[nodiscard]] static auto write_task(event_loop& loop, tls_stream& self,
                                         std::span<const std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    [[nodiscard]] static auto flush_task(event_loop& loop, tls_stream& self)
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] static auto close_task(event_loop& loop, tls_stream& self)
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] auto activate_async_tls() noexcept
        -> std::expected<void, std::error_code>;
    [[nodiscard]] auto receive_encrypted(std::span<const std::byte> data) noexcept
        -> std::error_code;
    auto take_plaintext(std::span<std::byte> buffer) noexcept -> std::size_t;

    class implementation;
    std::unique_ptr<implementation> implementation_;
    bool async_tls_mode_ {false};
    bool exclusive_operation_active_ {false};
    bool read_operation_active_ {false};
    bool write_operation_active_ {false};
    bool flush_active_ {false};
    flush_waiter* flush_waiter_ {nullptr};
    bool closing_ {false};
};

template<>
struct std::is_error_code_enum<tls_errc> : true_type {};
