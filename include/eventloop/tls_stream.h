#pragma once

#include "eventloop/tcp_stream.h"
#include "eventloop/task.h"
#include "eventloop/tls_context.h"

#include <expected>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

namespace eventloop {

namespace http2::detail { class client_access; }

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
    // Takes ownership of the accepted descriptor, including on failure.
    tls_stream(event_loop& loop, unique_fd descriptor,
               std::shared_ptr<tls_context> context,
               tls_client_options options);
    // Connect with async_connect() before async_handshake(). The hostname is
    // used for certificate verification and SNI.
    tls_stream(event_loop& loop, ip_endpoint endpoint,
               std::shared_ptr<tls_context> context,
               tls_client_options options);
    tls_stream(event_loop& loop, unique_fd descriptor,
               std::shared_ptr<tls_context> context,
               tls_server_options options = {});
    ~tls_stream() override;

    auto close() -> void override;
    [[nodiscard]] auto application_protocol() const -> std::string;

    // One read and one write may be pending together. A second operation in
    // either direction returns EBUSY. Handshake and close require an idle stream.
    // Cancellation or close of a pending operation returns ECANCELED. TLS tasks
    // drive the encrypted transport and require coroutine frames.
    [[nodiscard]] auto async_handshake()
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] auto async_read_some(std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Writes the buffers in order, as for tcp_stream; the array and the
    // buffers stay caller-owned until completion. One call writes at most
    // three full records (48 KiB) and makes one transport push for them.
    [[nodiscard]] auto async_write_some(
        std::span<const std::span<const std::byte>> buffers)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Available after handshake when OpenSSL enabled Linux transmit kTLS.
    // The file remains owned through completion or cancellation.
    [[nodiscard]] auto kernel_sendfile_available() const noexcept -> bool;
    [[nodiscard]] auto async_send_file(unique_fd file, std::uint64_t offset,
                                       std::size_t size)
        -> task<std::expected<void, std::error_code>>;
    // Borrows a descriptor; the caller must keep it open until completion,
    // including after cancellation is requested. Otherwise identical to the
    // ownership-taking overload, without duplicating or closing the file.
    // An optional prefix is sent before the file range in the same write
    // operation; its storage must remain valid and unchanged until completion.
    [[nodiscard]] auto async_send_file(native_socket file, std::uint64_t offset,
                                       std::size_t size,
                                       std::span<const std::byte> prefix = {})
        -> task<std::expected<void, std::error_code>>;
    // Flushes close_notify. Close the transport after this task completes.
    [[nodiscard]] auto async_close()
        -> task<std::expected<void, std::error_code>>;

private:
    friend class http2::detail::client_access;
    // Applies handshake hostname checks to the verified peer certificate.
    [[nodiscard]] auto certificate_matches(std::string_view hostname) const -> bool;
    // Raw sendfile would put unencrypted bytes on the TLS transport.
    using tcp_stream::async_send_file;
    class flush_waiter;
    auto release_flush() noexcept -> void;
    [[nodiscard]] static auto handshake_task(event_loop& loop, tls_stream& self)
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] static auto read_task(event_loop& loop, tls_stream& self,
                                        std::span<std::byte> buffer)
        -> task<std::expected<std::size_t, std::error_code>>;
    // Writes buffer when buffers is empty.
    [[nodiscard]] static auto write_task(event_loop& loop, tls_stream& self,
        std::span<const std::byte> buffer,
        std::span<const std::span<const std::byte>> buffers)
        -> task<std::expected<std::size_t, std::error_code>>;
    [[nodiscard]] static auto flush_task(event_loop& loop, tls_stream& self)
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] static auto close_task(event_loop& loop, tls_stream& self)
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] static auto send_file_task(event_loop& loop, tls_stream& self,
        unique_fd owned_file, native_socket file, std::uint64_t offset, std::size_t size,
        std::span<const std::byte> prefix)
        -> task<std::expected<void, std::error_code>>;
    [[nodiscard]] auto activate_async_tls() noexcept
        -> std::expected<void, std::error_code>;
    [[nodiscard]] auto receive_encrypted(std::span<const std::byte> data) noexcept
        -> std::error_code;

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

} // namespace eventloop

namespace std {
template<>
struct is_error_code_enum<eventloop::tls_errc> : true_type {};
}
