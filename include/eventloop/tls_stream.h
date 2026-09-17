#pragma once

#include "eventloop/tcp_stream.h"
#include "eventloop/tls_context.h"

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
    tls_stream(event_loop& loop, int descriptor, std::shared_ptr<tls_context> context,
               tls_server_options options = {});
    ~tls_stream() override;

    auto write(std::span<const std::byte> data) -> void override;
    auto close() -> void override;
    [[nodiscard]] auto ready() const noexcept -> bool override;
    [[nodiscard]] auto application_protocol() const -> std::string;

protected:
    auto on_transport_data(std::span<const std::byte> data) -> void override;
    auto on_transport_close() -> void override;
    auto on_transport_error(std::error_code error) -> void override;

private:
    class implementation;
    std::unique_ptr<implementation> implementation_;
    bool closing_ {false};
    bool close_emitted_ {false};
};

template<>
struct std::is_error_code_enum<tls_errc> : true_type {};
