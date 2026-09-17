#pragma once

#include <filesystem>
#include <memory>
#include <string_view>

class tls_context {
public:
    ~tls_context();

    tls_context(const tls_context&) = delete;
    auto operator=(const tls_context&) -> tls_context& = delete;

    [[nodiscard]] static auto make_system_client() -> std::shared_ptr<tls_context>;
    [[nodiscard]] static auto make_client(const std::filesystem::path& trusted_ca)
        -> std::shared_ptr<tls_context>;
    [[nodiscard]] static auto make_server(
        const std::filesystem::path& certificate_chain,
        const std::filesystem::path& private_key,
        std::string_view password = {}) -> std::shared_ptr<tls_context>;

private:
    class implementation;
    explicit tls_context(std::unique_ptr<implementation> implementation);

    std::unique_ptr<implementation> implementation_;

    friend class tls_stream;
};
