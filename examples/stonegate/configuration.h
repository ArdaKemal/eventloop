#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace stonegate {

inline constexpr std::size_t max_servers = 16;

struct server_config {
    std::string name;
    std::string root;
    std::string bind = "127.0.0.1";
    std::string certificate;
    std::string private_key;
    std::string key_password;
    std::string redirect_host = "localhost";
    std::uint16_t http_port = 8080;
    std::uint16_t https_port = 8443;
    std::uint16_t http3_port = 0;
    std::size_t http3_connections = 8;
    std::size_t http3_requests = 0;
    std::size_t http3_max_datagram = 1472;
    std::size_t open_file_cache_capacity = 0;
    int header_timeout_ms = 30000;
    int idle_timeout_ms = 60000;
    bool directory_listing = false;
    bool reuse_port = false;
    bool http2 = true;
    enum class http_mode { serve, redirect, off } mode = http_mode::serve;
};

struct configuration {
    std::vector<server_config> servers;
    int shutdown_seconds = 5;
    bool check = false;
};

// Owns all strings; no TOML views survive loading.
auto parse_configuration(int argc, char** argv) -> configuration;

} // namespace stonegate
