#include "eventloop/event_loop.h"
#include "eventloop/http/server.h"
#include "eventloop/tls_context.h"
#include "eventloop/util/arg_parser.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace eventloop;

namespace {
template<typename Listener>
[[nodiscard]] auto serve_listener(event_loop& loop, Listener& listener)
    -> task<void>
{
    (void)loop;
    (void)co_await listener.run();
}

template<typename Listener>
auto start_listener(event_loop& loop, std::unique_ptr<Listener> listener) -> void
{
    auto* active = listener.get();
    loop.add(std::move(listener));
    if (loop.spawn(serve_listener(loop, *active)) !=
        task_spawn_result::accepted) {
        active->close();
        throw std::runtime_error("could not start HTTP listener task");
    }
}

[[nodiscard]] auto valid_port(int port) -> std::uint16_t
{
    if (port <= 0 || port > 65535) {
        throw std::invalid_argument("port must be between 1 and 65535");
    }
    return static_cast<std::uint16_t>(port);
}

auto run_server(event_loop& loop, int shutdown_timeout) -> void
{
    if (shutdown_timeout < 0) {
        throw std::invalid_argument("shutdown timeout cannot be negative");
    }
    if (loop.run() == event_loop_result::stopped) {
        loop.shutdown(event_loop::clock::duration::zero());
        (void)loop.run();
        return;
    }

    loop.shutdown(std::chrono::seconds {shutdown_timeout});
    while (loop.run() == event_loop_result::interrupted) {
        loop.shutdown(event_loop::clock::duration::zero());
    }
}

} // namespace

auto main(int argc, char* argv[]) -> int
{
    try {
        std::string root;
        std::string certificate;
        std::string private_key;
        std::string key_password;
        std::string address = "127.0.0.1";
        std::string hostname = "localhost";
        int http_port_value = 8080;
        int https_port_value = 8443;
        int shutdown_timeout = 5;
        bool directory_listing = false;
        bool http_only = false;

        std::array options {
            arg_parser::option {'r', "root", &root, true},
            arg_parser::option {'c', "certificate", &certificate, false},
            arg_parser::option {'k', "private-key", &private_key, false},
            arg_parser::option {'w', "key-password", &key_password, false},
            arg_parser::option {'a', "address", &address, false},
            arg_parser::option {'n', "hostname", &hostname, false},
            arg_parser::option {'p', "http-port", &http_port_value, false},
            arg_parser::option {'s', "https-port", &https_port_value, false},
            arg_parser::option {'d', "directory-listing", &directory_listing, false},
            arg_parser::option {'o', "http-only", &http_only, false},
            arg_parser::option {'t', "shutdown-timeout", &shutdown_timeout, false},
        };
        arg_parser arguments(options.data(), options.size());
        arguments.set_usage(
            "usage: http_server --root <directory> [TLS options] [options]\n"
            "  -r, --root <directory>       document root (required)\n"
            "  -c, --certificate <file>     TLS certificate chain\n"
            "  -k, --private-key <file>     TLS private key\n"
            "  -w, --key-password <value>   private-key password\n"
            "  -a, --address <address>      listen address (default 127.0.0.1)\n"
            "  -n, --hostname <name>        HTTPS redirect host (default localhost)\n"
            "  -p, --http-port <port>       HTTP listener (default 8080)\n"
            "  -s, --https-port <port>      HTTPS listener (default 8443)\n"
            "  -d, --directory-listing      enable directory listings\n"
            "  -o, --http-only              serve HTTP without TLS or redirect\n"
            "  -t, --shutdown-timeout <s>   graceful shutdown deadline (default 5)\n"
            "  -h, --help                   show this help\n");
        arguments.parse(argc, argv);

        const auto http_port = valid_port(http_port_value);
        event_loop loop;

        const auto server_options =
            http::server_options {.directory_listing = directory_listing};
        if (http_only) {
            start_listener(loop, std::make_unique<http::server>(
                loop, http_port, root, address, server_options));
            std::cout << "HTTP server listening on http://" << address << ':'
                      << http_port << '\n';
            run_server(loop, shutdown_timeout);
            return 0;
        }

        if (certificate.empty() || private_key.empty()) {
            throw std::invalid_argument(
                "--certificate and --private-key are required unless "
                "--http-only is used");
        }

        const auto https_port = valid_port(https_port_value);
        auto context = tls_context::make_server(
            certificate, private_key, key_password);
        start_listener(loop, std::make_unique<http::redirect_server>(
            loop, http_port, hostname, https_port, address));
        start_listener(loop, std::make_unique<http::https_server>(
            loop, https_port, std::move(context), root, address, server_options));
        std::cout << "HTTP redirect listening on http://" << address << ':'
                  << http_port << '\n'
                  << "HTTPS server listening on https://" << address << ':'
                  << https_port << '\n';
        run_server(loop, shutdown_timeout);
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
