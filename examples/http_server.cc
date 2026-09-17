#include "eventloop/event_loop.h"
#include "eventloop/http/server.h"
#include "eventloop/tls_context.h"
#include "eventloop/util/arg_parser.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
[[nodiscard]] auto valid_port(int port) -> std::uint16_t
{
    if (port <= 0 || port > 65535) {
        throw std::invalid_argument("port must be between 1 and 65535");
    }
    return static_cast<std::uint16_t>(port);
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
        bool directory_listing = false;

        std::array options {
            arg_parser::option {'r', "root", &root, true},
            arg_parser::option {'c', "certificate", &certificate, true},
            arg_parser::option {'k', "private-key", &private_key, true},
            arg_parser::option {'w', "key-password", &key_password, false},
            arg_parser::option {'a', "address", &address, false},
            arg_parser::option {'n', "hostname", &hostname, false},
            arg_parser::option {'p', "http-port", &http_port_value, false},
            arg_parser::option {'s', "https-port", &https_port_value, false},
            arg_parser::option {'d', "directory-listing", &directory_listing, false},
        };
        arg_parser arguments(options.data(), options.size());
        arguments.set_usage(
            "usage: http_server --root <directory> --certificate <chain.pem> "
            "--private-key <key.pem> [options]\n"
            "  -r, --root <directory>       document root (required)\n"
            "  -c, --certificate <file>     TLS certificate chain (required)\n"
            "  -k, --private-key <file>     TLS private key (required)\n"
            "  -w, --key-password <value>   private-key password\n"
            "  -a, --address <address>      listen address (default 127.0.0.1)\n"
            "  -n, --hostname <name>        HTTPS redirect host (default localhost)\n"
            "  -p, --http-port <port>       redirect listener (default 8080)\n"
            "  -s, --https-port <port>      HTTPS listener (default 8443)\n"
            "  -d, --directory-listing      enable directory listings\n"
            "  -h, --help                   show this help\n");
        arguments.parse(argc, argv);

        const auto http_port = valid_port(http_port_value);
        const auto https_port = valid_port(https_port_value);
        auto context = tls_context::make_server(
            certificate, private_key, key_password);
        event_loop loop;
        loop.add(std::make_unique<http::redirect_server>(
            loop, http_port, hostname, https_port, address));
        loop.add(std::make_unique<http::https_server>(
            loop, https_port, std::move(context), root, address,
            http::server_options {.directory_listing = directory_listing}));
        std::cout << "HTTP redirect listening on http://" << address << ':'
                  << http_port << '\n'
                  << "HTTPS server listening on https://" << address << ':'
                  << https_port << '\n';
        loop.run();
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
