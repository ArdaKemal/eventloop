#include "eventloop/event_loop.h"
#include "eventloop/http/http3_server.h"
#include "eventloop/http/server.h"
#include "eventloop/tls_context.h"

#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {

struct config {
    std::string root;
    std::string bind = "127.0.0.1";
    std::string certificate;
    std::string private_key;
    std::string key_password;
    std::string redirect_host = "localhost";
    std::uint16_t http_port = 8080;
    std::uint16_t https_port = 8443;
    std::uint16_t http3_port = 0;
    int shutdown_seconds = 5;
    bool directory_listing = false;
    bool reuse_port = false;
    bool http2 = true;
    enum class http_mode { serve, redirect, off } mode = http_mode::serve;
};

auto usage() -> void
{
    std::cout <<
        "Stonegate: bounded static HTTP server\n"
        "usage: stonegate --root DIR [options] | --config FILE [options]\n"
        "  --config FILE           load key=value settings before CLI options\n"
        "  --bind ADDRESS          numeric IPv4/IPv6 bind address (default 127.0.0.1)\n"
        "  --http-port PORT        plain HTTP port (default 8080)\n"
        "  --http-mode MODE        serve, redirect, or off (default serve)\n"
        "  --https-port PORT       TLS port (default 8443)\n"
        "  --http3-port PORT       enable UDP HTTP/3 on this port (default off)\n"
        "  --certificate FILE      PEM certificate chain\n"
        "  --private-key FILE      PEM private key\n"
        "  --key-password TEXT     password for encrypted private key\n"
        "  --redirect-host HOST    host in HTTP to HTTPS redirect (default localhost)\n"
        "  --http2 on|off         TLS HTTP/2 ALPN (default on)\n"
        "  --directory-listing     list directories without index files\n"
        "  --no-directory-listing  disable directory listing\n"
        "  --reuse-port            allow multiple listeners to reuse a port\n"
        "  --no-reuse-port         disable port reuse\n"
        "  --shutdown-seconds N    shutdown deadline (default 5)\n"
        "  --help                  show this message\n";
}

template<typename T>
auto number(std::string_view text, std::string_view name, T minimum, T maximum) -> T
{
    T result {};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result);
    if (error != std::errc {} || end != text.data() + text.size() ||
        result < minimum || result > maximum) {
        throw std::invalid_argument(std::string(name) + " has an invalid value");
    }
    return result;
}

auto trim(std::string_view text) -> std::string_view
{
    const auto first = text.find_first_not_of(" \t");
    if (first == std::string_view::npos) return {};
    return text.substr(first, text.find_last_not_of(" \t") - first + 1);
}

auto on_off(std::string_view value, std::string_view name) -> bool
{
    if (value == "on") return true;
    if (value == "off") return false;
    throw std::invalid_argument(std::string(name) + " must be on or off");
}

auto apply(config& settings, std::string_view key, std::string_view value,
           const std::filesystem::path* config_dir = nullptr) -> void
{
    const auto path_value = [&] {
        const std::filesystem::path path {value};
        return (config_dir != nullptr && path.is_relative()
            ? (*config_dir / path).lexically_normal() : path).string();
    };
    if (value.empty()) throw std::invalid_argument(std::string(key) + " has an empty value");
    if (key == "root") settings.root = path_value();
    else if (key == "bind") settings.bind = value;
    else if (key == "certificate") settings.certificate = path_value();
    else if (key == "private-key") settings.private_key = path_value();
    else if (key == "key-password") settings.key_password = value;
    else if (key == "redirect-host") settings.redirect_host = value;
    else if (key == "http-port") settings.http_port = number<int>(value, key, 1, 65535);
    else if (key == "https-port") settings.https_port = number<int>(value, key, 1, 65535);
    else if (key == "http3-port") settings.http3_port = number<int>(value, key, 1, 65535);
    else if (key == "shutdown-seconds")
        settings.shutdown_seconds = number<int>(value, key, 0, 3600);
    else if (key == "http-mode") {
            if (value == "serve") settings.mode = config::http_mode::serve;
            else if (value == "redirect") settings.mode = config::http_mode::redirect;
            else if (value == "off") settings.mode = config::http_mode::off;
            else throw std::invalid_argument("http-mode must be serve, redirect, or off");
    } else if (key == "http2") settings.http2 = on_off(value, key);
    else if (key == "directory-listing") settings.directory_listing = on_off(value, key);
    else if (key == "reuse-port") settings.reuse_port = on_off(value, key);
    else throw std::invalid_argument("unknown setting");
}

auto load_config(config& settings, const std::filesystem::path& path) -> void
{
    std::ifstream file(path);
    if (!file) throw std::invalid_argument("cannot open config file");
    const auto directory = path.parent_path();
    std::set<std::string> keys;
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(file, line)) {
        ++line_number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto content = trim(line);
        if (content.empty() || content.front() == '#') continue;
        const auto equal = content.find('=');
        if (equal == std::string_view::npos)
            throw std::invalid_argument("config line " + std::to_string(line_number) + " needs key=value");
        const auto key = trim(content.substr(0, equal));
        const auto value = trim(content.substr(equal + 1));
        if (key.empty() || key.find_first_of(" \t") != std::string_view::npos)
            throw std::invalid_argument("invalid key on config line " + std::to_string(line_number));
        if (!keys.insert(std::string(key)).second)
            throw std::invalid_argument("duplicate config key on line " + std::to_string(line_number));
        try {
            apply(settings, key, value, &directory);
        } catch (const std::invalid_argument& error) {
            throw std::invalid_argument("config line " + std::to_string(line_number) + ": " + error.what());
        }
    }
    if (file.bad()) throw std::invalid_argument("error reading config file");
}

auto parse(int argc, char** argv) -> config
{
    config settings;
    std::string_view config_path;
    for (int index = 1; index < argc; ++index) {
        const std::string_view option = argv[index];
        if (option == "--help") { usage(); std::exit(0); }
        if (option == "--config") {
            if (!config_path.empty()) throw std::invalid_argument("duplicate --config");
            if (index + 1 >= argc || std::string_view(argv[index + 1]).starts_with("--"))
                throw std::invalid_argument("missing value for --config");
            config_path = argv[++index];
            if (config_path.empty()) throw std::invalid_argument("empty value for --config");
        } else if (option == "--directory-listing" || option == "--no-directory-listing" ||
                   option == "--reuse-port" || option == "--no-reuse-port") {
            continue;
        } else if (option == "--root" || option == "--bind" || option == "--certificate" ||
                   option == "--private-key" || option == "--key-password" ||
                   option == "--redirect-host" || option == "--http-port" ||
                   option == "--https-port" || option == "--http3-port" ||
                   option == "--shutdown-seconds" || option == "--http-mode" ||
                   option == "--http2") {
            if (index + 1 >= argc || std::string_view(argv[index + 1]).starts_with("--"))
                throw std::invalid_argument("missing value for " + std::string(option));
            ++index;
        } else {
            throw std::invalid_argument("unknown option: " + std::string(option));
        }
    }
    if (!config_path.empty()) load_config(settings, std::filesystem::path(config_path));
    for (int index = 1; index < argc; ++index) {
        const std::string_view option = argv[index];
        if (option == "--help") { usage(); std::exit(0); }
        if (option == "--config") { ++index; continue; }
        if (option == "--directory-listing") { settings.directory_listing = true; continue; }
        if (option == "--no-directory-listing") { settings.directory_listing = false; continue; }
        if (option == "--reuse-port") { settings.reuse_port = true; continue; }
        if (option == "--no-reuse-port") { settings.reuse_port = false; continue; }
        if (option != "--root" && option != "--bind" && option != "--certificate" &&
            option != "--private-key" && option != "--key-password" &&
            option != "--redirect-host" && option != "--http-port" &&
            option != "--https-port" && option != "--http3-port" &&
            option != "--shutdown-seconds" && option != "--http-mode" && option != "--http2")
            throw std::invalid_argument("unknown option: " + std::string(option));
        if (index + 1 >= argc || std::string_view(argv[index + 1]).starts_with("--"))
            throw std::invalid_argument("missing value for " + std::string(option));
        apply(settings, option.substr(2), argv[++index]);
    }

    if (settings.root.empty() || !std::filesystem::is_directory(settings.root))
        throw std::invalid_argument("--root must name an existing directory");
    const bool tls = !settings.certificate.empty() && !settings.private_key.empty();
    if (settings.certificate.empty() != settings.private_key.empty())
        throw std::invalid_argument("--certificate and --private-key must be supplied together");
    if (!settings.key_password.empty() && !tls)
        throw std::invalid_argument("--key-password requires TLS credentials");
    if (settings.http3_port != 0 && !tls)
        throw std::invalid_argument("--http3-port requires --certificate and --private-key");
    if (settings.http3_port != 0 && !settings.key_password.empty())
        throw std::invalid_argument("HTTP/3 does not accept --key-password; use an unencrypted key");
    if (!tls && settings.mode != config::http_mode::serve)
        throw std::invalid_argument("TLS credentials are required for redirect or HTTP-off mode");
    if (tls && settings.mode != config::http_mode::off && settings.http_port == settings.https_port)
        throw std::invalid_argument("HTTP and HTTPS ports must differ");
    if (settings.redirect_host.empty() ||
        settings.redirect_host.find_first_of("\r\n\t /\\@?#") != std::string::npos)
        throw std::invalid_argument("--redirect-host must be a hostname without whitespace or URL syntax");
    return settings;
}

template<typename Listener>
auto serve(eventloop::event_loop& loop, Listener& listener) -> eventloop::task<void>
{
    (void)loop;
    (void)co_await listener.run();
}

template<typename Listener, typename... Args>
auto start(eventloop::event_loop& loop, Args&&... args) -> void
{
    auto listener = std::make_unique<Listener>(loop, std::forward<Args>(args)...);
    auto* active = listener.get();
    loop.add(std::move(listener));
    if (loop.spawn(serve(loop, *active)) != eventloop::task_spawn_result::accepted) {
        active->close();
        throw std::runtime_error("listener task capacity exhausted");
    }
}

auto close_http3_and_stop(eventloop::event_loop& loop,
                          eventloop::http::http3_server& server)
    -> eventloop::task<void>
{
    (void)co_await server.async_close();
    loop.stop();
}

auto run(eventloop::event_loop& loop, int shutdown_seconds,
         eventloop::http::http3_server* http3,
         eventloop::task_handle<void>& http3_run) -> void
{
    if (loop.run() == eventloop::event_loop_result::stopped) {
        loop.shutdown(eventloop::event_loop::clock::duration::zero());
        (void)loop.run();
        return;
    }
    if (http3 != nullptr) {
        http3->close();
        eventloop::task_handle<void> closing;
        if (loop.spawn(close_http3_and_stop(loop, *http3), closing) ==
            eventloop::task_spawn_result::accepted) {
            while (!closing.done()) (void)loop.run();
        } else {
            // A full coroutine pool still has a safe shutdown path: the
            // observed run task owns endpoint retirement after close().
            loop.shutdown(eventloop::event_loop::clock::duration::zero());
            while (loop.run() == eventloop::event_loop_result::interrupted)
                loop.shutdown(eventloop::event_loop::clock::duration::zero());
            while (!http3_run.done()) (void)loop.run();
            return;
        }
    }
    loop.shutdown(std::chrono::seconds {shutdown_seconds});
    while (loop.run() == eventloop::event_loop_result::interrupted)
        loop.shutdown(eventloop::event_loop::clock::duration::zero());
    while (http3 != nullptr && !http3_run.done()) (void)loop.run();
}

} // namespace

auto main(int argc, char** argv) -> int
{
    try {
        const auto settings = parse(argc, argv);
        const eventloop::http::server_options options {
            .directory_listing = settings.directory_listing,
            .reuse_port = settings.reuse_port,
            .enable_http2 = settings.http2,
        };
        eventloop::event_loop loop;
        std::unique_ptr<eventloop::http::http3_server> http3;
        eventloop::task_handle<void> http3_run;
        if (settings.mode == config::http_mode::serve) {
            start<eventloop::http::server>(loop, settings.http_port, settings.root,
                                           settings.bind, options);
            std::cout << "Serving HTTP/1.1 on " << settings.bind << ':' << settings.http_port << '\n';
        }
#if !defined(_WIN32) || defined(EVENTLOOP_WINDOWS_TLS)
        if (!settings.certificate.empty()) {
            auto context = eventloop::tls_context::make_server(
                settings.certificate, settings.private_key, settings.key_password);
            if (settings.mode == config::http_mode::redirect) {
                start<eventloop::http::redirect_server>(loop, settings.http_port,
                    settings.redirect_host, settings.https_port, settings.bind);
                std::cout << "Redirecting HTTP on " << settings.bind << ':' << settings.http_port << '\n';
            }
            start<eventloop::http::https_server>(loop, settings.https_port,
                std::move(context), settings.root, settings.bind, options);
            std::cout << "Serving HTTPS (HTTP/1.1" << (settings.http2 ? ", HTTP/2" : "")
                      << ") on " << settings.bind << ':' << settings.https_port << '\n';
        }
#else
        if (!settings.certificate.empty())
            throw std::runtime_error("this eventloop build has no Windows TLS support");
#endif
        if (settings.http3_port != 0) {
            http3 = std::make_unique<eventloop::http::http3_server>(
                loop, eventloop::ip_endpoint::parse(settings.bind, settings.http3_port),
                settings.root, settings.certificate, settings.private_key);
            if (loop.spawn(http3->run(), http3_run) !=
                eventloop::task_spawn_result::accepted)
                throw std::runtime_error("HTTP/3 listener task capacity exhausted");
            std::cout << "Serving HTTP/3 on UDP " << settings.bind << ':'
                      << settings.http3_port << '\n';
        }
        std::cout.flush();
        run(loop, settings.shutdown_seconds, http3.get(), http3_run);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "stonegate: " << error.what() << '\n';
        return 1;
    }
}
