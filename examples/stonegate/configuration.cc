#include "configuration.h"

#include "eventloop/ip_endpoint.h"
#include "eventloop/util/toml.h"

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <set>
#include <span>
#include <stdexcept>
#include <string_view>

namespace stonegate {
namespace {

auto usage() -> void
{
    std::cout <<
        "Stonegate: bounded static HTTP server\n"
        "usage: stonegate --root DIR [options] | --config FILE [options]\n"
        "  --config FILE           load TOML settings before CLI options\n"
        "  --server NAME           select server for CLI overrides\n"
        "  --check                 validate config and credentials, then exit\n"
        "  --bind ADDRESS          numeric IPv4/IPv6 bind address (default 127.0.0.1)\n"
        "  --http-port PORT        plain HTTP port (default 8080)\n"
        "  --http-mode MODE        serve, redirect, or off (default serve)\n"
        "  --https-port PORT       TLS port (default 8443; 0 disables)\n"
        "  --http3-port PORT       UDP HTTP/3 port (0 disables; default off)\n"
        "  --http3-connections N  concurrent HTTP/3 connections (1..256; default 8)\n"
        "  --http3-requests N     concurrent HTTP/3 requests (0..8192; 0 selects 4 per connection)\n"
        "  --http3-max-datagram N max application UDP payload 1200..8192 (default 1472)\n"
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
        "  --open-file-cache-capacity N  cached file descriptors (0..65536)\n"
        "  --header-timeout-ms N    first head/TLS timeout (0..3600000)\n"
        "  --idle-timeout-ms N      next head timeout (0..3600000)\n"
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

auto on_off(std::string_view value, std::string_view name) -> bool
{
    if (value == "on") return true;
    if (value == "off") return false;
    throw std::invalid_argument(std::string(name) + " must be on or off");
}

auto apply(server_config& settings, std::string_view key, std::string_view value,
           const std::filesystem::path* config_dir = nullptr) -> void
{
    const auto path_value = [&] {
        if (value.empty()) return std::string {};
        const std::filesystem::path path {value};
        return (config_dir != nullptr && path.is_relative()
            ? (*config_dir / path).lexically_normal() : path).string();
    };
    if (value.empty() && key != "certificate" && key != "private-key" &&
        key != "key-password") throw std::invalid_argument(std::string(key) + " has an empty value");
    if (key == "root") settings.root = path_value();
    else if (key == "bind") settings.bind = value;
    else if (key == "certificate") settings.certificate = path_value();
    else if (key == "private-key") settings.private_key = path_value();
    else if (key == "key-password") settings.key_password = value;
    else if (key == "redirect-host") settings.redirect_host = value;
    else if (key == "http-port") settings.http_port = number<std::uint16_t>(value, key, 1, 65535);
    else if (key == "https-port") settings.https_port = number<std::uint16_t>(value, key, 0, 65535);
    else if (key == "http3-port") settings.http3_port = number<std::uint16_t>(value, key, 0, 65535);
    else if (key == "http3-connections") settings.http3_connections = number<std::size_t>(value, key, 1, 256);
    else if (key == "http3-requests") settings.http3_requests = number<std::size_t>(value, key, 0, 8192);
    else if (key == "http3-max-datagram")
        settings.http3_max_datagram = number<std::size_t>(value, key, 1200, 8192);
    else if (key == "open-file-cache-capacity")
        settings.open_file_cache_capacity = number<std::size_t>(value, key, 0, 65536);
    else if (key == "header-timeout-ms")
        settings.header_timeout_ms = number<int>(value, key, 0, 3600000);
    else if (key == "idle-timeout-ms")
        settings.idle_timeout_ms = number<int>(value, key, 0, 3600000);
    else if (key == "http-mode") {
            if (value == "serve") settings.mode = server_config::http_mode::serve;
            else if (value == "redirect") settings.mode = server_config::http_mode::redirect;
            else if (value == "off") settings.mode = server_config::http_mode::off;
            else throw std::invalid_argument("http-mode must be serve, redirect, or off");
    } else if (key == "http2") settings.http2 = on_off(value, key);
    else if (key == "directory-listing") settings.directory_listing = on_off(value, key);
    else if (key == "reuse-port") settings.reuse_port = on_off(value, key);
    else throw std::invalid_argument("unknown setting");
}

using eventloop::util::toml_type;
using eventloop::util::toml_value;

struct setting {
    std::string_view section, key, cli;
    toml_type type;
};
constexpr setting schema[] {
    {"", "root", "root", toml_type::string},
    {"", "bind", "bind", toml_type::string},
    {"", "directory_listing", "directory-listing", toml_type::boolean},
    {"", "reuse_port", "reuse-port", toml_type::boolean},
    {"", "open_file_cache_capacity", "open-file-cache-capacity", toml_type::integer},
    {"", "header_timeout_ms", "header-timeout-ms", toml_type::integer},
    {"", "idle_timeout_ms", "idle-timeout-ms", toml_type::integer},
    {"http", "mode", "http-mode", toml_type::string},
    {"http", "port", "http-port", toml_type::integer},
    {"http", "redirect_host", "redirect-host", toml_type::string},
    {"tls", "port", "https-port", toml_type::integer},
    {"tls", "certificate", "certificate", toml_type::string},
    {"tls", "private_key", "private-key", toml_type::string},
    {"tls", "key_password", "key-password", toml_type::string},
    {"tls", "http2", "http2", toml_type::boolean},
    {"http3", "port", "http3-port", toml_type::integer},
    {"http3", "connections", "http3-connections", toml_type::integer},
    {"http3", "requests", "http3-requests", toml_type::integer},
    {"http3", "max_datagram", "http3-max-datagram", toml_type::integer},
};

auto require_type(const toml_value& value, toml_type type,
                  std::string_view location = {}) -> void
{
    if (value.type != type)
        throw std::invalid_argument((location.empty() ? std::string {} :
            std::string(location) + ": ") + "wrong TOML type");
}

auto text(const toml_value& value) -> std::string_view
{
    require_type(value, toml_type::string);
    if (value.string.find('\0') != std::string_view::npos)
        throw std::invalid_argument("string contains NUL");
    return value.string;
}

auto read_server(server_config& settings, const toml_value& table,
                 const std::filesystem::path& directory,
                 const std::string& prefix, std::string_view section = {}) -> void
{
    require_type(table, toml_type::table, prefix);
    for (const auto& value : table) {
        const auto location = prefix + "." + std::string(value.key);
        if (section.empty() && (value.key == "http" || value.key == "tls" ||
                                value.key == "http3")) {
            read_server(settings, value, directory, location, value.key);
            continue;
        }
        try {
            if (section.empty() && value.key == "name" && prefix.starts_with("server[")) {
                settings.name = text(value);
                if (settings.name.empty() || settings.name.size() > 64 ||
                    settings.name.find_first_not_of(
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != std::string::npos)
                    throw std::invalid_argument("invalid server name");
                continue;
            }
            const auto entry = std::find_if(std::begin(schema), std::end(schema),
                [&](const auto& item) { return item.section == section && item.key == value.key; });
            if (entry == std::end(schema)) throw std::invalid_argument("unknown setting");
            require_type(value, entry->type);
            if (value.type == toml_type::string) apply(settings, entry->cli, text(value), &directory);
            else if (value.type == toml_type::boolean)
                apply(settings, entry->cli, value.boolean ? "on" : "off");
            else apply(settings, entry->cli, std::to_string(value.integer));
        } catch (const std::invalid_argument& error) {
            throw std::invalid_argument(location + ": " + error.what());
        }
    }
}

auto toml_error_name(eventloop::util::toml_error_code code) -> std::string_view
{
    using enum eventloop::util::toml_error_code;
    switch (code) {
    case invalid_syntax: return "invalid syntax";
    case invalid_utf8: return "invalid UTF-8";
    case invalid_string: return "invalid string";
    case invalid_number: return "invalid number";
    case invalid_datetime: return "invalid date/time";
    case duplicate_key: return "duplicate key";
    case conflicting_table: return "conflicting table";
    case node_capacity: return "TOML node capacity exhausted (2048)";
    case string_capacity: return "TOML string capacity exhausted (64 KiB)";
    case nesting_limit: return "TOML nesting limit exceeded";
    }
    return "invalid TOML";
}

class config_loader {
public:
    explicit config_loader(configuration& output) : output_(output) {}
    auto load(const std::filesystem::path& path, std::size_t depth = 1) -> void
    {
        try { load_file(path, depth); }
        catch (const std::exception& error) {
            throw std::invalid_argument(path.string() + ": " + error.what());
        }
    }
    server_config defaults;
private:
    configuration& output_;
    std::set<std::filesystem::path> seen_;
    std::size_t total_bytes_ = 0;

    auto load_file(const std::filesystem::path& path, std::size_t depth) -> void
    {
        if (depth > 8) throw std::invalid_argument("include depth exceeds 8");
        if (seen_.size() == 32) throw std::invalid_argument("config file capacity exhausted (32)");
        std::error_code error;
        const auto canonical = std::filesystem::canonical(path, error);
        if (error) throw std::invalid_argument("cannot open config file");
        if (!seen_.insert(canonical).second)
            throw std::invalid_argument("repeated or cyclic include");
        std::ifstream file(path, std::ios::binary);
        if (!file) throw std::invalid_argument("cannot open config file");
        constexpr std::size_t max_bytes = 64 * 1024;
        std::string input(max_bytes + 1, '\0');
        file.read(input.data(), static_cast<std::streamsize>(input.size()));
        if (file.bad()) throw std::invalid_argument("error reading config file");
        input.resize(static_cast<std::size_t>(file.gcount()));
        if (input.size() > max_bytes) throw std::invalid_argument("config file exceeds 64 KiB");
        total_bytes_ += input.size();
        if (total_bytes_ > 1024 * 1024) throw std::invalid_argument("combined config exceeds 1 MiB");
        // Heap-backed setup buffers avoid large per-include stack frames.
        auto nodes = std::make_unique<toml_value[]>(2048);
        auto strings = std::make_unique<char[]>(max_bytes);
        const auto document = eventloop::util::parse_toml(input,
            std::span(nodes.get(), 2048), std::span(strings.get(), max_bytes));
        if (!document) {
            const auto offset = std::min(document.error().offset, input.size());
            const auto before = std::string_view(input).substr(0, offset);
            const auto line = 1 + std::count(before.begin(), before.end(), '\n');
            const auto newline = before.rfind('\n');
            const auto column = newline == std::string_view::npos ? offset + 1 : offset - newline;
            throw std::invalid_argument("line " + std::to_string(line) + ", column " +
                std::to_string(column) + ": " + std::string(toml_error_name(document.error().code)));
        }
        const auto& root = document->root();
        for (const auto& value : root) {
            if (value.key != "include" && value.key != "server" &&
                !(depth == 1 && (value.key == "defaults" || value.key == "runtime")))
                throw std::invalid_argument("unknown top-level setting or setting forbidden in include");
        }
        const auto directory = path.parent_path();
        if (const auto* table = root.find("defaults"))
            read_server(defaults, *table, directory, "defaults");
        if (const auto* table = root.find("runtime")) {
            require_type(*table, toml_type::table, "runtime");
            for (const auto& value : *table) {
                if (value.key != "shutdown_seconds") throw std::invalid_argument("runtime: unknown setting");
                require_type(value, toml_type::integer, "runtime.shutdown_seconds");
                output_.shutdown_seconds = number<int>(std::to_string(value.integer),
                    "runtime.shutdown_seconds", 0, 3600);
            }
        }
        if (const auto* includes = root.find("include")) {
            require_type(*includes, toml_type::array, "include");
            for (const auto& entry : *includes) {
                require_type(entry, toml_type::string, "include[]");
                const auto name = text(entry);
                if (name.empty()) throw std::invalid_argument("empty include path");
                const std::filesystem::path included {name};
                load(included.is_absolute() ? included : directory / included, depth + 1);
            }
        }
        if (const auto* servers = root.find("server")) {
            require_type(*servers, toml_type::array, "server");
            for (const auto& table : *servers) {
                if (output_.servers.size() == max_servers)
                    throw std::invalid_argument("server capacity exhausted (16)");
                auto settings = defaults;
                read_server(settings, table, directory,
                    "server[" + std::to_string(output_.servers.size() + 1) + "]");
                output_.servers.push_back(std::move(settings));
            }
        }
    }
};

auto validate(const server_config& settings) -> void
{
    std::error_code root_error;
    if (settings.root.empty() || !std::filesystem::is_directory(settings.root, root_error))
        throw std::invalid_argument("root must name an existing directory");
    const bool tls = !settings.certificate.empty() && !settings.private_key.empty();
    if (settings.certificate.empty() != settings.private_key.empty())
        throw std::invalid_argument("certificate and private-key must be supplied together");
    if (!settings.key_password.empty() && !tls)
        throw std::invalid_argument("key-password requires TLS credentials");
    if (settings.http3_port != 0 && !tls)
        throw std::invalid_argument("http3-port requires certificate and private-key");
    if (settings.http3_port != 0 && !settings.key_password.empty())
        throw std::invalid_argument("HTTP/3 does not accept key-password; use an unencrypted key");
    if (settings.mode == server_config::http_mode::redirect && (!tls || settings.https_port == 0))
        throw std::invalid_argument("TLS credentials and a TLS port are required for redirect");
    if (settings.mode == server_config::http_mode::off &&
        !(tls && (settings.https_port != 0 || settings.http3_port != 0)))
        throw std::invalid_argument("HTTP-off requires a TLS or HTTP/3 listener");
    if (settings.redirect_host.empty() ||
        std::any_of(settings.redirect_host.begin(), settings.redirect_host.end(),
            [](unsigned char byte) { return byte <= 32 || byte == 127; }) ||
        settings.redirect_host.find_first_of("/\\@?#") != std::string::npos)
        throw std::invalid_argument("redirect-host must be a hostname without whitespace or URL syntax");
    (void)eventloop::ip_endpoint::parse(settings.bind, 0);
}

auto validate_endpoints(const std::vector<server_config>& servers) -> void
{
    struct listener { eventloop::ip_endpoint address; bool udp; };
    std::vector<listener> listeners;
    const auto add = [&](const server_config& server, std::uint16_t port, bool udp) {
        const auto address = eventloop::ip_endpoint::parse(server.bind, port);
        const auto wildcard = [](const auto& endpoint) {
            return std::all_of(endpoint.address.begin(), endpoint.address.end(),
                [](auto byte) { return byte == 0; });
        };
        for (const auto& other : listeners) {
            if (other.udp == udp && other.address.port == port &&
                other.address.address_family == address.address_family &&
                (wildcard(address) || wildcard(other.address) ||
                 (other.address.address == address.address && other.address.scope_id == address.scope_id)))
                throw std::invalid_argument("overlapping listening endpoints");
        }
        listeners.push_back({address, udp});
    };
    for (const auto& server : servers) {
        if (server.mode != server_config::http_mode::off) add(server, server.http_port, false);
        if (!server.certificate.empty() && server.https_port != 0) add(server, server.https_port, false);
        if (server.http3_port != 0) add(server, server.http3_port, true);
    }
}

} // namespace

auto parse_configuration(int argc, char** argv) -> configuration
{
    struct option { std::string_view key, value; };
    std::vector<option> overrides;
    std::string_view config_path, selected_server;
    configuration output;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument = argv[index];
        if (argument == "--help") { usage(); std::exit(0); }
        if (argument == "--check") { output.check = true; continue; }
        if (argument == "--directory-listing" || argument == "--no-directory-listing") {
            overrides.push_back({"directory-listing", argument == "--directory-listing" ? "on" : "off"});
            continue;
        }
        if (argument == "--reuse-port" || argument == "--no-reuse-port") {
            overrides.push_back({"reuse-port", argument == "--reuse-port" ? "on" : "off"});
            continue;
        }
        if (!argument.starts_with("--")) throw std::invalid_argument("unknown option");
        const auto key = argument.substr(2);
        if (key != "config" && key != "server" && key != "shutdown-seconds" &&
            std::none_of(std::begin(schema), std::end(schema), [&](const auto& entry) { return entry.cli == key; }))
            throw std::invalid_argument("unknown option");
        if (index + 1 >= argc || std::string_view(argv[index + 1]).starts_with("--"))
            throw std::invalid_argument("missing value for " + std::string(argument));
        const std::string_view value = argv[++index];
        if (key == "config" || key == "server") {
            auto& destination = key == "config" ? config_path : selected_server;
            if (!destination.empty()) throw std::invalid_argument("duplicate " + std::string(argument));
            if (value.empty()) throw std::invalid_argument("empty value for " + std::string(argument));
            destination = value;
        } else overrides.push_back({key, value});
    }
    if (!config_path.empty()) {
        config_loader loader(output);
        loader.load(std::filesystem::path(config_path));
        if (output.servers.empty()) output.servers.push_back(std::move(loader.defaults));
    } else output.servers.emplace_back();
    std::set<std::string> names;
    for (std::size_t index = 0; index < output.servers.size(); ++index) {
        auto& name = output.servers[index].name;
        if (name.empty()) name = "server-" + std::to_string(index + 1);
        if (!names.insert(name).second) throw std::invalid_argument("duplicate server name");
    }
    auto* target = &output.servers.front();
    if (!selected_server.empty()) {
        const auto selected = std::find_if(output.servers.begin(), output.servers.end(),
            [&](const auto& server) { return server.name == selected_server; });
        if (selected == output.servers.end()) throw std::invalid_argument("unknown --server name");
        target = &*selected;
    }
    for (const auto& entry : overrides) {
        if (entry.key == "shutdown-seconds") {
            output.shutdown_seconds = number<int>(entry.value, entry.key, 0, 3600);
            continue;
        }
        if (output.servers.size() > 1 && selected_server.empty())
            throw std::invalid_argument("server CLI overrides require --server NAME with multiple servers");
        apply(*target, entry.key, entry.value);
    }
    for (const auto& server : output.servers) {
        try { validate(server); }
        catch (const std::exception& error) {
            throw std::invalid_argument("server " + server.name + ": " + error.what());
        }
    }
    validate_endpoints(output.servers);
    return output;
}

} // namespace stonegate
