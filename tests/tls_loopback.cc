#include "eventloop/event_loop.h"
#include "eventloop/tls_context.h"
#include "eventloop/tls_stream.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <filesystem>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
constexpr std::string_view message = "Botan TLS loopback";

[[nodiscard]] auto system_error(const char* operation) -> std::system_error
{
    return {errno, std::system_category(), operation};
}

auto make_nonblocking(int descriptor) -> void
{
    const int flags = fcntl(descriptor, F_GETFL);
    if (flags == -1 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == -1) {
        throw system_error("fcntl");
    }
}

struct connected_pair {
    int client;
    int server;
};

[[nodiscard]] auto connect_loopback() -> connected_pair
{
    const int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener == -1) {
        throw system_error("socket");
    }

    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    try {
        if (bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == -1 ||
            listen(listener, 1) == -1) {
            throw system_error("bind/listen");
        }

        socklen_t address_size = sizeof(address);
        if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_size) == -1) {
            throw system_error("getsockname");
        }

        const int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (client == -1) {
            throw system_error("socket");
        }
        if (connect(client, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == -1) {
            const auto error = system_error("connect");
            ::close(client);
            throw error;
        }

        const int server = accept4(listener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (server == -1) {
            const auto error = system_error("accept4");
            ::close(client);
            throw error;
        }
        make_nonblocking(client);
        ::close(listener);
        return {.client = client, .server = server};
    } catch (...) {
        ::close(listener);
        throw;
    }
}

class echo_server_stream final : public tls_stream {
public:
    echo_server_stream(event_loop& loop, int descriptor,
                       std::shared_ptr<tls_context> context, bool& clean_close)
        : tls_stream(loop, descriptor, std::move(context),
                     tls_server_options {.application_protocols = {"echo"}}),
          loop_(loop), clean_close_(clean_close)
    {
    }

private:
    auto on_data(std::span<const std::byte> data) -> void override { write(data); }

    auto on_close() -> void override
    {
        clean_close_ = true;
        loop_.stop();
    }

    auto on_error(std::error_code error) -> void override
    {
        std::cerr << "TLS server error: " << error.message() << '\n';
        loop_.stop();
    }

    event_loop& loop_;
    bool& clean_close_;
};

class client_stream final : public tls_stream {
public:
    client_stream(event_loop& loop, int descriptor,
                  std::shared_ptr<tls_context> context, bool& passed)
        : tls_stream(loop, descriptor, std::move(context),
                     tls_client_options {
                         .hostname = "localhost",
                         .application_protocols = {"echo"},
                     }),
          loop_(loop), passed_(passed)
    {
    }

private:
    auto on_ready() -> void override
    {
        if (application_protocol() != "echo") {
            loop_.stop();
            return;
        }
        write(std::as_bytes(std::span {message}));
    }

    auto on_data(std::span<const std::byte> data) -> void override
    {
        received_.append(reinterpret_cast<const char*>(data.data()), data.size());
        if (received_.size() >= message.size()) {
            passed_ = received_ == message;
            close();
        }
    }

    auto on_error(std::error_code error) -> void override
    {
        std::cerr << "TLS client error: " << error.message() << '\n';
        loop_.stop();
    }

    event_loop& loop_;
    bool& passed_;
    std::string received_;
};

class passive_server_stream final : public tls_stream {
public:
    using tls_stream::tls_stream;

private:
    auto on_data(std::span<const std::byte>) -> void override {}
};

class rejecting_client_stream final : public tls_stream {
public:
    rejecting_client_stream(event_loop& loop, int descriptor,
                            std::shared_ptr<tls_context> context, bool& rejected)
        : tls_stream(loop, descriptor, std::move(context),
                     tls_client_options {
                         .hostname = "wrong.example",
                         .application_protocols = {},
                     }),
          loop_(loop), rejected_(rejected)
    {
    }

private:
    auto on_ready() -> void override { loop_.stop(); }
    auto on_data(std::span<const std::byte>) -> void override {}
    auto on_error(std::error_code) -> void override
    {
        rejected_ = true;
        loop_.stop();
    }

    event_loop& loop_;
    bool& rejected_;
};

class truncation_server_stream final : public tls_stream {
public:
    truncation_server_stream(event_loop& loop, int descriptor,
                             std::shared_ptr<tls_context> context, bool& detected)
        : tls_stream(loop, descriptor, std::move(context)),
          loop_(loop), detected_(detected)
    {
    }

private:
    auto on_data(std::span<const std::byte>) -> void override {}
    auto on_error(std::error_code error) -> void override
    {
        detected_ = error == make_error_code(tls_errc::truncated);
        loop_.stop();
    }

    event_loop& loop_;
    bool& detected_;
};

class truncating_client_stream final : public tls_stream {
public:
    using tls_stream::tls_stream;

private:
    auto on_ready() -> void override { abort(); }
    auto on_data(std::span<const std::byte>) -> void override {}
};

[[nodiscard]] auto test_echo_and_close(const std::filesystem::path& certificate,
                                       const std::filesystem::path& key) -> bool
{
    auto sockets = connect_loopback();
    event_loop loop;
    bool echoed = false;
    bool clean_close = false;
    loop.add(std::make_unique<echo_server_stream>(
        loop, sockets.server, tls_context::make_server(certificate, key), clean_close));
    loop.add(std::make_unique<client_stream>(
        loop, sockets.client, tls_context::make_client(certificate), echoed));
    loop.run();
    return echoed && clean_close;
}

[[nodiscard]] auto test_hostname_rejection(const std::filesystem::path& certificate,
                                           const std::filesystem::path& key) -> bool
{
    auto sockets = connect_loopback();
    event_loop loop;
    bool rejected = false;
    loop.add(std::make_unique<passive_server_stream>(
        loop, sockets.server, tls_context::make_server(certificate, key)));
    loop.add(std::make_unique<rejecting_client_stream>(
        loop, sockets.client, tls_context::make_client(certificate), rejected));
    loop.run();
    return rejected;
}

[[nodiscard]] auto test_truncation(const std::filesystem::path& certificate,
                                   const std::filesystem::path& key) -> bool
{
    auto sockets = connect_loopback();
    event_loop loop;
    bool detected = false;
    loop.add(std::make_unique<truncation_server_stream>(
        loop, sockets.server, tls_context::make_server(certificate, key), detected));
    loop.add(std::make_unique<truncating_client_stream>(
        loop, sockets.client, tls_context::make_client(certificate),
        tls_client_options {
            .hostname = "localhost",
            .application_protocols = {},
        }));
    loop.run();
    return detected;
}
} // namespace

auto main(int argc, char* argv[]) -> int
{
    if (argc != 3) {
        return 2;
    }

    try {
        const std::filesystem::path certificate = argv[1];
        const std::filesystem::path key = argv[2];
        const bool passed = test_echo_and_close(certificate, key) &&
                            test_hostname_rejection(certificate, key) &&
                            test_truncation(certificate, key);
        return passed ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
