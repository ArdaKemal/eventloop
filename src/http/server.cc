#include "eventloop/http/server.h"

#include "eventloop/http/session.h"
#include "eventloop/tcp_stream.h"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

namespace http {
namespace {

template<typename Stream>
class serving_connection final : public Stream {
public:
    template<typename... Arguments>
    serving_connection(int root_descriptor, server_options options,
                       Arguments&&... arguments)
        : Stream(std::forward<Arguments>(arguments)...),
          session_(*this, root_descriptor, options.directory_listing,
                   file_stream(this))
    {
    }

private:
    [[nodiscard]] static auto file_stream(Stream* stream) noexcept -> tcp_stream*
    {
        if constexpr (std::is_same_v<Stream, tcp_stream>) return stream;
        return nullptr;
    }

    auto on_data(std::span<const std::byte> data) -> void override
    {
        session_.receive(data);
    }

    auto on_close() -> void override { session_.closed(); }
    auto on_error(std::error_code error) -> void override { session_.failed(error); }
    auto on_write_drained() -> void override { session_.write_drained(); }
    auto on_shutdown() -> void override { session_.shutdown(); }

    session session_;
};

class redirect_connection final : public tcp_stream {
public:
    redirect_connection(event_loop& loop, int descriptor,
                        std::string_view hostname, std::uint16_t https_port)
        : tcp_stream(loop, descriptor), hostname_(hostname), https_port_(https_port)
    {
    }

private:
    auto on_data(std::span<const std::byte> data) -> void override
    {
        if (data.size() > input_.size() - input_size_) {
            fail();
            return;
        }
        std::memcpy(input_.data() + input_size_, data.data(), data.size());
        input_size_ += data.size();

        request request;
        const auto result = parse_request(
            std::string_view {input_.data(), input_size_}, request);
        if (result.status == parse_status::incomplete) return;
        if (result.status != parse_status::complete) {
            fail();
            return;
        }

        const int size = https_port_ == 443
            ? std::snprintf(
                  response_.data(), response_.size(),
                  "HTTP/1.1 308 Permanent Redirect\r\n"
                  "Location: https://%.*s%.*s\r\n"
                  "Content-Length: 0\r\nConnection: close\r\n\r\n",
                  static_cast<int>(hostname_.size()), hostname_.data(),
                  static_cast<int>(request.target.size()), request.target.data())
            : std::snprintf(
                  response_.data(), response_.size(),
                  "HTTP/1.1 308 Permanent Redirect\r\n"
                  "Location: https://%.*s:%u%.*s\r\n"
                  "Content-Length: 0\r\nConnection: close\r\n\r\n",
                  static_cast<int>(hostname_.size()), hostname_.data(),
                  static_cast<unsigned int>(https_port_),
                  static_cast<int>(request.target.size()), request.target.data());
        if (size < 0 || static_cast<std::size_t>(size) >= response_.size()) {
            fail();
            return;
        }
        write(std::as_bytes(std::span {response_}.first(
            static_cast<std::size_t>(size))));
        close();
    }

    auto on_close() -> void override {}
    auto on_error(std::error_code) -> void override {}

    auto fail() -> void
    {
        constexpr std::string_view response =
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        write(std::as_bytes(std::span {response.data(), response.size()}));
        close();
    }

    std::string_view hostname_;
    std::uint16_t https_port_;
    std::array<char, max_message_size> input_ {};
    std::array<char, 4096> response_ {};
    std::size_t input_size_ {0};
};

[[nodiscard]] auto system_error(const char* operation) -> std::system_error
{
    return {errno, std::system_category(), operation};
}

[[nodiscard]] auto open_root(std::string_view root) -> int
{
    std::array<char, 4096> path {};
    if (root.empty() || root.size() >= path.size()) {
        throw std::invalid_argument("HTTP root path is invalid or too long");
    }
    std::memcpy(path.data(), root.data(), root.size());
    const int descriptor = open(path.data(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (descriptor == -1) {
        throw system_error("open HTTP root");
    }
    return descriptor;
}

auto validate_hostname(std::string_view hostname) -> void
{
    if (hostname.empty()) {
        throw std::invalid_argument("redirect hostname cannot be empty");
    }
    for (const unsigned char value : hostname) {
        if (value <= 0x20 || value == 0x7f || value == '/' || value == '\\' ||
            value == '?' || value == '#' || value == '@') {
            throw std::invalid_argument("redirect hostname is invalid");
        }
    }
}

} // namespace

server::server(event_loop& loop, std::uint16_t port, std::string_view root,
               std::string_view address, server_options options)
    : tcp_acceptor(loop, port, address, options.reuse_port), options_(options)
{
    root_descriptor_ = open_root(root);
}

server::~server()
{
    if (root_descriptor_ != -1) {
        ::close(root_descriptor_);
    }
}

auto server::on_accept(int descriptor) -> void
{
    owner().add(std::make_unique<serving_connection<tcp_stream>>(
        root_descriptor_, options_, owner(), descriptor));
}

https_server::https_server(event_loop& loop, std::uint16_t port,
                           std::shared_ptr<tls_context> context,
                           std::string_view root, std::string_view address,
                           server_options options)
    : tls_acceptor(loop, port, std::move(context), address), options_(options)
{
    root_descriptor_ = open_root(root);
}

https_server::~https_server()
{
    if (root_descriptor_ != -1) {
        ::close(root_descriptor_);
    }
}

auto https_server::make_stream(int descriptor) -> std::unique_ptr<tls_stream>
{
    return std::make_unique<serving_connection<tls_stream>>(
        root_descriptor_, options_, owner(), descriptor, context(),
        tls_server_options {.application_protocols = {"http/1.1"}});
}

redirect_server::redirect_server(event_loop& loop, std::uint16_t port,
                                 std::string_view hostname,
                                 std::uint16_t https_port,
                                 std::string_view address)
    : tcp_acceptor(loop, port, address), hostname_(hostname),
      https_port_(https_port)
{
    validate_hostname(hostname_);
}

auto redirect_server::on_accept(int descriptor) -> void
{
    owner().add(std::make_unique<redirect_connection>(
        owner(), descriptor, hostname_, https_port_));
}

} // namespace http
