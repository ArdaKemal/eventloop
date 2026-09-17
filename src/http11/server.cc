#include "eventloop/http/server.h"

#include "eventloop/http/session.h"
#include "eventloop/tcp_stream.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <system_error>

#include <fcntl.h>
#include <unistd.h>

namespace http {
namespace {

class connection final : public tcp_stream {
public:
    connection(event_loop& loop, int descriptor, int root_descriptor)
        : tcp_stream(loop, descriptor), session_(*this, root_descriptor)
    {
    }

private:
    auto on_data(std::span<const std::byte> data) -> void override
    {
        session_.receive(data);
    }

    auto on_close() -> void override { session_.closed(); }
    auto on_error(std::error_code error) -> void override { session_.failed(error); }
    auto on_write_drained() -> void override { session_.write_drained(); }

    session session_;
};

[[nodiscard]] auto system_error(const char* operation) -> std::system_error
{
    return {errno, std::system_category(), operation};
}

} // namespace

server::server(event_loop& loop, std::uint16_t port, std::string_view root,
               std::string_view address)
    : tcp_acceptor(loop, port, address)
{
    std::array<char, 4096> path {};
    if (root.empty() || root.size() >= path.size()) {
        throw std::invalid_argument("HTTP root path is invalid or too long");
    }
    std::memcpy(path.data(), root.data(), root.size());
    root_descriptor_ = open(path.data(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_descriptor_ == -1) {
        throw system_error("open HTTP root");
    }
}

server::~server()
{
    if (root_descriptor_ != -1) {
        ::close(root_descriptor_);
    }
}

auto server::on_accept(int descriptor) -> void
{
    owner().add(std::make_unique<connection>(owner(), descriptor, root_descriptor_));
}

} // namespace http
