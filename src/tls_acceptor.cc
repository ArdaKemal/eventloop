#include "eventloop/tls_acceptor.h"

#include <stdexcept>
#include <utility>

tls_acceptor::tls_acceptor(event_loop& loop, std::uint16_t port,
                           std::shared_ptr<tls_context> context,
                           std::string_view address)
    : tcp_acceptor(loop, port, address), context_(std::move(context))
{
    if (!context_) {
        throw std::invalid_argument("TLS context cannot be null");
    }
}

auto tls_acceptor::context() const noexcept -> const std::shared_ptr<tls_context>&
{
    return context_;
}

auto tls_acceptor::on_accept(int descriptor) -> void
{
    owner().add(make_stream(descriptor));
}
