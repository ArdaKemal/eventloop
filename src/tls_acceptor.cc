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

auto tls_acceptor::make_owned_stream(unique_fd descriptor)
    -> std::unique_ptr<tls_stream>
{
    // Compatibility path for subclasses using the original int interface.
    return make_stream(descriptor.release());
}

auto tls_acceptor::on_accept_owned(unique_fd descriptor) -> void
{
    owner().add(make_owned_stream(std::move(descriptor)));
}

auto tls_acceptor::on_accept(int descriptor) -> void
{
    on_accept_owned(unique_fd(descriptor));
}
