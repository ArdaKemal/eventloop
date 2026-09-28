#pragma once

#include "eventloop/task.h"
#include "eventloop/tls_stream.h"
#include "eventloop/unique_fd.h"

#include <memory>

namespace eventloop::http2::detail {

[[nodiscard]] auto serve(event_loop& loop, tls_stream& peer,
                         std::shared_ptr<unique_fd> document_root,
                         bool directory_listing) -> task<bool>;

} // namespace eventloop::http2::detail
