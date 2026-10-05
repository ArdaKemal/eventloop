#pragma once

#include "eventloop/task.h"
#include "eventloop/tls_stream.h"
#include "eventloop/http/router.h"
#include "eventloop/unique_fd.h"
#include "../http/open_file_cache.h"

#include <memory>

namespace eventloop::http2::detail {

// Serves one TLS HTTP/2 connection. With routes, handlers run as tasks on
// loop beside a reader task; the document root and routes stay alive in the
// caller for the connection's lifetime.
[[nodiscard]] auto serve(event_loop& loop, tls_stream& peer,
                         std::shared_ptr<http::detail::document_root> document_root,
                         bool directory_listing,
                         std::shared_ptr<const http::router> routes = {},
                         std::uint64_t max_request_body = 0) -> task<bool>;

} // namespace eventloop::http2::detail
