#pragma once

#include "hub.h"
#include "store.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/router.h"
#include "eventloop/unique_fd.h"

#include <cstdint>
#include <memory>
#include <string>

namespace parley {

inline constexpr std::uint64_t max_upload_bytes = 16 * 1024 * 1024;

// Shared by every route handler through request::route_context(). Lives in
// main() for the whole loop run.
struct app {
    eventloop::event_loop& loop;
    store& data;
    hub& clients;
    eventloop::unique_fd media_directory;
    std::string alt_svc; // advertised when HTTP/3 is enabled
    eventloop::wakeup journal_ready;
};

[[nodiscard]] auto make_routes(app& application) -> std::shared_ptr<eventloop::http::router>;

} // namespace parley
