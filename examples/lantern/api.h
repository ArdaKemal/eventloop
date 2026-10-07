#pragma once

#include "catalog.h"

#include "eventloop/event_loop.h"
#include "eventloop/http/router.h"
#include "eventloop/unique_fd.h"

#include <cstdint>
#include <memory>
#include <string>

namespace lantern {

// Uploads arrive in chunks of at most this size, so one request body stays
// bounded however large the video is.
inline constexpr std::uint64_t chunk_bytes = 8 * 1024 * 1024;

// Shared by every route handler through request::route_context(). Lives in
// main() for the whole loop run.
struct app {
    eventloop::event_loop& loop;
    catalog& library;
    eventloop::unique_fd uploads;    // partial videos
    eventloop::unique_fd videos;     // published videos
    eventloop::unique_fd thumbnails;
    eventloop::unique_fd journal;
    std::uint64_t journal_end {0};
    std::uint64_t max_video_bytes {0};
    std::string alt_svc; // advertised when HTTP/3 is enabled
};

[[nodiscard]] auto make_routes(app& application) -> std::shared_ptr<eventloop::http::router>;

} // namespace lantern
