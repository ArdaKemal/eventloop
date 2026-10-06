#pragma once

#include <cstddef>

namespace eventloop {

struct ready_event {
    int descriptor;
    bool readable;
    bool writable;
    bool error;
};

struct poll_result {
    std::size_t event_count;
    bool stop_requested;
    bool signal_requested;
};

} // namespace eventloop
