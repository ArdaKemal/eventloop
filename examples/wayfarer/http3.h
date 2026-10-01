#pragma once

#include "http_client_url.h"
#include "eventloop/event_loop.h"
#include "eventloop/task.h"

#include <cstdio>

struct request_options;
struct request_state;

auto fetch_http3(eventloop::event_loop& loop,
                 const http_client_example::url_parts& url,
                 const request_options& options, std::FILE* output,
                 request_state& state, bool& success, unsigned& final_status) -> eventloop::task<void>;
