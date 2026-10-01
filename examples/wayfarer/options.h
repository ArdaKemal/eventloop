#pragma once

#include "eventloop/quic.h"
#include "eventloop/tcp_stream.h"
#include "eventloop/task.h"

#include <chrono>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

struct request_options {
    std::string url;
    std::string method = "GET";
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool body_supplied = false;
    std::filesystem::path body_file;
    std::filesystem::path output;
    std::filesystem::path ca_file;
    std::chrono::milliseconds timeout {30000};
    eventloop::quic_version quic_version {eventloop::quic_version::v1};
    int protocol = 1;
    bool show_headers = false;
    bool follow_redirects = false;
    bool fail_http_errors = false;
};

struct request_state {
    eventloop::tcp_stream* socket {};
    eventloop::quic_endpoint* endpoint {};
    eventloop::task_handle<void>* operation {};
    bool expired {};
};
