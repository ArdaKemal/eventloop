#pragma once

#include "eventloop/native_socket.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <span>
#include <string>

namespace eventloop::fuzz {

[[nodiscard]] inline auto bytes(const std::uint8_t* data, std::size_t size) noexcept
    -> std::span<const std::byte>
{
    return {reinterpret_cast<const std::byte*>(data), size};
}

// How many input bytes one simulated read delivers: often one byte at a
// time, otherwise up to 4 KiB, so parsers see every split point.
[[nodiscard]] inline auto piece_size(std::uint8_t selector) noexcept -> std::size_t
{
    return selector < 64 ? 1 + selector % 8 : 1 + std::size_t {selector} * 16;
}

// A document root for static responses: index.html, a file, and a
// subdirectory, created once per process.
[[nodiscard]] inline auto document_root() -> native_socket
{
    static const int root = [] {
        char path[] = "/tmp/eventloop-fuzz-XXXXXX";
        if (::mkdtemp(path) == nullptr) std::abort();
        const std::string base = path;
        std::ofstream(base + "/index.html") << "<p>index</p>\n";
        std::ofstream(base + "/data.txt") << "0123456789abcdef";
        ::mkdir((base + "/folder").c_str(), 0755);
        std::ofstream(base + "/folder/a.css") << "body{}";
        const int descriptor = ::open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (descriptor < 0) std::abort();
        return descriptor;
    }();
    return root;
}

} // namespace eventloop::fuzz
