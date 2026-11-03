// An HTTP/3 request stream: frames arriving in pieces, each header block
// QPACK-decoded and validated as a request (extended CONNECT allowed). The
// first input byte picks the piece size.
#include "fuzz_support.h"

#include "http3/qpack.h"
#include "http3/request_stream.h"

#include <algorithm>
#include <array>

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int
{
    using namespace eventloop;
    if (size == 0) return 0;
    const auto piece = fuzz::piece_size(data[0]);
    auto input = fuzz::bytes(data + 1, size - 1);
    static std::array<std::byte, 16 * 1024> storage;
    http3::detail::request_frames frames(storage);
    std::array<http3::detail::field, 64> fields {};
    std::array<char, 4096> strings {};
    bool first = true;
    while (!input.empty()) {
        auto chunk = input.first(std::min(piece, input.size()));
        input = input.subspan(chunk.size());
        while (!chunk.empty()) {
            const auto event = frames.receive(chunk);
            if (!event) return 0;
            if (*event != http3::detail::request_frames::event::header_block) continue;
            const auto decoded = http3::detail::qpack_decode(frames.block(), fields, strings);
            if (!decoded) return 0;
            if (first) {
                const auto head = http3::detail::validate_request(
                    std::span(fields).first(*decoded), true);
                if (!head) return 0;
                frames.set_content_length(head->content_length, head->content_length_too_large);
                first = false;
            }
        }
    }
    (void)frames.finish();
    return 0;
}
