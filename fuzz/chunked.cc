// An HTTP/1.1 chunked request body arriving in pieces, read in slices of a
// fuzzer-chosen size. The first byte picks the piece size, the second the
// largest slice handed out at once.
#include "fuzz_support.h"

#include "http/parser.h"

#include <algorithm>

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int
{
    using namespace eventloop;
    if (size < 2) return 0;
    const auto piece = fuzz::piece_size(data[0]);
    const auto slice = std::size_t {data[1]} + 1;
    auto input = fuzz::bytes(data + 2, size - 2);
    http::detail::chunked_decoder decoder;
    while (!input.empty()) {
        auto chunk = input.first(std::min(piece, input.size()));
        input = input.subspan(chunk.size());
        while (!chunk.empty()) {
            std::span<const std::byte> body;
            const auto status = decoder.feed(chunk, slice, body);
            if (status == http::detail::chunked_decoder::status::error ||
                status == http::detail::chunked_decoder::status::done)
                return 0;
            if (status == http::detail::chunked_decoder::status::need_input) break;
        }
    }
    return 0;
}
