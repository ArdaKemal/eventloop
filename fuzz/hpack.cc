// HPACK header blocks decoded in sequence by one decoder, so dynamic-table
// state carries across blocks. Each block is prefixed by a one-byte length;
// a zero length instead lowers the table size limit (as a SETTINGS change).
#include "fuzz_support.h"

#include "http2/hpack.h"

#include <vector>

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int
{
    using namespace eventloop;
    auto input = fuzz::bytes(data, size);
    http2::detail::hpack_decoder decoder;
    std::vector<http2::detail::field> fields;
    while (!input.empty()) {
        const auto length = std::to_integer<std::size_t>(input[0]);
        input = input.subspan(1);
        if (length == 0) {
            if (input.empty()) break;
            (void)decoder.set_table_size_limit(std::to_integer<std::size_t>(input[0]) * 64);
            input = input.subspan(1);
            continue;
        }
        const auto block = input.first(std::min(length, input.size()));
        input = input.subspan(block.size());
        fields.clear();
        if (decoder.decode(block, fields) != http2::detail::hpack_error::none) break;
    }
    return 0;
}
