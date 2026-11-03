// One QPACK field section (RFC 9204) and, separately, encoder-stream
// instructions; both come straight from HTTP/3 peers.
#include "fuzz_support.h"

#include "http3/qpack.h"

#include <array>

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int
{
    using namespace eventloop;
    const auto input = fuzz::bytes(data, size);
    std::array<http3::detail::field, 64> fields {};
    std::array<char, 4096> strings {};
    if (const auto decoded = http3::detail::qpack_decode(input, fields, strings)) {
        // Touch every decoded byte so the sanitizers check the views.
        std::size_t total = 0;
        for (const auto& field : std::span(fields).first(*decoded))
            for (const char byte : field.name) total += static_cast<unsigned char>(byte);
        static volatile std::size_t sink;
        sink = total;
    }
    (void)http3::detail::qpack_validate_encoder_instructions(input);
    return 0;
}
