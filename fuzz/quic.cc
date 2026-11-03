// QUIC wire decoding on untrusted datagrams: the packet header (long and
// short forms, with and without a greased QUIC bit) and a sequence of
// frames decoded back to back, as from a decrypted payload.
#include "fuzz_support.h"

#include "quic/frames.h"
#include "quic/packet_header.h"

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int
{
    using namespace eventloop;
    const auto input = fuzz::bytes(data, size);
    for (const bool grease : {false, true})
        (void)quic::detail::parse_packet_header(input, 0, 8, grease);
    (void)quic::detail::parse_packet_header(input, 0, std::nullopt);
    auto frames = input;
    while (!frames.empty()) {
        const auto frame = quic::detail::decode_frame(frames);
        if (!frame || frame->encoded_size == 0 || frame->encoded_size > frames.size()) break;
        frames = frames.subspan(frame->encoded_size);
    }
    return 0;
}
