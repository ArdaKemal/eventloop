// libFuzzer target for the protocol parsers that read peer input. The first
// byte selects the parser; the rest is its input. Build with
// -DEVENTLOOP_FUZZ=ON using Clang.
#include "http/parser.h"
#include "http2/hpack.h"
#include "http3/qpack.h"
#include "http3/request_stream.h"
#include "quic/frames.h"
#include "quic/packet_header.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>
#include <vector>

namespace {

auto check(bool condition) -> void
{
    if (!condition) std::abort();
}

auto http1(std::span<const std::byte> input) -> void
{
    namespace http = eventloop::http::detail;
    const std::string_view text {reinterpret_cast<const char*>(input.data()), input.size()};
    http::parsed_request request;
    const auto parsed = http::parse_request(text, request);
    check(parsed.consumed <= text.size());
    if (parsed.status == http::parse_status::complete)
        check(request.header_count <= http::max_headers);

    http::chunked_decoder decoder;
    auto rest = input;
    std::span<const std::byte> data;
    for (;;) {
        const auto before = rest.size();
        const auto status = decoder.feed(rest, 64, data);
        check(data.size() <= 64 && rest.size() <= before);
        if (status != http::chunked_decoder::status::data) break;
    }
}

auto hpack(std::span<const std::byte> input) -> void
{
    // Two blocks through one decoder exercise dynamic-table state.
    eventloop::http2::detail::hpack_decoder decoder;
    std::vector<eventloop::http2::detail::field> fields;
    const auto half = input.size() / 2;
    if (decoder.decode(input.first(half), fields) ==
        eventloop::http2::detail::hpack_error::none)
        (void)decoder.decode(input.subspan(half), fields);
}

auto qpack(std::span<const std::byte> input) -> void
{
    namespace h3 = eventloop::http3::detail;
    std::array<h3::field, h3::qpack_max_fields> fields {};
    static std::array<char, h3::qpack_max_field_list_size> strings {};
    const auto decoded = h3::qpack_decode(input, fields, strings);
    if (decoded) {
        check(*decoded <= fields.size());
        (void)h3::validate_request(std::span<const h3::field>(fields).first(*decoded), true);
    }
    (void)h3::qpack_validate_encoder_instructions(input);
}

auto http3_request(std::span<const std::byte> input) -> void
{
    namespace h3 = eventloop::http3::detail;
    std::array<std::byte, 4096> block {};
    h3::request_frames frames(block);
    auto rest = input;
    while (!rest.empty()) {
        const auto before = rest.size();
        const auto event = frames.receive(rest);
        if (!event || *event == h3::request_frames::event::need_input) break;
        check(rest.size() <= before);
    }
    (void)frames.finish();
}

auto quic(std::span<const std::byte> input) -> void
{
    namespace q = eventloop::quic::detail;
    // Walk coalesced packets as the endpoint does.
    for (std::size_t offset = 0; offset < input.size();) {
        const auto header = q::parse_packet_header(input, offset, 8, true);
        if (!header) break;
        check(header->packet_end_offset > offset &&
              header->packet_end_offset <= input.size());
        offset = header->packet_end_offset;
    }
    // Every decoded frame re-encodes to a frame that decodes again.
    std::array<std::byte, 2048> encoded {};
    auto rest = input;
    while (!rest.empty()) {
        const auto frame = q::decode_frame(rest);
        if (!frame) break;
        check(frame->encoded_size != 0 && frame->encoded_size <= rest.size());
        if (const auto size = q::encode_frame(*frame, encoded))
            check(q::decode_frame(std::span(encoded).first(*size)).has_value());
        rest = rest.subspan(frame->encoded_size);
    }
}

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int
{
    if (size == 0) return 0;
    const std::span input {reinterpret_cast<const std::byte*>(data + 1), size - 1};
    switch (data[0] % 5) {
    case 0: http1(input); break;
    case 1: hpack(input); break;
    case 2: qpack(input); break;
    case 3: http3_request(input); break;
    default: quic(input); break;
    }
    return 0;
}
