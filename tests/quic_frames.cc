#include "quic/frames.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {

using namespace eventloop::quic::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "QUIC frames: " << message << '\n';
    std::exit(1);
}

auto bytes(std::initializer_list<std::uint8_t> values) -> std::vector<std::byte>
{
    std::vector<std::byte> result;
    for (const auto value : values) result.push_back(std::byte {value});
    return result;
}

auto valid_forms() -> void
{
    const auto simple = bytes({0x00, 0x01, 0x1e});
    check(decode_frame(simple)->encoded_size == 1, "PADDING");
    const auto padding = bytes({0x00, 0x00, 0x00, 0x01});
    check(decode_frame(padding)->encoded_size == 3, "PADDING run");
    check(decode_frame(std::span(simple).subspan(1))->type == 1, "PING");
    check(decode_frame(std::span(simple).subspan(2))->type == 0x1e,
          "HANDSHAKE_DONE");

    const auto ack = bytes({0x02, 10, 3, 2, 1, 0, 2, 0, 1});
    const auto a = decode_frame(ack);
    check(a && a->encoded_size == ack.size() && a->ack_range_count == 2 &&
          a->largest_acknowledged == 10 && a->first_ack_range == 1 &&
          a->ack_ranges.data() == ack.data() + 5 && a->ack_ranges.size() == 4,
          "ACK ranges borrow input");
    const auto ack_ecn = bytes({0x03, 0, 0, 0, 0, 1, 2, 3});
    check(decode_frame(ack_ecn)->ecn_counts[2] == 3, "ACK_ECN");

    const auto reset = bytes({0x04, 2, 3, 4});
    check(decode_frame(reset)->final_size == 4, "RESET_STREAM");
    const auto stop = bytes({0x05, 2, 3});
    check(decode_frame(stop)->error_code == 3, "STOP_SENDING");
    const auto crypto = bytes({0x06, 4, 2, 0xaa, 0xbb, 0x01});
    const auto c = decode_frame(crypto);
    check(c && c->offset == 4 && c->encoded_size == 5 &&
          c->data.data() == crypto.data() + 3 && c->data.size() == 2,
          "CRYPTO length and borrowed payload");
    const auto token = bytes({0x07, 2, 0xaa, 0xbb});
    check(decode_frame(token)->data.size() == 2, "NEW_TOKEN");

    for (std::uint8_t type = 0x08; type <= 0x0f; ++type) {
        std::vector<std::byte> stream {std::byte {type}, std::byte {1}};
        if (type & 0x04) stream.push_back(std::byte {2});
        if (type & 0x02) stream.push_back(std::byte {1});
        stream.push_back(std::byte {0xaa});
        const auto s = decode_frame(stream);
        check(s && s->encoded_size == stream.size() && s->stream_id == 1 &&
              s->offset == ((type & 0x04) ? 2U : 0U) &&
              s->fin == ((type & 0x01) != 0) && s->data.size() == 1 &&
              s->data.data() == stream.data() + stream.size() - 1,
              "STREAM variants");
    }

    for (const auto type : {0x10, 0x12, 0x13, 0x14, 0x16, 0x17}) {
        const auto b = bytes({static_cast<std::uint8_t>(type), 7});
        check(decode_frame(b)->limit == 7, "flow control or blocked frame");
    }
    for (const auto type : {0x11, 0x15}) {
        const auto b = bytes({static_cast<std::uint8_t>(type), 3, 7});
        const auto f = decode_frame(b);
        check(f && f->stream_id == 3 && f->limit == 7,
              "stream flow control or blocked frame");
    }
    const auto new_cid = bytes({0x18, 2, 1, 1, 0xaa,
                                0, 1, 2, 3, 4, 5, 6, 7,
                                8, 9, 10, 11, 12, 13, 14, 15});
    const auto cid = decode_frame(new_cid);
    check(cid && cid->sequence_number == 2 && cid->retire_prior_to == 1 &&
          cid->connection_id.data() == new_cid.data() + 4 &&
          cid->stateless_reset_token.size() == 16, "NEW_CONNECTION_ID");
    const auto retire = bytes({0x19, 4});
    check(decode_frame(retire)->sequence_number == 4,
          "RETIRE_CONNECTION_ID");
    for (const auto type : {0x1a, 0x1b}) {
        const auto b = bytes({static_cast<std::uint8_t>(type),
                              1, 2, 3, 4, 5, 6, 7, 8});
        check(decode_frame(b)->data.size() == 8, "PATH frame");
    }
    const auto transport_close = bytes({0x1c, 5, 6, 2, 'o', 'k'});
    const auto t = decode_frame(transport_close);
    check(t && t->error_code == 5 && t->frame_type == 6 &&
          t->reason_phrase.size() == 2, "transport CONNECTION_CLOSE");
    const auto application_close = bytes({0x1d, 5, 0});
    check(decode_frame(application_close)->encoded_size == 3,
          "application CONNECTION_CLOSE");
    const auto datagram = bytes({0x30, 0xaa, 0xbb});
    check(decode_frame(datagram)->data.size() == 2, "DATAGRAM without length");
    const auto datagram_len = bytes({0x31, 1, 0xaa, 0x01});
    check(decode_frame(datagram_len)->encoded_size == 3,
          "DATAGRAM with length");
}

auto malformed_forms() -> void
{
    const auto truncated = bytes({0x06, 0, 2, 0xaa});
    check(decode_frame(truncated).error() == frame_error::truncated,
          "payload length exceeds input");
    const auto empty_token = bytes({0x07, 0});
    check(decode_frame(empty_token).error() == frame_error::invalid_value,
          "NEW_TOKEN must contain a token");
    const auto huge = bytes({0x31, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff});
    check(decode_frame(huge).error() == frame_error::truncated,
          "huge payload length is bounded");
    const auto partial_varint = bytes({0x10, 0x40});
    check(decode_frame(partial_varint).error() == frame_error::truncated,
          "incomplete varint");
    const auto unknown = bytes({0x1f});
    check(decode_frame(unknown).error() == frame_error::invalid_frame,
          "unknown type");
    const auto unknown_long = bytes({0x40, 0x21});
    check(decode_frame(unknown_long).error() == frame_error::invalid_frame,
          "unknown multibyte type");
    const auto bad_first_range = bytes({0x02, 1, 0, 0, 2});
    check(decode_frame(bad_first_range).error() ==
              frame_error::invalid_ack_range, "ACK first range underflow");
    const auto bad_gap = bytes({0x02, 3, 0, 1, 2, 0, 0});
    check(decode_frame(bad_gap).error() == frame_error::invalid_ack_range,
          "ACK gap underflow");
    const auto bad_range = bytes({0x02, 4, 0, 1, 0, 0, 3});
    check(decode_frame(bad_range).error() == frame_error::invalid_ack_range,
          "ACK subsequent range underflow");
    const auto missing_pair = bytes({0x02, 4, 0, 1, 0, 0});
    check(decode_frame(missing_pair).error() == frame_error::truncated,
          "ACK pair truncated");
    const auto huge_count = bytes({0x02, 0, 0, 0xff, 0xff, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0});
    check(decode_frame(huge_count).error() == frame_error::truncated,
          "ACK count bounded by input");
    const auto missing_ecn = bytes({0x03, 0, 0, 0, 0, 1, 2});
    check(decode_frame(missing_ecn).error() == frame_error::truncated,
          "ACK_ECN counters truncated");
    const auto zero_cid = bytes({0x18, 0, 0, 0});
    check(decode_frame(zero_cid).error() == frame_error::invalid_connection_id,
          "zero CID length");
    const auto long_cid = bytes({0x18, 0, 0, 21});
    check(decode_frame(long_cid).error() == frame_error::invalid_connection_id,
          "CID length above twenty");
    const auto bad_retire = bytes({0x18, 0, 1, 1});
    check(decode_frame(bad_retire).error() == frame_error::invalid_connection_id,
          "retire prior to sequence");
    const auto short_token = bytes({0x18, 0, 0, 1, 0xaa, 0});
    check(decode_frame(short_token).error() == frame_error::truncated,
          "stateless reset token truncated");
    const auto short_path = bytes({0x1a, 1, 2, 3, 4, 5, 6, 7});
    check(decode_frame(short_path).error() == frame_error::truncated,
          "path challenge truncated");
    const auto short_reason = bytes({0x1d, 0, 2, 'x'});
    check(decode_frame(short_reason).error() == frame_error::truncated,
          "reason phrase truncated");
    const auto too_many_streams = bytes({0x12, 0xd0, 0, 0, 0, 0, 0, 0, 1});
    check(decode_frame(too_many_streams).error() == frame_error::invalid_value,
          "MAX_STREAMS above 2^60");
    const auto blocked_streams = bytes({0x16, 0xd0, 0, 0, 0, 0, 0, 0, 1});
    check(decode_frame(blocked_streams).error() == frame_error::invalid_value,
          "STREAMS_BLOCKED above 2^60");
    const auto crypto_overflow = bytes({0x06, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 1, 0xaa});
    check(decode_frame(crypto_overflow).error() == frame_error::invalid_value,
          "CRYPTO offset plus data exceeds varint range");
    const auto stream_overflow = bytes({0x0e, 0, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 1, 0xaa});
    check(decode_frame(stream_overflow).error() == frame_error::invalid_value,
          "STREAM offset plus data exceeds varint range");
}

} // namespace

auto main() -> int
{
    valid_forms();
    malformed_forms();
}
