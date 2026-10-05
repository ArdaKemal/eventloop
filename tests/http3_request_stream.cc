#include "http3/request_stream.h"

#include <array>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {
using namespace eventloop::http3::detail;

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "HTTP/3 request stream: " << message << '\n';
    std::exit(1);
}

auto bytes(std::initializer_list<unsigned> values) -> std::vector<std::byte>
{
    std::vector<std::byte> result;
    for (auto value : values) result.push_back(static_cast<std::byte>(value));
    return result;
}

struct result {
    std::optional<h3_error> error;
    std::size_t blocks {0};
    bool finished {false};
    std::string body {};
    auto operator==(const result&) const -> bool = default;
};

// Runs a stream through the parser, applying content_length after the request
// HEADERS. Input is fed whole and one octet at a time; both must agree.
auto run(std::span<const std::byte> input, std::optional<std::uint64_t> content_length,
         bool fin = true) -> result
{
    const auto once = [&](std::size_t step) {
        std::array<std::byte, 16> storage {};
        request_frames frames(storage);
        result r;
        for (std::size_t offset = 0; offset < input.size() && !r.error;) {
            auto chunk = input.subspan(offset, std::min(step, input.size() - offset));
            const auto before = chunk.size();
            const auto event = frames.receive(chunk);
            offset += before - chunk.size();
            if (!event) { r.error = event.error(); break; }
            if (*event == request_frames::event::header_block) {
                if (r.blocks++ == 0) frames.set_content_length(content_length);
            } else if (*event == request_frames::event::data) {
                for (auto byte : frames.data()) r.body.push_back(static_cast<char>(byte));
            }
        }
        if (!r.error && fin) {
            const auto finished = frames.finish();
            if (!finished) r.error = finished.error();
            else r.finished = true;
        }
        return r;
    };
    const auto whole = once(input.size() == 0 ? 1 : input.size());
    check(whole == once(1), "split delivery changes the verdict");
    return whole;
}

auto run(std::initializer_list<unsigned> values, std::optional<std::uint64_t> length = {},
         bool fin = true)
{
    const auto input = bytes(values);
    return run(std::span<const std::byte>(input), length, fin);
}

auto framing() -> void
{
    // HEADERS(2) is the minimal static-only section prefix.
    check(run({0x01, 0x02, 0x00, 0x00}) == result {{}, 1, true}, "headers only");
    check(run({0x01, 0x02, 0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63, 0x01, 0x02, 0x00, 0x00}) ==
          result {{}, 2, true, "abc"}, "headers, DATA, trailers");
    check(run({0x01, 0x02, 0x00, 0x00, 0x00, 0x02, 0x61, 0x62, 0x00, 0x00, 0x21, 0x01, 0xff,
               0x00, 0x01, 0x63}).body == "abc", "DATA split by empty and unknown frames");
    check(run({0x21, 0x01, 0xff, 0x01, 0x02, 0x00, 0x00, 0x21, 0x00}) == result {{}, 1, true},
          "unknown frames before and after HEADERS");
    check(run({0x01, 0x00}).blocks == 1, "empty HEADERS payload is delivered");

    check(run({0x00, 0x00}).error == h3_error::frame_unexpected, "DATA before HEADERS");
    check(run({0x01, 0x02, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00}).error ==
          h3_error::frame_unexpected, "DATA after trailers");
    check(run({0x01, 0x02, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00}).error ==
          h3_error::frame_unexpected, "HEADERS after trailers");
    for (unsigned type : {0x03u, 0x04u, 0x05u, 0x07u, 0x0du, 0x02u, 0x06u, 0x08u, 0x09u})
        check(run({0x01, 0x02, 0x00, 0x00, type, 0x00}).error == h3_error::frame_unexpected,
              "control, PUSH_PROMISE, and HTTP/2 frames");
    check(run({0x01, 0x11}).error == h3_error::excessive_load, "HEADERS beyond storage");

    check(run({}).error == h3_error::request_incomplete, "FIN before HEADERS");
    check(run({0x21, 0x00}).error == h3_error::request_incomplete,
          "FIN after only an extension frame");
    check(run({0x01, 0x02, 0x00}).error == h3_error::frame_error, "FIN inside HEADERS");
    check(run({0x01, 0x02, 0x00, 0x00, 0x00, 0x03, 0x61}).error == h3_error::frame_error,
          "FIN inside DATA");
    check(run({0x01, 0x02, 0x00, 0x00, 0x40}).error == h3_error::frame_error,
          "FIN inside a frame type");
    check(run({0x01, 0x02, 0x00, 0x00, 0x00, 0x03, 0x61}, {}, false).error == std::nullopt,
          "partial DATA without FIN waits for input");
}

auto content_length() -> void
{
    check(!run({0x01, 0x02, 0x00, 0x00, 0x00, 0x02, 0x61, 0x62, 0x00, 0x01, 0x63}, 3).error,
          "DATA frames sum to Content-Length");
    check(!run({0x01, 0x02, 0x00, 0x00}, 0).error, "zero Content-Length without DATA");
    check(run({0x01, 0x02, 0x00, 0x00, 0x00, 0x02, 0x61, 0x62}, 3).error ==
          h3_error::message_error, "short body at FIN");
    // Detected from the DATA length before its payload arrives.
    check(run({0x01, 0x02, 0x00, 0x00, 0x00, 0x04}, 3, false).error ==
          h3_error::message_error, "DATA beyond Content-Length");
    check(!run({0x01, 0x02, 0x00, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5}).error,
          "body without Content-Length");
}

auto connect_framing() -> void
{
    std::array<std::byte, 16> storage {};
    request_frames parser(storage);
    const std::array<std::byte, 4> head {std::byte{1}, std::byte{2}, std::byte{0}, std::byte{0}};
    auto input = std::span<const std::byte>(head);
    check(parser.receive(input).value() == request_frames::event::header_block, "CONNECT headers");
    parser.accept_connect();
    const std::array<std::byte, 3> data {std::byte{0}, std::byte{1}, std::byte{'x'}};
    input = data;
    check(parser.receive(input).value() == request_frames::event::data, "CONNECT DATA");
    check(parser.finish().has_value(), "CONNECT FIN after DATA");
    input = head;
    check(parser.receive(input).error() == h3_error::frame_unexpected, "no trailers on CONNECT tunnel");
}

auto fields() -> void
{
    using list = std::vector<field>;
    const auto request = [](list extra) {
        list fields {{":method", "GET"}, {":scheme", "https"}, {":authority", "example.com"},
                     {":path", "/"}};
        fields.insert(fields.end(), extra.begin(), extra.end());
        return fields;
    };
    const auto validate = [](const list& fields) { return validate_request(fields); };
    const auto malformed = [&](const list& fields) {
        const auto r = validate(fields);
        return !r && r.error() == h3_error::message_error;
    };

    const auto ok = validate(request({{"content-length", "12"}, {"te", "trailers"}}));
    check(ok && ok->method == "GET" && ok->path == "/" && ok->authority == "example.com" &&
          ok->content_length == 12, "valid request");
    const auto host = validate({{":method", "GET"}, {":scheme", "https"}, {":path", "/"},
                                {"host", "example.com"}});
    check(host && host->authority == "example.com", "Host supplies the authority");
    check(validate(request({{"content-length", "4"}, {"content-length", "4"}})).has_value(),
          "repeated identical Content-Length");
    const auto connect = validate({{":method", "CONNECT"}, {":authority", "example.com:443"}});
    check(connect && connect->method == "CONNECT", "plain CONNECT");

    const list extended {{":method", "CONNECT"}, {":scheme", "https"},
        {":authority", "example.com"}, {":path", "/chat"}, {":protocol", "websocket"}};
    check(!validate_request(extended), "Extended CONNECT requires advertisement");
    const auto accepted = validate_request(extended, true);
    check(accepted && accepted->connect_protocol == "websocket" && accepted->path == "/chat",
          "Extended CONNECT pseudo-headers");
    for (std::size_t i = 1; i < extended.size(); ++i) {
        auto missing = extended;
        missing.erase(missing.begin() + static_cast<std::ptrdiff_t>(i));
        check(!validate_request(missing, true), "Extended CONNECT missing field");
    }
    auto duplicate = extended;
    duplicate.push_back({":protocol", "websocket"});
    check(!validate_request(duplicate, true), "duplicate :protocol");
    auto wrong_method = extended;
    wrong_method[0].value = "GET";
    check(!validate_request(wrong_method, true), ":protocol only on CONNECT");
    auto unknown = extended;
    unknown.back().value = "other";
    check(validate_request(unknown, true).has_value(), "unknown token reaches application rejection");

    check(malformed({{":scheme", "https"}, {":authority", "a"}, {":path", "/"}}), "missing :method");
    check(malformed({{":method", "GET"}, {":authority", "a"}, {":path", "/"}}), "missing :scheme");
    check(malformed({{":method", "GET"}, {":scheme", "https"}, {":authority", "a"}}), "missing :path");
    check(malformed({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}}), "missing authority");
    check(malformed({{":method", "GET"}, {":scheme", "https"}, {":authority", "a"}, {":path", ""}}),
          "empty :path");
    check(malformed(request({{":path", "/again"}})), "duplicate pseudo-header");
    check(malformed({{":method", "GET"}, {"accept", "*/*"}, {":scheme", "https"},
                     {":authority", "a"}, {":path", "/"}}), "pseudo-header after field");
    check(malformed(request({{":protocol", "websocket"}})), ":protocol without extended CONNECT");
    check(malformed(request({{":status", "200"}})), "response pseudo-header");
    check(malformed(request({{"Accept", "*/*"}})), "uppercase field name");
    check(malformed(request({{"x-bad", "a\r\nb"}})), "CR LF in value");
    for (auto name : {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"})
        check(malformed(request({{name, "x"}})), "connection-specific field");
    check(malformed(request({{"te", "gzip"}})), "TE other than trailers");
    check(malformed(request({{"content-length", "4"}, {"content-length", "5"}})),
          "conflicting Content-Length");
    check(malformed(request({{"content-length", "-1"}})), "non-numeric Content-Length");
    check(malformed(request({{"content-length", "12345678901234567890"}})),
          "Content-Length beyond 19 digits");
    check(malformed(request({{"host", "other.example"}})), "Host disagrees with :authority");
    check(malformed({{":method", "CONNECT"}, {":authority", "a"}, {":path", "/"}}),
          "CONNECT with :path");

    check(validate_trailers(list {{"x-checksum", "abc"}}).has_value(), "valid trailers");
    check(validate_trailers(list {{":path", "/"}}).error() == h3_error::message_error,
          "pseudo-header in trailers");
    check(validate_trailers(list {{"transfer-encoding", "chunked"}}).error() ==
          h3_error::message_error, "connection-specific trailer");

    check(qpack_failure(qpack_error::limit_exceeded) == h3_error::excessive_load &&
          qpack_failure(qpack_error::invalid) == h3_error::qpack_decompression_failed &&
          qpack_failure(qpack_error::dynamic_table_disabled) ==
              h3_error::qpack_decompression_failed, "QPACK failure mapping");
    check(stream_scoped(h3_error::message_error) && !stream_scoped(h3_error::frame_unexpected),
          "stream and connection scope");
}
} // namespace

auto main() -> int
{
    framing();
    content_length();
    connect_framing();
    fields();
}
