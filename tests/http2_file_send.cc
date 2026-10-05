#include "http2/session.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace {
using namespace eventloop::http2::detail;
using eventloop::unique_fd;

auto check(bool value, std::string_view message) -> void
{
    if (value) return;
    std::cerr << "HTTP/2 file send: " << message << '\n';
    std::exit(1);
}

auto feed(session& state, std::span<const std::byte> bytes) -> void
{
    while (!bytes.empty()) {
        const auto count = std::min(bytes.size(), state.read_buffer().size());
        std::memcpy(state.read_buffer().data(), bytes.data(), count);
        state.commit_read(count);
        bytes = bytes.subspan(count);
    }
    check(!state.closed(), "input unexpectedly closed session");
}

auto frame(session& state, unsigned type, unsigned flags, unsigned stream,
           std::span<const std::byte> payload = {}) -> void
{
    std::array<std::byte, 9> header {};
    header[0] = static_cast<std::byte>(payload.size() >> 16);
    header[1] = static_cast<std::byte>(payload.size() >> 8);
    header[2] = static_cast<std::byte>(payload.size());
    header[3] = static_cast<std::byte>(type);
    header[4] = static_cast<std::byte>(flags);
    header[8] = static_cast<std::byte>(stream);
    feed(state, header);
    feed(state, payload);
}

auto drain(session& state) -> std::vector<std::byte>
{
    std::vector<std::byte> bytes;
    while (!state.output().empty()) {
        // Exercise headers as partial transport writes.
        bytes.push_back(state.output().front());
        state.consume_output(1);
    }
    return bytes;
}

auto request_file(session& state, unsigned stream, std::string_view priority = "u=3")
    -> void
{
    std::vector<std::byte> block;
    const std::array<field, 5> fields {{{":method", "GET"}, {":scheme", "https"},
        {":path", "/file"}, {":authority", "localhost"},
        {"priority", std::string(priority)}}};
    check(hpack_encode(fields, block) == hpack_error::none, "request encoding");
    frame(state, 1, 5, stream, block);
    request incoming;
    check(state.pop_request(incoming) && incoming.stream_id == stream,
          "request delivery");
}

auto initialize(session& state) -> void
{
    constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    feed(state, std::as_bytes(std::span(preface)));
    const std::array<std::byte, 6> settings {std::byte {0}, std::byte {4},
        std::byte {0}, std::byte {0}, std::byte {0}, std::byte {7}};
    frame(state, 4, 0, 0, settings);
    (void)drain(state);
}

auto file_barrier() -> void
{
    session state(true);
    initialize(state);
    request_file(state, 1);
    const std::array<std::byte, 8> ping {};
    // Move the ring head, wrap pending output, then force storage growth before
    // publishing the file barrier.
    for (int index = 0; index < 200; ++index) frame(state, 6, 0, 0, ping);
    for (int index = 0; index < 1700; ++index) state.consume_output(1);
    for (int index = 0; index < 300; ++index) frame(state, 6, 0, 0, ping);
    std::array<char, 40> name {};
    constexpr std::string_view pattern = "/tmp/eventloop-h2-file-XXXXXX";
    std::copy(pattern.begin(), pattern.end(), name.begin());
    unique_fd file {mkstemp(name.data())};
    check(static_cast<bool>(file), "create file fixture");
    check(unlink(name.data()) == 0, "unlink file fixture");
    constexpr std::string_view contents = "prefix:0123456789abcdef";
    check(write(file.get(), contents.data(), contents.size()) ==
          static_cast<ssize_t>(contents.size()), "write file fixture");
    const int original = file.get();
    check(state.respond_file(1, 206, {}, std::move(file), 11, true, 7), "file response");
    check(!state.take_file_send(), "file became available before DATA header drained");

    // Queue a PING response behind the file DATA header. It must not be visible
    // until all seven bytes of this DATA payload have been transferred.
    // Stream 3 is more urgent, so it precedes the rest of the file (RFC 9218).
    request_file(state, 3, "u=2");
    const std::vector<std::byte> inline_body(5, std::byte {'x'});
    check(state.respond(3, 200, {}, inline_body), "inline response behind barrier");
    frame(state, 6, 0, 0, ping);
    const std::array<std::byte, 6> zero_window {std::byte {0}, std::byte {4}};
    frame(state, 4, 0, 0, zero_window);
    auto prefix = drain(state);
    check(prefix.size() >= 9, "missing DATA header");
    const auto data_header = std::span(prefix).last(9);
    check(data_header[2] == std::byte {7} && data_header[3] == std::byte {0} &&
          data_header[4] == std::byte {0} && data_header[8] == std::byte {1},
          "DATA header length/flags/stream");
    check(state.output().empty(), "later control frame crossed file barrier");
    auto transfer = state.take_file_send();
    check(transfer && transfer->file && transfer->file.get() == original &&
          transfer->offset == 7 && transfer->size == 7, "owned range without duplication");
    check(!state.take_file_send(), "file ownership taken twice");
    std::array<char, 7> body {};
    check(pread(transfer->file.get(), body.data(), body.size(),
          static_cast<off_t>(transfer->offset)) == 7 &&
          std::string_view(body.data(), body.size()) == "0123456", "range body");
    state.complete_file_send(std::move(transfer->file));
    auto after = drain(state);
    bool ping_seen = false;
    for (std::size_t offset = 0; offset < after.size();) {
        check(after.size() - offset >= 9, "incomplete frame after barrier");
        const auto size = (std::to_integer<unsigned>(after[offset]) << 16) |
            (std::to_integer<unsigned>(after[offset + 1]) << 8) |
            std::to_integer<unsigned>(after[offset + 2]);
        check(size + 9 <= after.size() - offset, "truncated frame after barrier");
        if (after[offset + 3] == std::byte {6}) ping_seen = true;
        check(after[offset + 3] != std::byte {0}, "negative stream window sent DATA");
        offset += size + 9;
    }
    check(ping_seen, "completion did not release later PING");
    check(!state.take_file_send(), "stream window overrun");

    const std::array<std::byte, 6> restored_window {std::byte {0}, std::byte {4},
        std::byte {0}, std::byte {0}, std::byte {0}, std::byte {11}};
    frame(state, 4, 0, 0, restored_window);
    auto final_header = drain(state);
    // Stream 3 receives its inline body before the next file frame; the final
    // file header must remain at the end of the transport-visible prefix.
    bool inline_seen = false;
    check(final_header.size() >= 9, "missing final DATA header");
    for (std::size_t offset = 0; offset < final_header.size() - 9;) {
        check(final_header.size() - offset >= 9, "incomplete frame before final DATA");
        const auto size = (std::to_integer<unsigned>(final_header[offset]) << 16) |
            (std::to_integer<unsigned>(final_header[offset + 1]) << 8) |
            std::to_integer<unsigned>(final_header[offset + 2]);
        check(size + 9 <= final_header.size() - 9 - offset,
              "frame crossed final file header");
        if (final_header[offset + 3] == std::byte {0} &&
            final_header[offset + 8] == std::byte {3}) {
            check(size == 5 && final_header[offset + 4] == std::byte {1},
                  "inline DATA frame size/flags");
            inline_seen = true;
        }
        offset += size + 9;
    }
    check(inline_seen, "more urgent inline response waited behind the file");
    const auto last_header = std::span(final_header).last(9);
    check(last_header[2] == std::byte {4} && last_header[4] == std::byte {1},
          "final DATA header after window update");
    auto final = state.take_file_send();
    check(final && final->offset == 14 && final->size == 4, "final range offset");
    check(final->file.get() == original, "final range duplicated descriptor");
    std::array<char, 4> tail {};
    check(pread(final->file.get(), tail.data(), tail.size(),
          static_cast<off_t>(final->offset)) == 4 &&
          std::string_view(tail.data(), tail.size()) == "789a",
          "final frame owner did not survive stream reset");
    state.complete_file_send(std::move(final->file));
    check(fcntl(original, F_GETFD) == -1, "completed file kept descriptor open");
    (void)drain(state); // SETTINGS acknowledgement queued after file barrier.
    check(!state.closed() && state.output().empty() && !state.take_file_send(),
          "file completion left pending output");
}
auto combined_prefix() -> void
{
    session state(true);
    initialize(state);
    request_file(state, 1);
    std::array<char, 40> name {};
    constexpr std::string_view pattern = "/tmp/eventloop-h2-prefix-XXXXXX";
    std::copy(pattern.begin(), pattern.end(), name.begin());
    unique_fd file {mkstemp(name.data())};
    check(static_cast<bool>(file), "create prefix fixture");
    check(unlink(name.data()) == 0, "unlink prefix fixture");
    constexpr std::string_view contents = "0123456";
    check(write(file.get(), contents.data(), contents.size()) ==
          static_cast<ssize_t>(contents.size()), "write prefix fixture");
    const auto descriptor = file.get();
    check(state.respond_file(1, 200, {}, std::move(file), contents.size(), true),
          "prefix fixture response");
    check(!state.take_file_send(), "uncombined send exposed undrained prefix");
    auto transfer = state.take_file_send(true);
    check(transfer && transfer->file.get() == descriptor &&
          transfer->prefix.size() >= 9 && transfer->size == contents.size(),
          "combined send missing prefix/file");
    check(transfer->prefix.data() == state.output().data() &&
          transfer->prefix.size() == state.output().size(), "combined prefix was copied");
    const auto header = transfer->prefix.last(9);
    check(header[2] == std::byte {7} && header[3] == std::byte {0} &&
          header[4] == std::byte {1} && header[8] == std::byte {1},
          "combined prefix does not end in final DATA header");
    check(!state.take_file_send(true), "combined file ownership taken twice");
    state.consume_output(transfer->prefix.size());
    state.complete_file_send(std::move(transfer->file));
    check(fcntl(descriptor, F_GETFD) == -1, "combined completion kept file open");
    check(!state.closed() && state.output().empty(), "combined completion left output");
}

auto reset_during_file_send() -> void
{
    session state(true);
    initialize(state);
    request_file(state, 1);
    std::array<char, 40> name {};
    constexpr std::string_view pattern = "/tmp/eventloop-h2-reset-XXXXXX";
    std::copy(pattern.begin(), pattern.end(), name.begin());
    unique_fd file {mkstemp(name.data())};
    check(static_cast<bool>(file), "create reset fixture");
    check(unlink(name.data()) == 0, "unlink reset fixture");
    constexpr std::string_view contents = "0123456789a";
    check(write(file.get(), contents.data(), contents.size()) ==
          static_cast<ssize_t>(contents.size()), "write reset fixture");
    const auto descriptor = file.get();
    check(state.respond_file(1, 200, {}, std::move(file), contents.size(), true),
          "reset fixture response");
    (void)drain(state);
    auto transfer = state.take_file_send();
    check(transfer && transfer->file.get() == descriptor, "reset transfer owner");
    const std::array<std::byte, 4> canceled {std::byte {0}, std::byte {0},
        std::byte {0}, std::byte {8}};
    frame(state, 3, 0, 1, canceled);
    // Reuse the retired stream slot before completion. The old descriptor
    // must remain valid for the borrowed send and must not enter the new stream.
    request_file(state, 3);
    check(fcntl(descriptor, F_GETFD) != -1, "reset closed pending borrowed file");
    state.complete_file_send(std::move(transfer->file));
    check(fcntl(descriptor, F_GETFD) == -1, "reset file owner survived completion");
    check(!state.closed(), "reset transfer closed connection");
}
// Without kernel sendfile, file DATA must not overwrite a partially
// received frame.
auto inbound_frame_survives_file_pump() -> void
{
    session state(false);
    initialize(state);
    request_file(state, 1);
    std::array<char, 40> name {};
    constexpr std::string_view pattern = "/tmp/eventloop-h2-file-XXXXXX";
    std::copy(pattern.begin(), pattern.end(), name.begin());
    unique_fd file {mkstemp(name.data())};
    check(static_cast<bool>(file), "create file fixture");
    check(unlink(name.data()) == 0, "unlink file fixture");
    const std::vector<char> contents(1000, 'F');
    check(write(file.get(), contents.data(), contents.size()) ==
          static_cast<ssize_t>(contents.size()), "write file fixture");

    constexpr std::array<std::byte, 9> ping_header {std::byte {0}, std::byte {0},
        std::byte {8}, std::byte {6}, std::byte {0}, std::byte {0}, std::byte {0},
        std::byte {0}, std::byte {0}};
    constexpr std::string_view opaque = "ABCDEFGH";
    feed(state, ping_header);
    feed(state, std::as_bytes(std::span(opaque)).first(4));
    check(state.respond_file(1, 200, {}, std::move(file), contents.size(), true),
          "file response");
    auto output = drain(state);
    feed(state, std::as_bytes(std::span(opaque)).subspan(4));
    const auto rest = drain(state);
    output.insert(output.end(), rest.begin(), rest.end());

    std::span<const std::byte> frames = output;
    bool acked = false;
    while (frames.size() >= 9) {
        const auto length = (std::to_integer<std::size_t>(frames[0]) << 16) |
            (std::to_integer<std::size_t>(frames[1]) << 8) |
            std::to_integer<std::size_t>(frames[2]);
        check(frames.size() >= 9 + length, "truncated output frame");
        if (frames[3] == std::byte {6} && frames[4] == std::byte {1}) {
            check(length == 8 && std::equal(opaque.begin(), opaque.end(),
                      reinterpret_cast<const char*>(frames.data() + 9)),
                  "PING ACK lost the received opaque data");
            acked = true;
        }
        frames = frames.subspan(9 + length);
    }
    check(acked, "PING was not acknowledged");
}
} // namespace

auto main() -> int
{
    file_barrier();
    combined_prefix();
    reset_during_file_send();
    inbound_frame_survives_file_pump();
    return 0;
}
