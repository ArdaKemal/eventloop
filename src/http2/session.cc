#include "session.h"
#include "../http/file_operations.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string_view>
#include <utility>

namespace eventloop::http2::detail {
namespace {

constexpr std::string_view client_preface =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr std::size_t max_output_size = 256 * 1024;
constexpr std::uint8_t data_frame = 0;
constexpr std::uint8_t headers_frame = 1;
constexpr std::uint8_t priority_frame = 2;
constexpr std::uint8_t reset_frame = 3;
constexpr std::uint8_t settings_frame = 4;
constexpr std::uint8_t push_promise_frame = 5;
constexpr std::uint8_t ping_frame = 6;
constexpr std::uint8_t goaway_frame = 7;
constexpr std::uint8_t window_update_frame = 8;
constexpr std::uint8_t continuation_frame = 9;
constexpr std::uint8_t priority_update_frame = 0x10;
constexpr std::uint8_t flag_end_stream = 0x1;
constexpr std::uint8_t flag_ack = 0x1;
constexpr std::uint8_t flag_end_headers = 0x4;
constexpr std::uint8_t flag_padded = 0x8;
constexpr std::uint8_t flag_priority = 0x20;
constexpr std::uint32_t protocol_error = 1;
constexpr std::uint32_t internal_error = 2;
constexpr std::uint32_t flow_control_error = 3;
constexpr std::uint32_t stream_closed_error = 5;
constexpr std::uint32_t frame_size_error = 6;
constexpr std::uint32_t refused_stream_error = 7;
constexpr std::uint32_t cancel_error = 8;
constexpr std::uint32_t compression_error = 9;
constexpr std::uint32_t enhance_your_calm_error = 11;
constexpr std::uint32_t max_window_size = 0x7fffffff;

[[nodiscard]] auto byte_value(std::byte value) noexcept -> std::uint8_t
{
    return std::to_integer<std::uint8_t>(value);
}

[[nodiscard]] auto read_u32(const std::byte* input) noexcept -> std::uint32_t
{
    return (static_cast<std::uint32_t>(byte_value(input[0])) << 24) |
           (static_cast<std::uint32_t>(byte_value(input[1])) << 16) |
           (static_cast<std::uint32_t>(byte_value(input[2])) << 8) |
           static_cast<std::uint32_t>(byte_value(input[3]));
}

auto write_u32(std::byte* output, std::uint32_t value) noexcept -> void
{
    output[0] = static_cast<std::byte>((value >> 24) & 0xff);
    output[1] = static_cast<std::byte>((value >> 16) & 0xff);
    output[2] = static_cast<std::byte>((value >> 8) & 0xff);
    output[3] = static_cast<std::byte>(value & 0xff);
}

[[nodiscard]] auto is_token_char(unsigned char value) noexcept -> bool
{
    if ((value >= '0' && value <= '9') ||
        (value >= 'a' && value <= 'z') ||
        (value >= 'A' && value <= 'Z')) return true;
    constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
    return punctuation.find(static_cast<char>(value)) != std::string_view::npos;
}

[[nodiscard]] auto valid_header_name(std::string_view name) noexcept -> bool
{
    if (name.empty()) return false;
    if (name.front() == ':') name.remove_prefix(1);
    if (name.empty()) return false;
    for (const unsigned char value : name) {
        if (value >= 'A' && value <= 'Z') return false;
        if (!is_token_char(value)) return false;
    }
    return true;
}

[[nodiscard]] auto valid_header_value(std::string_view value) noexcept -> bool
{
    if (!value.empty() && (value.front() == ' ' || value.front() == '\t' ||
                           value.back() == ' ' || value.back() == '\t')) {
        return false;
    }
    for (const unsigned char byte : value) {
        if (byte == 0x7f || (byte < 0x20 && byte != '\t')) return false;
    }
    return true;
}

[[nodiscard]] constexpr auto hex_digit(unsigned char value) noexcept -> bool
{
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

[[nodiscard]] auto valid_request_target(std::string_view target) noexcept -> bool
{
    for (std::size_t index = 0; index < target.size(); ++index) {
        const auto value = static_cast<unsigned char>(target[index]);
        if (value == '%') {
            if (index + 2 >= target.size() ||
                !hex_digit(static_cast<unsigned char>(target[index + 1])) ||
                !hex_digit(static_cast<unsigned char>(target[index + 2]))) {
                return false;
            }
            index += 2;
            continue;
        }
        const bool unreserved = (value >= 'a' && value <= 'z') ||
            (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') ||
            value == '-' || value == '.' || value == '_' || value == '~';
        constexpr std::string_view sub_delimiters = "!$&'()*+,;=";
        const bool pchar = unreserved || sub_delimiters.find(
            static_cast<char>(value)) != std::string_view::npos ||
            value == ':' || value == '@';
        if (!pchar && value != '/' && value != '?') return false;
    }
    return true;
}

// Reads the u and i members of an RFC 9218 Priority field, a Structured
// Fields Dictionary (RFC 8941). Other members and parameters are skipped.
// Returns false on a syntax error; the caller then keeps its current priority.
// Out-of-range or wrongly typed u and i values are ignored.
[[nodiscard]] auto parse_priority(std::string_view text, std::uint8_t& urgency,
                                  bool& incremental) noexcept -> bool
{
    std::size_t at = 0;
    const auto space = [&] {
        while (at < text.size() && (text[at] == ' ' || text[at] == '\t')) ++at;
    };
    const auto key = [&]() -> std::string_view {
        const auto start = at;
        if (at == text.size() || !((text[at] >= 'a' && text[at] <= 'z') || text[at] == '*'))
            return {};
        while (at < text.size() &&
               ((text[at] >= 'a' && text[at] <= 'z') || (text[at] >= '0' && text[at] <= '9') ||
                std::string_view("_-.*").find(text[at]) != std::string_view::npos)) ++at;
        return text.substr(start, at - start);
    };
    // Skips one bare item or inner list and returns its text.
    const auto item = [&]() -> std::optional<std::string_view> {
        const auto start = at;
        if (at < text.size() && text[at] == '"') {
            for (++at; at < text.size(); ++at) {
                if (text[at] == '\\') ++at;
                else if (text[at] == '"') return text.substr(start, ++at - start);
            }
            return std::nullopt;
        }
        if (at < text.size() && text[at] == '(') {
            bool quoted = false;
            for (++at; at < text.size(); ++at) {
                if (quoted && text[at] == '\\') ++at;
                else if (text[at] == '"') quoted = !quoted;
                else if (!quoted && text[at] == ')') return text.substr(start, ++at - start);
            }
            return std::nullopt;
        }
        while (at < text.size() && text[at] != ',' && text[at] != ';' && text[at] != ' ' &&
               text[at] != '\t') ++at;
        if (at == start) return std::nullopt;
        return text.substr(start, at - start);
    };
    // An sf-integer from 0 to 7.
    const auto urgency_value = [](std::string_view value) -> std::optional<std::uint8_t> {
        if (value.empty() || value.size() > 15) return std::nullopt;
        unsigned parsed = 0;
        for (const char digit : value) {
            if (digit < '0' || digit > '9') return std::nullopt;
            parsed = std::min(parsed * 10 + static_cast<unsigned>(digit - '0'), 8u);
        }
        if (parsed > 7) return std::nullopt;
        return static_cast<std::uint8_t>(parsed);
    };

    std::optional<std::uint8_t> parsed_urgency;
    std::optional<bool> parsed_incremental;
    space();
    while (at < text.size()) {
        const auto name = key();
        if (name.empty()) return false;
        std::optional<std::string_view> value;
        if (at < text.size() && text[at] == '=') {
            ++at;
            value = item();
            if (!value) return false;
        }
        while (at < text.size() && text[at] == ';') {
            ++at;
            space();
            if (key().empty()) return false;
            if (at < text.size() && text[at] == '=') {
                ++at;
                if (!item()) return false;
            }
        }
        if (name == "u") {
            parsed_urgency = value ? urgency_value(*value) : std::nullopt;
        } else if (name == "i") {
            if (!value || *value == "?1") parsed_incremental = true;
            else if (*value == "?0") parsed_incremental = false;
            else parsed_incremental.reset();
        }
        space();
        if (at == text.size()) break;
        if (text[at] != ',') return false;
        ++at;
        space();
        if (at == text.size()) return false;
    }
    if (parsed_urgency) urgency = *parsed_urgency;
    if (parsed_incremental) incremental = *parsed_incremental;
    return true;
}

[[nodiscard]] auto ascii_equal(std::string_view left,
                               std::string_view right) noexcept -> bool
{
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        auto a = static_cast<unsigned char>(left[index]);
        auto b = static_cast<unsigned char>(right[index]);
        if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b + ('a' - 'A'));
        if (a != b) return false;
    }
    return true;
}

[[nodiscard]] auto forbidden_connection_header(std::string_view name) noexcept
    -> bool
{
    return name == "connection" || name == "proxy-connection" ||
           name == "keep-alive" || name == "transfer-encoding" ||
           name == "upgrade";
}

[[nodiscard]] auto parse_decimal(std::string_view input,
                                 std::uint64_t& value) noexcept -> bool
{
    if (input.empty()) return false;
    std::uint64_t parsed = 0;
    for (const unsigned char digit : input) {
        if (digit < '0' || digit > '9') return false;
        const auto number = static_cast<std::uint64_t>(digit - '0');
        if (parsed > (std::numeric_limits<std::uint64_t>::max() - number) / 10) {
            return false;
        }
        parsed = parsed * 10 + number;
    }
    value = parsed;
    return true;
}

[[nodiscard]] auto valid_method(std::string_view value) noexcept -> bool
{
    if (value.empty()) return false;
    for (const unsigned char byte : value) {
        if (!is_token_char(byte)) return false;
    }
    return true;
}

} // namespace

session::session(bool file_sendfile, const http::router* routes,
                 std::uint64_t max_request_body)
    : file_sendfile_(file_sendfile), routes_(routes), max_routed_body_(max_request_body)
{
    requests_.reserve(8);
    if (routes_ != nullptr) routed_.reserve(route_body_slots);
    header_block_.reserve(4096);
    output_.resize(4096);
    decoded_fields_.reserve(16);

    std::array<std::byte, 42> settings {};
    auto setting = [&](std::size_t offset, std::uint16_t id,
                       std::uint32_t value) {
        settings[offset] = static_cast<std::byte>(id >> 8);
        settings[offset + 1] = static_cast<std::byte>(id & 0xff);
        write_u32(settings.data() + offset + 2, value);
    };
    setting(0, 1, static_cast<std::uint32_t>(hpack_max_table_size));
    setting(6, 2, 0); // This server does not implement push.
    setting(12, 3, static_cast<std::uint32_t>(max_concurrent_streams));
    setting(18, 6, static_cast<std::uint32_t>(hpack_max_field_list_size));
    setting(24, 9, 1); // SETTINGS_NO_RFC7540_PRIORITIES: RFC 9218 signals only.
    // With routes, a stream window is one body buffer slot.
    std::size_t settings_size = 30;
    if (routes_ != nullptr) {
        setting(30, 4, static_cast<std::uint32_t>(route_body_slot_size));
        setting(36, 8, 1); // RFC 8441 Extended CONNECT, dispatched through routes.
        settings_size = 42;
    }
    if (!append_frame(settings_frame, 0, 0, std::span {settings}.first(settings_size)))
        fatal_ = true;
}

auto session::read_buffer() noexcept -> std::span<std::byte>
{
    if (stalled_) return {};
    // A large payload remainder is read straight into its frame buffer.
    if (const auto payload = payload_read_space(); !payload.empty()) return payload;
    return read_buffer_;
}

auto session::commit_read(std::size_t size) -> void
{
    if (const auto payload = payload_read_space(); !payload.empty()) {
        if (size > payload.size()) {
            connection_error(internal_error);
            return;
        }
        frame_payload_size_ += size;
        if (frame_payload_size_ == expected_payload_size_) complete_frame();
        pump_responses();
        return;
    }
    if (size > read_buffer_.size()) {
        connection_error(internal_error);
        return;
    }
    consume_input(std::span {read_buffer_}.first(size));
    pump_responses();
}

auto session::output() const noexcept -> std::span<const std::byte>
{
    return std::span {output_}.subspan(output_offset_,
        std::min({output_size_, output_.size() - output_offset_,
            file_send_active_ ? file_send_prefix_ : output_size_}));
}

auto session::consume_output(std::size_t size) -> void
{
    if (size > output().size()) {
        connection_error(internal_error);
        return;
    }
    output_offset_ = (output_offset_ + size) % output_.size();
    output_size_ -= size;
    if (file_send_active_) file_send_prefix_ -= size;
    if (output_size_ == 0) output_offset_ = 0;
    pump_responses();
}

auto session::take_file_send(bool include_prefix) noexcept -> std::optional<file_send>
{
    if (!file_send_active_ || !file_send_.file) return std::nullopt;
    if (file_send_prefix_ != 0) {
        // A wrapped queue is drained normally until its remaining prefix is
        // contiguous. Never expose bytes after the file ordering barrier.
        if (!include_prefix || output().size() != file_send_prefix_)
            return std::nullopt;
        file_send_.prefix = output();
    }
    return std::move(file_send_);
}

auto session::complete_file_send(http::detail::static_file file) -> void
{
    if (!file_send_active_ || file_send_prefix_ != 0 || file_send_.file || !file) {
        connection_error(internal_error);
        return;
    }
    // A nonfinal frame returns its owner to the active response. A final
    // frame (or a reset stream) closes it here, after transport completion.
    auto& value = streams_[file_send_index_];
    if (value.active && value.id == file_send_stream_)
        value.response_file = std::move(file);
    file_send_active_ = false;
    file_send_ = {};
    file_send_stream_ = 0;
    pump_responses();
}

auto session::pop_request(request& value) -> bool
{
    while (!requests_.empty()) {
        const auto* source = find_stream(requests_.front());
        requests_.erase(requests_.begin());
        if (source == nullptr) continue;
        value.stream_id = source->id;
        value.method.assign(source->method);
        value.target.assign(source->target);
        value.if_none_match.assign(source->if_none_match);
        value.if_modified_since.assign(source->if_modified_since);
        if (source->duplicate_range) value.range.clear();
        else value.range.assign(source->range);
        value.body_size = source->request_body_size;
        return true;
    }
    return false;
}

auto session::respond(std::uint32_t stream_id, unsigned status,
                      std::span<const http::header> headers,
                      std::vector<std::byte> body) -> bool
{
    auto* value = find_stream(stream_id);
    if (value == nullptr || value->response_started || fatal_) return false;
    if (body.size() > max_queued_response_body - inline_response_bytes_) {
        return false;
    }
    value->response_size = body.size();
    value->response_accounted = body.size();
    inline_response_bytes_ += body.size();
    value->response_body = std::move(body);
    if (!append_response_headers(*value, status, headers, {}, value->response_size == 0)) {
        reset_stream(*value, closed_reason::local_reset);
        return false;
    }
    pump_responses();
    return true;
}

auto session::respond_file(std::uint32_t stream_id, unsigned status,
                           std::span<const http::header> headers,
                           http::detail::static_file file,
                           std::uint64_t size, bool send_body, std::uint64_t offset) -> bool
{
    auto* value = find_stream(stream_id);
    if (value == nullptr || value->response_started || fatal_) return false;
    value->response_size = send_body ? size : 0;
    value->response_offset = 0;
    value->response_file_start = offset;
    if (send_body) value->response_file = std::move(file);
    if (!append_response_headers(*value, status, headers, {}, value->response_size == 0)) {
        reset_stream(*value, closed_reason::local_reset);
        return false;
    }
    pump_responses();
    return true;
}

auto session::closed() const noexcept -> bool
{
    if (output_size_ != 0 || file_send_active_) return false;
    if (fatal_) return true;
    if (!peer_goaway_) return false;
    return std::none_of(streams_.begin(), streams_.end(),
                        [](const stream& value) { return value.active; });
}

auto session::idle() const noexcept -> bool
{
    // A stream counts once its request is routed or complete, so a partial
    // header block or request body does not hold the connection open.
    return std::none_of(streams_.begin(), streams_.end(), [](const stream& value) {
        return value.active && (value.routed || value.request_ready);
    });
}

auto session::consume_input(std::span<const std::byte> input) -> void
{
    while (!input.empty() && !fatal_) {
        if (stalled_) {
            // Keep the rest for resume_input(); input lies in read_buffer_.
            std::memmove(read_buffer_.data(), input.data(), input.size());
            held_input_ = input.size();
            return;
        }
        if (preface_size_ < client_preface.size()) {
            const auto expected = static_cast<unsigned char>(
                client_preface[preface_size_]);
            if (byte_value(input.front()) != expected) {
                connection_error(protocol_error);
                return;
            }
            ++preface_size_;
            input = input.subspan(1);
            continue;
        }

        if (frame_header_size_ < frame_header_.size()) {
            const auto count = std::min(input.size(),
                frame_header_.size() - frame_header_size_);
            std::memcpy(frame_header_.data() + frame_header_size_,
                        input.data(), count);
            frame_header_size_ += count;
            input = input.subspan(count);
            if (frame_header_size_ != frame_header_.size()) continue;

            expected_payload_size_ =
                (static_cast<std::size_t>(byte_value(frame_header_[0])) << 16) |
                (static_cast<std::size_t>(byte_value(frame_header_[1])) << 8) |
                static_cast<std::size_t>(byte_value(frame_header_[2]));
            frame_type_ = byte_value(frame_header_[3]);
            frame_flags_ = byte_value(frame_header_[4]);
            const auto raw_stream = read_u32(frame_header_.data() + 5);
            frame_stream_id_ = raw_stream & 0x7fffffffu;
            frame_payload_size_ = 0;
            if (expected_payload_size_ > max_frame_payload) {
                connection_error(frame_size_error);
                return;
            }
            if (continuation_stream_id_ != 0 &&
                (frame_type_ != continuation_frame ||
                 frame_stream_id_ != continuation_stream_id_)) {
                connection_error(protocol_error);
                return;
            }
            if (!got_first_settings_ &&
                (frame_type_ != settings_frame || frame_stream_id_ != 0 ||
                 (frame_flags_ & flag_ack) != 0)) {
                connection_error(protocol_error);
                return;
            }
        }

        const auto remaining = expected_payload_size_ - frame_payload_size_;
        if (frame_payload_size_ == 0 && input.size() >= remaining) {
            // The whole payload is in input: dispatch it where it lies.
            frame_data_ = input.data();
            frame_payload_size_ = remaining;
            input = input.subspan(remaining);
            dispatch_frame();
            if (stalled_) {
                // read_buffer_ moves while paused; keep the frame for redispatch.
                std::memcpy(frame_payload_.data(), frame_data_, frame_payload_size_);
            } else {
                clear_frame_state();
            }
            frame_data_ = frame_payload_.data();
            continue;
        }
        const auto count = std::min(input.size(), remaining);
        if (count != 0) {
            std::memcpy(frame_payload_.data() + frame_payload_size_,
                        input.data(), count);
            frame_payload_size_ += count;
            input = input.subspan(count);
        }
        if (frame_payload_size_ == expected_payload_size_) complete_frame();
    }
}

auto session::complete_frame() -> void
{
    dispatch_frame();
    // A paused DATA frame stays buffered and is dispatched again.
    if (!stalled_) clear_frame_state();
}

auto session::clear_frame_state() noexcept -> void
{
    frame_header_size_ = 0;
    frame_payload_size_ = 0;
    expected_payload_size_ = 0;
}

auto session::payload_read_space() noexcept -> std::span<std::byte>
{
    if (stalled_ || fatal_ || preface_size_ < client_preface.size() ||
        frame_header_size_ < frame_header_.size()) return {};
    const auto remaining = expected_payload_size_ - frame_payload_size_;
    // Smaller remainders share one read with the frames that follow.
    if (remaining < read_buffer_.size()) return {};
    return std::span {frame_payload_}.subspan(frame_payload_size_, remaining);
}

auto session::record_closed(std::uint32_t id, closed_reason reason) noexcept -> void
{
    auto& slot = closed_streams_[closed_next_];
    if (slot.id != 0) closed_floor_ = std::max(closed_floor_, slot.id);
    slot = closed_stream {id, reason};
    closed_next_ = (closed_next_ + 1) % closed_history;
}

auto session::closed_reason_of(std::uint32_t id) const noexcept
    -> std::optional<closed_reason>
{
    for (const auto& entry : closed_streams_) {
        if (entry.id == id) return entry.reason;
    }
    if (id <= closed_floor_) return closed_reason::local_reset;
    return std::nullopt;
}

auto session::dispatch_frame() -> void
{
    switch (frame_type_) {
    case data_frame: dispatch_data(); break;
    case headers_frame: dispatch_headers(); break;
    case priority_frame: {
        if (frame_stream_id_ == 0) {
            connection_error(protocol_error);
            return;
        }
        if (frame_payload_size_ != 5) {
            connection_error(frame_size_error);
            return;
        }
        const auto dependency = read_u32(frame_data_) & 0x7fffffffu;
        if (dependency == frame_stream_id_) {
            stream_error(frame_stream_id_, protocol_error);
        }
        break;
    }
    case reset_frame: {
        if (frame_stream_id_ == 0) {
            connection_error(protocol_error);
            return;
        }
        if (frame_payload_size_ != 4) {
            connection_error(frame_size_error);
            return;
        }
        if ((frame_stream_id_ & 1u) == 0) {
            connection_error(protocol_error);
            return;
        }
        if (auto* value = find_stream(frame_stream_id_)) {
            reset_stream(*value, closed_reason::peer_reset);
        } else if (frame_stream_id_ > last_stream_id_ ||
                   !closed_reason_of(frame_stream_id_)) {
            connection_error(protocol_error);
        }
        break;
    }
    case settings_frame: dispatch_settings(); break;
    case push_promise_frame:
        connection_error(protocol_error);
        break;
    case ping_frame:
        if (frame_stream_id_ != 0) {
            connection_error(protocol_error);
        } else if (frame_payload_size_ != 8) {
            connection_error(frame_size_error);
        } else if ((frame_flags_ & flag_ack) == 0 &&
                   !append_frame(ping_frame, flag_ack, 0,
                                 std::span {frame_data_, 8})) {
            connection_error(internal_error);
        }
        break;
    case goaway_frame:
        if (frame_stream_id_ != 0) {
            connection_error(protocol_error);
        } else if (frame_payload_size_ < 8) {
            connection_error(frame_size_error);
        } else {
            peer_goaway_ = true;
        }
        break;
    case window_update_frame: dispatch_window_update(); break;
    case priority_update_frame: dispatch_priority_update(); break;
    case continuation_frame:
        if (continuation_stream_id_ == 0 ||
            frame_stream_id_ != continuation_stream_id_) {
            connection_error(protocol_error);
            return;
        }
        if (frame_payload_size_ > hpack_max_block_size - header_block_.size()) {
            connection_error(enhance_your_calm_error);
            return;
        }
        header_block_.insert(header_block_.end(), frame_data_,
            frame_data_ + static_cast<std::ptrdiff_t>(frame_payload_size_));
        if ((frame_flags_ & flag_end_headers) != 0) finish_header_block();
        break;
    default:
        // Unknown extension frames are ignored as required by RFC 9113.
        break;
    }
}

auto session::dispatch_headers() -> void
{
    if (frame_stream_id_ == 0) {
        connection_error(protocol_error);
        return;
    }
    auto* value = find_stream(frame_stream_id_);
    header_refused_ = false;
    header_trailers_ = false;
    header_reject_error_ = refused_stream_error;
    header_closed_reply_ = false;
    if (value == nullptr) {
        if ((frame_stream_id_ & 1u) == 0) {
            connection_error(protocol_error);
            return;
        }
        if (frame_stream_id_ <= last_stream_id_) {
            const auto reason = closed_reason_of(frame_stream_id_);
            if (!reason) {
                // A lower id than one already opened was never used.
                connection_error(protocol_error);
                return;
            }
            if (*reason == closed_reason::ended) {
                connection_error(stream_closed_error);
                return;
            }
            header_refused_ = true;
            header_reject_error_ = stream_closed_error;
            header_closed_reply_ = *reason == closed_reason::peer_reset;
        } else {
            last_stream_id_ = frame_stream_id_;
            value = peer_goaway_ ? nullptr : allocate_stream(frame_stream_id_);
            if (value == nullptr) {
                header_refused_ = true;
                record_closed(frame_stream_id_, closed_reason::local_reset);
            }
        }
    } else if (!value->initial_headers || value->remote_closed ||
               value->request_ready) {
        header_refused_ = true;
        header_reject_error_ = stream_closed_error;
    } else {
        header_trailers_ = true;
    }

    std::size_t offset = 0;
    std::size_t padding = 0;
    if ((frame_flags_ & flag_padded) != 0) {
        if (frame_payload_size_ == 0) {
            connection_error(protocol_error);
            return;
        }
        padding = byte_value(frame_data_[offset++]);
    }
    if ((frame_flags_ & flag_priority) != 0) {
        if (frame_payload_size_ - offset < 5) {
            connection_error(frame_size_error);
            return;
        }
        const auto dependency = read_u32(frame_data_ + offset) & 0x7fffffffu;
        if (dependency == frame_stream_id_) {
            header_refused_ = true;
            header_reject_error_ = protocol_error;
        }
        offset += 5;
    }
    if (padding > frame_payload_size_ - offset) {
        connection_error(protocol_error);
        return;
    }

    header_stream_id_ = frame_stream_id_;
    header_end_stream_ = (frame_flags_ & flag_end_stream) != 0;
    const auto fragment_size = frame_payload_size_ - offset - padding;
    header_block_.clear();
    if (fragment_size > hpack_max_block_size) {
        connection_error(enhance_your_calm_error);
        return;
    }
    header_block_.insert(header_block_.end(),
        frame_data_ + static_cast<std::ptrdiff_t>(offset),
        frame_data_ + static_cast<std::ptrdiff_t>(offset + fragment_size));
    if ((frame_flags_ & flag_end_headers) != 0) {
        finish_header_block();
    } else {
        continuation_stream_id_ = frame_stream_id_;
    }
}

auto session::dispatch_data() -> void
{
    if (frame_stream_id_ == 0) {
        connection_error(protocol_error);
        return;
    }
    if ((frame_stream_id_ & 1u) == 0) {
        connection_error(protocol_error);
        return;
    }
    const auto flow_size = static_cast<std::int64_t>(frame_payload_size_);
    const auto return_connection_credit = [&] {
        connection_receive_window_ += flow_size;
        if (flow_size != 0) {
            send_window_update(0, static_cast<std::uint32_t>(flow_size));
        }
    };
    auto* value = find_stream(frame_stream_id_);
    if (value != nullptr && value->routed && value->body_slot != no_slot && !value->too_large) {
        // Checked before any accounting so a paused frame can be redispatched.
        std::size_t payload = frame_payload_size_;
        if ((frame_flags_ & flag_padded) != 0 && payload != 0) {
            const auto pad = byte_value(frame_data_[0]);
            payload = pad < payload ? payload - 1 - pad : 0;
        }
        if (payload > route_body_slot_size - (value->body_end - value->body_begin)) {
            stalled_ = true;
            stalled_need_ = payload;
            return;
        }
    }
    if (value == nullptr) {
        if (frame_stream_id_ > last_stream_id_) {
            connection_error(protocol_error);
            return;
        }
        const auto reason = closed_reason_of(frame_stream_id_);
        if (!reason) {
            connection_error(protocol_error);
            return;
        }
        connection_receive_window_ -= flow_size;
        if (connection_receive_window_ < 0) {
            connection_error(flow_control_error);
            return;
        }
        return_connection_credit();
        // After both sides ended RFC 9113 requires a connection error, after
        // the peer's RST_STREAM a stream error. Frames racing our own
        // RST_STREAM are discarded.
        if (*reason == closed_reason::ended) {
            connection_error(stream_closed_error);
        } else if (*reason == closed_reason::peer_reset) {
            stream_error(frame_stream_id_, stream_closed_error);
        }
        return;
    }
    connection_receive_window_ -= flow_size;
    if (connection_receive_window_ < 0) {
        connection_error(flow_control_error);
        return;
    }
    if (!value->initial_headers || value->remote_closed || value->request_ready) {
        return_connection_credit();
        stream_error(frame_stream_id_, stream_closed_error);
        return;
    }
    value->receive_window -= flow_size;
    if (value->receive_window < 0) {
        return_connection_credit();
        stream_error(frame_stream_id_, flow_control_error);
        return;
    }

    std::size_t offset = 0;
    std::size_t padding = 0;
    if ((frame_flags_ & flag_padded) != 0) {
        if (frame_payload_size_ == 0) {
            connection_error(protocol_error);
            return;
        }
        padding = byte_value(frame_data_[offset++]);
    }
    if (padding > frame_payload_size_ - offset) {
        connection_error(protocol_error);
        return;
    }
    const auto data_size = frame_payload_size_ - offset - padding;
    if (data_size > std::numeric_limits<std::uint64_t>::max() -
                        value->request_body_size) {
        return_connection_credit();
        stream_error(frame_stream_id_, enhance_your_calm_error);
        return;
    }
    value->request_body_size += data_size;
    if (value->content_length && value->request_body_size > *value->content_length) {
        return_connection_credit();
        stream_error(frame_stream_id_, protocol_error);
        return;
    }
    if (value->routed) {
        return_connection_credit();
        if (value->connect == connect_state::none && value->request_body_size > max_routed_body_)
            value->too_large = true;
        // Buffered bytes return their stream credit when the handler reads
        // them; padding, and bodies past the limit, return it now.
        std::int64_t credit = flow_size;
        if (!value->too_large && value->body_slot != no_slot && data_size != 0) {
            auto* slot = body_slot(*value);
            if (route_body_slot_size - value->body_end < data_size) {
                std::memmove(slot, slot + value->body_begin, value->body_end - value->body_begin);
                value->body_end -= value->body_begin;
                value->body_begin = 0;
            }
            std::memcpy(slot + value->body_end, frame_data_ + offset, data_size);
            value->body_end += data_size;
            credit -= static_cast<std::int64_t>(data_size);
        }
        if (credit > 0) {
            value->receive_window += credit;
            send_window_update(frame_stream_id_, static_cast<std::uint32_t>(credit));
        }
        if ((frame_flags_ & flag_end_stream) != 0) finish_request(*value);
        return;
    }
    if (value->request_body_size > max_request_body) {
        return_connection_credit();
        stream_error(frame_stream_id_, enhance_your_calm_error);
        return;
    }

    if (flow_size != 0) {
        return_connection_credit();
        value->receive_window += flow_size;
        send_window_update(frame_stream_id_, static_cast<std::uint32_t>(flow_size));
    }
    if ((frame_flags_ & flag_end_stream) != 0) finish_request(*value);
}

auto session::dispatch_settings() -> void
{
    if (frame_stream_id_ != 0) {
        connection_error(protocol_error);
        return;
    }
    const bool ack = (frame_flags_ & flag_ack) != 0;
    if (ack) {
        if (frame_payload_size_ != 0) {
            connection_error(frame_size_error);
        } else if (server_settings_acked_) {
            connection_error(protocol_error);
        } else {
            server_settings_acked_ = true;
        }
        return;
    }
    if (frame_payload_size_ % 6 != 0) {
        connection_error(frame_size_error);
        return;
    }
    got_first_settings_ = true;
    for (std::size_t offset = 0; offset < frame_payload_size_; offset += 6) {
        const auto id = static_cast<std::uint16_t>(
            (byte_value(frame_data_[offset]) << 8) |
             byte_value(frame_data_[offset + 1]));
        const auto value = read_u32(frame_data_ + offset + 2);
        if ((id == 2 || id == 8 || id == 9) && value > 1) {
            connection_error(protocol_error);
            return;
        }
        if (id == 4) {
            if (value > max_window_size) {
                connection_error(flow_control_error);
                return;
            }
            const auto delta = static_cast<std::int64_t>(value) -
                               static_cast<std::int64_t>(peer_initial_window_);
            peer_initial_window_ = value;
            for (auto& stream_value : streams_) {
                if (!stream_value.active) continue;
                stream_value.send_window += delta;
                if (stream_value.send_window > max_window_size) {
                    connection_error(flow_control_error);
                    return;
                }
            }
        } else if (id == 5 &&
                   (value < max_frame_payload || value > 0x00ffffffu)) {
            connection_error(protocol_error);
            return;
        }
    }
    if (!append_frame(settings_frame, flag_ack, 0)) {
        connection_error(internal_error);
    }
}

// RFC 9218 section 7.1. An update replaces the stream's priority; omitted
// parameters take their defaults. Updates for streams that are not open,
// including streams the client has not opened yet, are ignored.
auto session::dispatch_priority_update() -> void
{
    if (frame_stream_id_ != 0) {
        connection_error(protocol_error);
        return;
    }
    if (frame_payload_size_ < 4) {
        connection_error(frame_size_error);
        return;
    }
    const auto id = read_u32(frame_data_) & 0x7fffffffu;
    if (id == 0) {
        connection_error(protocol_error);
        return;
    }
    auto* value = find_stream(id);
    if (value == nullptr) return;
    std::uint8_t urgency = 3;
    bool incremental = false;
    const std::string_view text(reinterpret_cast<const char*>(frame_data_) + 4,
                                frame_payload_size_ - 4);
    if (!parse_priority(text, urgency, incremental)) return;
    value->urgency = urgency;
    value->incremental = incremental;
}

auto session::dispatch_window_update() -> void
{
    if (frame_payload_size_ != 4) {
        connection_error(frame_size_error);
        return;
    }
    const auto increment = read_u32(frame_data_) & 0x7fffffffu;
    if (increment == 0) {
        if (frame_stream_id_ == 0) connection_error(protocol_error);
        else stream_error(frame_stream_id_, protocol_error);
        return;
    }
    if (frame_stream_id_ == 0) {
        if (connection_send_window_ + increment > max_window_size) {
            connection_error(flow_control_error);
            return;
        }
        connection_send_window_ += increment;
        pump_responses();
        return;
    }
    if ((frame_stream_id_ & 1u) == 0) {
        connection_error(protocol_error);
        return;
    }
    if (auto* value = find_stream(frame_stream_id_)) {
        if (value->send_window + increment > max_window_size) {
            stream_error(frame_stream_id_, flow_control_error);
            return;
        }
        value->send_window += increment;
        pump_responses();
    } else if (frame_stream_id_ > last_stream_id_ ||
               !closed_reason_of(frame_stream_id_)) {
        connection_error(protocol_error);
    }
}

auto session::finish_header_block() -> void
{
    continuation_stream_id_ = 0;
    const auto decoded = decoder_.decode(header_block_, decoded_fields_);
    if (decoded != hpack_error::none) {
        connection_error(decoded == hpack_error::invalid
            ? compression_error : enhance_your_calm_error);
        return;
    }
    if (header_refused_) {
        // Frames racing our own RST_STREAM are discarded; after the peer's
        // RST_STREAM they draw STREAM_CLOSED (RFC 9113 section 5.1).
        const bool race = header_reject_error_ == stream_closed_error &&
            find_stream(header_stream_id_) == nullptr && !header_closed_reply_;
        if (!race && (header_reject_error_ != stream_closed_error ||
                      find_stream(header_stream_id_) != nullptr ||
                      header_closed_reply_)) {
            stream_error(header_stream_id_, header_reject_error_);
        }
        header_block_.clear();
        return;
    }
    auto* value = find_stream(header_stream_id_);
    if (value == nullptr) {
        stream_error(header_stream_id_, stream_closed_error);
        header_block_.clear();
        return;
    }
    if (header_trailers_) {
        if (value->connect == connect_state::accepted || !header_end_stream_ ||
            !validate_trailers(decoded_fields_)) {
            stream_error(header_stream_id_, protocol_error);
        } else {
            finish_request(*value);
        }
    } else if (value->initial_headers ||
               !validate_initial_headers(*value, decoded_fields_)) {
        stream_error(header_stream_id_, protocol_error);
    } else {
        value->initial_headers = true;
        if (value->connect == connect_state::unsupported) {
            (void)respond(value->id, 501, {}, {});
            stream_error(value->id, 0);
            header_block_.clear();
            return;
        }
        if (routes_ != nullptr) (void)route_stream(*value);
        // Routing may refuse the stream when no body buffer is free.
        if (header_end_stream_ && value->active) finish_request(*value);
    }
    header_block_.clear();
}

auto session::finish_request(stream& value) -> void
{
    if (value.remote_closed) {
        stream_error(value.id, stream_closed_error);
        return;
    }
    if (value.content_length && value.request_body_size != *value.content_length) {
        stream_error(value.id, protocol_error);
        return;
    }
    value.remote_closed = true;
    if (value.routed) {
        // The handler already has the request; its body is complete.
        value.body_ended = true;
        if (value.stream_finished) complete_stream(value);
        return;
    }
    value.request_ready = true;
    // The stream keeps its fields until pop_request() copies them out.
    requests_.push_back(value.id);
}

auto session::validate_initial_headers(stream& value,
                                       std::span<const field> fields) -> bool
{
    std::string_view method;
    std::string_view scheme;
    std::string_view target;
    std::string_view authority;
    std::string_view connect_protocol;
    std::string_view host;
    std::optional<std::uint64_t> content_length;
    bool regular_field_seen = false;
    bool method_seen = false;
    bool scheme_seen = false;
    bool target_seen = false;
    bool authority_seen = false;
    bool protocol_seen = false;
    bool host_seen = false;
    std::uint8_t urgency = 3;
    bool incremental = false;
    bool priority_valid = true;

    for (const auto& entry : fields) {
        if (!valid_header_name(entry.name) || !valid_header_value(entry.value)) {
            return false;
        }
        const bool pseudo = entry.name.front() == ':';
        if (pseudo && regular_field_seen) return false;
        if (!pseudo) regular_field_seen = true;

        if (pseudo) {
            if (entry.name == ":method") {
                if (method_seen) return false;
                method_seen = true;
                method = entry.value;
            } else if (entry.name == ":scheme") {
                if (scheme_seen) return false;
                scheme_seen = true;
                scheme = entry.value;
            } else if (entry.name == ":path") {
                if (target_seen) return false;
                target_seen = true;
                target = entry.value;
            } else if (entry.name == ":authority") {
                if (authority_seen) return false;
                authority_seen = true;
                authority = entry.value;
            } else if (entry.name == ":protocol") {
                if (routes_ == nullptr || protocol_seen || !valid_method(entry.value)) return false;
                protocol_seen = true;
                connect_protocol = entry.value;
            } else {
                return false;
            }
            continue;
        }
        if (forbidden_connection_header(entry.name)) return false;
        if (entry.name == "te" && !ascii_equal(entry.value, "trailers")) return false;
        if (entry.name == "host") {
            if (host_seen) return false;
            host_seen = true;
            host = entry.value;
        }
        if (entry.name == "content-length") {
            std::uint64_t parsed = 0;
            if (!parse_decimal(entry.value, parsed) ||
                (content_length && *content_length != parsed)) return false;
            content_length = parsed;
        }
        // Repeated Priority lines form one dictionary; a syntax error in any
        // of them leaves the defaults in place.
        if (entry.name == "priority" && priority_valid)
            priority_valid = parse_priority(entry.value, urgency, incremental);
        if (entry.name == "if-none-match") {
            if (!value.if_none_match.empty()) value.if_none_match += ',';
            value.if_none_match += entry.value;
        } else if (entry.name == "if-modified-since") {
            if (value.if_modified_since.empty()) value.if_modified_since = entry.value;
        } else if (entry.name == "range") {
            if (!value.range.empty()) value.duplicate_range = true;
            else value.range = entry.value;
        }
    }

    if (!method_seen || !valid_method(method)) return false;
    const bool connect = method == "CONNECT";
    if (protocol_seen && !connect) return false;
    const bool extended = connect && protocol_seen;
    if (connect && !extended) {
        if (!authority_seen || authority.empty() || scheme_seen || target_seen) {
            return false;
        }
        target = authority;
    } else if (!scheme_seen || scheme.empty() || !target_seen || target.empty()) {
        return false;
    } else if (target != "*" && target.front() != '/') {
        return false;
    } else if (target == "*" && method != "OPTIONS") {
        return false;
    }
    if (extended && (!authority_seen || authority.empty())) return false;
    if (connect_protocol == "websocket" && !ascii_equal(scheme, "http") &&
        !ascii_equal(scheme, "https")) return false;
    if (!connect || extended) {
        const auto alpha = [](unsigned char byte) {
            return (byte >= 'a' && byte <= 'z') ||
                   (byte >= 'A' && byte <= 'Z');
        };
        if (!alpha(static_cast<unsigned char>(scheme.front()))) return false;
        for (const unsigned char byte : scheme) {
            if (!alpha(byte) && !(byte >= '0' && byte <= '9') &&
                byte != '+' && byte != '-' && byte != '.') return false;
        }
        if (target.find('#') != std::string_view::npos) return false;
        if (!valid_request_target(target)) return false;
        if ((ascii_equal(scheme, "http") || ascii_equal(scheme, "https")) &&
            authority_seen && authority.find('@') != std::string_view::npos) {
            return false;
        }
    }
    if (authority_seen && authority.empty()) return false;
    if (authority_seen && host_seen && !ascii_equal(authority, host)) return false;
    value.method.assign(method);
    value.target.assign(target);
    value.content_length = content_length;
    value.connect = !extended ? connect_state::none : connect_protocol == "websocket"
        ? connect_state::websocket : connect_state::unsupported;
    if (priority_valid) {
        value.urgency = urgency;
        value.incremental = incremental;
    }
    return true;
}

auto session::validate_trailers(std::span<const field> fields) const -> bool
{
    for (const auto& entry : fields) {
        if (entry.name.empty() || entry.name.front() == ':' ||
            !valid_header_name(entry.name) || !valid_header_value(entry.value) ||
            forbidden_connection_header(entry.name) || entry.name == "content-length" ||
            entry.name == "host" || entry.name == "te") return false;
    }
    return true;
}

auto session::find_stream(std::uint32_t id) noexcept -> stream*
{
    const auto found = std::find_if(streams_.begin(), streams_.end(),
        [id](const stream& value) { return value.active && value.id == id; });
    return found == streams_.end() ? nullptr : &*found;
}

auto session::allocate_stream(std::uint32_t id) noexcept -> stream*
{
    const auto found = std::find_if(streams_.begin(), streams_.end(),
        [](const stream& value) { return !value.active; });
    if (found == streams_.end()) return nullptr;
    found->id = id;
    found->receive_window = 65535;
    found->send_window = peer_initial_window_;
    found->request_body_size = 0;
    found->content_length.reset();
    found->method.clear();
    found->target.clear();
    found->if_none_match.clear();
    found->if_modified_since.clear();
    found->range.clear();
    found->duplicate_range = false;
    found->response_body.clear();
    found->response_file.reset();
    found->response_size = 0;
    found->response_offset = 0;
    found->response_accounted = 0;
    found->active = true;
    found->initial_headers = false;
    found->remote_closed = false;
    found->request_ready = false;
    found->response_started = false;
    found->urgency = 3;
    found->incremental = false;
    return &*found;
}

auto session::reset_stream(stream& value, closed_reason reason) noexcept -> void
{
    record_closed(value.id, reason);
    if (value.response_accounted <= inline_response_bytes_) {
        inline_response_bytes_ -= value.response_accounted;
    } else {
        inline_response_bytes_ = 0;
    }
    std::erase(requests_, value.id);
    if (value.body_slot != no_slot) slot_used_[value.body_slot] = false;
    if (value.routed) {
        std::erase_if(routed_, [&value](const routed_request& pending) {
            return pending.stream_id == value.id;
        });
        if (release_hook_ != nullptr)
            release_hook_(release_context_, value.id, value.stream_finished);
    }
    // Keep header string capacity for the slot's next stream, which
    // allocate_stream clears: libc++ frees it when a fresh stream is
    // move-assigned, so steady-state requests would allocate.
    static constexpr std::string stream::* kept[] {&stream::method, &stream::target,
        &stream::if_none_match, &stream::if_modified_since, &stream::range};
    std::array<std::string, std::size(kept)> buffers;
    for (std::size_t i = 0; i < buffers.size(); ++i) buffers[i] = std::move(value.*kept[i]);
    value = stream {};
    for (std::size_t i = 0; i < buffers.size(); ++i) value.*kept[i] = std::move(buffers[i]);
}

// Routes a stream whose request headers were just validated. Returns false
// when the path has no handler for the method, leaving static dispatch.
auto session::route_stream(stream& value) -> bool
{
    const std::string_view target = value.target;
    const auto match = http::detail::router_access::match(*routes_,
        http::detail::method_from_name(value.method), target.substr(0, target.find('?')));
    if (match.function == nullptr) {
        if (value.connect == connect_state::none) return false;
        std::array<char, 96> allow {};
        const auto count = http::detail::format_allow(match.allowed, allow);
        const std::array<http::header, 1> headers {{{"allow", {allow.data(), count}}}};
        (void)respond(value.id, match.allowed == 0 ? 404 : 405,
            match.allowed == 0 ? std::span<const http::header> {} : std::span<const http::header>(headers), {});
        stream_error(value.id, 0);
        return true;
    }
    value.routed = true;
    const bool too_large = value.connect == connect_state::none && value.content_length &&
                          *value.content_length > max_routed_body_;
    if (!header_end_stream_ && !too_large) {
        value.body_slot = acquire_body_slot();
        if (value.body_slot == no_slot) {
            // Every body buffer is busy: the request was not processed and a
            // client may retry it (RFC 9113 8.7).
            value.routed = false;
            stream_error(value.id, refused_stream_error);
            return true;
        }
    }
    value.too_large = too_large;
    routed_request announced {
        .stream_id = value.id,
        .match = match,
        .fields = {},
        .content_length = value.content_length,
        .too_large = too_large,
    };
    announced.fields.swap(decoded_fields_);
    routed_.push_back(std::move(announced));
    return true;
}

auto session::acquire_body_slot() noexcept -> std::uint8_t
{
    if (!body_arena_) {
        body_arena_.reset(new (std::nothrow) std::byte[route_body_slots * route_body_slot_size]);
        if (!body_arena_) return no_slot;
    }
    for (std::uint8_t index = 0; index < route_body_slots; ++index) {
        if (slot_used_[index]) continue;
        slot_used_[index] = true;
        return index;
    }
    return no_slot;
}

auto session::body_slot(const stream& value) noexcept -> std::byte*
{
    return body_arena_.get() + std::size_t {value.body_slot} * route_body_slot_size;
}

// Releases a routed stream whose response has ended. A request body still
// arriving is no longer needed (RFC 9113 8.1).
auto session::complete_stream(stream& value) -> void
{
    if (!value.body_ended) {
        stream_error(value.id, 0);
    } else {
        reset_stream(value);
    }
}

auto session::set_release_hook(release_hook hook, void* context) noexcept -> void
{
    release_hook_ = hook;
    release_context_ = context;
}

auto session::recycle_fields(std::vector<field>&& fields) noexcept -> void
{
    if (decoded_fields_.capacity() == 0) decoded_fields_.swap(fields);
}

auto session::pop_routed(routed_request& value) -> bool
{
    if (routed_.empty()) return false;
    value = std::move(routed_.front());
    routed_.erase(routed_.begin());
    return true;
}

auto session::read_body(std::uint32_t stream_id, std::span<std::byte> output,
                        std::size_t& count) -> body_state
{
    count = 0;
    auto* value = find_stream(stream_id);
    if (value == nullptr || !value->routed || fatal_) return body_state::failed;
    if (value->too_large) return body_state::too_large;
    const auto available = value->body_end - value->body_begin;
    if (available != 0) {
        count = std::min(output.size(), available);
        std::memcpy(output.data(), body_slot(*value) + value->body_begin, count);
        value->body_begin += count;
        if (value->body_begin == value->body_end) value->body_begin = value->body_end = 0;
        if (!value->remote_closed) {
            value->receive_window += static_cast<std::int64_t>(count);
            send_window_update(stream_id, static_cast<std::uint32_t>(count));
        }
        return body_state::data;
    }
    return value->body_ended ? body_state::ended : body_state::waiting;
}

auto session::start_streamed(std::uint32_t stream_id, unsigned status,
                             std::span<const http::header> headers,
                             std::span<const http::header> extra, bool websocket) -> bool
{
    auto* value = find_stream(stream_id);
    if (value == nullptr || !value->routed || value->response_started || fatal_) return false;
    if (websocket && (value->connect != connect_state::websocket || value->content_length))
        return false;
    value->streaming = true;
    if (!append_response_headers(*value, status, headers, extra, false)) {
        stream_error(stream_id, internal_error);
        return false;
    }
    if (websocket) value->connect = connect_state::accepted;
    return true;
}

auto session::queue_chunk(std::uint32_t stream_id, std::span<const std::byte> data) -> bool
{
    auto* value = find_stream(stream_id);
    if (value == nullptr || !value->streaming || value->stream_finished || fatal_) return false;
    value->chunk = data;
    pump_responses();
    return true;
}

auto session::chunk_pending(std::uint32_t stream_id) const noexcept -> bool
{
    const auto found = std::find_if(streams_.begin(), streams_.end(),
        [stream_id](const stream& value) { return value.active && value.id == stream_id; });
    return found != streams_.end() && !found->chunk.empty() && !fatal_;
}

auto session::finish_streamed(std::uint32_t stream_id, std::span<const http::header> trailers)
    -> bool
{
    auto* value = find_stream(stream_id);
    if (value == nullptr || !value->streaming || value->stream_finished ||
        !value->chunk.empty() || fatal_) return false;
    const bool queued = trailers.empty()
        ? append_frame(data_frame, flag_end_stream, stream_id)
        : append_header_block(*value, 0, trailers, {}, true);
    if (!queued) {
        stream_error(stream_id, internal_error);
        return false;
    }
    value->stream_finished = true;
    if (value->connect != connect_state::accepted || value->body_ended) complete_stream(*value);
    return true;
}

auto session::send_streamed_file(std::uint32_t stream_id, unique_fd file,
                                 std::uint64_t offset, std::uint64_t size) -> bool
{
    auto* value = find_stream(stream_id);
    if (value == nullptr || !value->streaming || value->stream_finished || size == 0 ||
        fatal_) return false;
    // The file is sent by the static scheduler, which ends the stream.
    value->streaming = false;
    value->response_file = std::move(file);
    value->response_file_start = offset;
    value->response_offset = 0;
    value->response_size = size;
    pump_responses();
    return true;
}

auto session::stream_open(std::uint32_t stream_id) const noexcept -> bool
{
    return !fatal_ && std::any_of(streams_.begin(), streams_.end(),
        [stream_id](const stream& value) { return value.active && value.id == stream_id; });
}

auto session::body_ready(std::uint32_t stream_id) const noexcept -> bool
{
    const auto found = std::find_if(streams_.begin(), streams_.end(),
        [stream_id](const stream& value) { return value.active && value.id == stream_id; });
    return found == streams_.end() || fatal_ || found->too_large ||
           found->body_end != found->body_begin || found->body_ended;
}

auto session::abandon(std::uint32_t stream_id, std::uint32_t error) -> void
{
    if (find_stream(stream_id) != nullptr) stream_error(stream_id, error);
}

auto session::resume_input() -> void
{
    if (!stalled_ || fatal_) return;
    // Retry only once the stream has released room, or is gone.
    const auto* value = find_stream(frame_stream_id_);
    if (value != nullptr && value->routed && value->body_slot != no_slot && !value->too_large &&
        stalled_need_ > route_body_slot_size - (value->body_end - value->body_begin)) return;
    stalled_ = false;
    complete_frame();
    if (stalled_) return;
    const auto held = held_input_;
    held_input_ = 0;
    consume_input(std::span {read_buffer_}.first(held));
    pump_responses();
}

auto session::stream_error(std::uint32_t id, std::uint32_t error) -> void
{
    std::array<std::byte, 4> payload {};
    write_u32(payload.data(), error);
    if (!append_frame(reset_frame, 0, id, payload)) {
        fatal_ = true;
        return;
    }
    if (auto* value = find_stream(id)) reset_stream(*value, closed_reason::local_reset);
}

auto session::connection_error(std::uint32_t error) -> void
{
    if (fatal_) return;
    std::array<std::byte, 8> payload {};
    write_u32(payload.data(), last_stream_id_ & 0x7fffffffu);
    write_u32(payload.data() + 4, error);
    (void)append_frame(goaway_frame, 0, 0, payload);
    requests_.clear();
    fatal_ = true;
}

auto session::send_window_update(std::uint32_t id,
                                 std::uint32_t increment) -> void
{
    if (increment == 0 || increment > max_window_size) return;
    std::array<std::byte, 4> payload {};
    write_u32(payload.data(), increment);
    if (!append_frame(window_update_frame, 0, id, payload)) {
        connection_error(internal_error);
    }
}

auto session::reserve_output(std::size_t needed, std::size_t file_payload_size) -> bool
{
    const auto reserved = file_send_active_ ? file_send_.size : 0;
    if (needed + file_payload_size > max_output_size - output_size_ - reserved)
        return false;
    if (needed > output_.size() - output_size_) {
        // Grow only when needed, up to the queue bound. Once grown, partial
        // transport writes recycle space without moving any pending bytes.
        const auto capacity = std::min(max_output_size,
            std::max(output_.size() * 2, output_size_ + needed));
        std::vector<std::byte> grown(capacity);
        const auto first = std::min(output_size_, output_.size() - output_offset_);
        std::memcpy(grown.data(), output_.data() + output_offset_, first);
        if (first != output_size_) {
            std::memcpy(grown.data() + first, output_.data(), output_size_ - first);
        }
        output_ = std::move(grown);
        output_offset_ = 0;
    }
    return true;
}

auto session::append_output(std::span<const std::byte> bytes) noexcept -> void
{
    if (bytes.empty()) return;
    const auto tail = (output_offset_ + output_size_) % output_.size();
    if (bytes.size() <= output_.size() - tail) {
        // Keeps fixed-size headers a fixed-size copy once inlined.
        std::memcpy(output_.data() + tail, bytes.data(), bytes.size());
    } else {
        const auto first = output_.size() - tail;
        std::memcpy(output_.data() + tail, bytes.data(), first);
        std::memcpy(output_.data(), bytes.data() + first, bytes.size() - first);
    }
    output_size_ += bytes.size();
}

auto session::frame_header(std::size_t size, std::uint8_t type, std::uint8_t flags,
                           std::uint32_t stream_id) noexcept -> std::array<std::byte, 9>
{
    std::array<std::byte, 9> header {};
    header[0] = static_cast<std::byte>((size >> 16) & 0xff);
    header[1] = static_cast<std::byte>((size >> 8) & 0xff);
    header[2] = static_cast<std::byte>(size & 0xff);
    header[3] = static_cast<std::byte>(type);
    header[4] = static_cast<std::byte>(flags);
    write_u32(header.data() + 5, stream_id & 0x7fffffffu);
    return header;
}

auto session::append_frame(std::uint8_t type, std::uint8_t flags,
                           std::uint32_t stream_id,
                           std::span<const std::byte> payload,
                           std::size_t file_payload_size) -> bool
{
    if (file_payload_size > max_frame_payload ||
        payload.size() > max_frame_payload - file_payload_size) return false;
    if (!reserve_output(payload.size() + 9, file_payload_size)) return false;
    append_output(frame_header(payload.size() + file_payload_size, type, flags, stream_id));
    append_output(payload);
    return true;
}

auto session::append_file_frame(std::uint8_t flags, std::uint32_t stream_id,
                                native_socket file, std::uint64_t offset,
                                std::size_t size) -> file_frame
{
    if (size > max_frame_payload || !reserve_output(size + 9, 0)) return file_frame::full;
    append_output(frame_header(size, data_frame, flags, stream_id));
    const auto tail = (output_offset_ + output_size_) % output_.size();
    const auto first = std::min(size, output_.size() - tail);
    if (!http::detail::read_file_at(file, offset, std::span {output_}.subspan(tail, first)) ||
        (first != size && !http::detail::read_file_at(file, offset + first,
                              std::span {output_}.first(size - first)))) {
        output_size_ -= 9;
        return file_frame::read_failed;
    }
    output_size_ += size;
    return file_frame::appended;
}

auto session::append_response_headers(stream& value, unsigned status,
                                      std::span<const http::header> headers,
                                      std::span<const http::header> extra,
                                      bool end_stream) -> bool
{
    if (!append_header_block(value, status, headers, extra, end_stream)) return false;
    value.response_started = true;
    return true;
}

// Encodes the fields as HEADERS plus CONTINUATION frames for value. Status 0
// means no :status (trailers). The encoded block reuses one session buffer.
auto session::append_header_block(stream& value, unsigned status,
                                  std::span<const http::header> first_fields,
                                  std::span<const http::header> second_fields,
                                  bool end_stream) -> bool
{
    if (first_fields.size() + second_fields.size() >= hpack_max_fields) return false;
    auto& block = encoded_block_;
    block.clear();
    if (status != 0) {
        const std::array<char, 3> status_text {
            static_cast<char>('0' + (status / 100) % 10),
            static_cast<char>('0' + (status / 10) % 10),
            static_cast<char>('0' + status % 10),
        };
        const std::array<http::header, 1> status_field {{
            {":status", {status_text.data(), status_text.size()}}}};
        if (hpack_encode(status_field, block, true) != hpack_error::none) return false;
    }
    if (hpack_encode(first_fields, block, true) != hpack_error::none ||
        hpack_encode(second_fields, block, true) != hpack_error::none) return false;
    const auto frames = (block.size() + max_frame_payload - 1) / max_frame_payload;
    const auto needed = block.size() + 9 * std::max<std::size_t>(frames, 1);
    const auto reserved = file_send_active_ ? file_send_.size : 0;
    if (needed > max_output_size - output_size_ - reserved) return false;

    std::size_t offset = 0;
    bool first = true;
    do {
        const auto count = std::min<std::size_t>(max_frame_payload,
                                                  block.size() - offset);
        const bool last = offset + count == block.size();
        std::uint8_t flags = last ? flag_end_headers : 0;
        if (first && end_stream) flags |= flag_end_stream;
        const auto type = first ? headers_frame : continuation_frame;
        if (!append_frame(type, flags, value.id,
                std::span {block}.subspan(offset, count))) return false;
        first = false;
        offset += count;
    } while (offset < block.size());
    return true;
}

// Picks the next stream with sendable response work under RFC 9218: the
// lowest urgency first; within it, non-incremental responses one at a time in
// stream order, then incremental responses round-robin from the cursor.
// Streams blocked by flow control are skipped so they do not stall others.
auto session::next_response() const noexcept -> std::optional<std::size_t>
{
    const auto sendable = [this](const stream& value) {
        if (!value.active || !value.response_started) return false;
        if (value.streaming)
            return !value.chunk.empty() && connection_send_window_ > 0 && value.send_window > 0;
        if (value.response_size == 0) return !value.routed;
        return value.response_offset < value.response_size &&
               connection_send_window_ > 0 && value.send_window > 0;
    };
    std::optional<std::size_t> sequential;
    std::optional<std::size_t> incremental;
    std::uint8_t urgency = 8;
    for (std::size_t step = 0; step < streams_.size(); ++step) {
        const auto index = (response_cursor_ + step) % streams_.size();
        const auto& value = streams_[index];
        if (!sendable(value) || value.urgency > urgency) continue;
        if (value.urgency < urgency) {
            urgency = value.urgency;
            sequential.reset();
            incremental.reset();
        }
        if (value.incremental) {
            if (!incremental) incremental = index;
        } else if (!sequential || value.id < streams_[*sequential].id) {
            sequential = index;
        }
    }
    return sequential ? sequential : incremental;
}

auto session::pump_responses() -> void
{
    if (fatal_ || file_send_active_) return;
    while (const auto next = next_response()) {
        const auto index = *next;
        auto& value = streams_[index];
        if (value.streaming) {
            // A handler's borrowed chunk; finish_streamed() ends the stream.
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>({
                value.chunk.size(), static_cast<std::uint64_t>(max_frame_payload),
                static_cast<std::uint64_t>(connection_send_window_),
                static_cast<std::uint64_t>(value.send_window)}));
            if (!append_frame(data_frame, 0, value.id, value.chunk.first(count))) return;
            value.chunk = value.chunk.subspan(count);
            connection_send_window_ -= static_cast<std::int64_t>(count);
            value.send_window -= static_cast<std::int64_t>(count);
            continue;
        }
        if (value.response_size == 0) {
            reset_stream(value);
            continue;
        }

        const auto available = std::min<std::uint64_t>({
            value.response_size - value.response_offset,
            static_cast<std::uint64_t>(max_frame_payload),
            static_cast<std::uint64_t>(connection_send_window_),
            static_cast<std::uint64_t>(value.send_window),
        });
        const auto count = static_cast<std::size_t>(available);
        if (count + 9 > max_output_size - output_size_) {
            // Do not read a file range that cannot be queued yet.
            // consume_output() retries after the transport drains output.
            return;
        }
        if (value.response_file && file_sendfile_) {
#if defined(__linux__)
            // Move the response owner into the frame instead of duplicating
            // it. The transport borrows it and completion returns ownership
            // to this response, or closes it for the final/reset stream.
            const bool last = value.response_offset + count == value.response_size;
            if (!append_frame(data_frame, last ? flag_end_stream : 0,
                              value.id, {}, count)) return;
            file_send_ = {std::move(value.response_file),
                value.response_file_start + value.response_offset, count};
            file_send_stream_ = value.id;
            file_send_index_ = index;
            file_send_prefix_ = output_size_;
            file_send_active_ = true;
            value.response_offset += count;
            connection_send_window_ -= static_cast<std::int64_t>(count);
            value.send_window -= static_cast<std::int64_t>(count);
            response_cursor_ = (index + 1) % streams_.size();
            if (last) {
                if (value.routed) {
                    value.stream_finished = true;
                    complete_stream(value);
                } else {
                    reset_stream(value);
                }
            }
            return;
#endif
        }
        const bool last = value.response_offset + count == value.response_size;
        const auto flags = static_cast<std::uint8_t>(last ? flag_end_stream : 0);
        if (value.response_file) {
            const auto appended = append_file_frame(flags, value.id, value.response_file.get(),
                value.response_file_start + value.response_offset, count);
            if (appended == file_frame::read_failed) {
                stream_error(value.id, internal_error);
                if (fatal_) return;
                continue;
            }
            // consume_output() resumes pumping after the transport drains.
            if (appended == file_frame::full) return;
        } else if (!append_frame(data_frame, flags, value.id, std::span {value.response_body}
                       .subspan(static_cast<std::size_t>(value.response_offset), count))) {
            // The bounded output queue is full. consume_output() resumes
            // pumping after the transport drains it.
            return;
        }
        response_cursor_ = (index + 1) % streams_.size();
        value.response_offset += count;
        connection_send_window_ -= static_cast<std::int64_t>(count);
        value.send_window -= static_cast<std::int64_t>(count);
        if (last) {
                if (value.routed) {
                    value.stream_finished = true;
                    complete_stream(value);
                } else {
                    reset_stream(value);
                }
            }
    }
}

} // namespace eventloop::http2::detail
