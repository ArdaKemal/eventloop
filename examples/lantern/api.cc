#include "api.h"

#include "eventloop/file_io.h"
#include "eventloop/http/request.h"
#include "eventloop/http/response.h"
#include "eventloop/task.h"

#include <openssl/rand.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

using namespace eventloop;

namespace lantern {

namespace {

constexpr std::size_t max_form_body = 16 * 1024;
constexpr std::size_t max_thumbnail = 512 * 1024;
// Body reads deliver at most 16 KiB; collecting them first keeps a large
// upload from costing one file-worker round trip per read.
constexpr std::size_t write_buffer = 256 * 1024;
constexpr std::size_t list_limit = 60;

constexpr std::array<std::string_view, 4> video_types {
    "video/mp4", "video/webm", "video/ogg", "video/quicktime"};

auto bytes(std::string_view text) -> std::span<const std::byte>
{
    return std::as_bytes(std::span(text.data(), text.size()));
}

auto app_of(http::request& request) -> app&
{
    return *static_cast<app*>(request.route_context());
}

auto lower(std::string_view text) -> std::string
{
    std::string out(text);
    for (auto& c : out)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c | 0x20);
    return out;
}

auto equal_ci(std::string_view a, std::string_view b) -> bool
{
    return std::ranges::equal(a, b, [](char x, char y) { return (x | 0x20) == (y | 0x20); });
}

auto query_value(std::string_view query, std::string_view name) -> std::string_view
{
    while (!query.empty()) {
        const auto end = query.find('&');
        const auto pair = query.substr(0, end);
        if (pair.size() > name.size() && pair.starts_with(name) && pair[name.size()] == '=')
            return pair.substr(name.size() + 1);
        if (end == std::string_view::npos) break;
        query.remove_prefix(end + 1);
    }
    return {};
}

template<typename T>
auto to_number(std::string_view text) -> std::optional<T>
{
    T value {};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc {} || parsed.ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

// application/x-www-form-urlencoded and query values.
auto percent_decode(std::string_view text) -> std::optional<std::string>
{
    std::string out;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '+') { out.push_back(' '); continue; }
        if (text[i] != '%') { out.push_back(text[i]); continue; }
        unsigned value = 0;
        if (i + 2 >= text.size()) return std::nullopt;
        const auto parsed = std::from_chars(text.data() + i + 1, text.data() + i + 3, value, 16);
        if (parsed.ec != std::errc {} || parsed.ptr != text.data() + i + 3) return std::nullopt;
        out.push_back(static_cast<char>(value));
        i += 2;
    }
    return out;
}

// Trims spaces and accepts 1..limit bytes without control characters;
// multiline text keeps its line feeds and may be empty.
auto clean_text(std::optional<std::string> text, std::size_t limit, bool multiline)
    -> std::optional<std::string>
{
    if (!text) return std::nullopt;
    std::erase(*text, '\r');
    const auto first = text->find_first_not_of(" \n");
    const auto last = text->find_last_not_of(" \n");
    *text = first == std::string::npos ? std::string {} : text->substr(first, last - first + 1);
    if ((text->empty() && !multiline) || text->size() > limit) return std::nullopt;
    const bool control = std::ranges::any_of(*text, [&](char c) {
        return (static_cast<unsigned char>(c) < 0x20 && !(multiline && c == '\n')) || c == 0x7f;
    });
    if (control) return std::nullopt;
    return text;
}

// Uploads and other changes come from this page only. There are no accounts:
// Lantern binds to loopback by default.
auto same_origin(const http::request& request) -> bool
{
    const auto origin = request.header_value("origin");
    if (!origin) return true; // non-browser clients
    auto host = *origin;
    if (!host.starts_with("https://") && !host.starts_with("http://")) return false;
    host.remove_prefix(host.find("//") + 2);
    return equal_ci(host, request.authority());
}

auto random_id() -> std::string
{
    constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::array<unsigned char, 11> raw {};
    if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) return {};
    std::string id;
    for (const auto byte : raw) id.push_back(alphabet[byte & 63]);
    return id;
}

struct header_list {
    std::array<http::header, 8> fields {};
    std::size_t size {0};

    auto add(std::string_view name, std::string_view value) -> header_list&
    {
        if (!value.empty()) fields[size++] = {name, value};
        return *this;
    }
    [[nodiscard]] auto view() const -> std::span<const http::header>
    {
        return std::span(fields).first(size);
    }
};

auto json_string(std::string& out, std::string_view text) -> void
{
    out.push_back('"');
    for (const char c : text) {
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
        } else if (c == '\n') {
            out += "\\n";
        } else if (static_cast<unsigned char>(c) < 0x20) {
            std::array<char, 8> escaped {};
            std::snprintf(escaped.data(), escaped.size(), "\\u%04x", c);
            out += escaped.data();
        } else {
            out.push_back(c);
        }
    }
    out.push_back('"');
}

auto video_json(std::string& out, const video& item) -> void
{
    out += "{\"id\":";
    json_string(out, item.id);
    out += ",\"title\":";
    json_string(out, item.title);
    out += ",\"description\":";
    json_string(out, item.description);
    out += ",\"channel\":";
    json_string(out, item.channel);
    out += ",\"mime\":";
    json_string(out, item.mime);
    out += ",\"size\":" + std::to_string(item.size) +
        ",\"duration\":" + std::to_string(item.duration_ms) +
        ",\"created\":" + std::to_string(item.created) +
        ",\"views\":" + std::to_string(item.views) +
        ",\"thumbnail\":" + (item.thumbnail ? "true" : "false") + "}";
}

auto progress_json(const upload& pending) -> std::string
{
    return "{\"id\":\"" + pending.details.id + "\",\"received\":" + std::to_string(pending.received) +
        ",\"size\":" + std::to_string(pending.details.size) +
        ",\"chunk\":" + std::to_string(chunk_bytes) + "}";
}

auto send_json(event_loop& loop, http::response& response, unsigned status, std::string body,
               std::string_view alt_svc = {}) -> task<void>
{
    (void)loop;
    header_list headers;
    headers.add("content-type", "application/json")
        .add("cache-control", "no-store")
        .add("alt-svc", alt_svc);
    (void)co_await response.async_send(status, headers.view(), bytes(body));
}

auto send_error(event_loop& loop, http::response& response, unsigned status, std::string_view text)
    -> task<void>
{
    std::string body = "{\"error\":";
    json_string(body, text);
    body.push_back('}');
    co_await send_json(loop, response, status, std::move(body));
}

auto send_empty(event_loop& loop, http::response& response) -> task<void>
{
    (void)loop;
    (void)co_await response.async_send(204, {});
}

// Reads a whole body of at most limit bytes.
auto read_body(event_loop& loop, http::request& request, std::size_t limit)
    -> task<std::optional<std::string>>
{
    (void)loop;
    if (request.content_length().value_or(0) > limit) co_return std::nullopt;
    std::string body;
    for (;;) {
        const auto used = body.size();
        if (used == limit) co_return std::nullopt;
        body.resize(std::min(limit, used + 16 * 1024));
        const auto read = flatten_result(co_await request.async_read_body(
            std::as_writable_bytes(std::span(body.data() + used, body.size() - used))));
        if (!read) co_return std::nullopt;
        body.resize(used + *read);
        if (*read == 0) co_return body;
    }
}

auto write_all(event_loop& loop, int descriptor, std::span<const std::byte> data,
               std::uint64_t offset) -> task<std::size_t>
{
    std::size_t done = 0;
    while (done < data.size()) {
        const auto wrote = co_await async_write_at(loop, descriptor, data.subspan(done),
                                                   static_cast<std::int64_t>(offset + done));
        if (!wrote || *wrote == 0) break;
        done += *wrote;
    }
    co_return done;
}

// Applies a change and appends it to the journal. Concurrent records reserve
// disjoint ranges, so they need no queue.
auto record(event_loop& loop, app& application, std::string line) -> task<bool>
{
    if (!application.library.apply(line)) co_return false;
    line.push_back('\n');
    const auto offset = application.journal_end;
    application.journal_end += line.size();
    co_return (co_await write_all(loop, application.journal.get(), bytes(line), offset)).value_or(0) == line.size();
}

// ---------------------------------------------------------------------------
// Catalog

auto list_videos(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    const auto search = lower(percent_decode(query_value(request.query(), "q")).value_or(""));
    const auto channel = percent_decode(query_value(request.query(), "channel")).value_or("");
    std::vector<const video*> found;
    for (const auto& [id, item] : application.library.videos()) {
        if (!channel.empty() && item.channel != channel) continue;
        if (!search.empty() && !lower(item.title).contains(search) &&
            !lower(item.channel).contains(search))
            continue;
        found.push_back(&item);
    }
    const auto shown = std::min(found.size(), list_limit);
    std::ranges::partial_sort(found, found.begin() + static_cast<std::ptrdiff_t>(shown),
        [](const video* a, const video* b) {
            return a->created != b->created ? a->created > b->created : a->id < b->id;
        });
    std::string out = "{\"videos\":[";
    for (std::size_t i = 0; i < shown; ++i) {
        if (i != 0) out.push_back(',');
        video_json(out, *found[i]);
    }
    out += "]}";
    co_await send_json(loop, response, 200, std::move(out), application.alt_svc);
}

auto video_details(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    const auto* item = application.library.find_video(request.path().substr(12));
    if (!item) co_return (void)co_await send_error(loop, response, 404, "No such video");
    std::string out;
    video_json(out, *item);
    co_await send_json(loop, response, 200, std::move(out), application.alt_svc);
}

auto count_view(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    auto rest = request.path().substr(12);
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    if (!rest.ends_with("/view")) co_return (void)co_await send_error(loop, response, 404, "Not found");
    const std::string id(rest.substr(0, rest.size() - 5));
    if (!application.library.find_video(id))
        co_return (void)co_await send_error(loop, response, 404, "No such video");
    if (!(co_await record(loop, application, "view\t" + id)).value_or(false))
        co_return (void)co_await send_error(loop, response, 500, "Cannot record the view");
    const auto views = application.library.find_video(id)->views;
    co_await send_json(loop, response, 200, "{\"views\":" + std::to_string(views) + "}");
}

// ---------------------------------------------------------------------------
// Resumable uploads: create, PUT chunks at the received offset, add a
// thumbnail, then publish. GET reports the offset to resume from.

auto create_upload(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    const auto form = (co_await read_body(loop, request, max_form_body)).value_or(std::nullopt);
    if (!form) co_return (void)co_await send_error(loop, response, 400, "Invalid request");
    const auto size = to_number<std::uint64_t>(query_value(*form, "size"));
    const auto duration = to_number<std::uint64_t>(query_value(*form, "duration"));
    const auto mime = percent_decode(query_value(*form, "type"));
    auto title = clean_text(percent_decode(query_value(*form, "title")), 100, false);
    auto description = clean_text(percent_decode(query_value(*form, "description")), 5000, true);
    auto channel = clean_text(percent_decode(query_value(*form, "channel")), 50, false);
    if (!size || *size == 0 || !duration || !title || !description || !channel)
        co_return (void)co_await send_error(loop, response, 400, "A title, channel name, and video are required");
    if (*size > application.max_video_bytes)
        co_return (void)co_await send_error(loop, response, 413, "This video is larger than the server allows");
    if (!mime || std::ranges::find(video_types, *mime) == video_types.end())
        co_return (void)co_await send_error(loop, response, 415, "Lantern stores MP4, WebM, Ogg, and QuickTime video");

    const auto id = random_id();
    if (id.empty()) co_return (void)co_await send_error(loop, response, 500, "Cannot create an id");
    auto created = co_await async_openat(loop, application.uploads.get(), id,
                                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (!created) co_return (void)co_await send_error(loop, response, 500, "Cannot store the upload");
    created->reset();
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const auto line = "upload\t" + id + "\t" + std::to_string(*size) + "\t" + *mime + "\t" +
        std::to_string(now) + "\t" + std::to_string(*duration) + "\t" + catalog::field(*title) + "\t" +
        catalog::field(*description) + "\t" + catalog::field(*channel);
    if (!(co_await record(loop, application, line)).value_or(false)) {
        (void)::unlinkat(application.uploads.get(), id.c_str(), 0);
        co_return (void)co_await send_error(loop, response, 500, "Cannot record the upload");
    }
    co_await send_json(loop, response, 201, progress_json(*application.library.find_upload(id)),
                       application.alt_svc);
}

auto upload_status(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    const auto* pending = application.library.find_upload(request.path().substr(13));
    if (!pending) co_return (void)co_await send_error(loop, response, 404, "No such upload");
    co_await send_json(loop, response, 200, progress_json(*pending));
}

auto put_thumbnail(event_loop& loop, http::request& request, http::response& response,
                   std::string id) -> task<void>
{
    auto& application = app_of(request);
    if (!application.library.find_upload(id))
        co_return (void)co_await send_error(loop, response, 404, "No such upload");
    if (request.header_value("content-type") != "image/jpeg")
        co_return (void)co_await send_error(loop, response, 415, "Thumbnails are JPEG images");
    const auto image = (co_await read_body(loop, request, max_thumbnail)).value_or(std::nullopt);
    if (!image || image->empty()) co_return (void)co_await send_error(loop, response, 400, "Invalid thumbnail");
    auto opened = co_await async_openat(loop, application.thumbnails.get(), id,
                                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (!opened || (co_await write_all(loop, opened->get(), bytes(*image), 0)).value_or(0) != image->size())
        co_return (void)co_await send_error(loop, response, 500, "Cannot store the thumbnail");
    // The upload may have been discarded while the image arrived.
    const auto* pending = application.library.find_upload(id);
    if (!pending) co_return (void)co_await send_error(loop, response, 404, "No such upload");
    if (!pending->details.thumbnail && !(co_await record(loop, application, "thumbnail\t" + id)).value_or(false))
        co_return (void)co_await send_error(loop, response, 500, "Cannot record the thumbnail");
    co_await send_empty(loop, response);
}

auto put_chunk(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    const auto rest = request.path().substr(13);
    if (rest.ends_with("/thumbnail"))
        co_return (void)co_await put_thumbnail(loop, request, response, std::string(rest.substr(0, rest.size() - 10)));
    const std::string id(rest);
    auto* pending = application.library.find_upload(id);
    if (!pending) co_return (void)co_await send_error(loop, response, 404, "No such upload");
    if (pending->busy) co_return (void)co_await send_error(loop, response, 409, "Another request is writing this upload");
    const auto offset = to_number<std::uint64_t>(query_value(request.query(), "offset"));
    const auto length = request.content_length();
    if (!length) co_return (void)co_await send_error(loop, response, 411, "Chunks need a content-length");
    if (offset != pending->received) co_return (void)co_await send_json(loop, response, 409, progress_json(*pending));
    if (*length > chunk_bytes || *length > pending->details.size - pending->received)
        co_return (void)co_await send_error(loop, response, 413, "Chunk too large");

    // busy keeps the upload from being published or discarded, so the
    // reference stays valid while this request writes.
    pending->busy = true;
    struct release {
        upload& item;
        ~release() { item.busy = false; }
    } guard {*pending};
    auto opened = co_await async_openat(loop, application.uploads.get(), id, O_WRONLY | O_CLOEXEC);
    if (!opened) co_return (void)co_await send_error(loop, response, 500, "Cannot open the upload");
    auto buffer = std::make_unique<std::byte[]>(write_buffer);
    bool ended = false;
    bool failed = false;
    while (!ended) {
        std::size_t filled = 0;
        while (filled < write_buffer) {
            const auto read = flatten_result(co_await request.async_read_body(
                std::span(buffer.get() + filled, write_buffer - filled)));
            if (!read || *read == 0) {
                failed = !read;
                ended = true;
                break;
            }
            filled += *read;
        }
        // Bytes that arrived before a reset are kept: the client resumes
        // from received.
        const auto written = (co_await write_all(loop, opened->get(),
            std::span<const std::byte>(buffer.get(), filled), pending->received)).value_or(0);
        pending->received += written;
        if (written != filled) failed = ended = true;
    }
    if (failed) co_return (void)co_await send_error(loop, response, 500, "Upload interrupted");
    co_await send_json(loop, response, 200, progress_json(*pending));
}

auto publish(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    const auto rest = request.path().substr(13);
    if (!rest.ends_with("/publish")) co_return (void)co_await send_error(loop, response, 404, "Not found");
    const std::string id(rest.substr(0, rest.size() - 8));
    const auto* pending = application.library.find_upload(id);
    if (!pending) co_return (void)co_await send_error(loop, response, 404, "No such upload");
    if (pending->busy || pending->received != pending->details.size)
        co_return (void)co_await send_json(loop, response, 409, progress_json(*pending));
    // A rename within one file system only updates metadata.
    if (::renameat(application.uploads.get(), id.c_str(), application.videos.get(), id.c_str()) != 0 ||
        !(co_await record(loop, application, "publish\t" + id)).value_or(false))
        co_return (void)co_await send_error(loop, response, 500, "Cannot publish the video");
    std::string out;
    video_json(out, *application.library.find_video(id));
    co_await send_json(loop, response, 201, std::move(out));
}

auto discard(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    if (!same_origin(request)) co_return (void)co_await send_error(loop, response, 403, "Bad origin");
    const std::string id(request.path().substr(13));
    const auto* pending = application.library.find_upload(id);
    if (!pending) co_return (void)co_await send_error(loop, response, 404, "No such upload");
    if (pending->busy) co_return (void)co_await send_error(loop, response, 409, "The upload is being written");
    (void)::unlinkat(application.uploads.get(), id.c_str(), 0);
    (void)::unlinkat(application.thumbnails.get(), id.c_str(), 0);
    if (!(co_await record(loop, application, "discard\t" + id)).value_or(false))
        co_return (void)co_await send_error(loop, response, 500, "Cannot record the change");
    co_await send_empty(loop, response);
}

// ---------------------------------------------------------------------------
// Playback. Browsers fetch video with byte ranges and drop the request when
// the viewer seeks.

struct byte_range {
    std::uint64_t first;
    std::uint64_t length;
};

// A single bytes range. Returns nothing to send the whole file; sets
// unsatisfiable for a valid range outside the file.
auto parse_range(std::string_view value, std::uint64_t size, bool& unsatisfiable)
    -> std::optional<byte_range>
{
    unsatisfiable = false;
    if (!value.starts_with("bytes=") || value.contains(',')) return std::nullopt;
    value.remove_prefix(6);
    const auto dash = value.find('-');
    if (dash == std::string_view::npos) return std::nullopt;
    const auto first = value.substr(0, dash);
    const auto last = value.substr(dash + 1);
    if (first.empty()) {
        const auto suffix = to_number<std::uint64_t>(last);
        if (!suffix) return std::nullopt;
        if (*suffix == 0 || size == 0) { unsatisfiable = true; return std::nullopt; }
        const auto length = std::min(*suffix, size);
        return byte_range {size - length, length};
    }
    const auto start = to_number<std::uint64_t>(first);
    if (!start) return std::nullopt;
    auto end = last.empty() ? std::optional<std::uint64_t>(size - 1) : to_number<std::uint64_t>(last);
    if (!end || *end < *start) return std::nullopt;
    if (*start >= size) { unsatisfiable = true; return std::nullopt; }
    *end = std::min(*end, size - 1);
    return byte_range {*start, *end - *start + 1};
}

// Ids never change content, so files are cached for good.
auto send_stored(event_loop& loop, http::request& request, http::response& response, int directory,
                 std::string_view id, std::string_view mime) -> task<void>
{
    auto opened = co_await async_openat(loop, directory, id, O_RDONLY | O_CLOEXEC);
    struct stat status {};
    if (!opened || ::fstat(opened->get(), &status) != 0)
        co_return (void)co_await send_error(loop, response, 404, "Not found");
    const auto size = static_cast<std::uint64_t>(status.st_size);
    bool unsatisfiable = false;
    const auto range = parse_range(request.header_value("range").value_or(""), size, unsatisfiable);
    std::string range_text;
    header_list headers;
    headers.add("content-type", mime)
        .add("cache-control", "public, max-age=31536000, immutable")
        .add("x-content-type-options", "nosniff")
        .add("accept-ranges", "bytes");
    if (unsatisfiable) {
        range_text = "bytes */" + std::to_string(size);
        headers.add("content-range", range_text);
        co_return (void)co_await response.async_send(416, headers.view());
    }
    if (!range) co_return (void)co_await response.async_send_file(200, headers.view(), std::move(*opened), 0, size);
    range_text = "bytes " + std::to_string(range->first) + "-" +
        std::to_string(range->first + range->length - 1) + "/" + std::to_string(size);
    headers.add("content-range", range_text);
    (void)co_await response.async_send_file(206, headers.view(), std::move(*opened), range->first, range->length);
}

auto serve_video(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    const auto* item = application.library.find_video(request.path().substr(3));
    if (!item) co_return (void)co_await send_error(loop, response, 404, "No such video");
    const std::string id = item->id;
    const std::string mime = item->mime;
    co_await send_stored(loop, request, response, application.videos.get(), id, mime);
}

auto serve_thumbnail(event_loop& loop, http::request& request, http::response& response) -> task<void>
{
    auto& application = app_of(request);
    const auto id = request.path().substr(3);
    if (!valid_id(id)) co_return (void)co_await send_error(loop, response, 404, "Not found");
    co_await send_stored(loop, request, response, application.thumbnails.get(), id, "image/jpeg");
}

auto add(http::router& routes, http::method_type method, std::string_view path, http::handler function,
         app& application, bool prefix = false) -> void
{
    const auto added = prefix ? routes.add_prefix(method, path, function, &application)
                              : routes.add(method, path, function, &application);
    if (!added) throw std::runtime_error("cannot register route " + std::string(path));
}

} // namespace

auto make_routes(app& application) -> std::shared_ptr<http::router>
{
    using enum http::method_type;
    auto routes = std::make_shared<http::router>();
    add(*routes, get, "/api/videos", list_videos, application);
    add(*routes, get, "/api/videos/", video_details, application, true);
    add(*routes, post, "/api/videos/", count_view, application, true);
    add(*routes, post, "/api/uploads", create_upload, application);
    add(*routes, get, "/api/uploads/", upload_status, application, true);
    add(*routes, put, "/api/uploads/", put_chunk, application, true);
    add(*routes, post, "/api/uploads/", publish, application, true);
    add(*routes, delete_, "/api/uploads/", discard, application, true);
    add(*routes, get, "/v/", serve_video, application, true);
    add(*routes, get, "/t/", serve_thumbnail, application, true);
    return routes;
}

} // namespace lantern
