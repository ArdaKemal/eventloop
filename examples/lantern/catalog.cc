#include "catalog.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <optional>

namespace lantern {

namespace {

template<typename T>
auto number(std::string_view text) -> std::optional<T>
{
    T value {};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc {} || parsed.ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

auto decode(std::string_view text) -> std::optional<std::string>
{
    std::string out;
    for (std::size_t i = 0; i < text.size(); ++i) {
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

} // namespace

auto valid_id(std::string_view id) noexcept -> bool
{
    return id.size() == 11 && std::ranges::all_of(id, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_';
    });
}

auto catalog::field(std::string_view text) -> std::string
{
    constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    for (const char c : text) {
        const auto byte = static_cast<unsigned char>(c);
        if (byte < 0x20 || c == '%' || c == 0x7f) {
            out.push_back('%');
            out.push_back(digits[byte >> 4]);
            out.push_back(digits[byte & 0xf]);
        } else {
            out.push_back(c);
        }
    }
    return out;
}

auto catalog::apply(std::string_view record) -> bool
{
    std::array<std::string_view, 9> fields;
    std::size_t count = 0;
    for (;;) {
        const auto tab = record.find('\t');
        if (count == fields.size()) return false;
        fields[count++] = record.substr(0, tab);
        if (tab == std::string_view::npos) break;
        record.remove_prefix(tab + 1);
    }
    const auto kind = fields[0];
    const auto id = fields[1];
    if (count < 2 || !valid_id(id)) return false;

    if (kind == "upload" && count == 9) {
        const auto size = number<std::uint64_t>(fields[2]);
        const auto created = number<std::int64_t>(fields[4]);
        const auto duration = number<std::uint64_t>(fields[5]);
        auto title = decode(fields[6]);
        auto description = decode(fields[7]);
        auto channel = decode(fields[8]);
        if (!size || !created || !duration || !title || !description || !channel ||
            videos_.contains(id))
            return false;
        return uploads_.try_emplace(std::string(id), upload {.details = {
            .id = std::string(id), .mime = std::string(fields[3]), .title = std::move(*title),
            .description = std::move(*description), .channel = std::move(*channel),
            .size = *size, .duration_ms = *duration, .created = *created}}).second;
    }
    if (count != 2) return false;
    if (kind == "thumbnail") {
        if (auto* pending = find_upload(id)) return pending->details.thumbnail = true;
        if (auto* published = find_video(id)) return published->thumbnail = true;
        return false;
    }
    if (kind == "publish") {
        const auto pending = uploads_.find(id);
        if (pending == uploads_.end()) return false;
        videos_.try_emplace(std::string(id), std::move(pending->second.details));
        uploads_.erase(pending);
        return true;
    }
    if (kind == "view") {
        auto* watched = find_video(id);
        if (watched) ++watched->views;
        return watched != nullptr;
    }
    if (kind == "discard") return uploads_.erase(id) != 0;
    return false;
}

auto catalog::replay(std::string_view journal) -> void
{
    while (!journal.empty()) {
        const auto end = journal.find('\n');
        auto record = journal.substr(0, end);
        // A cancelled write leaves zeros in front of the next record.
        record.remove_prefix(std::min(record.find_first_not_of('\0'), record.size()));
        (void)apply(record);
        if (end == std::string_view::npos) break;
        journal.remove_prefix(end + 1);
    }
}

auto catalog::find_video(std::string_view id) -> video*
{
    const auto found = videos_.find(id);
    return found == videos_.end() ? nullptr : &found->second;
}

auto catalog::find_upload(std::string_view id) -> upload*
{
    const auto found = uploads_.find(id);
    return found == uploads_.end() ? nullptr : &found->second;
}

} // namespace lantern
