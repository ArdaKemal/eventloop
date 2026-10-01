#pragma once

#include "file_operations.h"

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string_view>

namespace eventloop::http::detail {

struct file_conditions {
    std::string_view if_none_match;
    std::string_view if_modified_since;
    std::string_view range;
};

struct file_response {
    unsigned status {200};
    std::uint64_t offset {0};
    std::uint64_t length {0};
    std::array<char, 160> etag {};
    std::array<char, 64> modified {};
    std::array<char, 96> content_range {};
    std::size_t etag_size {0};
    std::size_t modified_size {0};
    std::size_t content_range_size {0};
};

[[nodiscard]] inline auto parse_number(std::string_view text, std::uint64_t& number) noexcept -> bool
{
    if (text.empty()) return false;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), number);
    return error == std::errc{} && end == text.data() + text.size();
}

[[nodiscard]] inline auto trim_http(std::string_view text) noexcept -> std::string_view
{
    const auto first = text.find_first_not_of(" \t");
    if (first == std::string_view::npos) return {};
    return text.substr(first, text.find_last_not_of(" \t") - first + 1);
}

[[nodiscard]] inline auto modified_since(std::string_view text, std::int64_t modified) noexcept -> bool
{
    // The server emits IMF-fixdate; invalid and obsolete dates are ignored.
    char weekday[4] {}, month[4] {}, zone[4] {};
    std::array<char, 30> terminated {};
    if (text.size() != 29) return false;
    for (std::size_t i = 0; i < text.size(); ++i) terminated[i] = text[i];
    int day = 0, year = 0, hour = 0, minute = 0, second = 0, used = 0;
    if (std::sscanf(terminated.data(),
            "%3[A-Za-z], %d %3[A-Za-z] %d %d:%d:%d %3[A-Za-z]%n",
            weekday, &day, month, &year, &hour, &minute, &second, zone, &used) != 8 ||
        used != 29 || std::string_view(zone) != "GMT" || year < 1970 ||
        hour > 23 || minute > 59 || second > 59 || hour < 0 || minute < 0 || second < 0)
        return false;
    constexpr std::array<std::string_view, 12> months {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    unsigned month_number = 0;
    for (unsigned i = 0; i < months.size(); ++i)
        if (months[i] == month) { month_number = i + 1; break; }
    if (month_number == 0) return false;
    using namespace std::chrono;
    const year_month_day date {std::chrono::year {year}, std::chrono::month {month_number},
                               std::chrono::day {static_cast<unsigned>(day)}};
    if (!date.ok()) return false;
    const auto seconds = duration_cast<std::chrono::seconds>(sys_days {date}.time_since_epoch()).count()
        + hour * 3600 + minute * 60 + second;
    return modified <= seconds;
}

[[nodiscard]] inline auto etag_matches(std::string_view header, std::string_view etag) noexcept -> bool
{
    const auto opaque_etag = etag.starts_with("W/") ? etag.substr(2) : etag;
    while (!header.empty()) {
        const auto comma = header.find(',');
        const auto token = trim_http(header.substr(0, comma));
        const auto opaque = token.starts_with("W/") ? token.substr(2) : token;
        if (token == "*" || opaque == opaque_etag) return true;
        if (comma == std::string_view::npos) break;
        header.remove_prefix(comma + 1);
    }
    return false;
}

[[nodiscard]] inline auto choose_file_response(const file_info& info,
                                                file_conditions conditions) noexcept -> file_response
{
    file_response result;
    result.length = info.size;
    result.modified_size = format_http_time(info.modified, result.modified);
    const int etag_size = std::snprintf(result.etag.data(), result.etag.size(),
        "W/\"%llx-%llx-%x-%llx-%x-%llx-%llx\"",
        static_cast<unsigned long long>(info.size),
        static_cast<unsigned long long>(info.modified), info.modified_nanoseconds,
        static_cast<unsigned long long>(info.changed), info.changed_nanoseconds,
        static_cast<unsigned long long>(info.volume),
        static_cast<unsigned long long>(info.identity));
    if (etag_size > 0 && static_cast<std::size_t>(etag_size) < result.etag.size())
        result.etag_size = static_cast<std::size_t>(etag_size);
    const std::string_view etag {result.etag.data(), result.etag_size};
    if ((!conditions.if_none_match.empty() && etag_matches(conditions.if_none_match, etag)) ||
        (conditions.if_none_match.empty() && !conditions.if_modified_since.empty() &&
         modified_since(conditions.if_modified_since, info.modified))) {
        result.status = 304;
        result.length = 0;
        return result;
    }
    auto range = trim_http(conditions.range);
    if (!range.starts_with("bytes=") || range.find(',') != std::string_view::npos) return result;
    range.remove_prefix(6);
    const auto hyphen = range.find('-');
    if (hyphen == std::string_view::npos || range.find('-', hyphen + 1) != std::string_view::npos)
        return result;
    const auto left = range.substr(0, hyphen), right = range.substr(hyphen + 1);
    std::uint64_t first = 0, last = 0;
    if (left.empty()) {
        if (!parse_number(right, last)) return result;
        if (last == 0 || info.size == 0) result.status = 416;
        else { result.offset = last >= info.size ? 0 : info.size - last; result.length = info.size - result.offset; }
    } else if (parse_number(left, first) &&
               (right.empty() || parse_number(right, last))) {
        if (first >= info.size || (!right.empty() && last < first)) result.status = 416;
        else { result.offset = first; result.length = right.empty() || last >= info.size
            ? info.size - first : last - first + 1; }
    } else return result;
    if (result.status != 416) result.status = 206;
    const int content_range_size = result.status == 416
        ? std::snprintf(result.content_range.data(), result.content_range.size(),
            "bytes */%llu", static_cast<unsigned long long>(info.size))
        : std::snprintf(result.content_range.data(), result.content_range.size(),
            "bytes %llu-%llu/%llu", static_cast<unsigned long long>(result.offset),
            static_cast<unsigned long long>(result.offset + result.length - 1),
            static_cast<unsigned long long>(info.size));
    if (content_range_size > 0 && static_cast<std::size_t>(content_range_size) < result.content_range.size())
        result.content_range_size = static_cast<std::size_t>(content_range_size);
    if (result.status == 416) result.length = 0;
    return result;
}

} // namespace eventloop::http::detail
