#include "json.h"

#include <array>
#include <charconv>
#include <cmath>

namespace parley {

auto valid_utf8(std::string_view text) noexcept -> bool
{
    std::size_t i = 0;
    while (i < text.size()) {
        const auto c = static_cast<unsigned char>(text[i]);
        std::size_t extra = 0;
        std::uint32_t code = 0;
        if (c < 0x80) { ++i; continue; }
        if ((c & 0xe0) == 0xc0) { extra = 1; code = c & 0x1f; }
        else if ((c & 0xf0) == 0xe0) { extra = 2; code = c & 0x0f; }
        else if ((c & 0xf8) == 0xf0) { extra = 3; code = c & 0x07; }
        else return false;
        if (i + extra >= text.size()) return false;
        for (std::size_t k = 1; k <= extra; ++k) {
            const auto next = static_cast<unsigned char>(text[i + k]);
            if ((next & 0xc0) != 0x80) return false;
            code = (code << 6) | (next & 0x3f);
        }
        constexpr std::array<std::uint32_t, 4> minimum {0, 0x80, 0x800, 0x10000};
        if (code < minimum[extra] || code > 0x10ffff || (code >= 0xd800 && code < 0xe000))
            return false;
        i += extra + 1;
    }
    return true;
}

class json_parser {
public:
    explicit json_parser(std::string_view text) : text_(text) {}

    auto document() -> std::optional<json>
    {
        json result;
        if (!value(result, 0)) return std::nullopt;
        skip_space();
        if (position_ != text_.size()) return std::nullopt;
        return result;
    }

private:
    static constexpr int max_depth = 16;

    auto skip_space() -> void
    {
        while (position_ < text_.size() &&
               (text_[position_] == ' ' || text_[position_] == '\t' ||
                text_[position_] == '\n' || text_[position_] == '\r')) ++position_;
    }

    auto consume(std::string_view word) -> bool
    {
        if (text_.substr(position_, word.size()) != word) return false;
        position_ += word.size();
        return true;
    }

    auto value(json& out, int depth) -> bool
    {
        if (depth > max_depth) return false;
        skip_space();
        if (position_ >= text_.size()) return false;
        switch (text_[position_]) {
        case 'n': out.kind_ = json::kind::null; return consume("null");
        case 't': out.kind_ = json::kind::boolean; out.boolean_ = true; return consume("true");
        case 'f': out.kind_ = json::kind::boolean; out.boolean_ = false; return consume("false");
        case '"': out.kind_ = json::kind::string; return string(out.string_);
        case '[': return array(out, depth);
        case '{': return object(out, depth);
        default: return number(out);
        }
    }

    auto number(json& out) -> bool
    {
        const auto* begin = text_.data() + position_;
        const auto* end = text_.data() + text_.size();
        const auto parsed = std::from_chars(begin, end, out.number_);
        if (parsed.ec != std::errc {} || !std::isfinite(out.number_)) return false;
        out.kind_ = json::kind::number;
        position_ += static_cast<std::size_t>(parsed.ptr - begin);
        return true;
    }

    auto hex4(std::uint32_t& code) -> bool
    {
        if (position_ + 4 > text_.size()) return false;
        const auto parsed = std::from_chars(text_.data() + position_,
                                            text_.data() + position_ + 4, code, 16);
        if (parsed.ec != std::errc {} || parsed.ptr != text_.data() + position_ + 4) return false;
        position_ += 4;
        return true;
    }

    static auto append_utf8(std::string& out, std::uint32_t code) -> void
    {
        if (code < 0x80) {
            out.push_back(static_cast<char>(code));
        } else if (code < 0x800) {
            out.push_back(static_cast<char>(0xc0 | (code >> 6)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3f)));
        } else if (code < 0x10000) {
            out.push_back(static_cast<char>(0xe0 | (code >> 12)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3f)));
        } else {
            out.push_back(static_cast<char>(0xf0 | (code >> 18)));
            out.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3f)));
        }
    }

    auto string(std::string& out) -> bool
    {
        ++position_; // opening quote
        while (position_ < text_.size()) {
            const char c = text_[position_++];
            if (c == '"') return true;
            if (static_cast<unsigned char>(c) < 0x20) return false;
            if (c != '\\') { out.push_back(c); continue; }
            if (position_ >= text_.size()) return false;
            switch (text_[position_++]) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                std::uint32_t code = 0;
                if (!hex4(code)) return false;
                if (code >= 0xd800 && code < 0xdc00) {
                    std::uint32_t low = 0;
                    if (!consume("\\u") || !hex4(low) || low < 0xdc00 || low > 0xdfff) return false;
                    code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                } else if (code >= 0xdc00 && code < 0xe000) {
                    return false;
                }
                append_utf8(out, code);
                break;
            }
            default: return false;
            }
        }
        return false;
    }

    auto array(json& out, int depth) -> bool
    {
        out.kind_ = json::kind::array;
        ++position_;
        skip_space();
        if (consume("]")) return true;
        for (;;) {
            json item;
            if (!value(item, depth + 1)) return false;
            out.items_.push_back(std::move(item));
            skip_space();
            if (consume("]")) return true;
            if (!consume(",")) return false;
        }
    }

    auto object(json& out, int depth) -> bool
    {
        out.kind_ = json::kind::object;
        ++position_;
        skip_space();
        if (consume("}")) return true;
        for (;;) {
            skip_space();
            std::string name;
            if (position_ >= text_.size() || text_[position_] != '"' || !string(name)) return false;
            skip_space();
            if (!consume(":")) return false;
            json item;
            if (!value(item, depth + 1)) return false;
            out.members_.emplace_back(std::move(name), std::move(item));
            skip_space();
            if (consume("}")) return true;
            if (!consume(",")) return false;
        }
    }

    std::string_view text_;
    std::size_t position_ {0};
};

auto json::parse(std::string_view text) -> std::optional<json>
{
    if (!valid_utf8(text)) return std::nullopt;
    return json_parser(text).document();
}

auto json::operator[](std::string_view key) const noexcept -> const json&
{
    static const json missing;
    for (const auto& [name, item] : members_)
        if (name == key) return item;
    return missing;
}

auto json::str(std::string_view fallback) const -> std::string_view
{
    return kind_ == kind::string ? std::string_view(string_) : fallback;
}

auto json::integer(std::int64_t fallback) const noexcept -> std::int64_t
{
    if (kind_ != kind::number || number_ != std::trunc(number_) ||
        std::fabs(number_) > 9007199254740992.0) return fallback;
    return static_cast<std::int64_t>(number_);
}

auto json::boolean(bool fallback) const noexcept -> bool
{
    return kind_ == kind::boolean ? boolean_ : fallback;
}

auto json_writer::separate() -> void
{
    if (need_comma_) out_.push_back(',');
    need_comma_ = true;
}

auto json_writer::begin_object() -> json_writer&
{
    separate();
    out_.push_back('{');
    need_comma_ = false;
    return *this;
}

auto json_writer::end_object() -> json_writer&
{
    out_.push_back('}');
    need_comma_ = true;
    return *this;
}

auto json_writer::begin_array() -> json_writer&
{
    separate();
    out_.push_back('[');
    need_comma_ = false;
    return *this;
}

auto json_writer::end_array() -> json_writer&
{
    out_.push_back(']');
    need_comma_ = true;
    return *this;
}

auto json_writer::key(std::string_view name) -> json_writer&
{
    value(name);
    out_.push_back(':');
    need_comma_ = false;
    return *this;
}

auto json_writer::value(std::string_view text) -> json_writer&
{
    separate();
    out_.push_back('"');
    for (const char c : text) {
        switch (c) {
        case '"': out_ += "\\\""; break;
        case '\\': out_ += "\\\\"; break;
        case '\n': out_ += "\\n"; break;
        case '\r': out_ += "\\r"; break;
        case '\t': out_ += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                constexpr char digits[] = "0123456789abcdef";
                out_ += "\\u00";
                out_.push_back(digits[(c >> 4) & 0xf]);
                out_.push_back(digits[c & 0xf]);
            } else {
                out_.push_back(c);
            }
        }
    }
    out_.push_back('"');
    return *this;
}

auto json_writer::value(std::int64_t number) -> json_writer&
{
    separate();
    out_ += std::to_string(number);
    return *this;
}

auto json_writer::value(std::uint64_t number) -> json_writer&
{
    separate();
    out_ += std::to_string(number);
    return *this;
}

auto json_writer::value(bool flag) -> json_writer&
{
    separate();
    out_ += flag ? "true" : "false";
    return *this;
}

auto json_writer::null() -> json_writer&
{
    separate();
    out_ += "null";
    return *this;
}

auto json_writer::raw(std::string_view encoded) -> json_writer&
{
    separate();
    out_ += encoded;
    return *this;
}

} // namespace parley
