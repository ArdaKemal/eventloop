#pragma once

// A small JSON reader and writer for Parley's API bodies, realtime frames,
// and journal lines. Input is bounded by the caller (request body and frame
// limits); nesting is limited to 16 levels.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace parley {

[[nodiscard]] auto valid_utf8(std::string_view text) noexcept -> bool;

class json {
public:
    enum class kind { null, boolean, number, string, array, object };

    [[nodiscard]] static auto parse(std::string_view text) -> std::optional<json>;

    [[nodiscard]] auto type() const noexcept -> kind { return kind_; }
    // Missing members and wrong types yield the fallback.
    [[nodiscard]] auto operator[](std::string_view key) const noexcept -> const json&;
    [[nodiscard]] auto str(std::string_view fallback = {}) const -> std::string_view;
    [[nodiscard]] auto integer(std::int64_t fallback = 0) const noexcept -> std::int64_t;
    [[nodiscard]] auto boolean(bool fallback = false) const noexcept -> bool;
    [[nodiscard]] auto items() const noexcept -> const std::vector<json>& { return items_; }

private:
    friend class json_parser;

    kind kind_ {kind::null};
    bool boolean_ {false};
    double number_ {0};
    std::string string_;
    std::vector<json> items_;
    std::vector<std::pair<std::string, json>> members_;
};

// Appends compact JSON. Callers write keys and values in order; the writer
// inserts commas.
class json_writer {
public:
    explicit json_writer(std::string& out) : out_(out) {}

    auto begin_object() -> json_writer&;
    auto end_object() -> json_writer&;
    auto begin_array() -> json_writer&;
    auto end_array() -> json_writer&;
    auto key(std::string_view name) -> json_writer&;
    auto value(std::string_view text) -> json_writer&;
    auto value(const char* text) -> json_writer& { return value(std::string_view(text)); }
    auto value(std::int64_t number) -> json_writer&;
    auto value(std::uint64_t number) -> json_writer&;
    auto value(int number) -> json_writer& { return value(static_cast<std::int64_t>(number)); }
    auto value(unsigned number) -> json_writer& { return value(static_cast<std::uint64_t>(number)); }
    auto value(bool flag) -> json_writer&;
    auto null() -> json_writer&;
    // Appends an already encoded JSON value.
    auto raw(std::string_view encoded) -> json_writer&;

    template<typename T>
    auto field(std::string_view name, T&& v) -> json_writer&
    {
        key(name);
        return value(std::forward<T>(v));
    }

private:
    auto separate() -> void;

    std::string& out_;
    bool need_comma_ {false};
};

} // namespace parley
