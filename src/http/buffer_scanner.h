#pragma once

#include "../util/array_ref.h"
#include <string_view>

static bool is_same_w_any_of(const char c, array_ref<char> list, char &out) {
    for (std::size_t i = 0; i < list.size(); i++) {
        if (c == list[i]) {
            out = c;
            return true;
        }
    }
    return false;
}

class buffer_scanner {
public:
    struct result {
        char c;
        std::string_view literal;
    };

    buffer_scanner(std::string_view buffer) noexcept
        : pos_(0)
        , buffer_(buffer)
    {}

    buffer_scanner(const char *buffer, std::size_t length) noexcept
        : pos_(0)
        , buffer_(buffer, length)
    {}

    std::string_view get(char stop) {
        const char *begin = &buffer_[pos_];

        while (!is_eof() && current() != stop)
            pos_++;

        const char *end = &buffer_[pos_++];

        return {begin, end};
    }

    result get(const char expected[], std::size_t count) {
        char c{};
        const char *begin = &buffer_[pos_];

        while (!is_eof()) {
            if (is_same_w_any_of(current(), {expected, count}, c))
                break;
            pos_++;
        }

        const char *end = &buffer_[pos_++];

        return {c, std::string_view{begin, end}};
    }

    inline bool skip(char c) {
        return (pos_ + 1) < buffer_.length() && buffer_[pos_++] == c;
    }

    inline void step_forward(std::size_t n) {
        pos_ += n;
    }

    inline void step_backward(std::size_t n) {
        pos_ -= n;
    }

    inline bool peek(std::string_view pattern) const {
        return
            (pos_ + pattern.length() - 1) < buffer_.length() &&
            std::char_traits<char>::compare(&buffer_[pos_], pattern.data(), pattern.length()) == 0;
    }

    inline std::size_t position() const noexcept {
        return pos_;
    }

private:
    inline bool is_eof() const {
        return pos_ >= buffer_.length();
    }

    inline char current() const {
        return buffer_[pos_];
    }

    std::size_t pos_;
    std::string_view buffer_;
};
