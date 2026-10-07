#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace lantern {

struct video {
    std::string id;
    std::string mime;
    std::string title;
    std::string description;
    std::string channel;
    std::uint64_t size {0};
    std::uint64_t duration_ms {0};
    std::int64_t created {0}; // Unix seconds
    std::uint64_t views {0};
    bool thumbnail {false};
};

// A video whose bytes are still arriving in uploads/<id>.
struct upload {
    video details;
    std::uint64_t received {0};
    bool busy {false}; // a request is writing a chunk
};

// Ids name files, so they are exactly 11 base64url characters.
[[nodiscard]] auto valid_id(std::string_view id) noexcept -> bool;

// The library state, rebuilt at startup from a journal of tab-separated
// records. Every change is a record too: apply() is the only way to change
// the catalog, so replay and live requests share one code path.
//
//   upload <id> <size> <mime> <created> <duration ms> <title> <description> <channel>
//   thumbnail <id>
//   publish <id>
//   view <id>
//   discard <id>
//
// Text fields are percent-encoded. A record cut short by a crash or a
// cancelled write does not parse and is skipped.
class catalog {
public:
    [[nodiscard]] auto apply(std::string_view record) -> bool;
    auto replay(std::string_view journal) -> void;

    [[nodiscard]] auto find_video(std::string_view id) -> video*;
    [[nodiscard]] auto find_upload(std::string_view id) -> upload*;
    [[nodiscard]] auto videos() const noexcept -> const auto& { return videos_; }
    [[nodiscard]] auto uploads() noexcept -> auto& { return uploads_; }

    // Percent-encodes a text field for a record.
    [[nodiscard]] static auto field(std::string_view text) -> std::string;

private:
    struct hash {
        using is_transparent = void;
        auto operator()(std::string_view text) const noexcept -> std::size_t
        {
            return std::hash<std::string_view> {}(text);
        }
    };
    template<typename T>
    using table = std::unordered_map<std::string, T, hash, std::equal_to<>>;

    table<video> videos_;
    table<upload> uploads_;
};

} // namespace lantern
