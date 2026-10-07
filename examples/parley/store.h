#pragma once

// Parley's state: users, sessions, conversations, messages, media, and
// receipts. Everything lives in memory on the loop thread. Each change is
// appended to a JSON-lines journal that is replayed at startup; the journal
// writer coroutine in main.cc drains journal_backlog().

#include "json.h"

#include "eventloop/wakeup.h"

#include <cstdint>
#include <deque>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace parley {

using user_id = std::uint32_t;
using conversation_id = std::uint32_t;
using message_id = std::uint64_t;

inline constexpr std::size_t max_users = 4096;
inline constexpr std::size_t max_conversations = 65536;
inline constexpr std::size_t max_group_members = 256;
inline constexpr std::size_t max_text_bytes = 4096;
// Older messages leave memory (and history) past this many per conversation.
inline constexpr std::size_t max_retained_messages = 20000;
// Mutations fail with "storage busy" while this much journal is unwritten.
inline constexpr std::size_t max_journal_backlog = 16 * 1024 * 1024;

[[nodiscard]] auto now_ms() -> std::int64_t;
[[nodiscard]] auto random_hex(std::size_t bytes) -> std::string;

struct user {
    user_id id {0};
    std::string username;
    std::string name;
    std::string about;
    std::string password; // pbkdf2$<iterations>$<salt hex>$<hash hex>
    std::int64_t created {0};
    std::int64_t last_seen {0};
};

struct media {
    std::string id; // 32 hex digits, also the file name in the media directory
    user_id owner {0};
    conversation_id conversation {0}; // 0 until a message uses it
    std::string kind; // image, audio, or file
    std::string mime;
    std::string name;
    std::uint64_t size {0};
};

struct message {
    message_id id {0};
    conversation_id conversation {0};
    user_id sender {0};
    std::int64_t time {0};
    std::string kind; // text, image, audio, or file
    std::string text;
    std::string media_id;
    std::int64_t duration_ms {0}; // voice notes
    message_id reply_to {0};
    std::string client_id;
};

struct member {
    user_id user {0};
    message_id delivered {0};
    message_id read {0};
};

struct conversation {
    conversation_id id {0};
    bool group {false};
    std::string title;
    user_id creator {0};
    std::int64_t created {0};
    std::vector<member> members;
    std::deque<message> messages;

    [[nodiscard]] auto find_member(user_id user) -> member*;
};

class store {
public:
    using error = std::string;

    // Replays the journal; a torn final line is ignored.
    explicit store(const std::filesystem::path& journal_path);

    [[nodiscard]] auto journal_size() const noexcept -> std::uint64_t { return replayed_bytes_; }
    [[nodiscard]] auto journal_backlog() -> std::string& { return backlog_; }
    // Notified whenever a journal line is appended.
    auto set_journal_wakeup(eventloop::wakeup* ready) noexcept -> void { journal_ready_ = ready; }
    [[nodiscard]] auto writable() const noexcept -> bool
    {
        return backlog_.size() < max_journal_backlog;
    }

    [[nodiscard]] auto add_user(std::string_view username, std::string_view name,
                                std::string password) -> std::expected<user*, error>;
    [[nodiscard]] auto find_user(user_id id) -> user*;
    [[nodiscard]] auto find_username(std::string_view username) -> user*;
    [[nodiscard]] auto users() const -> const std::vector<std::unique_ptr<user>>& { return users_; }
    auto update_profile(user& who, std::string_view name, std::string_view about) -> void;
    auto record_last_seen(user& who, std::int64_t time) -> void;

    // Returns a new bearer token; only its SHA-256 is stored.
    [[nodiscard]] auto create_session(user_id who) -> std::string;
    [[nodiscard]] auto session_user(std::string_view token) -> user*;
    auto revoke_session(std::string_view token) -> void;

    [[nodiscard]] auto find_conversation(conversation_id id) -> conversation*;
    // Finds or creates the direct conversation; second is true when created.
    [[nodiscard]] auto direct_conversation(user_id a, user_id b)
        -> std::expected<std::pair<conversation*, bool>, error>;
    [[nodiscard]] auto create_group(user_id creator, std::string_view title,
                                    std::vector<user_id> members)
        -> std::expected<conversation*, error>;
    [[nodiscard]] auto conversations_of(user_id who) const -> const std::vector<conversation_id>&;

    [[nodiscard]] auto add_media(media item) -> media*;
    [[nodiscard]] auto find_media(std::string_view id) -> media*;

    [[nodiscard]] auto add_message(message item) -> std::expected<message*, error>;
    // Receipts only move forward; returns false when nothing changed.
    auto mark(conversation& where, user_id who, message_id delivered, message_id read) -> bool;

    auto write_user(json_writer& out, const user& who, bool online) const -> void;
    auto write_conversation(json_writer& out, const conversation& where, user_id viewer) const -> void;
    auto write_message(json_writer& out, const message& item) const -> void;

private:
    auto apply(const json& record) -> void;
    auto journal(std::string line) -> void;
    auto insert_user(std::unique_ptr<user> who) -> user*;
    auto insert_conversation(std::unique_ptr<conversation> where) -> conversation*;
    auto insert_message(message item) -> message*;

    std::vector<std::unique_ptr<user>> users_; // index is id - 1
    std::unordered_map<std::string, user_id> usernames_;
    std::unordered_map<std::string, user_id> sessions_; // SHA-256 hex -> user
    std::vector<std::unique_ptr<conversation>> conversations_; // index is id - 1
    std::unordered_map<std::uint64_t, conversation_id> directs_;
    std::unordered_map<user_id, std::vector<conversation_id>> memberships_;
    std::unordered_map<std::string, std::unique_ptr<media>> media_;
    message_id next_message_ {1};
    std::uint64_t replayed_bytes_ {0};
    bool replaying_ {false};
    std::string backlog_;
    eventloop::wakeup* journal_ready_ {nullptr};
};

} // namespace parley
