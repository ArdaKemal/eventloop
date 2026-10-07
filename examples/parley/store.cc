#include "store.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace parley {

namespace {

auto to_hex(const unsigned char* data, std::size_t size) -> std::string
{
    constexpr char digits[] = "0123456789abcdef";
    std::string out(size * 2, '0');
    for (std::size_t i = 0; i < size; ++i) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 0xf];
    }
    return out;
}

auto token_hash(std::string_view token) -> std::string
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned size = 0;
    if (EVP_Digest(token.data(), token.size(), digest.data(), &size, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("SHA-256 failed");
    return to_hex(digest.data(), size);
}

auto pair_key(user_id a, user_id b) -> std::uint64_t
{
    if (a > b) std::swap(a, b);
    return (std::uint64_t {a} << 32) | b;
}

} // namespace

auto now_ms() -> std::int64_t
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

auto random_hex(std::size_t bytes) -> std::string
{
    std::array<unsigned char, 64> data {};
    if (bytes > data.size() || RAND_bytes(data.data(), static_cast<int>(bytes)) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return to_hex(data.data(), bytes);
}

auto conversation::find_member(user_id user) -> member*
{
    for (auto& entry : members)
        if (entry.user == user) return &entry;
    return nullptr;
}

store::store(const std::filesystem::path& journal_path)
{
    std::ifstream file(journal_path, std::ios::binary);
    if (!file) return;
    replaying_ = true;
    std::string line;
    std::size_t number = 0;
    while (std::getline(file, line)) {
        ++number;
        if (file.eof()) break; // no trailing newline: a torn write
        replayed_bytes_ += line.size() + 1;
        auto record = json::parse(line);
        if (!record) throw std::runtime_error("journal line " + std::to_string(number) + " is invalid");
        apply(*record);
    }
    replaying_ = false;
}

auto store::journal(std::string line) -> void
{
    if (replaying_) return;
    backlog_ += line;
    backlog_.push_back('\n');
    if (journal_ready_) journal_ready_->notify();
}

auto store::apply(const json& r) -> void
{
    const auto op = r["op"].str();
    if (op == "user") {
        auto who = std::make_unique<user>();
        who->id = static_cast<user_id>(r["id"].integer());
        who->username = r["username"].str();
        who->name = r["name"].str();
        who->password = r["password"].str();
        who->created = r["created"].integer();
        insert_user(std::move(who));
    } else if (op == "profile") {
        if (auto* who = find_user(static_cast<user_id>(r["id"].integer()))) {
            who->name = r["name"].str(who->name);
            who->about = r["about"].str(who->about);
        }
    } else if (op == "seen") {
        if (auto* who = find_user(static_cast<user_id>(r["id"].integer())))
            who->last_seen = r["time"].integer();
    } else if (op == "session") {
        sessions_[std::string(r["hash"].str())] = static_cast<user_id>(r["user"].integer());
    } else if (op == "revoke") {
        sessions_.erase(std::string(r["hash"].str()));
    } else if (op == "conv") {
        auto where = std::make_unique<conversation>();
        where->id = static_cast<conversation_id>(r["id"].integer());
        where->group = r["group"].boolean();
        where->title = r["title"].str();
        where->creator = static_cast<user_id>(r["creator"].integer());
        where->created = r["created"].integer();
        for (const auto& id : r["members"].items())
            where->members.push_back({.user = static_cast<user_id>(id.integer())});
        insert_conversation(std::move(where));
    } else if (op == "media") {
        auto item = std::make_unique<media>();
        item->id = r["id"].str();
        item->owner = static_cast<user_id>(r["owner"].integer());
        item->kind = r["kind"].str();
        item->mime = r["mime"].str();
        item->name = r["name"].str();
        item->size = static_cast<std::uint64_t>(r["size"].integer());
        media_[item->id] = std::move(item);
    } else if (op == "msg") {
        message item;
        item.id = static_cast<message_id>(r["id"].integer());
        item.conversation = static_cast<conversation_id>(r["conv"].integer());
        item.sender = static_cast<user_id>(r["from"].integer());
        item.time = r["time"].integer();
        item.kind = r["kind"].str();
        item.text = r["text"].str();
        item.media_id = r["media"].str();
        item.duration_ms = r["duration"].integer();
        item.reply_to = static_cast<message_id>(r["reply_to"].integer());
        item.client_id = r["client_id"].str();
        insert_message(std::move(item));
    } else if (op == "mark") {
        if (auto* where = find_conversation(static_cast<conversation_id>(r["conv"].integer())))
            (void)mark(*where, static_cast<user_id>(r["user"].integer()),
                       static_cast<message_id>(r["delivered"].integer()),
                       static_cast<message_id>(r["read"].integer()));
    }
}

auto store::insert_user(std::unique_ptr<user> who) -> user*
{
    if (who->id != users_.size() + 1) throw std::runtime_error("journal user ids are not sequential");
    usernames_[who->username] = who->id;
    users_.push_back(std::move(who));
    return users_.back().get();
}

auto store::add_user(std::string_view username, std::string_view name, std::string password)
    -> std::expected<user*, error>
{
    if (username.size() < 3 || username.size() > 24 ||
        !std::ranges::all_of(username, [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.';
        }))
        return std::unexpected("Username must be 3-24 characters: a-z, 0-9, '.', '_'");
    if (name.empty() || name.size() > 64 || !valid_utf8(name))
        return std::unexpected("Display name must be 1-64 characters");
    if (find_username(username)) return std::unexpected("That username is taken");
    if (users_.size() >= max_users) return std::unexpected("This server is full");
    if (!writable()) return std::unexpected("Storage is busy; try again");

    auto who = std::make_unique<user>();
    who->id = static_cast<user_id>(users_.size() + 1);
    who->username = username;
    who->name = name;
    who->password = std::move(password);
    who->created = now_ms();
    std::string line;
    json_writer(line).begin_object().field("op", "user").field("id", who->id)
        .field("username", who->username).field("name", who->name)
        .field("password", who->password).field("created", who->created).end_object();
    journal(std::move(line));
    return insert_user(std::move(who));
}

auto store::find_user(user_id id) -> user*
{
    return id >= 1 && id <= users_.size() ? users_[id - 1].get() : nullptr;
}

auto store::find_username(std::string_view username) -> user*
{
    const auto found = usernames_.find(std::string(username));
    return found == usernames_.end() ? nullptr : find_user(found->second);
}

auto store::update_profile(user& who, std::string_view name, std::string_view about) -> void
{
    who.name = name;
    who.about = about;
    std::string line;
    json_writer(line).begin_object().field("op", "profile").field("id", who.id)
        .field("name", name).field("about", about).end_object();
    journal(std::move(line));
}

auto store::record_last_seen(user& who, std::int64_t time) -> void
{
    who.last_seen = time;
    std::string line;
    json_writer(line).begin_object().field("op", "seen").field("id", who.id)
        .field("time", time).end_object();
    journal(std::move(line));
}

auto store::create_session(user_id who) -> std::string
{
    auto token = random_hex(32);
    auto hash = token_hash(token);
    std::string line;
    json_writer(line).begin_object().field("op", "session").field("hash", hash)
        .field("user", who).end_object();
    journal(std::move(line));
    sessions_[std::move(hash)] = who;
    return token;
}

auto store::session_user(std::string_view token) -> user*
{
    if (token.size() != 64) return nullptr;
    const auto found = sessions_.find(token_hash(token));
    return found == sessions_.end() ? nullptr : find_user(found->second);
}

auto store::revoke_session(std::string_view token) -> void
{
    auto hash = token_hash(token);
    if (sessions_.erase(hash) == 0) return;
    std::string line;
    json_writer(line).begin_object().field("op", "revoke").field("hash", hash).end_object();
    journal(std::move(line));
}

auto store::find_conversation(conversation_id id) -> conversation*
{
    return id >= 1 && id <= conversations_.size() ? conversations_[id - 1].get() : nullptr;
}

auto store::insert_conversation(std::unique_ptr<conversation> where) -> conversation*
{
    if (where->id != conversations_.size() + 1)
        throw std::runtime_error("journal conversation ids are not sequential");
    if (!where->group && where->members.size() == 2)
        directs_[pair_key(where->members[0].user, where->members[1].user)] = where->id;
    for (const auto& entry : where->members) memberships_[entry.user].push_back(where->id);
    conversations_.push_back(std::move(where));
    return conversations_.back().get();
}

auto store::direct_conversation(user_id a, user_id b)
    -> std::expected<std::pair<conversation*, bool>, error>
{
    if (a == b || !find_user(a) || !find_user(b)) return std::unexpected("Unknown contact");
    if (const auto found = directs_.find(pair_key(a, b)); found != directs_.end())
        return std::pair {find_conversation(found->second), false};
    if (conversations_.size() >= max_conversations) return std::unexpected("This server is full");
    if (!writable()) return std::unexpected("Storage is busy; try again");
    auto where = std::make_unique<conversation>();
    where->id = static_cast<conversation_id>(conversations_.size() + 1);
    where->creator = a;
    where->created = now_ms();
    where->members = {{.user = a}, {.user = b}};
    std::string line;
    json_writer(line).begin_object().field("op", "conv").field("id", where->id)
        .field("group", false).field("title", "").field("creator", a)
        .field("created", where->created).key("members").begin_array().value(a).value(b)
        .end_array().end_object();
    journal(std::move(line));
    return std::pair {insert_conversation(std::move(where)), true};
}

auto store::create_group(user_id creator, std::string_view title, std::vector<user_id> members)
    -> std::expected<conversation*, error>
{
    if (title.empty() || title.size() > 64 || !valid_utf8(title))
        return std::unexpected("Group name must be 1-64 characters");
    members.push_back(creator);
    std::ranges::sort(members);
    members.erase(std::ranges::unique(members).begin(), members.end());
    if (members.size() < 2) return std::unexpected("Pick at least one other member");
    if (members.size() > max_group_members) return std::unexpected("Too many members");
    for (const auto id : members)
        if (!find_user(id)) return std::unexpected("Unknown member");
    if (conversations_.size() >= max_conversations) return std::unexpected("This server is full");
    if (!writable()) return std::unexpected("Storage is busy; try again");

    auto where = std::make_unique<conversation>();
    where->id = static_cast<conversation_id>(conversations_.size() + 1);
    where->group = true;
    where->title = title;
    where->creator = creator;
    where->created = now_ms();
    std::string line;
    json_writer out(line);
    out.begin_object().field("op", "conv").field("id", where->id).field("group", true)
        .field("title", title).field("creator", creator).field("created", where->created)
        .key("members").begin_array();
    for (const auto id : members) {
        where->members.push_back({.user = id});
        out.value(id);
    }
    out.end_array().end_object();
    journal(std::move(line));
    return insert_conversation(std::move(where));
}

auto store::conversations_of(user_id who) const -> const std::vector<conversation_id>&
{
    static const std::vector<conversation_id> none;
    const auto found = memberships_.find(who);
    return found == memberships_.end() ? none : found->second;
}

auto store::add_media(media item) -> media*
{
    std::string line;
    json_writer(line).begin_object().field("op", "media").field("id", item.id)
        .field("owner", item.owner).field("kind", item.kind).field("mime", item.mime)
        .field("name", item.name).field("size", item.size).end_object();
    journal(std::move(line));
    auto stored = std::make_unique<media>(std::move(item));
    auto* result = stored.get();
    media_[result->id] = std::move(stored);
    return result;
}

auto store::find_media(std::string_view id) -> media*
{
    const auto found = media_.find(std::string(id));
    return found == media_.end() ? nullptr : found->second.get();
}

auto store::insert_message(message item) -> message*
{
    auto* where = find_conversation(item.conversation);
    if (!where) throw std::runtime_error("journal message has no conversation");
    if (!item.media_id.empty())
        if (auto* attached = find_media(item.media_id)) attached->conversation = where->id;
    next_message_ = std::max(next_message_, item.id + 1);
    where->messages.push_back(std::move(item));
    if (where->messages.size() > max_retained_messages) where->messages.pop_front();
    auto& stored = where->messages.back();
    // The sender has trivially seen its own message.
    if (auto* sender = where->find_member(stored.sender)) {
        sender->delivered = std::max(sender->delivered, stored.id);
        sender->read = std::max(sender->read, stored.id);
    }
    return &stored;
}

auto store::add_message(message item) -> std::expected<message*, error>
{
    auto* where = find_conversation(item.conversation);
    if (!where || !where->find_member(item.sender)) return std::unexpected("Unknown conversation");
    if (item.text.size() > max_text_bytes || !valid_utf8(item.text))
        return std::unexpected("Message is too long");
    if (item.client_id.size() > 64 || !valid_utf8(item.client_id))
        return std::unexpected("Invalid client id");
    if (!item.media_id.empty()) {
        auto* attached = find_media(item.media_id);
        if (!attached || attached->owner != item.sender ||
            (attached->conversation != 0 && attached->conversation != where->id))
            return std::unexpected("Unknown attachment");
        item.kind = attached->kind;
    } else {
        if (item.text.empty()) return std::unexpected("Message is empty");
        item.kind = "text";
        item.duration_ms = 0;
    }
    if (item.reply_to >= next_message_) item.reply_to = 0;
    if (!writable()) return std::unexpected("Storage is busy; try again");
    item.id = next_message_++;
    item.time = now_ms();
    std::string line;
    json_writer out(line);
    out.begin_object().field("op", "msg").field("id", item.id).field("conv", item.conversation)
        .field("from", item.sender).field("time", item.time).field("kind", item.kind)
        .field("text", item.text);
    if (!item.media_id.empty()) out.field("media", item.media_id).field("duration", item.duration_ms);
    if (item.reply_to) out.field("reply_to", item.reply_to);
    if (!item.client_id.empty()) out.field("client_id", item.client_id);
    out.end_object();
    journal(std::move(line));
    return insert_message(std::move(item));
}

auto store::mark(conversation& where, user_id who, message_id delivered, message_id read) -> bool
{
    auto* entry = where.find_member(who);
    if (!entry || where.messages.empty()) return false;
    const auto last = where.messages.back().id;
    read = std::min(read, last);
    delivered = std::min(std::max(delivered, read), last);
    if (delivered <= entry->delivered && read <= entry->read) return false;
    entry->delivered = std::max(entry->delivered, delivered);
    entry->read = std::max(entry->read, read);
    std::string line;
    json_writer(line).begin_object().field("op", "mark").field("conv", where.id)
        .field("user", who).field("delivered", entry->delivered).field("read", entry->read)
        .end_object();
    journal(std::move(line));
    return true;
}

auto store::write_user(json_writer& out, const user& who, bool online) const -> void
{
    out.begin_object().field("id", who.id).field("username", who.username)
        .field("name", who.name).field("about", who.about).field("online", online)
        .field("last_seen", who.last_seen).end_object();
}

auto store::write_conversation(json_writer& out, const conversation& where, user_id viewer) const
    -> void
{
    out.begin_object().field("id", where.id).field("group", where.group)
        .field("title", where.title).field("creator", where.creator)
        .field("created", where.created).key("members").begin_array();
    message_id my_read = 0;
    for (const auto& entry : where.members) {
        out.begin_object().field("user", entry.user).field("delivered", entry.delivered)
            .field("read", entry.read).end_object();
        if (entry.user == viewer) my_read = entry.read;
    }
    out.end_array();
    std::uint64_t unread = 0;
    for (auto item = where.messages.rbegin(); item != where.messages.rend() && item->id > my_read; ++item)
        if (item->sender != viewer) ++unread;
    out.field("unread", unread).key("last");
    if (where.messages.empty()) out.null();
    else write_message(out, where.messages.back());
    out.end_object();
}

auto store::write_message(json_writer& out, const message& item) const -> void
{
    out.begin_object().field("id", item.id).field("conv", item.conversation)
        .field("from", item.sender).field("time", item.time).field("kind", item.kind)
        .field("text", item.text);
    if (item.reply_to) out.field("reply_to", item.reply_to);
    if (!item.client_id.empty()) out.field("client_id", item.client_id);
    if (!item.media_id.empty()) {
        out.key("media").begin_object().field("id", item.media_id)
            .field("url", "/media/" + item.media_id).field("duration", item.duration_ms);
        if (const auto found = media_.find(item.media_id); found != media_.end())
            out.field("name", found->second->name).field("mime", found->second->mime)
                .field("size", found->second->size);
        out.end_object();
    }
    out.end_object();
}

} // namespace parley
