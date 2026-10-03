#include "eventloop/quic.h"

#include "quic/connection.h"
#include "quic/connection_driver.h"
#include "quic/retry_packet.h"
#include "quic/stream_registry.h"
#include "quic/transport_parameters.h"
#include "quic/transport_parameter_validation.h"
#include "quic/udp_endpoint.h"

#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <vector>
#include <coroutine>
#include <cstring>
#include <optional>
#include <utility>

namespace eventloop {

using namespace eventloop::quic::detail;

namespace {

auto quic_category() noexcept -> const std::error_category&
{
    static const struct category final : std::error_category {
        [[nodiscard]] auto name() const noexcept -> const char* override
        { return "eventloop.quic"; }
        [[nodiscard]] auto message(int value) const -> std::string override
        {
            switch (static_cast<quic_errc>(value)) {
            case quic_errc::invalid_argument: return "invalid argument";
            case quic_errc::invalid_state: return "invalid state";
            case quic_errc::capacity_exceeded: return "capacity exceeded";
            case quic_errc::not_connected: return "connection is not established";
            case quic_errc::wrong_loop: return "operation on the wrong event loop";
            case quic_errc::stream_limit: return "stream limit reached";
            case quic_errc::stream_reset: return "stream reset by peer";
            case quic_errc::peer_closed: return "peer closed the connection";
            case quic_errc::datagram_not_supported: return "DATAGRAM not negotiated";
            case quic_errc::output_too_small: return "output buffer too small";
            case quic_errc::tls_failure: return "TLS configuration failure";
            }
            return "unknown QUIC error";
        }
    } instance;
    return instance;
}

// Preserve the driver's exact failure in the public expected error without
// exposing internal transport enums in the public API.
auto driver_error_code(connection_error value) noexcept -> std::error_code
{
    static const struct category final : std::error_category {
        auto name() const noexcept -> const char* override
        { return "eventloop.quic.driver"; }
        auto message(int value) const -> std::string override
        {
            switch (static_cast<connection_error>(value - 1)) {
            case connection_error::invalid_state: return "invalid connection state";
            case connection_error::invalid_configuration: return "invalid connection configuration";
            case connection_error::unavailable_keys: return "packet keys unavailable";
            case connection_error::malformed_packet: return "malformed packet";
            case connection_error::authentication_failed: return "packet authentication failed";
            case connection_error::protocol_violation: return "protocol violation";
            case connection_error::capacity_exceeded: return "connection capacity exceeded";
            case connection_error::tls_failure: return "TLS failure";
            case connection_error::provider_failure: return "transport provider failure";
            case connection_error::output_too_small: return "packet output buffer too small";
            case connection_error::unsupported_frame: return "unsupported frame";
            case connection_error::key_update_violation: return "key update violation";
            case connection_error::aead_limit_reached: return "AEAD usage limit reached";
            }
            return "unknown connection driver error";
        }
    } instance;
    // connection_error starts at zero; reserve zero for success in error_code.
    return {static_cast<int>(value) + 1, instance};
}

constexpr std::size_t short_cid_length = 8;
constexpr auto close_poll_interval = std::chrono::milliseconds(1);
constexpr std::size_t parameter_buffer_size = 512;

auto as_u8(std::span<const std::byte> value) noexcept
    -> std::span<const std::uint8_t>
{
    return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}

auto to_internal_version(quic_version version) noexcept -> std::uint32_t
{
    return version == quic_version::v2 ? version_2 : version_1;
}

} // namespace

auto make_error_code(quic_errc value) noexcept -> std::error_code
{
    return {static_cast<int>(value), quic_category()};
}

class quic_endpoint::implementation {
public:
    struct waiter_state {
        static constexpr auto no_index = static_cast<std::size_t>(-1);

        struct group {
            std::size_t head {no_index};
            std::size_t tail {no_index};
            std::size_t count {0};
            bool pending {false};
        };

        explicit waiter_state(std::size_t slots)
            : handles(slots * 256), next(handles.size()), groups(slots + 1),
              pending(groups.size())
        {
            for (std::size_t i = 0; i < next.size(); ++i)
                next[i] = i + 1 == next.size() ? no_index : i + 1;
            if (!handles.empty()) free_head = 0;
        }

        // Group zero is endpoint acceptance; each slot has its own group.
        // All groups share the same pool, retaining the aggregate capacity.
        auto register_waiter(std::size_t index,
                             std::coroutine_handle<> handle) noexcept -> bool
        {
            if (free_head == no_index) return false;
            const auto node = free_head;
            free_head = next[node];
            next[node] = no_index;
            handles[node] = handle;
            auto& queue = groups[index];
            if (queue.tail == no_index) queue.head = node;
            else next[queue.tail] = node;
            queue.tail = node;
            ++queue.count;
            return true;
        }

        auto request_wake(std::size_t index) noexcept -> void
        {
            auto& queue = groups[index];
            if (queue.pending || queue.count == 0) return;
            queue.pending = true;
            pending[(pending_head + pending_count) % pending.size()] = index;
            ++pending_count;
        }

        auto drain() noexcept -> void
        {
            if (waking) return;
            waking = true;
            while (pending_count != 0) {
                const auto index = pending[pending_head];
                pending_head = (pending_head + 1) % pending.size();
                --pending_count;
                auto& queue = groups[index];
                queue.pending = false;
                const auto initial = queue.count;
                for (std::size_t i = 0; i < initial; ++i) {
                    const auto node = queue.head;
                    auto handle = handles[node];
                    queue.head = next[node];
                    if (queue.head == no_index) queue.tail = no_index;
                    --queue.count;
                    handles[node] = {};
                    next[node] = free_head;
                    free_head = node;
                    if (handle && !handle.done()) handle.resume();
                }
            }
            waking = false;
        }

        auto wake_connection(std::size_t slot_index) noexcept -> void
        {
            request_wake(slot_index + 1);
            request_wake(0);
            drain();
        }

        auto wake_all() noexcept -> void
        {
            for (std::size_t i = 0; i < groups.size(); ++i) request_wake(i);
            drain();
        }

        std::vector<std::coroutine_handle<>> handles;
        std::vector<std::size_t> next;
        std::vector<group> groups;
        std::vector<std::size_t> pending;
        std::size_t free_head {no_index};
        std::size_t pending_head {0};
        std::size_t pending_count {0};
        bool waking {false};
    };

    struct slot {
        implementation* owner {nullptr};
        bool occupied {false};
        bool accepted {false};
        bool closing {false};
        bool driver_finished {false};
        std::uint32_t generation {0};
        // Retained after clear() until this slot receives a new generation.
        std::error_code terminal_error {};
        std::optional<quic::detail::bounded_connection> connection;
        std::optional<quic::detail::connection_driver> driver;
        ip_endpoint peer {};
        std::array<std::byte, short_cid_length> local_cid {};
        std::array<std::byte, 20> original_dcid {};
        std::size_t original_dcid_size {0};
        std::uint32_t version {version_1};
        bool client {false};
        bool retry_used {false};
        bool retry_pending {false};
        std::array<std::byte, 20> retry_scid {};
        std::size_t retry_scid_size {0};
        // Bound accepted tokens so a restarted Initial fits the driver's packet.
        std::array<std::uint8_t, 512> retry_token {};
        std::size_t retry_token_size {0};
        std::array<std::uint8_t, parameter_buffer_size> parameters {};
        std::size_t parameters_size {0};
        endpoint_connection route {0};

        auto clear() noexcept -> void
        {
            driver.reset();
            connection.reset();
            occupied = false;
            accepted = false;
            closing = false;
            driver_finished = false;
            original_dcid_size = 0;
            retry_used = retry_pending = false;
            retry_scid_size = retry_token_size = 0;
            parameters_size = 0;
            route = 0;
            peer = {};
        }
    };

    implementation(event_loop& loop, ip_endpoint local, quic_server_options options)
        : loop_(loop),
          endpoint_(loop, local, path_endpoint_role::server, short_cid_length,
                    endpoint_accept_callback {this, accept_initial}, true,
                    options.connection_capacity),
          server_options_(std::move(options)),
          slots_(server_options_.connection_capacity),
          waiters_(std::make_shared<waiter_state>(server_options_.connection_capacity))
    {
        common_init();
    }

    implementation(event_loop& loop, ip_endpoint local, quic_client_options options)
        : loop_(loop),
          endpoint_(loop, local, path_endpoint_role::client, short_cid_length,
                    endpoint_accept_callback {}, true, 8),
          client_options_(std::move(options)),
          slots_(8), client_mode_(true),
          waiters_(std::make_shared<waiter_state>(8))
    {
        common_init();
    }

    ~implementation()
    {
        if (receiving_) std::terminate();
        for (auto& entry : slots_)
            if (entry.driver && !entry.driver_finished) std::terminate();
        if (context_) SSL_CTX_free(context_);
    }

    implementation(const implementation&) = delete;
    auto operator=(const implementation&) -> implementation& = delete;

    [[nodiscard]] auto configured() const noexcept -> bool { return configured_; }
    [[nodiscard]] auto client_mode() const noexcept -> bool { return client_mode_; }
    [[nodiscard]] auto local_endpoint() const noexcept -> ip_endpoint
    { return endpoint_.local_endpoint(); }

    // Progress-hook waiters: each public operation registers its coroutine
    // handle once and is resumed by the connection-driver progress callback, so
    // stream/DATAGRAM operations do not poll on a timer.
    auto register_waiter(std::size_t group,
                         std::coroutine_handle<> handle) noexcept -> bool
    { return waiters_->register_waiter(group, handle); }

    auto wake_connection(std::size_t slot_index) noexcept -> void
    {
        auto state = waiters_; // A resumed waiter may destroy this endpoint.
        state->wake_connection(slot_index);
    }

    auto wake_all() noexcept -> void
    {
        auto state = waiters_; // A resumed waiter may destroy this endpoint.
        state->wake_all();
    }

    auto stop_all() noexcept -> void
    {
        closing_ = true;
        endpoint_.close();
        for (auto& entry : slots_)
            if (entry.driver) entry.driver->stop();
        wake_all();
    }

    [[nodiscard]] auto all_retired() const noexcept -> bool
    {
        if (receiving_) return false;
        for (const auto& entry : slots_)
            if (entry.driver && !entry.driver_finished) return false;
        return true;
    }

    auto reap() noexcept -> void
    {
        for (auto& entry : slots_) {
            if (!entry.occupied) continue;
            if (entry.driver && !entry.driver_finished) continue;
            if (entry.terminal_error && !entry.accepted) continue;
            entry.clear();
        }
    }

    [[nodiscard]] auto slot_of(slot& entry) const noexcept -> std::size_t
    { return static_cast<std::size_t>(&entry - slots_.data()); }

    auto start_client(slot& entry, ip_endpoint server,
                      std::string_view server_name) noexcept -> bool
    {
        entry.occupied = true;
        entry.accepted = true;
        entry.closing = false;
        entry.generation = ++next_generation_;
        entry.terminal_error = {};
        entry.peer = server;
        entry.client = true;
        entry.version = to_internal_version(client_options_.version);
        if (RAND_bytes(reinterpret_cast<unsigned char*>(entry.local_cid.data()),
                static_cast<int>(entry.local_cid.size())) != 1) {
            entry.clear();
            return false;
        }
        std::array<std::byte, short_cid_length> initial_dcid {};
        if (RAND_bytes(reinterpret_cast<unsigned char*>(initial_dcid.data()),
                static_cast<int>(initial_dcid.size())) != 1) {
            entry.clear();
            return false;
        }
        entry.original_dcid_size = initial_dcid.size();
        std::copy(initial_dcid.begin(), initial_dcid.end(), entry.original_dcid.begin());
        if (!build_parameters(entry, true)) {
            entry.clear();
            return false;
        }
        if (!initialize_client(entry, as_u8(std::span<const std::byte>(initial_dcid)), server_name)) {
            entry.clear();
            return false;
        }
        if (loop_.spawn(drive(loop_, *this, entry)) !=
            task_spawn_result::accepted) {
            entry.clear();
            return false;
        }
        entry.driver->set_progress(&entry, &implementation::on_progress);
        return true;
    }

    event_loop& loop_;
    udp_endpoint endpoint_;
    quic_server_options server_options_ {};
    quic_client_options client_options_ {};
    SSL_CTX* context_ {nullptr};
    std::array<std::uint8_t, 255> alpn_ {};
    std::size_t alpn_size_ {0};
    std::vector<slot> slots_;
    quic_endpoint* owner_ {nullptr};
    bool client_mode_ {false};
    bool configured_ {false};
    bool closing_ {false};
    bool receiving_ {false};
    std::uint32_t next_generation_ {0};
    std::shared_ptr<waiter_state> waiters_;

private:
    static auto accept_retry(void* argument, std::span<const std::uint8_t> packet) noexcept -> bool
    {
        auto& entry = *static_cast<slot*>(argument);
        if (!entry.client || entry.retry_used || entry.closing) return false;
        const auto retry = parse_and_validate_retry_packet(packet, entry.version,
            as_u8(std::span(entry.original_dcid).first(entry.original_dcid_size)));
        if (!retry || !std::ranges::equal(retry->destination_cid, entry.local_cid) ||
            retry->token.size() > entry.retry_token.size())
            return false;
        std::copy(retry->source_cid.begin(), retry->source_cid.end(), entry.retry_scid.begin());
        entry.retry_scid_size = retry->source_cid.size();
        std::ranges::copy(as_u8(retry->token), entry.retry_token.begin());
        entry.retry_token_size = retry->token.size();
        entry.retry_used = entry.retry_pending = true;
        return true;
    }

    auto initialize_client(slot& entry, std::span<const std::uint8_t> dcid,
                           std::string_view server_name) noexcept -> bool
    {
        entry.connection.emplace(endpoint_role::client,
            connection_callbacks {&entry, validate_peer, accept_frame},
            lifecycle_time_point::clock::now());
        quic::detail::tls_options tls;
        tls.server_name = server_name;
        tls.alpn = {alpn_.data(), alpn_size_};
        tls.transport_parameters = {entry.parameters.data(), entry.parameters_size};
        if (!entry.connection->initialize(context_, tls, entry.version, dcid)) return false;
        return initialize_client_driver(entry, dcid);
    }

    auto initialize_client_driver(slot& entry, std::span<const std::uint8_t> dcid) noexcept -> bool
    {
        entry.driver.emplace(loop_, endpoint_, *entry.connection,
            as_u8(std::span<const std::byte>(entry.local_cid)), dcid, entry.peer, true);
        entry.route = endpoint_.router().lookup(entry.local_cid);
        entry.driver->set_retry_handler(&entry, accept_retry);
        entry.driver->set_initial_token(std::span(entry.retry_token).first(entry.retry_token_size));
        entry.driver->set_progress(&entry, &implementation::on_progress);
        return entry.route != 0;
    }

    auto common_init() noexcept -> void
    {
        for (auto& entry : slots_) entry.owner = this;
        const auto alpn = client_mode_ ? client_options_.alpn : server_options_.alpn;
        if (alpn.empty() || alpn.size() > alpn_.size()) return;
        std::copy(alpn.begin(), alpn.end(), alpn_.begin());
        alpn_size_ = alpn.size();
        if (!build_context()) return;
        configured_ = true;
        (void)loop_.spawn(receiver(loop_, *this));
    }

    [[nodiscard]] auto limits() const noexcept -> const quic_transport_limits&
    { return client_mode_ ? client_options_.limits : server_options_.limits; }

    auto build_context() noexcept -> bool
    {
        if (client_mode_) {
            context_ = SSL_CTX_new(TLS_client_method());
            if (!context_) return false;
            if (client_options_.trusted_ca.empty())
                return SSL_CTX_set_default_verify_paths(context_) == 1;
            const auto ca = client_options_.trusted_ca.string();
            return SSL_CTX_load_verify_locations(context_, ca.c_str(), nullptr) == 1;
        }
        if (server_options_.certificate_chain.empty() || server_options_.private_key.empty())
            return false;
        context_ = SSL_CTX_new(TLS_server_method());
        if (!context_) return false;
        const auto chain = server_options_.certificate_chain.string();
        const auto key = server_options_.private_key.string();
        return SSL_CTX_use_certificate_chain_file(context_, chain.c_str()) == 1 &&
            SSL_CTX_use_PrivateKey_file(context_, key.c_str(), SSL_FILETYPE_PEM) == 1 &&
            SSL_CTX_check_private_key(context_) == 1 &&
            (quic::detail::tls_provider::configure_server_context(context_), true);
    }

    static auto receiver(event_loop&, implementation& self) -> task<void>
    {
        self.receiving_ = true;
        (void)co_await self.endpoint_.run();
        self.receiving_ = false;
    }

    static auto drive(event_loop&, implementation& self, slot& entry) -> task<void>
    {
        auto result = co_await entry.driver->run();
        while (entry.retry_pending && result && *result && !self.closing_ && !entry.closing) {
            // Awaited run() and its suspended sends have retired. The destructor
            // removes the old route before new Initial keys are installed.
            entry.driver.reset();
            entry.route = 0;
            entry.retry_pending = false;
            const auto dcid = as_u8(std::span(entry.retry_scid).first(entry.retry_scid_size));
            if (!entry.connection->apply_retry(dcid) || !self.initialize_client_driver(entry, dcid)) {
                entry.terminal_error = make_error_code(quic_errc::tls_failure);
                break;
            }
            result = co_await entry.driver->run();
        }
        entry.driver_finished = true;
        if (!entry.terminal_error) {
            if (!result)
                entry.terminal_error = detail::task_error_code(result.error());
            else if (!*result)
                entry.terminal_error = driver_error_code(result->error());
            else
                entry.terminal_error = make_error_code(quic_errc::peer_closed);
        }
        entry.closing = true;
        // run() has retired before resuming this wrapper. Reap before waking:
        // resumed operations may close and destroy the endpoint inline.
        const auto index = self.slot_of(entry);
        self.reap();
        self.wake_connection(index);
    }

    static auto accept_initial(void* argument, endpoint_router& router,
        const packet_header& header, ip_endpoint source) noexcept -> bool
    {
        (void)router;
        auto& self = *static_cast<implementation*>(argument);
        if (self.closing_ || self.client_mode_ ||
            header.kind != packet_kind::initial || header.destination_cid.empty())
            return false;
        slot* entry = nullptr;
        for (auto& candidate : self.slots_)
            if (!candidate.occupied) { entry = &candidate; break; }
        if (entry == nullptr) return false;

        entry->occupied = true;
        entry->closing = false;
        entry->generation = ++self.next_generation_;
        entry->terminal_error = {};
        entry->peer = source;
        entry->client = false;
        entry->version = header.version;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(entry->local_cid.data()),
                static_cast<int>(entry->local_cid.size())) != 1) {
            entry->clear();
            return false;
        }
        const auto original = header.destination_cid;
        entry->original_dcid_size = std::min(original.size(), entry->original_dcid.size());
        std::copy_n(original.begin(), entry->original_dcid_size, entry->original_dcid.begin());
        if (!self.build_parameters(*entry, false)) {
            entry->clear();
            return false;
        }
        entry->connection.emplace(endpoint_role::server,
            connection_callbacks {entry, validate_peer, accept_frame},
            lifecycle_time_point::clock::now());
        quic::detail::tls_options tls;
        tls.server = true;
        tls.alpn = {self.alpn_.data(), self.alpn_size_};
        tls.transport_parameters = {entry->parameters.data(), entry->parameters_size};
        if (!entry->connection->initialize(self.context_, tls, header.version,
                as_u8(std::span<const std::byte>(entry->original_dcid).first(
                    entry->original_dcid_size))).has_value()) {
            entry->clear();
            return false;
        }
        if (!entry->connection->peer_ids().set_initial(header.source_cid)) {
            entry->clear();
            return false;
        }
        entry->driver.emplace(self.loop_, self.endpoint_, *entry->connection,
            as_u8(std::span<const std::byte>(entry->local_cid)),
            as_u8(header.source_cid), source, false);
        entry->route = self.endpoint_.router().lookup(
            std::span<const std::byte>(entry->local_cid));
        if (entry->route == 0 ||
            !self.endpoint_.router().add_cid(entry->route, original)) {
            entry->clear();
            return false;
        }
        if (self.loop_.spawn(self.drive(self.loop_, self, *entry)) !=
            task_spawn_result::accepted) {
            (void)self.endpoint_.router().remove(entry->route);
            entry->clear();
            return false;
        }
        entry->driver->set_progress(entry, &implementation::on_progress);
        return true;
    }

    static auto on_progress(void* argument) noexcept -> void
    {
        auto& entry = *static_cast<slot*>(argument);
        auto& self = *entry.owner;
        const auto index = self.slot_of(entry);
        // The pumping driver is still running. Retired slots are reaped by
        // drive(), connection acceptance, and endpoint close instead.
        self.wake_connection(index);
    }

    static auto validate_peer(void* argument, std::span<const std::uint8_t> bytes) noexcept -> bool
    {
        auto& entry = *static_cast<slot*>(argument);
        const auto peer_role = entry.client ? parameter_sender::server : parameter_sender::client;
        const auto parameters = decode_transport_parameters(std::as_bytes(bytes), peer_role);
        const auto source = entry.connection->core().peer_initial_source_cid();
        if (!parameters || !source) return false;
        const std::array available {entry.version};
        parameter_handshake_observations seen;
        seen.peer_role = peer_role;
        seen.peer_first_initial_scid = *source;
        seen.original_initial_dcid = std::span(entry.original_dcid).first(entry.original_dcid_size);
        seen.retry_used = entry.retry_used;
        seen.retry_scid = std::span(entry.retry_scid).first(entry.retry_scid_size);
        seen.client_chosen_version = seen.negotiated_version = entry.version;
        seen.client_available_versions = available;
        return validate_peer_transport_parameters(*parameters, seen).has_value();
    }
    static auto accept_frame(void*, tls_level, const decoded_frame&) noexcept -> bool
    { return true; }

    auto build_parameters(slot& entry, bool client) noexcept -> bool
    {
        std::array<transport_parameter, 16> entries {};
        std::array<std::array<std::byte, 8>, 12> numbers {};
        std::size_t count = 0;
        const auto add_number = [&](std::uint64_t id, std::uint64_t value) {
            const auto encoded = encode_varint(value, numbers[count]);
            if (!encoded) return false;
            entries[count] = {id, {numbers[count].data(), *encoded}};
            ++count;
            return true;
        };
        const auto add_bytes = [&](std::uint64_t id, std::span<const std::byte> value) {
            entries[count] = {id, value};
            ++count;
            return true;
        };
        const auto& settings = limits();
        const auto receive_data = std::min<std::uint64_t>(
            settings.max_data, bounded_connection::receive_bytes);
        const auto receive_stream_data = std::min<std::uint64_t>(
            settings.max_stream_data, bounded_connection::stream_bytes);
        if (!client &&
            !add_bytes(static_cast<std::uint64_t>(parameter_id::original_destination_connection_id),
                {entry.original_dcid.data(), entry.original_dcid_size}))
            return false;
        if (!add_bytes(static_cast<std::uint64_t>(parameter_id::initial_source_connection_id),
                {entry.local_cid.data(), entry.local_cid.size()}) ||
            !add_number(static_cast<std::uint64_t>(parameter_id::max_idle_timeout),
                settings.max_idle_timeout_ms) ||
            !add_number(static_cast<std::uint64_t>(parameter_id::initial_max_data),
                receive_data) ||
            !add_number(static_cast<std::uint64_t>(parameter_id::initial_max_stream_data_bidi_local),
                receive_stream_data) ||
            !add_number(static_cast<std::uint64_t>(parameter_id::initial_max_stream_data_bidi_remote),
                receive_stream_data) ||
            !add_number(static_cast<std::uint64_t>(parameter_id::initial_max_stream_data_uni),
                receive_stream_data) ||
            !add_number(static_cast<std::uint64_t>(parameter_id::initial_max_streams_bidi),
                std::min<std::uint64_t>(settings.max_streams_bidi,
                    bounded_connection::bidi_stream_capacity)) ||
            !add_number(static_cast<std::uint64_t>(parameter_id::initial_max_streams_uni),
                std::min<std::uint64_t>(settings.max_streams_uni,
                    bounded_connection::uni_stream_capacity)))
            return false;
        if (!add_number(static_cast<std::uint64_t>(parameter_id::max_udp_payload_size),
                std::clamp<std::uint64_t>(settings.max_udp_payload_size, 1200, 8192)))
            return false;
        if (settings.max_datagram_frame_size > 0 &&
            !add_number(static_cast<std::uint64_t>(parameter_id::max_datagram_frame_size),
                settings.max_datagram_frame_size))
            return false;
        // A v2-capable endpoint sends this on v1 sessions too (RFC 9369 Section 4).
        std::array<std::byte, 12> version_information {};
        const auto version_size = encode_fixed_version_information(entry.version, client,
                                                                   version_information);
        if (!version_size) return false;
        add_bytes(static_cast<std::uint64_t>(parameter_id::version_information),
                  std::span(version_information).first(*version_size));
        const auto encoded = encode_transport_parameters(
            {entries.data(), count},
            client ? parameter_sender::client : parameter_sender::server,
            std::as_writable_bytes(std::span(entry.parameters)));
        if (!encoded) return false;
        entry.parameters_size = *encoded;
        return true;
    }
};

namespace {

// Resumes when the connection-driver progress hook fires. It does not attach a
// cancellation node: operations observe cancellation on their next resume, and
// stop_all() wakes every waiter so shutdown cannot deadlock.
class notify_awaiter {
public:
    explicit notify_awaiter(quic_endpoint::implementation& impl,
                            std::size_t group = 0) noexcept
        : impl_(&impl), group_(group) {}
    [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }
    template<typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool
    { return impl_->register_waiter(group_, handle); }
    auto await_resume() const noexcept -> void {}
private:
    quic_endpoint::implementation* impl_;
    std::size_t group_;
};

auto notify(quic_endpoint::implementation& impl,
            std::size_t group = 0) noexcept -> notify_awaiter
{ return notify_awaiter(impl, group); }

auto failure_task(event_loop&) -> task<std::expected<quic_connection, std::error_code>>
{ co_return std::unexpected(make_error_code(quic_errc::tls_failure)); }

auto open_stream_task(event_loop&, quic_endpoint::implementation& impl,
    std::size_t slot_index, std::uint32_t generation, quic_stream_direction direction)
    -> task<std::expected<std::uint64_t, std::error_code>>
{
    if (slot_index >= impl.slots_.size())
        co_return std::unexpected(make_error_code(quic_errc::not_connected));
    auto& slot = impl.slots_[slot_index];
    if (slot.generation == generation && slot.terminal_error)
        co_return std::unexpected(slot.terminal_error);
    if (!slot.occupied || slot.generation != generation || !slot.connection)
        co_return std::unexpected(make_error_code(quic_errc::not_connected));
    const auto internal = direction == quic_stream_direction::bidirectional
        ? stream_direction::bidirectional : stream_direction::unidirectional;
    const auto id = slot.connection->open_stream(internal);
    if (!id) co_return std::unexpected(make_error_code(quic_errc::stream_limit));
    co_return *id;
}

auto read_stream(event_loop&, quic_endpoint::implementation& impl,
    std::size_t slot_index, std::uint32_t generation, std::uint64_t stream_id,
    std::span<std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
    for (;;) {
        if (co_await cancellation_requested())
            co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (slot_index >= impl.slots_.size())
            co_return std::unexpected(make_error_code(quic_errc::not_connected));
        auto& slot = impl.slots_[slot_index];
        if (slot.generation == generation && slot.terminal_error)
            co_return std::unexpected(slot.terminal_error);
        if (!slot.occupied || slot.generation != generation || !slot.connection)
            co_return std::unexpected(make_error_code(quic_errc::not_connected));
        auto* stream = slot.connection->stream(stream_id);
        const auto local_role = impl.client_mode() ? stream_role::client : stream_role::server;
        if (stream == nullptr && slot.connection->streams().is_retired(stream_id) &&
            (stream_type(stream_id) == stream_direction::bidirectional ||
             stream_initiator(stream_id) != local_role))
            co_return std::size_t {0};
        if (stream == nullptr || !stream->receive)
            co_return std::unexpected(make_error_code(quic_errc::invalid_argument));
        if (stream->state.receiving() == stream_receive_state::reset_received) {
            (void)slot.connection->consume_reset(stream_id);
            co_return std::unexpected(make_error_code(quic_errc::stream_reset));
        }
        const auto readable = stream->receive->readable();
        if (!readable.empty()) {
            const auto count = std::min(buffer.size(), readable.size());
            std::copy_n(readable.begin(), count, buffer.begin());
            if (!slot.connection->consume_stream(stream_id, count))
                co_return std::unexpected(make_error_code(quic_errc::invalid_state));
            if (slot.driver) slot.driver->notify();
            co_return count;
        }
        if (stream->receive->complete() ||
            stream->state.receiving() == stream_receive_state::data_read) {
            (void)slot.connection->finish_read(stream_id);
            co_return std::size_t {0};
        }
        co_await notify(impl, slot_index + 1);
    }
}

auto write_stream(event_loop&, quic_endpoint::implementation& impl,
    std::size_t slot_index, std::uint32_t generation, std::uint64_t stream_id,
    std::span<const std::byte> buffer, bool fin)
    -> task<std::expected<std::size_t, std::error_code>>
{
    for (;;) {
        if (co_await cancellation_requested())
            co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (slot_index >= impl.slots_.size())
            co_return std::unexpected(make_error_code(quic_errc::not_connected));
        auto& slot = impl.slots_[slot_index];
        if (slot.generation == generation && slot.terminal_error)
            co_return std::unexpected(slot.terminal_error);
        if (!slot.occupied || slot.generation != generation || !slot.connection)
            co_return std::unexpected(make_error_code(quic_errc::not_connected));
        auto* stream = slot.connection->stream(stream_id);
        if (stream == nullptr || !stream->receive)
            co_return std::unexpected(make_error_code(quic_errc::invalid_argument));
        if (buffer.empty() && !fin) co_return std::size_t {0};
        const auto writable = stream->send.writable_bytes();
        if (writable >= buffer.size()) {
            if (!buffer.empty() && !stream->send.append(buffer))
                co_return std::unexpected(make_error_code(quic_errc::invalid_state));
            if (fin && !stream->send.close())
                co_return std::unexpected(make_error_code(quic_errc::invalid_state));
            if (slot.driver) slot.driver->notify();
            co_return buffer.size();
        }
        if (writable > 0) {
            const auto accepted = std::min(writable, buffer.size());
            if (!stream->send.append(buffer.first(accepted)))
                co_return std::unexpected(make_error_code(quic_errc::invalid_state));
            if (slot.driver) slot.driver->notify();
            co_return accepted;
        }
        co_await notify(impl, slot_index + 1);
    }
}

auto accept_stream(event_loop&, quic_endpoint::implementation& impl,
    std::size_t slot_index, std::uint32_t generation)
    -> task<std::expected<std::uint64_t, std::error_code>>
{
    for (;;) {
        if (co_await cancellation_requested())
            co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (slot_index >= impl.slots_.size())
            co_return std::unexpected(make_error_code(quic_errc::not_connected));
        auto& slot = impl.slots_[slot_index];
        if (slot.generation == generation && slot.terminal_error)
            co_return std::unexpected(slot.terminal_error);
        if (!slot.occupied || slot.generation != generation || !slot.connection)
            co_return std::unexpected(make_error_code(quic_errc::not_connected));
        const auto peer_role = impl.client_mode()
            ? stream_role::server : stream_role::client;
        for (auto* candidate_ptr : slot.connection->active_slots()) {
            auto& candidate = *candidate_ptr;
            if (!candidate.occupied || stream_initiator(candidate.id) != peer_role)
                continue;
            if (candidate.accepted) continue;
            candidate.accepted = true;
            co_return candidate.id;
        }
        if (slot.closing) co_return std::unexpected(make_error_code(quic_errc::peer_closed));
        co_await notify(impl, slot_index + 1);
    }
}

auto send_datagram_task(event_loop&, quic_endpoint::implementation& impl,
    std::size_t slot_index, std::uint32_t generation, std::span<const std::byte> payload)
    -> task<std::expected<void, std::error_code>>
{
    for (;;) {
        if (co_await cancellation_requested())
            co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (slot_index >= impl.slots_.size())
            co_return std::unexpected(make_error_code(quic_errc::not_connected));
        auto& slot = impl.slots_[slot_index];
        if (slot.generation == generation && slot.terminal_error)
            co_return std::unexpected(slot.terminal_error);
        if (!slot.occupied || slot.generation != generation || !slot.connection)
            co_return std::unexpected(make_error_code(quic_errc::not_connected));
        const auto result = slot.connection->queue_datagram(payload);
        if (result.has_value()) co_return std::expected<void, std::error_code> {};
        if (result.error() == datagram_queue_error::frame_too_large)
            co_return std::unexpected(make_error_code(quic_errc::invalid_argument));
        co_await notify(impl, slot_index + 1);
    }
}

auto receive_datagram_task(event_loop&, quic_endpoint::implementation& impl,
    std::size_t slot_index, std::uint32_t generation, std::span<std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
    for (;;) {
        if (co_await cancellation_requested())
            co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (slot_index >= impl.slots_.size())
            co_return std::unexpected(make_error_code(quic_errc::not_connected));
        auto& slot = impl.slots_[slot_index];
        if (slot.generation == generation && slot.terminal_error)
            co_return std::unexpected(slot.terminal_error);
        if (!slot.occupied || slot.generation != generation || !slot.connection)
            co_return std::unexpected(make_error_code(quic_errc::not_connected));
        const auto received = slot.connection->receive_datagram(buffer);
        if (received.has_value()) co_return *received;
        co_await notify(impl, slot_index + 1);
    }
}

auto accept_connection(event_loop&, quic_endpoint::implementation& impl)
    -> task<std::expected<quic_connection, std::error_code>>
{
    for (;;) {
        if (co_await cancellation_requested())
            co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        impl.reap();
        for (std::size_t i = 0; i < impl.slots_.size(); ++i) {
            auto& slot = impl.slots_[i];
            if (slot.occupied && !slot.accepted && slot.terminal_error) {
                const auto error = slot.terminal_error;
                slot.accepted = true;
                // Error delivery releases an otherwise retained failed slot;
                // it must not depend on another driver's progress callback.
                impl.reap();
                co_return std::unexpected(error);
            }
            if (slot.occupied && !slot.accepted && slot.connection &&
                slot.connection->core().state() == connection_state::active) {
                slot.accepted = true;
                co_return quic_connection {impl.owner_, i, slot.generation};
            }
        }
        if (impl.closing_)
            co_return std::unexpected(make_error_code(quic_errc::peer_closed));
        co_await notify(impl);
    }
}

auto connect_task(event_loop&, quic_endpoint::implementation& impl,
    ip_endpoint server, std::string_view server_name)
    -> task<std::expected<quic_connection, std::error_code>>
{
    quic_endpoint::implementation::slot* entry = nullptr;
    for (auto& candidate : impl.slots_)
        if (!candidate.occupied) { entry = &candidate; break; }
    if (entry == nullptr)
        co_return std::unexpected(make_error_code(quic_errc::capacity_exceeded));
    const auto index = impl.slot_of(*entry);
    if (!impl.start_client(*entry, server, server_name))
        co_return std::unexpected(make_error_code(quic_errc::not_connected));
    const auto generation = entry->generation;
    for (;;) {
        if (co_await cancellation_requested())
            co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        auto& slot = impl.slots_[index];
        if (slot.generation == generation && slot.terminal_error)
            co_return std::unexpected(slot.terminal_error);
        if (!slot.occupied || slot.generation != generation)
            co_return std::unexpected(make_error_code(quic_errc::not_connected));
        if (slot.connection &&
            slot.connection->core().state() == connection_state::active)
            co_return quic_connection {impl.owner_, index, generation};
        if (slot.closing || impl.closing_)
            co_return std::unexpected(make_error_code(quic_errc::peer_closed));
        co_await notify(impl, index + 1);
    }
}

auto close_endpoint(event_loop& loop, quic_endpoint::implementation& impl)
    -> task<void>
{
    impl.stop_all();
    for (;;) {
        impl.reap();
        if (impl.all_retired()) break;
        if (co_await sleep_for(loop, close_poll_interval) != timer_wait_result::expired)
            break;
    }
}

} // namespace

quic_connection::quic_connection(quic_endpoint* endpoint, std::size_t slot,
                                 std::uint32_t generation) noexcept
    : endpoint_(endpoint), slot_(slot), generation_(generation) {}

quic_connection::quic_connection(quic_connection&& other) noexcept
    : endpoint_(std::exchange(other.endpoint_, nullptr)),
      slot_(std::exchange(other.slot_, 0)),
      generation_(std::exchange(other.generation_, 0)) {}

auto quic_connection::operator=(quic_connection&& other) noexcept -> quic_connection&
{
    if (this != &other) {
        endpoint_ = std::exchange(other.endpoint_, nullptr);
        slot_ = std::exchange(other.slot_, 0);
        generation_ = std::exchange(other.generation_, 0);
    }
    return *this;
}

auto quic_connection::valid() const noexcept -> bool
{
    if (endpoint_ == nullptr || !endpoint_->implementation_) return false;
    const auto& impl = *endpoint_->implementation_;
    if (slot_ >= impl.slots_.size()) return false;
    const auto& slot = impl.slots_[slot_];
    return slot.generation == generation_ &&
        ((slot.occupied && slot.connection.has_value()) || slot.terminal_error);
}

auto quic_connection::remote_endpoint() const noexcept -> ip_endpoint
{
    if (!valid()) return {};
    return endpoint_->implementation_->slots_[slot_].peer;
}

auto quic_connection::async_open_stream(quic_stream_direction direction)
    -> task<std::expected<std::uint64_t, std::error_code>>
{
    if (!valid()) std::terminate();
    auto& impl = *endpoint_->implementation_;
    return open_stream_task(impl.loop_, impl, slot_, generation_, direction);
}

auto quic_connection::async_accept_stream()
    -> task<std::expected<std::uint64_t, std::error_code>>
{
    if (!valid()) std::terminate();
    auto& impl = *endpoint_->implementation_;
    return accept_stream(impl.loop_, impl, slot_, generation_);
}

auto quic_connection::async_read(std::uint64_t stream_id,
                                 std::span<std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
    if (!valid()) std::terminate();
    auto& impl = *endpoint_->implementation_;
    return read_stream(impl.loop_, impl, slot_, generation_, stream_id, buffer);
}

auto quic_connection::async_write(std::uint64_t stream_id,
                                  std::span<const std::byte> buffer, bool fin)
    -> task<std::expected<std::size_t, std::error_code>>
{
    if (!valid()) std::terminate();
    auto& impl = *endpoint_->implementation_;
    return write_stream(impl.loop_, impl, slot_, generation_, stream_id, buffer, fin);
}

auto quic_connection::async_send_datagram(std::span<const std::byte> payload)
    -> task<std::expected<void, std::error_code>>
{
    if (!valid()) std::terminate();
    auto& impl = *endpoint_->implementation_;
    return send_datagram_task(impl.loop_, impl, slot_, generation_, payload);
}

auto quic_connection::async_receive_datagram(std::span<std::byte> buffer)
    -> task<std::expected<std::size_t, std::error_code>>
{
    if (!valid()) std::terminate();
    auto& impl = *endpoint_->implementation_;
    return receive_datagram_task(impl.loop_, impl, slot_, generation_, buffer);
}

auto quic_connection::close(std::error_code) noexcept -> void
{
    if (!valid()) return;
    auto& slot = endpoint_->implementation_->slots_[slot_];
    // A retired slot retains its terminal error so an old handle can observe
    // completion. Its later cleanup must not poison a slot reused by a new
    // connection.
    if (!slot.occupied || !slot.connection || slot.generation != generation_)
        return;
    slot.closing = true;
    if (slot.driver) slot.driver->stop();
}

quic_endpoint::quic_endpoint(event_loop& loop, ip_endpoint local,
                             quic_server_options options)
    : implementation_(std::make_unique<implementation>(loop, local,
          std::move(options)))
{
    implementation_->owner_ = this;
}

quic_endpoint::quic_endpoint(event_loop& loop, ip_endpoint local,
                             quic_client_options options)
    : implementation_(std::make_unique<implementation>(loop, local,
          std::move(options)))
{
    implementation_->owner_ = this;
}

quic_endpoint::~quic_endpoint() = default;

auto quic_endpoint::local_endpoint() const noexcept -> ip_endpoint
{
    return implementation_ ? implementation_->local_endpoint() : ip_endpoint {};
}

auto quic_endpoint::async_accept()
    -> task<std::expected<quic_connection, std::error_code>>
{
    auto& impl = *implementation_;
    if (!impl.configured() || impl.client_mode()) return failure_task(impl.loop_);
    return accept_connection(impl.loop_, impl);
}

auto quic_endpoint::async_connect(ip_endpoint server, std::string_view server_name)
    -> task<std::expected<quic_connection, std::error_code>>
{
    auto& impl = *implementation_;
    if (!impl.configured() || !impl.client_mode()) return failure_task(impl.loop_);
    return connect_task(impl.loop_, impl, server, server_name);
}

auto quic_endpoint::async_close() -> task<void>
{
    auto& impl = *implementation_;
    return close_endpoint(impl.loop_, impl);
}

auto quic_endpoint::close() noexcept -> void
{
    if (implementation_) implementation_->stop_all();
}

} // namespace eventloop
