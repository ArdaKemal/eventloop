#include "quic/connection_core.h"
#include "quic/transport_parameters.h"
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <exception>

namespace eventloop::quic::detail {
namespace {
auto index(tls_level level) noexcept -> std::size_t
{ return static_cast<std::size_t>(level); }
auto index(tls_direction direction) noexcept -> std::size_t
{ return static_cast<std::size_t>(direction); }
auto level_for(packet_kind kind) noexcept -> std::optional<tls_level>
{
    switch (kind) {
    case packet_kind::initial: return tls_level::initial;
    case packet_kind::handshake: return tls_level::handshake;
    case packet_kind::short_header: return tls_level::application;
    default: return {};
    }
}
auto packet_error(protected_packet_error error) noexcept -> connection_error
{
    switch (error) {
    case protected_packet_error::authentication_failed: return connection_error::authentication_failed;
    case protected_packet_error::output_too_small: return connection_error::output_too_small;
    case protected_packet_error::provider_failure: return connection_error::provider_failure;
    default: return connection_error::malformed_packet;
    }
}
auto timeout_from_milliseconds(std::uint64_t value) noexcept -> lifecycle_duration
{
    using milliseconds = std::chrono::milliseconds;
    if (value == 0) return lifecycle_duration::zero();
    const auto maximum = std::chrono::duration_cast<milliseconds>(
        lifecycle_duration::max()).count();
    if (maximum <= 0 || value > static_cast<std::uint64_t>(maximum))
        return lifecycle_duration::max();
    return std::chrono::duration_cast<lifecycle_duration>(
        milliseconds(static_cast<milliseconds::rep>(value)));
}
auto idle_timeout(const transport_parameters& parameters) noexcept -> lifecycle_duration
{
    const auto* parameter = parameters.find(static_cast<std::uint64_t>(parameter_id::max_idle_timeout));
    if (!parameter) return lifecycle_duration::zero();
    const auto value = parameter_integer(parameter->value);
    return value ? timeout_from_milliseconds(*value) : lifecycle_duration::zero();
}
}

connection_core::connection_core(endpoint_role role, connection_callbacks callbacks,
                                 lifecycle_time_point started)
    : role_(role), callbacks_(callbacks), lifecycle_(started) {}
connection_core::~connection_core()
{ check_owner(); OPENSSL_cleanse(application_secrets_.data(), sizeof(application_secrets_)); }
auto connection_core::check_owner() const noexcept -> void
{ if (owner_ != std::this_thread::get_id()) std::terminate(); }
auto connection_core::fail(connection_error error) noexcept -> std::unexpected<connection_error>
{ if (!failure_) failure_ = error; return std::unexpected(*failure_); }

auto connection_core::initialize(SSL_CTX* context, const tls_options& options,
    std::uint32_t version, std::span<const std::uint8_t> original_dcid)
    -> std::expected<void, connection_error>
{
    check_owner();
    if (initialized_ || failure_) return std::unexpected(connection_error::invalid_state);
    if (options.server != (role_ == endpoint_role::server) ||
        !callbacks_.validate_parameters || !is_supported_version(version) ||
        original_dcid.empty() || original_dcid.size() > 20 || !protection_.ready())
        return std::unexpected(connection_error::invalid_configuration);
    const auto local_parameters = decode_transport_parameters(
        std::as_bytes(options.transport_parameters),
        role_ == endpoint_role::client ? parameter_sender::client : parameter_sender::server);
    if (!local_parameters) return std::unexpected(connection_error::invalid_configuration);
    local_idle_timeout_ = idle_timeout(*local_parameters);
    lifecycle_.set_local_idle_timeout(local_idle_timeout_);
    version_ = version;
    // tls_provider appends the empty grease_quic_bit parameter when the caller
    // does not supply it, so this endpoint always advertises RFC 9287 support
    // and accepts either value of the QUIC bit.
    local_grease_quic_bit_ = true;
    std::uint64_t seed = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&seed),
                   static_cast<int>(sizeof(seed))) == 1 && seed != 0)
        grease_prng_ = seed;
    const auto secrets = derive_initial_secrets(version_, original_dcid);
    if (!secrets) return fail(connection_error::provider_failure);
    const auto client = derive_aes_128_gcm_keys(version_, secrets->client);
    const auto server = derive_aes_128_gcm_keys(version_, secrets->server);
    if (!client || !server) return fail(connection_error::provider_failure);
    keys_[0][0] = role_ == endpoint_role::client ? *server : *client;
    keys_[0][1] = role_ == endpoint_role::client ? *client : *server;
    if (!tls_.initialize(context, options)) return fail(connection_error::tls_failure);
    initialized_ = true;
    return {};
}
auto connection_core::send_crypto(void* argument, tls_level level,
                                  std::span<const std::byte> data) noexcept -> bool
{
    auto& self = *static_cast<connection_core*>(argument);
    if (index(level) >= 3 || self.discarded_levels_[index(level)]) return false;
    const auto result = self.output_[index(level)].append(data);
    if (!result) { (void)self.fail(connection_error::capacity_exceeded); return false; }
    return true;
}
auto connection_core::install_secret(void* argument, tls_level level,
    tls_direction direction, std::uint16_t cipher, std::span<const std::uint8_t> secret)
    noexcept -> bool
{
    auto& self = *static_cast<connection_core*>(argument);
    if (index(level) >= 3 || self.discarded_levels_[index(level)]) return false;
    if (cipher != 0x1301 || secret.size() != 32 || level == tls_level::initial) return false;
    const auto result = derive_aes_128_gcm_keys(self.version_, secret);
    if (!result) { (void)self.fail(connection_error::provider_failure); return false; }
    self.keys_[index(level)][index(direction)] = *result;
    if (level == tls_level::application) {
        if (self.key_update_ready_ || self.application_secret_ready_[index(direction)]) return false;
        std::copy(secret.begin(), secret.end(), self.application_secrets_[index(direction)].begin());
        self.application_secret_ready_[index(direction)] = true;
        if (self.application_secret_ready_[0] && self.application_secret_ready_[1]) {
            if (!self.key_update_.initialize(self.version_, self.application_secrets_[1],
                    self.application_secrets_[0])) {
                (void)self.fail(connection_error::provider_failure); return false;
            }
            OPENSSL_cleanse(self.application_secrets_.data(), sizeof(self.application_secrets_));
            for (auto& key : self.keys_[2]) {
                if (key) OPENSSL_cleanse(&*key, sizeof(*key));
                key.reset();
            }
            self.key_update_ready_ = true;
        }
    }
    return true;
}
auto connection_core::advance(lifecycle_time_point now)
    -> std::expected<tls_progress, connection_error>
{
    check_owner();
    if (failure_) return std::unexpected(*failure_);
    if (!initialized_ || !lifecycle_.can_send_data())
        return std::unexpected(connection_error::invalid_state);
    const auto result = tls_.advance();
    if (!result) return fail(connection_error::tls_failure);
    if (*result == tls_progress::complete && lifecycle_.state() == connection_state::handshake) {
        if (!callbacks_.validate_parameters(callbacks_.argument, tls_.peer_transport_parameters()))
            return fail(connection_error::protocol_violation);
        const auto peer_parameters = decode_transport_parameters(
            std::as_bytes(tls_.peer_transport_parameters()),
            role_ == endpoint_role::client ? parameter_sender::server : parameter_sender::client);
        if (!peer_parameters || !lifecycle_.negotiate_idle_timeout(
                local_idle_timeout_, idle_timeout(*peer_parameters), now))
            return fail(connection_error::protocol_violation);
        // RFC 9287: only an authenticated, validated peer parameter enables
        // greasing (clearing) the QUIC bit on subsequent sends.
        peer_grease_quic_bit_ = peer_parameters->find(
            static_cast<std::uint64_t>(parameter_id::grease_quic_bit)) != nullptr;
        if (!lifecycle_.handshake_complete(now)) return fail(connection_error::invalid_state);
        confirmed_ = role_ == endpoint_role::server;
        if (confirmed_) {
            key_update_.confirm_handshake();
            discard_level(tls_level::handshake);
        }
    }
    return *result;
}
auto connection_core::state() const noexcept -> connection_state
{ check_owner(); return lifecycle_.state(); }
auto connection_core::failure() const noexcept -> std::optional<connection_error>
{ check_owner(); return failure_; }
auto connection_core::handshake_confirmed() const noexcept -> bool
{ check_owner(); return confirmed_; }
auto connection_core::local_grease_quic_bit() const noexcept -> bool
{ check_owner(); return local_grease_quic_bit_; }
auto connection_core::peer_grease_quic_bit() const noexcept -> bool
{ check_owner(); return peer_grease_quic_bit_; }
auto connection_core::keys_available(tls_level level, tls_direction direction) const noexcept -> bool
{
    check_owner();
    return index(level) < 3 && index(direction) < 2 &&
        (level == tls_level::application ? application_secret_ready_[index(direction)] :
            keys_[index(level)][index(direction)].has_value());
}
auto connection_core::next_packet_number(tls_level level) const noexcept
    -> std::optional<std::uint64_t>
{
    check_owner();
    if (index(level) >= 3 || next_packet_number_[index(level)] > max_packet_number) return {};
    return next_packet_number_[index(level)];
}
auto connection_core::packet_number_length(tls_level level) const noexcept -> std::uint8_t
{
    check_owner();
    if (index(level) >= 3) return 4;
    return packet_number_length_for(next_packet_number_[index(level)],
                                    largest_acknowledged_[index(level)]);
}
auto connection_core::packet_acknowledged(tls_level level, std::uint64_t largest) noexcept -> void
{
    check_owner();
    if (index(level) >= 3) return;
    auto& current = largest_acknowledged_[index(level)];
    if (!current || largest > *current) current = largest;
}

auto connection_core::apply_retry(std::span<const std::uint8_t> dcid)
    -> std::expected<void, connection_error>
{
    check_owner();
    if (!initialized_ || failure_ || role_ != endpoint_role::client || retry_applied_ ||
        peer_initial_source_cid_seen_ || dcid.size() > 20 ||
        keys_available(tls_level::handshake,tls_direction::read) ||
        keys_available(tls_level::application,tls_direction::read))
        return std::unexpected(connection_error::invalid_state);
    const auto secrets = derive_initial_secrets(version_, dcid);
    if (!secrets) return std::unexpected(connection_error::provider_failure);
    const auto client = derive_aes_128_gcm_keys(version_, secrets->client);
    const auto server = derive_aes_128_gcm_keys(version_, secrets->server);
    if (!client || !server) return std::unexpected(connection_error::provider_failure);
    if (!output_[0].retransmit_initial())
        return std::unexpected(connection_error::invalid_state);
    keys_[0][0] = *server;
    keys_[0][1] = *client;
    retry_applied_ = true;
    return {};
}

auto connection_core::initiate_key_update(lifecycle_time_point now, lifecycle_duration pto)
    -> std::expected<void, key_update_error>
{
    check_owner();
    if (!key_update_ready_) return std::unexpected(key_update_error::not_initialized);
    if (!lifecycle_.can_send_data() || pto <= lifecycle_duration::zero())
        return std::unexpected(key_update_error::invalid_input);
    if (next_local_update_ && now < *next_local_update_)
        return std::unexpected(key_update_error::retirement_not_due);
    const auto result = key_update_.initiate_update();
    if (result) {
        encrypted_packets_[2] = 0;
        phase_first_sent_.reset();
        phase_acknowledged_ = false;
        update_occurred_ = true;
    }
    return result;
}

auto connection_core::acknowledge_application_packet(std::uint64_t number,
    lifecycle_time_point now, lifecycle_duration pto) noexcept
    -> std::expected<void, key_update_error>
{
    check_owner();
    if (pto <= lifecycle_duration::zero()) return std::unexpected(key_update_error::invalid_input);
    const auto result = key_update_.on_acknowledged(number);
    if (result && phase_first_sent_ && number >= *phase_first_sent_ && !phase_acknowledged_) {
        phase_acknowledged_ = true;
        if (update_occurred_) next_local_update_ = lifecycle_deadline(now, lifecycle_three_pto(pto));
    }
    return result;
}

auto connection_core::application_packet_sent(std::uint64_t number,
    std::optional<std::uint64_t> acknowledged_peer_packet) noexcept
    -> std::expected<void, key_update_error>
{
    check_owner();
    if (number >= next_packet_number_[2]) return std::unexpected(key_update_error::invalid_packet_number);
    const auto result = key_update_.on_sent(number);
    if (!result) return result;
    if (!phase_first_sent_) phase_first_sent_ = number;
    return acknowledged_peer_packet ? key_update_.on_ack_sent(number, *acknowledged_peer_packet)
        : std::expected<void, key_update_error> {};
}

auto connection_core::peer_update_packet() const noexcept -> std::optional<std::uint64_t>
{ check_owner(); return key_update_.peer_update_packet(); }
auto connection_core::application_key_phase() const noexcept -> bool
{ check_owner(); return key_update_.send_phase(); }

auto connection_core::discard_level(tls_level level) noexcept -> void
{
    const auto slot = index(level);
    if (slot >= 2 || discarded_levels_[slot]) return;
    for (auto& key : keys_[slot]) {
        if (key) OPENSSL_cleanse(&*key, sizeof(*key));
        key.reset();
    }
    output_[slot].reset();
    received_[slot].reset();
    OPENSSL_cleanse(input_bytes_[slot].data(), input_bytes_[slot].size());
    if (level == tls_level::initial) initial_.reset(); else handshake_.reset();
    discarded_levels_[slot] = true;
}

auto connection_core::encryption_level_sent(tls_level level) noexcept -> void
{
    check_owner();
    if (role_ == endpoint_role::client && level == tls_level::handshake)
        discard_level(tls_level::initial);
}

auto connection_core::level_discarded(tls_level level) const noexcept -> bool
{ check_owner(); return index(level) < 3 && discarded_levels_[index(level)]; }
auto connection_core::next_crypto(tls_level level, std::size_t maximum) const noexcept -> crypto_send_chunk
{ check_owner(); return index(level) < 3 ? output_[index(level)].next_pending(maximum) : crypto_send_chunk {}; }
auto connection_core::next_crypto_probe(tls_level level, std::size_t maximum,
    std::uint64_t from) const noexcept -> crypto_send_chunk
{ check_owner(); return index(level) < 3 ? output_[index(level)].next_unacknowledged(maximum, from) : crypto_send_chunk {}; }
auto connection_core::mark_crypto_sent(tls_level level, std::uint64_t offset, std::size_t size)
    -> std::expected<void, connection_error>
{
    check_owner();
    if (index(level) >= 3 || !output_[index(level)].mark_sent(offset, size))
        return std::unexpected(connection_error::invalid_state);
    return {};
}
auto connection_core::acknowledge_crypto(tls_level level, std::uint64_t offset, std::size_t size)
    -> std::expected<void, connection_error>
{
    check_owner();
    if (index(level) >= 3 || !output_[index(level)].acknowledge(offset, size))
        return std::unexpected(connection_error::invalid_state);
    return {};
}
auto connection_core::lose_crypto(tls_level level, std::uint64_t offset, std::size_t size)
    -> std::expected<void, connection_error>
{
    check_owner();
    if (index(level) >= 3 || !output_[index(level)].mark_lost(offset, size))
        return std::unexpected(connection_error::invalid_state);
    return {};
}
auto connection_core::build(protected_packet_fields fields,
    std::span<const std::uint8_t> payload, std::span<std::uint8_t> output,
    std::span<std::uint8_t> scratch) -> std::expected<std::size_t, connection_error>
{
    check_owner();
    bool close_only = false;
    bool data_frame = false;
    for (std::size_t cursor = 0; cursor < payload.size();) {
        const auto frame = decode_frame(std::as_bytes(payload.subspan(cursor)));
        if (!frame || !validate_frame_policy(fields.kind, *frame,
                role_ == endpoint_role::client ? endpoint_role::server : endpoint_role::client))
            return std::unexpected(connection_error::protocol_violation);
        if (frame->type == 0x1c || frame->type == 0x1d) close_only = true;
        else if (frame->type != 0x00) data_frame = true;
        cursor += frame->encoded_size;
    }
    close_only = close_only && !data_frame;
    if (!initialized_ || (close_only ? !lifecycle_.can_send_close()
        : (failure_.has_value() || !lifecycle_.can_send_data())))
        return std::unexpected(connection_error::invalid_state);
    const auto level = level_for(fields.kind);
    if (!level || !keys_available(*level, tls_direction::write))
        return std::unexpected(connection_error::unavailable_keys);
    const bool application = *level == tls_level::application;
    if (application && !key_update_ready_)
        return std::unexpected(connection_error::unavailable_keys);
    if (encrypted_packets_[index(*level)] >= (std::uint64_t {1} << 23))
        return fail(connection_error::aead_limit_reached);
    fields.key_phase = application && key_update_.send_phase();
    auto& number = next_packet_number_[index(*level)];
    if (number > max_packet_number) return fail(connection_error::capacity_exceeded);
    fields.version = version_;
    fields.packet_number = number;
    fields.packet_number_length = packet_number_length(*level);
    // RFC 9287: only grease the QUIC bit once the peer has advertised support.
    // Before that the bit must remain set. xorshift avoids a per-packet CSPRNG.
    if (peer_grease_quic_bit_) {
        grease_prng_ ^= grease_prng_ << 13;
        grease_prng_ ^= grease_prng_ >> 7;
        grease_prng_ ^= grease_prng_ << 17;
        fields.quic_bit = (grease_prng_ & 1U) != 0;
    } else {
        fields.quic_bit = true;
    }
    const auto result = build_protected_packet(protection_, fields,
        application ? *key_update_.send_keys() : *keys_[index(*level)][1], payload, output, scratch);
    if (!result) return std::unexpected(packet_error(result.error()));
    ++number;
    ++encrypted_packets_[index(*level)];
    return *result;
}
auto connection_core::unbuild(tls_level level) noexcept -> void
{
    check_owner();
    --next_packet_number_[index(level)];
    --encrypted_packets_[index(level)];
}

auto connection_core::dispatch(tls_level level, packet_kind kind,
    std::span<const std::byte> payload, lifecycle_time_point now, lifecycle_duration pto)
    -> std::expected<void, connection_error>
{
    if (payload.empty()) return fail(connection_error::protocol_violation);
    // Validate the complete frame sequence before delivering any borrowed views.
    for (std::size_t cursor = 0; cursor < payload.size();) {
        const auto frame = decode_frame(payload.subspan(cursor));
        if (!frame || !validate_frame_policy(kind, *frame, role_))
            return fail(connection_error::protocol_violation);
        if (frame->type == 0x1e && lifecycle_.state() != connection_state::active)
            return fail(connection_error::protocol_violation);
        cursor += frame->encoded_size;
    }
    for (std::size_t cursor = 0; cursor < payload.size();) {
        const auto frame = *decode_frame(payload.subspan(cursor));
        cursor += frame.encoded_size;
        switch (frame.type) {
        case 0x00: case 0x01: break;
        case 0x06:
            if (!tls_.provide_crypto(level, frame.offset, frame.data))
                return fail(connection_error::tls_failure);
            break;
        case 0x1e:
            confirmed_ = true; key_update_.confirm_handshake();
            discard_level(tls_level::handshake); break;
        case 0x1c: case 0x1d:
            if (!lifecycle_.enter_draining(now, pto))
                return fail(connection_error::invalid_state);
            return {};
        default:
            if (!callbacks_.frame) return fail(connection_error::unsupported_frame);
            if (!callbacks_.frame(callbacks_.argument, level, frame))
                return fail(connection_error::protocol_violation);
        }
    }
    return {};
}
auto connection_core::authenticate_application_packet(
    std::span<const std::uint8_t> datagram, std::size_t offset,
    std::size_t short_cid_length, std::span<std::uint8_t> packet_scratch,
    std::span<std::uint8_t> plaintext, std::span<std::uint8_t> auth_scratch)
    -> std::expected<opened_protected_packet, connection_error>
{
    check_owner();
    if (!initialized_ || failure_ || !lifecycle_.can_send_data())
        return std::unexpected(connection_error::invalid_state);
    const auto header = parse_packet_header(std::as_bytes(datagram), offset, short_cid_length,
                                            local_grease_quic_bit_);
    if (!header || header->kind != packet_kind::short_header)
        return std::unexpected(connection_error::malformed_packet);
    if (!key_update_ready_)
        return std::unexpected(connection_error::unavailable_keys);
    const auto largest = received_[index(tls_level::application)].largest_received();
    std::optional<receive_key_slot> authenticated_slot;
    for (const auto slot : {receive_key_slot::current, receive_key_slot::next,
            receive_key_slot::previous}) {
        const auto* candidate = key_update_.receive_keys(slot);
        const auto attempt = open_protected_packet(protection_, datagram, offset,
            short_cid_length, version_, candidate ? *candidate :
                *key_update_.receive_keys(receive_key_slot::current),
            largest, packet_scratch, plaintext, auth_scratch,
            local_grease_quic_bit_);
        if (attempt && candidate) authenticated_slot = slot;
    }
    const auto selected = authenticated_slot.value_or(receive_key_slot::current);
    const auto opened = open_protected_packet(protection_, datagram, offset,
        short_cid_length, version_, *key_update_.receive_keys(selected), largest,
        packet_scratch, plaintext, auth_scratch, local_grease_quic_bit_);
    if (!opened) return std::unexpected(packet_error(opened.error()));
    return *opened;
}

auto connection_core::receive(std::span<const std::uint8_t> datagram, std::size_t offset,
    std::size_t short_cid_length, std::span<std::uint8_t> packet_scratch,
    std::span<std::uint8_t> plaintext, std::span<std::uint8_t> auth_scratch,
    lifecycle_time_point now, lifecycle_duration pto)
    -> std::expected<opened_protected_packet, connection_error>
{
    check_owner();
    if (!initialized_ || failure_ || !lifecycle_.can_send_data())
        return std::unexpected(connection_error::invalid_state);
    if (pto <= lifecycle_duration::zero()) return std::unexpected(connection_error::invalid_configuration);
    const auto header = parse_packet_header(std::as_bytes(datagram), offset, short_cid_length,
                                            local_grease_quic_bit_);
    if (!header) return std::unexpected(connection_error::malformed_packet);
    const auto level = level_for(header->kind);
    if (!level || !keys_available(*level, tls_direction::read))
        return std::unexpected(connection_error::unavailable_keys);
    auto& numbers = received_[index(*level)];
    auto opened = std::expected<opened_protected_packet, protected_packet_error>(
        std::unexpected(protected_packet_error::authentication_failed));
    std::optional<receive_key_slot> selected_slot;
    if (*level == tls_level::application) {
        if (!key_update_ready_) return std::unexpected(connection_error::unavailable_keys);
        const auto deadline = key_update_.retirement_deadline();
        const auto update_now = std::chrono::duration_cast<key_update_time>(now.time_since_epoch());
        if (deadline && update_now >= *deadline) (void)key_update_.retire_previous(update_now);
        if (previous_key_retirement_ && now >= *previous_key_retirement_) previous_key_retirement_.reset();
        std::optional<receive_key_slot> authenticated_slot;
        // Perform the same three authentication attempts regardless of the
        // protected phase. Missing old keys use the current key as a dummy.
        for (const auto slot : {receive_key_slot::current, receive_key_slot::next,
                receive_key_slot::previous}) {
            const auto* candidate = key_update_.receive_keys(slot);
            const auto attempt = open_protected_packet(protection_, datagram, offset,
                short_cid_length, version_, candidate ? *candidate : *key_update_.receive_keys(receive_key_slot::current),
                numbers.largest_received(), packet_scratch, plaintext, auth_scratch,
                local_grease_quic_bit_);
            if ((attempt || attempt.error() == protected_packet_error::reserved_bits) &&
                candidate) authenticated_slot = slot;
        }
        const auto selected = authenticated_slot.value_or(receive_key_slot::current);
        selected_slot = selected;
        opened = open_protected_packet(protection_, datagram, offset,
            short_cid_length, version_, *key_update_.receive_keys(selected), numbers.largest_received(),
            packet_scratch, plaintext, auth_scratch, local_grease_quic_bit_);
    } else {
        opened = open_protected_packet(protection_, datagram, offset,
            short_cid_length, version_, *keys_[index(*level)][0], numbers.largest_received(),
            packet_scratch, plaintext, auth_scratch, local_grease_quic_bit_);
    }
    // Unauthenticated garbage never poisons the connection.
    if (!opened) {
        if (opened.error() == protected_packet_error::reserved_bits)
            return fail(connection_error::protocol_violation);
        if (*level != tls_level::initial && opened.error() == protected_packet_error::authentication_failed &&
            ++failed_authentications_ >= (std::uint64_t {1} << 52))
            return fail(connection_error::aead_limit_reached);
        return std::unexpected(packet_error(opened.error()));
    }
    if (opened->kind == packet_kind::initial && !peer_initial_source_cid_seen_) {
        std::copy(header->source_cid.begin(), header->source_cid.end(),
                  peer_initial_source_cid_.begin());
        peer_initial_source_cid_size_ = header->source_cid.size();
        peer_initial_source_cid_seen_ = true;
    }
    const auto inserted = numbers.insert(opened->packet_number);
    if (!inserted) {
        if (inserted.error() == received_packet_error::retired_packet_number) return *opened;
        return fail(connection_error::capacity_exceeded);
    }
    if (!*inserted) return *opened;
    if (selected_slot) {
        const auto send_phase = key_update_.send_phase();
        const auto update = key_update_.on_received(*selected_slot, opened->key_phase,
            opened->packet_number, true,
            std::chrono::duration_cast<key_update_time>(now.time_since_epoch()),
            std::max(key_update_time {1}, std::chrono::duration_cast<key_update_time>(pto)));
        if (!update) return fail(connection_error::key_update_violation);
        if (*selected_slot == receive_key_slot::next)
            previous_key_retirement_ = lifecycle_deadline(now, lifecycle_three_pto(pto));
        if (send_phase != key_update_.send_phase()) {
            encrypted_packets_[2] = 0;
            phase_first_sent_.reset();
            phase_acknowledged_ = false;
            update_occurred_ = true;
        }
    }
    const auto result = dispatch(*level, opened->kind,
        std::as_bytes(plaintext.first(opened->plaintext_size)), now, pto);
    if (!result) return std::unexpected(result.error());
    if (role_ == endpoint_role::server && *level == tls_level::handshake)
        discard_level(tls_level::initial);
    if (lifecycle_.can_send_data()) {
        if (!lifecycle_.packet_received(now)) return fail(connection_error::invalid_state);
        if (!advance(now)) return std::unexpected(*failure_);
    }
    return *opened;
}
auto connection_core::make_ack(tls_level level, std::uint64_t delay,
    std::span<std::byte> storage) const -> std::expected<decoded_frame, received_packet_error>
{
    check_owner();
    if (index(level) >= 3) return std::unexpected(received_packet_error::empty);
    return received_[index(level)].make_ack(delay, storage);
}
auto connection_core::retire_ack(tls_level level, std::uint64_t largest)
    -> std::expected<bool, received_packet_error>
{
    check_owner();
    if (index(level) >= 3) return std::unexpected(received_packet_error::invalid_retirement);
    return received_[index(level)].retire_through(largest);
}
auto connection_core::close_sent(lifecycle_time_point now, lifecycle_duration pto) noexcept -> bool
{ check_owner(); return lifecycle_.close_sent(now, pto); }
auto connection_core::poll(lifecycle_time_point now, lifecycle_duration pto) noexcept -> bool
{
    check_owner();
    if (previous_key_retirement_ && now >= *previous_key_retirement_) {
        (void)key_update_.retire_previous(std::chrono::duration_cast<key_update_time>(now.time_since_epoch()));
        previous_key_retirement_.reset();
    }
    return lifecycle_.poll(now, pto);
}
auto connection_core::packet_sent(lifecycle_time_point now, bool ack_eliciting) noexcept -> bool
{ check_owner(); return lifecycle_.packet_sent(now, ack_eliciting); }
auto connection_core::next_deadline(lifecycle_duration current_pto) const noexcept
    -> std::optional<lifecycle_time_point>
{
    check_owner();
    auto deadline = lifecycle_.next_deadline(current_pto);
    if (previous_key_retirement_ && (!deadline || *previous_key_retirement_ < *deadline))
        deadline = previous_key_retirement_;
    return deadline;
}
} // namespace eventloop::quic::detail
