#include "quic/connection_core.h"
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <cstdio>
#include <cstdlib>
#include <memory>
using namespace eventloop::quic::detail;
static auto checked(bool value, int line) -> void
{ if (!value) { std::fprintf(stderr, "connection core check failed at line %d\n", line); std::abort(); } }
#define check(value) checked((value), __LINE__)
struct contexts {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client {SSL_CTX_new(TLS_method()), SSL_CTX_free};
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> server {SSL_CTX_new(TLS_method()), SSL_CTX_free};

    contexts()
    {
        check(client && server);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key {
            EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1"), EVP_PKEY_free};
        std::unique_ptr<X509, decltype(&X509_free)> certificate {X509_new(), X509_free};
        check(key && certificate);
        check(X509_set_version(certificate.get(), 2) == 1);
        check(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) == 1);
        check(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) != nullptr);
        check(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600) != nullptr);
        check(X509_set_pubkey(certificate.get(), key.get()) == 1);
        auto* name = X509_get_subject_name(certificate.get());
        check(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
              reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) == 1);
        check(X509_set_issuer_name(certificate.get(), name) == 1);
        std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> san {
            X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                               const_cast<char*>("DNS:localhost")), X509_EXTENSION_free};
        check(san && X509_add_ext(certificate.get(), san.get(), -1) == 1);
        check(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0);
        check(SSL_CTX_use_certificate(server.get(), certificate.get()) == 1);
        check(SSL_CTX_use_PrivateKey(server.get(), key.get()) == 1);
        check(X509_STORE_add_cert(SSL_CTX_get_cert_store(client.get()), certificate.get()) == 1);
        tls_provider::configure_server_context(server.get());
    }
};


static constexpr std::array<std::uint8_t, 4> protocol {'t','e','s','t'};
static constexpr std::array<std::uint8_t, 6> parameters {1,1,10,15,1,42};
static constexpr std::array<std::uint8_t, 8> dcid {1,2,3,4,5,6,7,8};
static bool valid_parameters(void*, std::span<const std::uint8_t> value) noexcept
{
    // The TLS adapter appends the empty RFC 9287 grease_quic_bit parameter
    // (0x2ab2) to the configured transport parameters.
    constexpr std::array<std::uint8_t, 3> grease {0x6a, 0xb2, 0};
    return value.size() == parameters.size() + grease.size() &&
        std::ranges::equal(value.first(parameters.size()), parameters) &&
        std::ranges::equal(value.subspan(parameters.size()), grease);
}
static bool on_frame(void* argument, tls_level, const decoded_frame&) noexcept
{ ++*static_cast<int*>(argument); return true; }
struct buffers {
    std::array<std::uint8_t, 2048> encoded {}, frame {}, build_scratch {},
        packet_scratch {}, plaintext {}, auth_scratch {};
};
static auto transfer(connection_core& sender, connection_core& receiver,
                     tls_level level, buffers& buffer, lifecycle_time_point now) -> bool
{
    if (!receiver.keys_available(level, tls_direction::read)) return false;
    const auto chunk = sender.next_crypto(level, 900);
    if (chunk.data.empty()) return false;
    decoded_frame frame;
    frame.type = 6; frame.offset = chunk.offset; frame.data = chunk.data;
    const auto frame_size = encode_frame(frame, std::as_writable_bytes(std::span(buffer.frame)));
    check(frame_size.has_value());
    protected_packet_fields fields;
    fields.kind = level == tls_level::initial ? packet_kind::initial :
        level == tls_level::handshake ? packet_kind::handshake : packet_kind::short_header;
    fields.destination_cid = dcid;
    const auto size = sender.build(fields, std::span(buffer.frame).first(*frame_size),
                                    buffer.encoded, buffer.build_scratch);
    check(size.has_value());
    if (level == tls_level::application)
        check(sender.application_packet_sent(*sender.next_packet_number(level) - 1).has_value());
    check(sender.mark_crypto_sent(level, chunk.offset, chunk.data.size()).has_value());
    sender.encryption_level_sent(level);
    if (level != tls_level::application) {
        const auto inspection = receiver.authenticate_application_packet(
            std::span(buffer.encoded).first(*size),0,dcid.size(),buffer.packet_scratch,
            buffer.plaintext,buffer.auth_scratch);
        check(!inspection && inspection.error() == connection_error::malformed_packet);
    }
    if (level == tls_level::handshake && sender.level_discarded(tls_level::initial))
        check(!sender.keys_available(tls_level::initial,tls_direction::write));
    const auto opened = receiver.receive(std::span(buffer.encoded).first(*size), 0,
        dcid.size(), buffer.packet_scratch, buffer.plaintext, buffer.auth_scratch,
        now, std::chrono::milliseconds(10));
    check(opened.has_value());
    if (!receiver.level_discarded(level)) {
        const auto duplicate = receiver.receive(std::span(buffer.encoded).first(*size), 0,
            dcid.size(), buffer.packet_scratch, buffer.plaintext, buffer.auth_scratch,
            now, std::chrono::milliseconds(10));
        check(duplicate.has_value());
    }
    check(sender.acknowledge_crypto(level, chunk.offset, chunk.data.size()).has_value());
    std::array<std::byte, 256> ack_storage {};
    if (!receiver.level_discarded(level)) check(receiver.make_ack(level, 0, ack_storage).has_value());
    return true;
}
int main()
{
    contexts context;
    for (const auto version : {version_1, version_2}) {
        int frame_count = 0;
        connection_callbacks callbacks {&frame_count, valid_parameters, on_frame};
        auto client = std::make_unique<connection_core>(endpoint_role::client, callbacks);
        auto server = std::make_unique<connection_core>(endpoint_role::server, callbacks);
        check(client->initialize(context.client.get(), {false,"localhost",protocol,parameters},version,dcid).has_value());
        check(server->initialize(context.server.get(), {true,{},protocol,parameters},version,dcid).has_value());
        auto now = lifecycle_time_point {};
        check(client->advance(now).has_value());
        check(server->advance(now).has_value());
        buffers buffer;
        for (int step = 0; step < 40; ++step) {
            now += std::chrono::milliseconds(1);
            bool progress = false;
            for (const auto level : {tls_level::initial,tls_level::handshake,tls_level::application}) {
                progress |= transfer(*client,*server,level,buffer,now);
                progress |= transfer(*server,*client,level,buffer,now);
            }
            if (!progress) break;
        }
        check(client->state() == connection_state::active && server->state() == connection_state::active);
        // RFC 9287: both endpoints advertise grease_quic_bit, so each accepts a
        // zero QUIC bit and greases the bit on subsequent sends.
        check(client->local_grease_quic_bit() && server->local_grease_quic_bit());
        check(client->peer_grease_quic_bit() && server->peer_grease_quic_bit());
        {
            protected_packet_fields probe_fields;
            probe_fields.kind = packet_kind::short_header;
            probe_fields.destination_cid = dcid;
            const std::array<std::uint8_t, 1> ping {1};
            bool saw_set = false;
            bool saw_clear = false;
            for (int i = 0; i < 64 && !(saw_set && saw_clear); ++i) {
                const auto probe_size = client->build(probe_fields, ping,
                    buffer.encoded, buffer.build_scratch);
                check(probe_size.has_value());
                const auto quic_bit = (buffer.encoded[0] & 0x40) != 0;
                saw_set = saw_set || quic_bit;
                saw_clear = saw_clear || !quic_bit;
            }
            check(saw_set && saw_clear);
        }
        const auto first_idle_deadline = client->next_deadline(std::chrono::milliseconds(1));
        check(first_idle_deadline && *first_idle_deadline >= now + std::chrono::milliseconds(8) &&
              *first_idle_deadline <= now + std::chrono::milliseconds(10));
        check(client->packet_sent(now + std::chrono::milliseconds(1), true));
        check(client->next_deadline(std::chrono::milliseconds(1)) ==
              std::optional(now + std::chrono::milliseconds(11)));
        // Further eliciting sends do not extend the timer until a peer packet arrives.
        check(client->packet_sent(now + std::chrono::milliseconds(2), true));
        check(client->next_deadline(std::chrono::milliseconds(1)) ==
              std::optional(now + std::chrono::milliseconds(11)));
        check(server->handshake_confirmed() && !client->handshake_confirmed());
        const auto premature_update = client->initiate_key_update(now,std::chrono::milliseconds(10));
        check(!premature_update && premature_update.error() == key_update_error::handshake_not_confirmed);
        check(client->level_discarded(tls_level::initial) && server->level_discarded(tls_level::initial));
        check(server->level_discarded(tls_level::handshake) && !client->level_discarded(tls_level::handshake));
        check(!server->keys_available(tls_level::handshake,tls_direction::read));
        check(client->keys_available(tls_level::application,tls_direction::read));
        check(server->keys_available(tls_level::application,tls_direction::write));
        protected_packet_fields fields;
        fields.kind = packet_kind::short_header;
        fields.destination_cid = dcid;
        const std::array<std::uint8_t,1> done {0x1e};
        const auto size = server->build(fields,done,buffer.encoded,buffer.build_scratch);
        check(size.has_value());
        check(server->application_packet_sent(*server->next_packet_number(tls_level::application) - 1).has_value());
        const auto inspected_deadline = client->next_deadline(std::chrono::milliseconds(1));
        const auto inspected_frames = frame_count;
        std::array<std::byte,256> before_ack_storage{}, after_ack_storage{};
        const auto before_ack = client->make_ack(tls_level::application,0,before_ack_storage);
        const auto inspection = client->authenticate_application_packet(
            std::span(buffer.encoded).first(*size),0,dcid.size(),buffer.packet_scratch,
            buffer.plaintext,buffer.auth_scratch);
        check(inspection && inspection->kind == packet_kind::short_header);
        check(inspection->plaintext_size && buffer.plaintext[inspection->plaintext_size - 1] == 0x1e);
        check(!client->handshake_confirmed());
        check(frame_count == inspected_frames && !client->failure());
        check(client->next_deadline(std::chrono::milliseconds(1)) == inspected_deadline);
        const auto after_ack = client->make_ack(tls_level::application,0,after_ack_storage);
        check(before_ack.has_value() == after_ack.has_value());
        if (before_ack) check(before_ack->largest_acknowledged == after_ack->largest_acknowledged);
        now += std::chrono::milliseconds(3);
        check(server->packet_sent(now, true));
        buffer.encoded[*size - 1] ^= 1;
        const auto bad_inspection = client->authenticate_application_packet(
            std::span(buffer.encoded).first(*size),0,dcid.size(),buffer.packet_scratch,
            buffer.plaintext,buffer.auth_scratch);
        check(!bad_inspection && bad_inspection.error() == connection_error::authentication_failed);
        check(!client->failure() && !client->handshake_confirmed());
        auto bad = client->receive(std::span(buffer.encoded).first(*size),0,dcid.size(),buffer.packet_scratch,
            buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10));
        check(!bad && bad.error() == connection_error::authentication_failed && !client->failure());
        buffer.encoded[*size - 1] ^= 1;
        check(client->receive(std::span(buffer.encoded).first(*size),0,dcid.size(),buffer.packet_scratch,
            buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10)).has_value());
        check(client->handshake_confirmed());
        check(client->level_discarded(tls_level::handshake));
        check(!client->keys_available(tls_level::handshake,tls_direction::write));
        check(client->next_deadline(std::chrono::milliseconds(1)) ==
              std::optional(now + std::chrono::milliseconds(10)));
        // Keep a lower-numbered old-phase packet in flight across an update.
        const std::array<std::uint8_t, 1> ping {1};
        const auto delayed_number = *client->next_packet_number(tls_level::application);
        const auto delayed_size = client->build(fields,ping,buffer.encoded,buffer.build_scratch);
        check(delayed_size.has_value());
        const auto delayed = buffer.encoded;
        check(client->application_packet_sent(delayed_number).has_value());
        check(!client->initiate_key_update(now, std::chrono::milliseconds(10)));
        check(client->acknowledge_application_packet(delayed_number,now,std::chrono::milliseconds(10)).has_value());
        check(client->initiate_key_update(now, std::chrono::milliseconds(10)).has_value());
        const auto updated_number = *client->next_packet_number(tls_level::application);
        const auto updated_size = client->build(fields,ping,buffer.encoded,buffer.build_scratch);
        check(updated_size.has_value());
        check(client->application_packet_sent(updated_number).has_value());
        // Invalid authentication cannot commit a phase or poison the connection.
        buffer.encoded[*updated_size - 1] ^= 1;
        const auto forged = server->receive(std::span(buffer.encoded).first(*updated_size),0,dcid.size(),
            buffer.packet_scratch,buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10));
        check(!forged && !server->failure() && !server->peer_update_packet());
        buffer.encoded[*updated_size - 1] ^= 1;
        const auto before_update_deadline = server->next_deadline(std::chrono::milliseconds(1));
        const auto inspected_update = server->authenticate_application_packet(
            std::span(buffer.encoded).first(*updated_size),0,dcid.size(),
            buffer.packet_scratch,buffer.plaintext,buffer.auth_scratch);
        check(inspected_update && inspected_update->key_phase &&
              inspected_update->packet_number == updated_number);
        check(!server->peer_update_packet() && !server->application_key_phase());
        check(server->next_deadline(std::chrono::milliseconds(1)) == before_update_deadline);
        const auto updated = server->receive(std::span(buffer.encoded).first(*updated_size),0,dcid.size(),
            buffer.packet_scratch,buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10));
        check(updated && updated->key_phase && server->peer_update_packet() == updated_number);
        const auto update_deadline = server->next_deadline(std::chrono::milliseconds(1));
        const auto updated_duplicate = server->receive(std::span(buffer.encoded).first(*updated_size),0,dcid.size(),
            buffer.packet_scratch,buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10));
        check(updated_duplicate && updated_duplicate->key_phase && !server->failure());
        check(server->peer_update_packet() == updated_number && server->application_key_phase());
        check(server->next_deadline(std::chrono::milliseconds(1)) == update_deadline);
        const auto inspected_old = server->authenticate_application_packet(
            std::span(delayed).first(*delayed_size),0,dcid.size(),
            buffer.packet_scratch,buffer.plaintext,buffer.auth_scratch);
        check(inspected_old && !inspected_old->key_phase && inspected_old->packet_number == delayed_number);
        check(server->peer_update_packet() == updated_number && server->application_key_phase());
        const auto old = server->receive(std::span(delayed).first(*delayed_size),0,dcid.size(),
            buffer.packet_scratch,buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10));
        check(old && !old->key_phase && old->packet_number == delayed_number);
        const auto response_number = *server->next_packet_number(tls_level::application);
        const auto phase_response = server->build(fields,ping,buffer.encoded,buffer.build_scratch);
        check(phase_response.has_value());
        check(server->application_packet_sent(response_number, updated_number).has_value());
        const auto response = client->receive(std::span(buffer.encoded).first(*phase_response),0,dcid.size(),
            buffer.packet_scratch,buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10));
        check(response && response->key_phase);
        const auto ack_number = *client->next_packet_number(tls_level::application);
        check(client->build(fields,ping,buffer.encoded,buffer.build_scratch).has_value());
        check(client->application_packet_sent(ack_number,response_number).has_value());
        check(client->acknowledge_application_packet(updated_number,now,std::chrono::milliseconds(10)).has_value());
        const auto rapid = client->initiate_key_update(now + std::chrono::milliseconds(29),std::chrono::milliseconds(10));
        check(!rapid && rapid.error() == key_update_error::retirement_not_due);
        // At three PTOs the previous key is discarded, even for delayed packets.
        const auto expired = server->receive(std::span(delayed).first(*delayed_size),0,dcid.size(),
            buffer.packet_scratch,buffer.plaintext,buffer.auth_scratch,now + std::chrono::milliseconds(30),
            std::chrono::milliseconds(10));
        check(!expired && expired.error() == connection_error::authentication_failed && !server->failure());
        now += std::chrono::milliseconds(30);
        check(client->initiate_key_update(now,std::chrono::milliseconds(10)).has_value());
        const auto second_number = *client->next_packet_number(tls_level::application);
        const auto second_size = client->build(fields,ping,buffer.encoded,buffer.build_scratch);
        check(second_size.has_value());
        check(client->application_packet_sent(second_number).has_value());
        const auto second = server->receive(std::span(buffer.encoded).first(*second_size),0,dcid.size(),
            buffer.packet_scratch,buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10));
        check(second && !second->key_phase);
        const std::array<std::uint8_t, 4> close {0x1c,0,0,0};
        const auto close_size = client->build(fields,close,buffer.encoded,buffer.build_scratch);
        check(close_size.has_value());
        check(client->close_sent(now,std::chrono::milliseconds(10)));
        check(client->build(fields,close,buffer.encoded,buffer.build_scratch).has_value());
        const auto response_size = client->build(fields,close,buffer.encoded,buffer.build_scratch);
        check(response_size.has_value());
        check(server->receive(std::span(buffer.encoded).first(*response_size),0,dcid.size(),buffer.packet_scratch,
            buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10)).has_value());
        check(server->state() == connection_state::draining);
        check(client->poll(now + std::chrono::milliseconds(30),std::chrono::milliseconds(10)));
        check(server->poll(now + std::chrono::milliseconds(30),std::chrono::milliseconds(10)));
        check(client->state() == connection_state::closed && server->state() == connection_state::closed);
    }
    std::puts("QUIC connection core tests passed");
}
