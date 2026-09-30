#include "quic/connection.h"
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
static constexpr std::array<std::uint8_t, 29> parameters {15,1,42,4,2,0x60,0,5,2,0x60,0,6,2,0x60,0,7,2,0x60,0,8,1,32,9,1,32,0x20,2,0x44,0xb0};
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
static auto transfer(bounded_connection& sender, bounded_connection& receiver,
                     tls_level level, buffers& buffer, lifecycle_time_point now) -> bool
{
    if (!receiver.core().keys_available(level, tls_direction::read)) return false;
    const auto chunk = sender.core().next_crypto(level, 900);
    if (chunk.data.empty()) return false;
    decoded_frame frame;
    frame.type = 6; frame.offset = chunk.offset; frame.data = chunk.data;
    const auto frame_size = encode_frame(frame, std::as_writable_bytes(std::span(buffer.frame)));
    check(frame_size.has_value());
    protected_packet_fields fields;
    fields.kind = level == tls_level::initial ? packet_kind::initial :
        level == tls_level::handshake ? packet_kind::handshake : packet_kind::short_header;
    fields.destination_cid = dcid;
    const auto size = sender.core().build(fields, std::span(buffer.frame).first(*frame_size),
                                    buffer.encoded, buffer.build_scratch);
    check(size.has_value());
    check(sender.core().mark_crypto_sent(level, chunk.offset, chunk.data.size()).has_value());
    const auto opened = receiver.receive(std::span(buffer.encoded).first(*size), 0,
        dcid.size(), buffer.packet_scratch, buffer.plaintext, buffer.auth_scratch,
        now, std::chrono::milliseconds(10));
    check(opened.has_value());
    if (!receiver.core().level_discarded(level)) {
        const auto duplicate = receiver.receive(std::span(buffer.encoded).first(*size), 0,
            dcid.size(), buffer.packet_scratch, buffer.plaintext, buffer.auth_scratch,
            now, std::chrono::milliseconds(10));
        check(duplicate.has_value());
    }
    check(sender.core().acknowledge_crypto(level, chunk.offset, chunk.data.size()).has_value());
    std::array<std::byte, 256> ack_storage {};
    if (!receiver.core().level_discarded(level)) check(receiver.core().make_ack(level, 0, ack_storage).has_value());
    return true;
}
int main()
{
    contexts context;
    for (auto version : {version_1, version_2}) {
        connection_callbacks callbacks {nullptr, valid_parameters, nullptr};
        auto client = std::make_unique<bounded_connection>(endpoint_role::client, callbacks);
        auto server = std::make_unique<bounded_connection>(endpoint_role::server, callbacks);
        check(client->initialize(context.client.get(), {false,"localhost",protocol,parameters},version,dcid).has_value());
        check(server->initialize(context.server.get(), {true,{},protocol,parameters},version,dcid).has_value());
        auto now = lifecycle_time_point {};
        check(client->core().advance(now).has_value());
        check(server->core().advance(now).has_value());
        buffers buffer;
        for (int step = 0; step < 40; ++step) {
            now += std::chrono::milliseconds(1);
            bool progress = false;
            for (auto level : {tls_level::initial,tls_level::handshake,tls_level::application}) {
                progress |= transfer(*client,*server,level,buffer,now);
                progress |= transfer(*server,*client,level,buffer,now);
            }
            if (!progress) break;
        }
        check(client->core().state() == connection_state::active);
        check(server->core().state() == connection_state::active);
        const auto id = client->open_stream(stream_direction::bidirectional);
        check(id && *id == 0);
        auto* send = client->stream(*id);
        const std::array<std::byte, 3> data {std::byte{1},std::byte{2},std::byte{3}};
        check(send->send.append(data).has_value());
        check(send->send.close().has_value());
        decoded_frame stream;
        stream.type = 0x0f; stream.stream_id = *id; stream.data = data; stream.fin = true;
        const auto size = encode_frame(stream, std::as_writable_bytes(std::span(buffer.frame)));
        check(size.has_value());
        protected_packet_fields fields;
        fields.kind = packet_kind::short_header; fields.destination_cid = dcid;
        check(client->core().next_packet_number(tls_level::application) == 0);
        check(!client->core().next_packet_number(static_cast<tls_level>(3)));
        const auto encoded = client->core().build(fields, std::span(buffer.frame).first(*size),buffer.encoded,buffer.build_scratch);
        check(encoded.has_value());
        check(client->core().next_packet_number(tls_level::application) == 1);
        const bounded_connection::transmitted_range range {false,*id,0,data.size(),true};
        check(client->record_sent(tls_level::application,{0,now,true,true,*encoded},std::span(&range,1)).has_value());
        check(server->receive(std::span(buffer.encoded).first(*encoded),0,dcid.size(),buffer.packet_scratch,
            buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10)).has_value());
        auto* received = server->stream(*id);
        check(received && std::ranges::equal(received->receive->readable(),data));
        check(server->consume_stream(*id,data.size()).has_value());
        check(received->state.receiving() == stream_receive_state::data_read);
        std::array<std::byte,256> ack_storage;
        const auto ack = server->core().make_ack(tls_level::application,0,ack_storage);
        check(ack.has_value());
        const auto ack_size = encode_frame(*ack,std::as_writable_bytes(std::span(buffer.frame)));
        check(ack_size.has_value());
        const auto ack_packet = server->core().build(fields,std::span(buffer.frame).first(*ack_size),buffer.encoded,buffer.build_scratch);
        check(ack_packet.has_value());
        check(client->receive(std::span(buffer.encoded).first(*ack_packet),0,dcid.size(),buffer.packet_scratch,
            buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10)).has_value());
        check(send->send.complete() && send->state.sending() == stream_send_state::data_received);
        decoded_frame datagram;
        datagram.type = 0x31; datagram.data = data;
        const auto datagram_size = encode_frame(datagram,std::as_writable_bytes(std::span(buffer.frame)));
        check(datagram_size.has_value());
        for (int i = 0; i < 9; ++i) {
            const auto packet = client->core().build(fields,std::span(buffer.frame).first(*datagram_size),buffer.encoded,buffer.build_scratch);
            check(packet.has_value());
            check(server->receive(std::span(buffer.encoded).first(*packet),0,dcid.size(),buffer.packet_scratch,
                buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10)).has_value());
        }
        std::array<std::byte,3> output;
        for (int i = 0; i < 8; ++i) check(server->receive_datagram(output).value() == 3 && output == data);
        check(!server->receive_datagram(output));
        // Three later actual transmissions cause packet-threshold loss, then
        // retransmission ACK releases the original stream bytes and FIN.
        const auto second = client->open_stream(stream_direction::bidirectional);
        check(second.has_value());
        auto* retransmit = client->stream(*second);
        check(retransmit->send.append(data).has_value());
        check(retransmit->send.close().has_value());
        stream.stream_id = *second;
        const auto lost_size = encode_frame(stream,std::as_writable_bytes(std::span(buffer.frame)));
        check(lost_size.has_value());
        const auto lost_packet = client->core().build(fields,std::span(buffer.frame).first(*lost_size),buffer.encoded,buffer.build_scratch);
        check(lost_packet.has_value());
        const bounded_connection::transmitted_range lost_range {false,*second,0,data.size(),true};
        check(client->record_sent(tls_level::application,{10,now,true,true,*lost_packet},std::span(&lost_range,1)).has_value());
        const std::array<std::uint8_t,1> ping {1};
        for (std::uint64_t n = 11; n <= 13; ++n) {
            const auto packet = client->core().build(fields,ping,buffer.encoded,buffer.build_scratch);
            check(packet.has_value());
            check(client->record_sent(tls_level::application,{n,now,true,true,*packet},{}).has_value());
        }
        decoded_frame loss_ack;
        loss_ack.type = 2; loss_ack.largest_acknowledged = 13;
        auto frame_size = encode_frame(loss_ack,std::as_writable_bytes(std::span(buffer.frame)));
        check(frame_size.has_value());
        auto packet_size = server->core().build(fields,std::span(buffer.frame).first(*frame_size),buffer.encoded,buffer.build_scratch);
        check(packet_size.has_value());
        check(client->receive(std::span(buffer.encoded).first(*packet_size),0,dcid.size(),buffer.packet_scratch,
            buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10)).has_value());
        check(std::ranges::equal(retransmit->send.next_pending(100).data,data));
        check(retransmit->send.next_pending(100).fin);
        frame_size = encode_frame(stream,std::as_writable_bytes(std::span(buffer.frame)));
        check(frame_size.has_value());
        packet_size = client->core().build(fields,std::span(buffer.frame).first(*frame_size),buffer.encoded,buffer.build_scratch);
        check(packet_size.has_value());
        check(client->record_sent(tls_level::application,{14,now,true,true,*packet_size},std::span(&lost_range,1)).has_value());
        check(server->receive(std::span(buffer.encoded).first(*packet_size),0,dcid.size(),buffer.packet_scratch,
            buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10)).has_value());
        loss_ack.largest_acknowledged = 14;
        frame_size = encode_frame(loss_ack,std::as_writable_bytes(std::span(buffer.frame)));
        packet_size = server->core().build(fields,std::span(buffer.frame).first(*frame_size),buffer.encoded,buffer.build_scratch);
        check(packet_size.has_value());
        check(client->receive(std::span(buffer.encoded).first(*packet_size),0,dcid.size(),buffer.packet_scratch,
            buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10)).has_value());
        check(retransmit->send.complete());
        for (int i = 2; i < 32; ++i) check(client->open_stream(stream_direction::bidirectional).has_value());
        check(!client->open_stream(stream_direction::bidirectional));
        // Path migration: an unvalidated candidate cannot be promoted; promotion
        // resets path-specific RTT/congestion state while cancellation and
        // rejected transitions preserve the active path.
        check(client->path_recovery().active_handle() == 0);
        check(client->recovery().reset(1200).has_value());
        const sent_packet probe_packet {0, now, true, true, 1200};
        check(client->recovery().record(packet_number_space::application_data,
              probe_packet).has_value());
        check(client->recovery().congestion().bytes_in_flight() == 1200);
        check(client->begin_path_candidate(1).has_value());
        check(client->path_recovery().active_handle() == 0 &&
              client->path_recovery().candidate_handle() == 1);
        check(client->promote_path_candidate().error() ==
              path_recovery_error::not_validated);
        check(client->path_recovery().active_handle() == 0 &&
              client->recovery().congestion().bytes_in_flight() == 1200);
        check(client->mark_path_validated().has_value());
        check(client->promote_path_candidate().has_value());
        check(client->path_recovery().active_handle() == 1 &&
              !client->path_recovery().candidate_handle() &&
              client->path_recovery().find(0) == nullptr);
        check(client->recovery().congestion().bytes_in_flight() == 0 &&
              !client->recovery().rtt().has_sample());
        check(client->begin_path_candidate(2).has_value());
        check(client->cancel_path_candidate().has_value());
        check(client->path_recovery().active_handle() == 1 &&
              client->path_recovery().find(2) == nullptr);
    }
    std::puts("QUIC bounded connection tests passed");
}
