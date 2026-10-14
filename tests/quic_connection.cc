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
        std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name {
            X509_NAME_new(), X509_NAME_free};
        check(name != nullptr);
        check(X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
              reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) == 1);
        check(X509_set_subject_name(certificate.get(), name.get()) == 1);
        check(X509_set_issuer_name(certificate.get(), name.get()) == 1);
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
static constexpr std::array<std::uint8_t, 29> parameters {15,1,42,4,2,0x60,0,5,2,0x50,0,6,2,0x50,0,7,2,0x50,0,8,1,32,9,1,8,0x20,2,0x44,0xb0};
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
    for (const auto index : {21u, 24u}) {
        auto unsafe = parameters;
        unsafe[index] = index == 21 ? 33 : 9;
        connection_callbacks callbacks {nullptr, valid_parameters, nullptr};
        auto connection = std::make_unique<bounded_connection>(endpoint_role::client, callbacks);
        const auto initialized = connection->initialize(context.client.get(),
            {false,"localhost",protocol,unsafe},version_1,dcid);
        check(!initialized && initialized.error() == connection_error::invalid_configuration);
    }
    // Internal callers must not bypass the endpoint's storage caps by passing
    // raw transport parameters with an unsafe stream or connection window.
    for (const auto index : {8u, 12u, 16u}) {
        auto unsafe = parameters;
        unsafe[index + 1] = 0x60; // 8192 bytes, versus the 4096-byte ring
        connection_callbacks callbacks {nullptr, valid_parameters, nullptr};
        auto connection = std::make_unique<bounded_connection>(endpoint_role::client, callbacks);
        const auto initialized = connection->initialize(context.client.get(),
            {false,"localhost",protocol,unsafe},version_1,dcid);
        check(!initialized && initialized.error() == connection_error::invalid_configuration);
    }
    {
        // Preserve the rest of the parameters while replacing initial_max_data
        // with the four-byte encoding of 131073 (one byte beyond all rings).
        std::array<std::uint8_t, parameters.size() + 2> unsafe {};
        std::copy_n(parameters.begin(), 4, unsafe.begin());
        unsafe[4] = 4;
        unsafe[5] = 0x80; unsafe[6] = 2; unsafe[7] = 0; unsafe[8] = 1;
        std::copy(parameters.begin() + 7, parameters.end(), unsafe.begin() + 9);
        connection_callbacks callbacks {nullptr, valid_parameters, nullptr};
        auto connection = std::make_unique<bounded_connection>(endpoint_role::client, callbacks);
        const auto initialized = connection->initialize(context.client.get(),
            {false,"localhost",protocol,unsafe},version_1,dcid);
        check(!initialized && initialized.error() == connection_error::invalid_configuration);
        unsafe[8] = 0; // The full 128 KiB reserved connection window is valid.
        auto exact = std::make_unique<bounded_connection>(endpoint_role::client, callbacks);
        check(exact->initialize(context.client.get(),
            {false,"localhost",protocol,unsafe},version_1,dcid).has_value());
        check(exact->flow().receive_max_data() == bounded_connection::receive_bytes);
    }
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
        {
            // A client discards a server Initial that carries a token
            // (RFC 9000 17.2.2).
            const std::array<std::uint8_t, 1> ping {1};
            const std::array<std::uint8_t, 4> token {9, 9, 9, 9};
            protected_packet_fields fields;
            fields.kind = packet_kind::initial; fields.destination_cid = dcid; fields.token = token;
            const auto size = server->core().build(fields, ping, buffer.encoded, buffer.build_scratch);
            check(size.has_value());
            const auto opened = client->receive(std::span(buffer.encoded).first(*size), 0,
                dcid.size(), buffer.packet_scratch, buffer.plaintext, buffer.auth_scratch,
                now, std::chrono::milliseconds(10));
            check(!opened && opened.error() == connection_error::malformed_packet);
        }
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
        // Fill a receive ring, including a sparse range ending exactly at the
        // advertised boundary, then slide the window only after consumption.
        const auto buffered_id = client->open_stream(stream_direction::bidirectional);
        check(buffered_id.has_value());
        const auto deliver = [&](std::uint64_t offset, std::size_t length) {
            std::array<std::byte, 1170> payload {};
            decoded_frame incoming;
            incoming.type = 0x0e; incoming.stream_id = *buffered_id;
            incoming.offset = offset; incoming.data = std::span(payload).first(length);
            const auto frame_length = encode_frame(incoming,
                std::as_writable_bytes(std::span(buffer.frame)));
            check(frame_length.has_value());
            const auto packet = client->core().build(fields,
                std::span(buffer.frame).first(*frame_length), buffer.encoded, buffer.build_scratch);
            check(packet.has_value());
            check(server->receive(std::span(buffer.encoded).first(*packet), 0,
                dcid.size(), buffer.packet_scratch, buffer.plaintext,
                buffer.auth_scratch, now, std::chrono::milliseconds(10)).has_value());
        };
        deliver(3501, 595);
        auto* buffered = server->stream(*buffered_id);
        check(buffered && buffered->receive_limit == bounded_connection::stream_bytes);
        check(buffered->receive->readable().empty());
        const std::array<std::byte, 1170> oversized {};
        const auto rejected = buffered->receive->insert(3501, oversized);
        check(!rejected && rejected.error() == stream_receive_error::flow_limit_exceeded);
        check(buffered->receive->highest_received_offset() == 4096);
        deliver(0, 1170);
        deliver(1170, 1170);
        deliver(2340, 1161);
        check(buffered->receive->readable().size() == bounded_connection::stream_bytes);
        check(server->consume_stream(*buffered_id, 64).has_value());
        check(buffered->receive_limit == bounded_connection::stream_bytes + 64);
        check(buffered->receive_limit - buffered->consumed == bounded_connection::stream_bytes);
        deliver(4096, 64);
        check(server->consume_stream(*buffered_id, 4032).has_value());
        check(buffered->receive->readable().size() == 64);
        check(server->consume_stream(*buffered_id, 64).has_value());
        check(buffered->receive->readable().empty());
        check(server->flow().receive_max_data() == 8192 + 3 + 4160);
        for (int i = 3; i < 32; ++i) check(client->open_stream(stream_direction::bidirectional).has_value());
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
        check(client->recovery().congestion().bytes_in_flight() == 1200 &&
              !client->recovery().rtt().has_sample());
        check(client->begin_path_candidate(2).has_value());
        check(client->cancel_path_candidate().has_value());
        check(client->path_recovery().active_handle() == 1 &&
              client->path_recovery().find(2) == nullptr);

        // Filling local lifetime quotas must leave every advertised peer slot
        // available, for both initiators and directions. Higher peer IDs arrive
        // first so implicit opening cannot hide an admission failure later.
        const auto deliver_frame = [&](bounded_connection& sender,
                                       bounded_connection& receiver,
                                       const decoded_frame& frame) {
            const auto size = encode_frame(frame,
                std::as_writable_bytes(std::span(buffer.frame)));
            check(size.has_value());
            protected_packet_fields packet;
            packet.kind = packet_kind::short_header; packet.destination_cid = dcid;
            const auto encoded = sender.core().build(packet,
                std::span(buffer.frame).first(*size), buffer.encoded, buffer.build_scratch);
            check(encoded.has_value());
            return receiver.receive(std::span(buffer.encoded).first(*encoded), 0,
                dcid.size(), buffer.packet_scratch, buffer.plaintext,
                buffer.auth_scratch, now, std::chrono::milliseconds(10));
        };
        // Even larger authenticated peer grants cannot expand local storage or
        // consume the independently reserved peer slots.
        for (const auto type : {0x12u, 0x13u}) {
            decoded_frame grant; grant.type = type; grant.limit = 100;
            check(deliver_frame(*server, *client, grant).has_value());
            check(deliver_frame(*client, *server, grant).has_value());
        }
        const auto opened_before = client->streams().local_opened(stream_direction::bidirectional);
        check(!client->open_stream(stream_direction::bidirectional));
        check(client->streams().local_opened(stream_direction::bidirectional) == opened_before);
        for (auto* connection : {client.get(), server.get()}) {
            while (connection->streams().local_opened(stream_direction::bidirectional) <
                   bounded_connection::bidi_stream_capacity)
                check(connection->open_stream(stream_direction::bidirectional).has_value());
            for (std::size_t i = 0; i < bounded_connection::uni_stream_capacity; ++i)
                check(connection->open_stream(stream_direction::unidirectional).has_value());
            check(!connection->open_stream(stream_direction::bidirectional));
            check(!connection->open_stream(stream_direction::unidirectional));
        }
        const auto deliver_streams = [&](bounded_connection& sender,
                                         bounded_connection& receiver,
                                         std::uint64_t initiator) {
            for (auto direction : {stream_direction::bidirectional,
                                   stream_direction::unidirectional}) {
                const auto capacity = direction == stream_direction::bidirectional
                    ? bounded_connection::bidi_stream_capacity
                    : bounded_connection::uni_stream_capacity;
                for (std::size_t i = capacity; i > 0; --i) {
                    const auto id = 4 * (i - 1) + initiator +
                        (direction == stream_direction::unidirectional ? 2 : 0);
                    if (receiver.stream(id)) continue; // Existing traffic above.
                    decoded_frame stream;
                    stream.type = 0x0b; stream.stream_id = id; stream.fin = true;
                    check(deliver_frame(sender, receiver, stream).has_value());
                    check(receiver.stream(id) != nullptr);
                    check(receiver.stream(id)->receive->complete());
                }
            }
        };
        deliver_streams(*client, *server, 0);
        deliver_streams(*server, *client, 1);
        for (auto* connection : {client.get(), server.get()}) {
            check(connection->streams().size() == bounded_connection::stream_capacity);
            check(std::ranges::count_if(connection->stream_slots(),
                [](const auto& slot) { return slot.occupied; }) ==
                bounded_connection::stream_capacity);
            // FIN-complete peer streams retain their lifetime reservation.
            check(!connection->open_stream(stream_direction::bidirectional));
            check(!connection->open_stream(stream_direction::unidirectional));
            check(connection->core().state() == connection_state::active);
        }
        decoded_frame excessive;
        excessive.type = 0x0b; excessive.fin = true;
        excessive.stream_id = version == version_1
            ? 4 * bounded_connection::bidi_stream_capacity
            : 4 * bounded_connection::uni_stream_capacity + 2;
        check(!deliver_frame(*client, *server, excessive));
    }
    std::puts("QUIC bounded connection tests passed");
}
