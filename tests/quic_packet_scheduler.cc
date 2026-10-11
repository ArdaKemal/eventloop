#include "quic/packet_scheduler.h"
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
static constexpr std::array<std::uint8_t, 29> parameters {15,1,42,4,2,0x44,0,5,2,0x44,0,6,2,0x44,0,7,2,0x44,0,8,1,32,9,1,8,0x20,2,0x44,0xb0};
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
    std::array<std::uint8_t, packet_scheduler::maximum_datagram> encoded {}, frame {},
        build_scratch {}, packet_scratch {}, plaintext {}, auth_scratch {};
};
int main()
{
    crypto_send_buffer<8> probe_buffer;
    const std::array<std::byte,4> probe_bytes{};
    check(probe_buffer.append(probe_bytes).has_value());
    check(probe_buffer.mark_sent(0,4).has_value());
    check(probe_buffer.next_pending(8).data.empty());
    check(probe_buffer.next_unacknowledged(8).data.size()==4);
    check(probe_buffer.acknowledge(1,2).has_value());
    check(probe_buffer.next_unacknowledged(8).data.size()==1);
    check(probe_buffer.acknowledge(0,1).has_value());
    check(probe_buffer.next_unacknowledged(8).offset==3);
    check(probe_buffer.acknowledge(3,1).has_value());
    check(probe_buffer.next_unacknowledged(8).data.empty());
    contexts context;
    for (auto version : {version_1,version_2}) {
        connection_callbacks callbacks {nullptr,valid_parameters,nullptr};
        auto client=std::make_unique<bounded_connection>(endpoint_role::client,callbacks);
        auto server=std::make_unique<bounded_connection>(endpoint_role::server,callbacks);
        check(client->initialize(context.client.get(),{false,"localhost",protocol,parameters},version,dcid).has_value());
        check(server->initialize(context.server.get(),{true,{},protocol,parameters},version,dcid).has_value());
        // A zero-length Retry SCID becomes an empty destination CID. The
        // client keeps its route/SCID; only Initial key input and wire DCID
        // change. Verify the packet with independently derived empty-CID keys.
        {
            auto retry_client=std::make_unique<bounded_connection>(endpoint_role::client,callbacks);
            check(retry_client->initialize(context.client.get(),
                {false,"localhost",protocol,parameters},version,dcid).has_value());
            check(retry_client->core().advance(lifecycle_time_point{}).has_value());
            const auto hello=retry_client->core().next_crypto(tls_level::initial,2048);
            std::array<std::byte,2048> saved {};
            std::ranges::copy(hello.data,saved.begin());
            const auto hello_size=hello.data.size();
            packet_scheduler scheduler(*retry_client);
            protected_packet_fields fields; fields.destination_cid=dcid; fields.source_cid=dcid;
            buffers buffer;
            check(scheduler.prepare(tls_level::initial,fields,lifecycle_time_point{},
                buffer.encoded,buffer.build_scratch).has_value());
            check(scheduler.complete(true,lifecycle_time_point{}).has_value());
            const auto next=retry_client->core().next_packet_number(tls_level::initial);
            check(retry_client->apply_retry({}).has_value());
            check(retry_client->core().next_packet_number(tls_level::initial)==next);
            const auto repeated=retry_client->core().next_crypto(tls_level::initial,2048);
            check(std::ranges::equal(repeated.data,std::span(saved).first(hello_size)));
            fields.destination_cid={};
            const auto size=scheduler.prepare(tls_level::initial,fields,lifecycle_time_point{},
                buffer.encoded,buffer.build_scratch);
            check(size && *size==1200);
            const auto header=parse_packet_header(std::as_bytes(std::span(buffer.encoded).first(*size)));
            check(header && header->destination_cid.empty() &&
                std::ranges::equal(header->source_cid,std::as_bytes(std::span(dcid))));
            const auto secrets=derive_initial_secrets(version,{});
            check(secrets.has_value());
            const auto keys=derive_aes_128_gcm_keys(version,secrets->client);
            check(keys.has_value());
            packet_protection_context protection;
            const auto opened=open_protected_packet(protection,std::span(buffer.encoded).first(*size),
                0,dcid.size(),version,*keys,{},buffer.packet_scratch,buffer.plaintext,buffer.auth_scratch);
            check(opened && opened->packet_number==next);
        }
        packet_scheduler outgoing(*client), incoming(*server);
        buffers buffer;
        // A bounded maximum Retry token leaves less CRYPTO room per Initial.
        // The handshake must still progress through multiple bounded packets.
        std::array<std::uint8_t,512> retry_token {};
        std::ranges::fill(retry_token,0xa5);
        std::size_t last_plaintext_size=0;
        auto now=lifecycle_time_point{};
        check(client->core().advance(now).has_value());
        check(server->core().advance(now).has_value());
        auto send=[&](bounded_connection& from, bounded_connection& to, packet_scheduler& scheduler,
                      packet_scheduler& receiver, tls_level level, bool fail=false, bool probe=false) {
            if (!to.core().keys_available(level,tls_direction::read)) return false;
            protected_packet_fields fields; fields.destination_cid=dcid;
            if (level==tls_level::initial && &from==client.get()) {
                fields.source_cid=dcid;
                fields.token=retry_token;
            }
            auto size=scheduler.prepare(level,fields,now,buffer.encoded,buffer.build_scratch,probe);
            if (!size) return false;
            check(scheduler.pending());
            if (level==tls_level::initial) {
                check(*size==1200);
                const auto header=parse_packet_header(std::as_bytes(std::span(buffer.encoded).first(*size)),0,dcid.size(),true);
                check(header.has_value());
                check(std::ranges::equal(header->token,std::as_bytes(fields.token)));
            }
            check(!scheduler.prepare(level,fields,now,buffer.encoded,buffer.build_scratch));
            check(scheduler.complete(!fail,now).has_value());
            if (fail) return true;
            const auto opened=to.receive(std::span(buffer.encoded).first(*size),0,dcid.size(),
                buffer.packet_scratch,buffer.plaintext,buffer.auth_scratch,now,std::chrono::milliseconds(10));
            check(opened.has_value());
            last_plaintext_size=opened->plaintext_size;
            bool eliciting=false;
            std::size_t cursor=0;
            while(cursor<opened->plaintext_size) {
                const auto frame=decode_frame(std::as_bytes(std::span(buffer.plaintext).first(opened->plaintext_size)).subspan(cursor));
                check(frame.has_value()); cursor+=frame->encoded_size;
                eliciting |= frame->type!=0 && frame->type!=2 && frame->type!=3;
            }
            if(eliciting) receiver.request_ack(level);
            return true;
        };
        // Failed submission keeps Initial CRYPTO pending and consumes no history.
        check(send(*client,*server,outgoing,incoming,tls_level::initial,true));
        check(client->recovery().history(packet_number_space::initial)->size()==0);
        // Retry preserves the exact ClientHello, including bytes already sent,
        // and consumes no Initial packet number. The endpoint validates the
        // Retry SCID separately; this core test reuses the same key input.
        const auto hello=client->core().next_crypto(tls_level::initial,2048);
        check(hello.offset==0 && !hello.data.empty());
        std::array<std::byte,2048> saved_hello {};
        std::ranges::copy(hello.data,saved_hello.begin());
        const auto hello_size=hello.data.size();
        const auto next_number=client->core().next_packet_number(tls_level::initial);
        check(client->core().mark_crypto_sent(tls_level::initial,0,hello_size).has_value());
        check(client->core().next_crypto(tls_level::initial,2048).data.empty());
        check(client->apply_retry(dcid).has_value());
        check(client->core().next_packet_number(tls_level::initial)==next_number);
        const auto repeated=client->core().next_crypto(tls_level::initial,2048);
        check(repeated.offset==0 && std::ranges::equal(repeated.data,
            std::span(saved_hello).first(hello_size)));
        check(!client->apply_retry(dcid));
        // A PTO sends outstanding CRYPTO even though it is no longer pending.
        // Failed probe submissions neither retire the original nor change it.
        check(send(*client,*server,outgoing,incoming,tls_level::initial));
        const auto crypto_probe=client->core().next_crypto_probe(tls_level::initial,100);
        check(!crypto_probe.data.empty());
        check(crypto_probe.offset==0);
        check(send(*client,*server,outgoing,incoming,tls_level::initial,true,true));
        check(client->recovery().history(packet_number_space::initial)->size()==1);
        check(client->core().next_crypto_probe(tls_level::initial,100).offset==crypto_probe.offset);
        check(send(*client,*server,outgoing,incoming,tls_level::initial,false,true));
        check(client->recovery().history(packet_number_space::initial)->size()==2);
        check(decode_frame(std::as_bytes(std::span(buffer.plaintext).first(last_plaintext_size)))->type==6);
        for(int step=0;step<100;++step) {
            now+=std::chrono::milliseconds(1); bool progress=false;
            for(auto level:{tls_level::initial,tls_level::handshake,tls_level::application}) {
                progress|=send(*client,*server,outgoing,incoming,level);
                progress|=send(*server,*client,incoming,outgoing,level);
            }
            if(!progress) break;
        }
        check(client->core().state()==connection_state::active);
        check(server->core().state()==connection_state::active);
        const auto id=client->open_stream(stream_direction::bidirectional); check(id.has_value());
        const std::array<std::byte,3> bytes{std::byte{1},std::byte{2},std::byte{3}};
        check(client->stream(*id)->send.append(bytes).has_value());
        check(client->stream(*id)->send.close().has_value());
        check(client->queue_datagram(bytes).has_value());
        check(send(*client,*server,outgoing,incoming,tls_level::application,true));
        check(client->outgoing_datagrams().size()==1);
        check(client->stream(*id)->send.next_pending(100).data.size()==3);
        check(send(*client,*server,outgoing,incoming,tls_level::application));
        check(client->outgoing_datagrams().empty());
        check(server->stream(*id)->receive->readable().size()==3);
        check(client->stream(*id)->send.next_pending(100).data.empty());
        check(client->stream(*id)->send.next_unacknowledged(100).data.size()==3);
        const auto sent_credit=client->flow().sent_total();
        check(send(*client,*server,outgoing,incoming,tls_level::application,true,true));
        check(client->flow().sent_total()==sent_credit);
        check(send(*client,*server,outgoing,incoming,tls_level::application,false,true));
        check(client->flow().sent_total()==sent_credit);
        const auto probe_frame=decode_frame(std::as_bytes(std::span(buffer.plaintext).first(last_plaintext_size)));
        check(probe_frame && probe_frame->type==15 && probe_frame->stream_id==*id && probe_frame->fin);
        check(send(*server,*client,incoming,outgoing,tls_level::application));
        check(client->stream(*id)->send.complete());
        check(client->stream(*id)->send.next_unacknowledged(100).data.empty());
        check(!client->stream(*id)->send.next_unacknowledged(100).fin);
        decoded_frame control; control.type=0x10; control.limit=10000;
        check(outgoing.queue_control(tls_level::application,control).has_value());
        check(send(*client,*server,outgoing,incoming,tls_level::application));
        const auto number=outgoing.packet_number();
        outgoing.lose_control(tls_level::application,number);
        check(send(*client,*server,outgoing,incoming,tls_level::application));
        outgoing.acknowledge_control(tls_level::application,outgoing.packet_number());
        // Consuming receive storage renews both credits and reliably advertises
        // them, so a bounded ring supports a transfer beyond its initial window.
        check(server->consume_stream(*id,3).has_value());
        check(send(*server,*client,incoming,outgoing,tls_level::application));
        const auto bulk=client->open_stream(stream_direction::bidirectional); check(bulk.has_value());
        const std::array<std::byte,1024> block{};
        for(int round=0;round<3;++round) {
            check(client->stream(*bulk)->send.append(block).has_value());
            check(send(*client,*server,outgoing,incoming,tls_level::application));
            check(server->stream(*bulk)->receive->readable().size()==block.size());
            check(server->consume_stream(*bulk,block.size()).has_value());
            check(server->flow().receive_max_data()==1027u+(round+1)*1024u);
            check(server->stream(*bulk)->receive->flow_limit()==1024u+(round+1)*1024u);
            check(send(*server,*client,incoming,outgoing,tls_level::application));
        }
        check(client->flow().sent_total()==3075);
        // STOP_SENDING after a partial transmission fixes RESET_STREAM's final
        // size at the bytes actually sent, discarding the queued unsent tail.
        const auto stopped=client->open_stream(stream_direction::bidirectional); check(stopped.has_value());
        const std::array<std::byte,2000> tail{};
        check(client->stream(*stopped)->send.append(tail).has_value());
        check(send(*client,*server,outgoing,incoming,tls_level::application));
        const auto final=client->stream(*stopped)->sent_highest;
        check(final>0 && final<tail.size());
        decoded_frame stop; stop.type=5; stop.stream_id=*stopped; stop.error_code=42;
        check(incoming.queue_control(tls_level::application,stop).has_value());
        check(send(*server,*client,incoming,outgoing,tls_level::application));
        check(client->stream(*stopped)->state.sending()==stream_send_state::reset_sent);
        check(client->stream(*stopped)->state.send_final_size()==final);
        check(client->stream(*stopped)->state.stop_error()==42);
        check(send(*client,*server,outgoing,incoming,tls_level::application));
        check(server->stream(*stopped)->state.receive_final_size()==final);
        check(server->stream(*stopped)->state.receiving()==stream_receive_state::reset_received);
        check(server->consume_reset(*stopped).has_value());
        check(server->flow().consumed_total()==3075+final);
        outgoing.lose_control(tls_level::application,outgoing.packet_number());
        check(send(*client,*server,outgoing,incoming,tls_level::application));
        check(send(*server,*client,incoming,outgoing,tls_level::application));
        check(client->stream(*stopped)->state.sending()==stream_send_state::reset_received);
        // Old STREAM losses cannot resurrect data on a reset stream.
        if (send(*client,*server,outgoing,incoming,tls_level::application)) {
            std::size_t cursor=0;
            while(cursor<last_plaintext_size) {
                const auto frame=decode_frame(std::as_bytes(std::span(buffer.plaintext).first(last_plaintext_size)).subspan(cursor));
                check(frame.has_value());
                check(frame->type<8 || frame->type>15 || frame->stream_id!=*stopped);
                cursor+=frame->encoded_size;
            }
        }
        // Filling the range reservation ends selection at exactly eight
        // streams, including FIN-only frames that consume no byte credit.
        // PTO retransmissions still precede the ninth stream's pending FIN.
        std::array<std::uint64_t,bounded_connection::frames_per_packet+1> fin_streams {};
        for (auto& stream_id : fin_streams) {
            const auto opened=client->open_stream(stream_direction::bidirectional);
            check(opened.has_value()); stream_id=*opened;
            check(client->stream(stream_id)->send.close().has_value());
        }
        const auto fin_credit=client->flow().sent_total();
        check(send(*client,*server,outgoing,incoming,tls_level::application,true));
        check(client->flow().sent_total()==fin_credit);
        for (const auto stream_id : fin_streams)
            check(client->stream(stream_id)->send.next_pending(0).fin);
        auto check_fin_packet=[&] {
            std::size_t cursor=0, stream_count=0;
            while (cursor<last_plaintext_size) {
                const auto frame=decode_frame(std::as_bytes(std::span(buffer.plaintext)
                    .first(last_plaintext_size)).subspan(cursor));
                check(frame.has_value()); cursor+=frame->encoded_size;
                if (frame->type<8 || frame->type>15) continue;
                check(stream_count<bounded_connection::frames_per_packet);
                check(frame->stream_id==fin_streams[stream_count++]);
                check(frame->fin && frame->offset==0 && frame->data.empty());
            }
            check(stream_count==bounded_connection::frames_per_packet);
        };
        check(send(*client,*server,outgoing,incoming,tls_level::application));
        check_fin_packet();
        check(server->stream(fin_streams.back())==nullptr);
        check(send(*client,*server,outgoing,incoming,tls_level::application,false,true));
        check_fin_packet();
        check(server->stream(fin_streams.back())==nullptr);
        check(client->flow().sent_total()==fin_credit);
        check(send(*server,*client,incoming,outgoing,tls_level::application));
        check(send(*client,*server,outgoing,incoming,tls_level::application));
        const auto* last_fin=server->stream(fin_streams.back());
        check(last_fin && last_fin->receive && last_fin->receive->final_size()==0);
        check(client->flow().sent_total()==fin_credit);
        check(send(*server,*client,incoming,outgoing,tls_level::application));
        for (const auto stream_id : fin_streams) check(client->stream(stream_id)->send.complete());
        // A candidate rejected by the packet-local flow table must leave its
        // encoded bytes uncommitted and preserve credit for later streams.
        // Deliberately make the send ring offer bytes past its stream credit.
        const auto rejected=client->open_stream(stream_direction::bidirectional);
        check(rejected.has_value());
        auto* rejected_stream=client->stream(*rejected);
        check(rejected_stream->send.extend_flow_limit(2048).has_value());
        check(rejected_stream->send.append(block).has_value());
        check(rejected_stream->send.mark_sent(0,block.size()).has_value());
        check(rejected_stream->send.append(std::span(block).first(1)).has_value());
        std::array<std::uint64_t,2> selected {};
        const std::array<std::byte,400> selected_bytes {};
        for (auto& stream_id : selected) {
            const auto opened=client->open_stream(stream_direction::bidirectional);
            check(opened.has_value()); stream_id=*opened;
            check(client->stream(stream_id)->send.append(selected_bytes).has_value());
            check(client->stream(stream_id)->send.close().has_value());
        }
        const auto credit_before=client->flow().sent_total();
        check(send(*client,*server,outgoing,incoming,tls_level::application,true));
        check(client->flow().sent_total()==credit_before);
        for (const auto stream_id : selected)
            check(client->stream(stream_id)->send.next_pending(1000).data.size()==selected_bytes.size());
        check(send(*client,*server,outgoing,incoming,tls_level::application));
        check(client->flow().sent_total()==credit_before+selected.size()*selected_bytes.size());
        check(server->stream(*rejected)==nullptr);
        check(rejected_stream->send.next_pending(1000).offset==block.size());
        for (const auto stream_id : selected) {
            const auto* received=server->stream(stream_id);
            check(received && received->receive && received->receive->final_size()==selected_bytes.size());
            check(std::ranges::equal(received->receive->readable(),selected_bytes));
        }
        check(send(*server,*client,incoming,outgoing,tls_level::application));
        for (const auto stream_id : selected) check(client->stream(stream_id)->send.complete());
        // A packet that preflight refuses (full window or sent history) must
        // not consume its packet number: each gap permanently uses one
        // sent-range slot, so repeated refusals would exhaust them and stall.
        auto* history=client->recovery().history(packet_number_space::application_data);
        while (history->size()<bounded_connection::packet_capacity)
            check(send(*client,*server,outgoing,incoming,tls_level::application,false,true));
        const auto fin_only=client->open_stream(stream_direction::bidirectional);
        check(fin_only.has_value() && client->stream(*fin_only)->send.close().has_value());
        const auto blocked_number=client->core().next_packet_number(tls_level::application);
        protected_packet_fields blocked_fields; blocked_fields.destination_cid=dcid;
        for (int i=0;i<200;++i) {
            const auto blocked=outgoing.prepare(tls_level::application,blocked_fields,now,
                buffer.encoded,buffer.build_scratch);
            check(!blocked && blocked.error()==connection_error::capacity_exceeded);
        }
        check(client->core().next_packet_number(tls_level::application)==blocked_number);
        check(send(*server,*client,incoming,outgoing,tls_level::application));
        check(send(*client,*server,outgoing,incoming,tls_level::application));
        check(outgoing.packet_number()==*blocked_number);
        check(server->stream(*fin_only)!=nullptr);
    }
}
