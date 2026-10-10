#include "quic/connection_driver.h"
#include "eventloop/task_composition.h"
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <vector>
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
static bool on_frame(void* argument, tls_level, const decoded_frame&) noexcept
{ ++*static_cast<int*>(argument); return true; }
struct buffers {
    std::array<std::uint8_t, 2048> encoded {}, frame {}, build_scratch {},
        packet_scratch {}, plaintext {}, auth_scratch {};
};

using namespace eventloop;
using namespace std::chrono_literals;
static auto receiver(event_loop&,udp_endpoint& endpoint) -> task<void>
{ (void)co_await endpoint.run(); }
static auto drive(event_loop&,connection_driver& driver,bool& clean) -> task<void>
{ const auto result=co_await driver.run(); clean=result && result->has_value(); if (!clean) std::fprintf(stderr,"driver failure %d\n", result ? static_cast<int>(result->error()) : -1); }
struct send_progress {
    bounded_connection& connection;
    std::optional<std::uint64_t> id;
    std::uint64_t previous {}, largest_step {};
    static auto observe(void* argument) noexcept -> void
    {
        auto& self=*static_cast<send_progress*>(argument);
        if (!self.id) return;
        const auto highest=self.connection.stream(*self.id)->sent_highest;
        self.largest_step=std::max(self.largest_step,highest-self.previous);
        self.previous=highest;
    }
};
static auto wait_for_notification(event_loop& loop,connection_driver& driver,
    bool& finished,bool& completed) -> task<void>
{
    // A distant deadline makes this a signal/cancellation test rather than a
    // latency threshold test: the ordinary timeout cannot finish this wait.
    completed=co_await connection_driver::idle_wait(driver,eventloop::detail::deadline_after(1h));
    finished=true;
}
static auto notify_waiter(event_loop& loop,connection_driver& driver,
    bool& finished,bool& completed,task_handle<void>& cancelled,
    bool& cancel_finished,bool& cancel_completed) -> task<void>
{
    (void)co_await yield(loop);
    check(!finished);
    driver.notify();
    driver.notify(); // Repeated signals must not register the same timer twice.
    check(!finished); // Never resume the pump inside router/application calls.
    (void)co_await sleep_for(loop,10ms);
    check(finished && completed);
    check(loop.spawn(wait_for_notification(loop,driver,cancel_finished,cancel_completed),cancelled)==task_spawn_result::accepted);
    (void)co_await yield(loop);
    check(!cancel_finished);
    check(cancelled.cancel());
    check(cancel_finished && !cancel_completed);
    driver.notify(); // The cancelled frame no longer owns the driver's wait.
    loop.shutdown(event_loop::clock::duration::zero());
}
static auto notification_scenario() -> void
{
    event_loop loop;
    // Endpoints hold large datagram buffers; keep them off the 1 MiB Windows stack.
    auto owned_endpoint=std::make_unique<udp_endpoint>(loop,ip_endpoint::loopback_v4(),path_endpoint_role::client);
    auto& endpoint=*owned_endpoint;
    auto connection=std::make_unique<bounded_connection>(endpoint_role::client,connection_callbacks{});
    connection_driver driver(loop,endpoint,*connection,dcid,dcid,ip_endpoint::loopback_v4(12345),true);
    bool finished=false,completed=false,cancel_finished=false,cancel_completed=true;
    task_handle<void> cancelled;
    check(loop.spawn(wait_for_notification(loop,driver,finished,completed))==task_spawn_result::accepted);
    check(loop.spawn(notify_waiter(loop,driver,finished,completed,cancelled,cancel_finished,cancel_completed))==task_spawn_result::accepted);
    (void)loop.run();
    check(finished && completed && cancel_finished && !cancel_completed);
    check(cancelled.done());
    (void)cancelled.take_result();
    check(loop.coroutine_statistics().live==0);
}

static auto receive_packet(event_loop&,udp_socket& peer,std::span<std::byte> buffer)
    -> task<std::expected<udp_datagram,std::error_code>>
{ co_return co_await peer.async_receive_from(buffer); }

// The raw peer intentionally ignores the first close and sends another packet.
// It must receive the cached close while the driver retains its route (10.2).
static auto lost_close(event_loop& loop,connection_driver& driver,bounded_connection& server,
    bounded_connection& client,udp_endpoint& endpoint,udp_socket& peer,buffers& storage,bool& done)
    -> task<void>
{
    driver.stop_with_application_error(0x123);
    auto input=std::as_writable_bytes(std::span(storage.plaintext));
    auto first=co_await peer.async_receive_from(input);
    check(first && first->size>=1200);
    const std::vector<std::byte> cached(input.begin(),input.begin()+static_cast<std::ptrdiff_t>(first->size));
    check(driver.run_active() && !driver.retired());
    const auto pto=server.application_pto().value_or(1s);
    const auto deadline=server.core().next_deadline(pto);
    check(deadline && *deadline>lifecycle_time_point::clock::now());
    // Initial packets must be padded to at least 1200 bytes even in closing.
    std::fill(storage.frame.begin(),storage.frame.end(),0);
    storage.frame[0]=1; // PING.
    protected_packet_fields fields;
    fields.kind=packet_kind::initial;
    fields.destination_cid=dcid; fields.source_cid=dcid;
    const auto size=client.core().build(fields,std::span(storage.frame).first(1200),
                                      storage.encoded,storage.build_scratch);
    check(size.has_value());
    check((co_await peer.async_send_to(std::as_bytes(std::span(storage.encoded).first(*size)),
                                      endpoint.local_endpoint())).has_value());
    auto second=co_await peer.async_receive_from(input);
    check(second && std::ranges::equal(input.first(second->size),cached));
    check(server.core().next_deadline(pto)==deadline);
    // A full-sized retry earns credit, but cannot trigger a second immediate
    // response. It is answered at the next PTO without extending retention.
    check((co_await peer.async_send_to(std::as_bytes(std::span(storage.encoded).first(*size)),
                                      endpoint.local_endpoint())).has_value());
    auto throttled=co_await with_timeout(loop,receive_packet(loop,peer,input),10ms);
    check((throttled && throttled->state==timeout_result<
        std::expected<udp_datagram,std::error_code>>::outcome::timed_out));
    auto third=co_await peer.async_receive_from(input);
    check(third && std::ranges::equal(input.first(third->size),cached));
    check(server.core().next_deadline(pto)==deadline);
    // Even a validated address cannot amplify unauthenticated closing traffic.
    std::array<std::byte,32> tiny {};
    tiny[0]=std::byte{0x40};
    std::memcpy(tiny.data()+1,dcid.data(),dcid.size());
    check((co_await peer.async_send_to(tiny,endpoint.local_endpoint())).has_value());
    auto withheld=co_await with_timeout(loop,receive_packet(loop,peer,input),10ms);
    check((withheld && withheld->state==timeout_result<
        std::expected<udp_datagram,std::error_code>>::outcome::timed_out));
    while (!driver.retired()) check(co_await sleep_for(loop,1ms)==timer_wait_result::expired);
    check(server.core().state()==connection_state::closed);
    check(lifecycle_time_point::clock::now()>=*deadline);
    done=true;
    loop.shutdown(event_loop::clock::duration::zero());
}

static auto lost_close_scenario(contexts& context,std::uint32_t version) -> void
{
    event_loop loop;
    auto owned=std::make_unique<udp_socket>(loop,ip_endpoint::loopback_v4());
    auto* peer=owned.get();
    const auto address=peer->local_endpoint();
    loop.add(std::move(owned));
    auto owned_endpoint=std::make_unique<udp_endpoint>(loop,ip_endpoint::loopback_v4(),path_endpoint_role::server);
    auto& endpoint=*owned_endpoint;
    connection_callbacks callbacks{nullptr,valid_parameters,nullptr};
    auto server=std::make_unique<bounded_connection>(endpoint_role::server,callbacks,lifecycle_time_point::clock::now());
    auto client=std::make_unique<bounded_connection>(endpoint_role::client,callbacks,lifecycle_time_point::clock::now());
    check(server->initialize(context.server.get(),{true,{},protocol,parameters},version,dcid).has_value());
    check(client->initialize(context.client.get(),{false,"localhost",protocol,parameters},version,dcid).has_value());
    auto driver=std::make_unique<connection_driver>(loop,endpoint,*server,dcid,dcid,address,true);
    auto storage=std::make_unique<buffers>();
    bool done=false,clean=false;
    check(loop.spawn(receiver(loop,endpoint))==task_spawn_result::accepted);
    check(loop.spawn(drive(loop,*driver,clean))==task_spawn_result::accepted);
    check(loop.spawn(lost_close(loop,*driver,*server,*client,endpoint,*peer,*storage,done))==task_spawn_result::accepted);
    (void)loop.run();
    check(done && clean && loop.coroutine_statistics().live==0);
}
static auto queue_peer_close(bounded_connection& server,udp_endpoint& client_endpoint,
    ip_endpoint server_peer,bool trailing_ping=true) -> void
{
    // Queue a close and another authenticated packet before the client
    // pump runs. The second packet must not turn peer closure into an
    // invalid-state driver failure or cause another transmission.
    buffers buffer;
    protected_packet_fields fields; fields.kind=packet_kind::short_header;
    fields.destination_cid=dcid;
    for (const auto type : {0x1cU,0x01U}) {
        if (type==0x01U && !trailing_ping) break;
        decoded_frame frame; frame.type=type;
        const auto encoded=encode_frame(frame,std::as_writable_bytes(std::span(buffer.frame)));
        check(encoded.has_value());
        const auto built=server.core().build(fields,std::span(buffer.frame).first(*encoded),
            buffer.encoded,buffer.build_scratch);
        check(built.has_value());
        const auto dispatched=client_endpoint.router().dispatch(
            std::as_bytes(std::span(buffer.encoded).first(*built)),
            server_peer);
        check(dispatched && *dispatched==1);
    }
}
static auto receive_summary_scenario(event_loop& loop,bounded_connection& client,
    bounded_connection& server,udp_endpoint& client_endpoint,ip_endpoint server_peer) -> task<void>
{
    // Use established connections and actual encrypted packets. Recording each
    // injected transmission keeps the driver's eventual ACKs valid for recovery.
    auto storage=std::make_unique<buffers>();
    auto& buffer=*storage;
    protected_packet_fields fields; fields.kind=packet_kind::short_header;
    fields.destination_cid=dcid;
    std::size_t packet_size=0;
    auto queue=[&] {
        const auto dispatched=client_endpoint.router().dispatch(
            std::as_bytes(std::span(buffer.encoded).first(packet_size)),server_peer);
        check(dispatched && *dispatched==1);
    };
    auto inject=[&](std::size_t payload_size,bool eliciting) {
        const auto number=*server.core().next_packet_number(tls_level::application);
        const auto built=server.core().build(fields,std::span(buffer.frame).first(payload_size),
            buffer.encoded,buffer.build_scratch);
        check(built.has_value()); packet_size=*built;
        check(server.record_sent(tls_level::application,
            {number,lifecycle_time_point::clock::now(),eliciting,eliciting,*built},{}).has_value());
        queue(); return number;
    };
    std::array<std::byte,256> ack_storage {};
    // Let the transfer's existing ACKs settle before observing packet numbers.
    check(co_await sleep_for(loop,10ms)==timer_wait_result::expired);
    const auto ack=server.core().make_ack(tls_level::application,0,ack_storage);
    check(ack.has_value());
    buffer.frame[0]=0; // Leading PADDING must not make an ACK packet eliciting.
    const auto encoded=encode_frame(*ack,std::as_writable_bytes(std::span(buffer.frame).subspan(1)));
    check(encoded.has_value());
    const auto before_ack=client.core().next_packet_number(tls_level::application);
    const auto ack_number=inject(1+*encoded,false);
    bool ack_received=false;
    for (int attempt=0;attempt<1000 && !ack_received;++attempt) {
        const auto received=client.core().make_ack(tls_level::application,0,ack_storage);
        ack_received=received && received->largest_acknowledged>=ack_number;
        if (!ack_received) check(co_await sleep_for(loop,1ms)==timer_wait_result::expired);
    }
    check(ack_received && client.core().next_packet_number(tls_level::application)==before_ack);
    queue(); // A duplicate ACK-only packet also needs no response.
    check(co_await sleep_for(loop,5ms)==timer_wait_result::expired);
    check(client.core().next_packet_number(tls_level::application)==before_ack);
    buffer.frame[0]=1;
    const auto before_ping=*client.core().next_packet_number(tls_level::application);
    (void)inject(1,true);
    for (int attempt=0;attempt<1000 &&
        *client.core().next_packet_number(tls_level::application)==before_ping;++attempt)
        check(co_await sleep_for(loop,1ms)==timer_wait_result::expired);
    check(*client.core().next_packet_number(tls_level::application)>before_ping);
    const auto before_duplicate=*client.core().next_packet_number(tls_level::application);
    queue(); // The core suppresses redispatch, but the driver still sends an ACK.
    for (int attempt=0;attempt<1000 &&
        *client.core().next_packet_number(tls_level::application)==before_duplicate;++attempt)
        check(co_await sleep_for(loop,1ms)==timer_wait_result::expired);
    check(*client.core().next_packet_number(tls_level::application)>before_duplicate);
    // Two challenges and their duplicate occupy all four response jobs. Both
    // new and duplicate packets must receive path responses followed by an ACK.
    const path_challenge first {std::byte{1}},second {std::byte{2}};
    check(server.paths().add(100).has_value());
    check(server.paths().add(101).has_value());
    check(server.paths().issue_challenge(100,first).has_value());
    check(server.paths().issue_challenge(101,second).has_value());
    decoded_frame challenge; challenge.type=0x1a; challenge.data=first;
    const auto first_size=encode_frame(challenge,std::as_writable_bytes(std::span(buffer.frame)));
    check(first_size.has_value()); challenge.data=second;
    const auto second_size=encode_frame(challenge,
        std::as_writable_bytes(std::span(buffer.frame).subspan(*first_size)));
    check(second_size.has_value());
    const auto before_paths=*client.core().next_packet_number(tls_level::application);
    const auto& path_history=*client.recovery().history(packet_number_space::application_data);
    (void)inject(*first_size+*second_size,true);
    queue();
    // Wait for all four responses and their ACK to commit; a built packet's
    // number alone does not establish that its asynchronous send has retired.
    for (int attempt=0;attempt<1000 &&
        (!*server.paths().is_validated(100) || !*server.paths().is_validated(101) ||
         !path_history.highest_sent() || *path_history.highest_sent()<before_paths+4);++attempt)
        check(co_await sleep_for(loop,1ms)==timer_wait_result::expired);
    check(*server.paths().is_validated(100) && *server.paths().is_validated(101));
    check(path_history.highest_sent() && *path_history.highest_sent()>=before_paths+4);
}
static auto observe(event_loop& loop,bounded_connection& client,bounded_connection& server,
    connection_driver& client_driver,connection_driver& server_driver,
    udp_endpoint& client_endpoint,ip_endpoint server_peer,bool& delivered,
    send_progress& progress) -> task<void>
{
    auto& id=progress.id;
    static constexpr auto data=[] {
        std::array<std::byte,bounded_connection::stream_bytes> bytes {};
        for (std::size_t i=0;i<bytes.size();++i) bytes[i]=static_cast<std::byte>(i%251);
        return bytes;
    }();
    for (int i=0;i<4000;++i) {
        if (!id && client.core().state()==connection_state::active && server.core().state()==connection_state::active) {
            id=client.open_stream(stream_direction::bidirectional).value();
            check(client.stream(*id)->send.append(data).has_value());
            check(client.stream(*id)->send.close().has_value());
        }
        if (id && client.stream(*id)->send.complete()) {
            const auto* stream=server.stream(*id);
            delivered=stream && stream->receive && std::ranges::equal(stream->receive->readable(),data);
            break;
        }
        if (co_await sleep_for(loop,1ms)!=timer_wait_result::expired) co_return;
    }
    if (delivered) {
        const auto tested=co_await receive_summary_scenario(loop,client,server,client_endpoint,server_peer);
        check(tested==task_result::success);
        queue_peer_close(server,client_endpoint,server_peer);
    }
    else client_driver.stop();
    server_driver.stop();
    // Draining retains the route through its deadline and sends no data.
    (void)co_await sleep_for(loop,10ms);
    if (delivered) {
        check(!client_driver.retired());
        check(client.core().state()==connection_state::draining);
        const auto before=client.core().next_packet_number(tls_level::application);
        queue_peer_close(server,client_endpoint,server_peer,false);
        check(co_await sleep_for(loop,5ms)==timer_wait_result::expired);
        check(client.core().next_packet_number(tls_level::application)==before);
    }
    for (int attempt=0;attempt<4000 && (!client_driver.retired() || !server_driver.retired());++attempt)
        (void)co_await sleep_for(loop,1ms);
    check(client_driver.retired() && server_driver.retired());
    loop.shutdown(event_loop::clock::duration::zero());
}
int main()
{
#ifdef _WIN32
    WSADATA data{}; check(WSAStartup(MAKEWORD(2,2),&data)==0);
#endif
    contexts context;
    notification_scenario();
    for (auto version : {version_1,version_2}) lost_close_scenario(context,version);
    for (auto version : {version_1,version_2}) {
        event_loop loop;
        auto owned_client=std::make_unique<udp_endpoint>(loop,ip_endpoint::loopback_v4(),path_endpoint_role::client);
        auto owned_server=std::make_unique<udp_endpoint>(loop,ip_endpoint::loopback_v4(),path_endpoint_role::server);
        auto& client_endpoint=*owned_client;
        auto& server_endpoint=*owned_server;
        connection_callbacks callbacks{nullptr,valid_parameters,nullptr};
        const auto now=lifecycle_time_point::clock::now();
        auto client=std::make_unique<bounded_connection>(endpoint_role::client,callbacks,now);
        auto server=std::make_unique<bounded_connection>(endpoint_role::server,callbacks,now);
        check(client->initialize(context.client.get(),{false,"localhost",protocol,parameters},version,dcid).has_value());
        check(server->initialize(context.server.get(),{true,{},protocol,parameters},version,dcid).has_value());
        auto client_driver=std::make_unique<connection_driver>(loop,client_endpoint,*client,dcid,dcid,server_endpoint.local_endpoint(),true);
        auto server_driver=std::make_unique<connection_driver>(loop,server_endpoint,*server,dcid,dcid,client_endpoint.local_endpoint());
        send_progress progress {*client};
        client_driver->set_progress(&progress,send_progress::observe);
        bool delivered=false,client_clean=false,server_clean=false;
        check(loop.spawn(receiver(loop,client_endpoint))==task_spawn_result::accepted);
        check(loop.spawn(receiver(loop,server_endpoint))==task_spawn_result::accepted);
        check(loop.spawn(drive(loop,*client_driver,client_clean))==task_spawn_result::accepted);
        check(loop.spawn(drive(loop,*server_driver,server_clean))==task_spawn_result::accepted);
        check(loop.spawn(observe(loop,*client,*server,*client_driver,*server_driver,client_endpoint,server_endpoint.local_endpoint(),delivered,progress))==task_spawn_result::accepted);
        (void)loop.run();
        if (!delivered) std::fprintf(stderr,"delivery failure state %d/%d dropped %zu/%zu\n",static_cast<int>(client->core().state()),static_cast<int>(server->core().state()),client_driver->dropped_packets(),server_driver->dropped_packets()); check(delivered && client_clean && server_clean);
        check(loop.coroutine_statistics().live==0);
        // Queued data with available congestion/flow credit must make more
        // than one packet of progress before the pump retries on a timer.
        // This checks scheduling behavior without a wall-clock threshold.
        check(progress.largest_step>packet_scheduler::maximum_packet);
    }
#ifdef _WIN32
    (void)WSACleanup();
#endif
    std::puts("QUIC UDP TLS driver passed");
}
