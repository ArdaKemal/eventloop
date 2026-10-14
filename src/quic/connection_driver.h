#pragma once
#include "quic/packet_scheduler.h"
#include "quic/udp_endpoint.h"
#include <cstring>
#include <openssl/rand.h>
#include <openssl/rand.h>

namespace eventloop::quic::detail {

// Internal single-connection pump. Caller owns endpoint, initialized connection
// and driver until run() retires. Endpoint run() is started separately. Fixed
// CIDs/peer address are supplied after authenticated parameter validation.
// A bounded receive queue serializes ACK processing with pending UDP sends.
class connection_driver {
public:
    static constexpr std::size_t queue_capacity = 16;
    static_assert(queue_capacity >= 2 * udp_endpoint::receive_burst);
    static constexpr std::size_t packet_capacity = bounded_connection::datagram_buffer_size;
    static constexpr std::array<std::uint8_t,12> v4_mapped_prefix{0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    connection_driver(event_loop& loop, udp_endpoint& endpoint, bounded_connection& connection,
        std::span<const std::uint8_t> local_cid, std::span<const std::uint8_t> peer_cid,
        ip_endpoint peer, bool validated = false)
        : loop_(loop), endpoint_(endpoint), connection_(connection), scheduler_(connection)
    {
        if (local_cid.empty() || local_cid.size() > 20 || peer_cid.size() > 20)
            throw std::invalid_argument("QUIC driver CID");
        std::copy(local_cid.begin(), local_cid.end(), local_.begin()); local_size_=local_cid.size();
        std::copy(peer_cid.begin(), peer_cid.end(), peer_.begin()); peer_size_=peer_cid.size();
        const auto route=endpoint_.router().add(std::as_bytes(local_cid),peer,
            {this,enqueue,authenticate_changed_peer,stateless_reset},validated);
        if (!route) throw std::runtime_error("QUIC driver route capacity");
        route_=*route;
        // Start from a 1500-byte MTU and probe upward only when datagrams
        // cannot be fragmented; IPv6 headers are 20 bytes longer.
        mtu_search_=dont_fragment_=endpoint_.dont_fragment();
        const bool v6=peer.address_family==ip_endpoint::family::ipv6 &&
            !std::equal(peer.address.begin(),peer.address.begin()+12,v4_mapped_prefix.begin());
        connection_.set_datagram_base(mtu_search_ && v6 ? 1452 : 1472);
    }
    ~connection_driver()
    {
        check_owner();
        if (running_ || idle_) std::terminate();
        if (!endpoint_.router().remove(route_)) std::terminate();
    }
    connection_driver(const connection_driver&)=delete;
    auto operator=(const connection_driver&)-> connection_driver& = delete;
    // Endpoint shutdown may end retention early because it closes the socket
    // (RFC 9000 10.2). Otherwise retain the route through three current PTOs.
    auto stop(bool retain = true) noexcept -> void
    { check_owner(); if (!retain) retain_close_=false; if (!close_frame_) close_frame_={0x1c,0x00}; stopped_=true; notify(); }
    // As stop(), with an application CONNECTION_CLOSE (RFC 9000 19.19). Before
    // 1-RTT keys exist it is sent as APPLICATION_ERROR in a transport close
    // (10.2.3). The first close requested wins.
    auto stop_with_application_error(std::uint64_t error) noexcept -> void
    { check_owner(); if (!close_frame_) close_frame_={0x1d,error}; stop(); }
    // True while the route is held through the closing or draining period.
    [[nodiscard]] auto retaining() const noexcept -> bool { return retaining_ && retain_close_; }
    // Releases the route early for new connections (RFC 9000 10.2 permits
    // dropping this state; a late packet then draws a stateless reset).
    auto end_retention() noexcept -> void
    { check_owner(); retain_close_=false; notify(); }
    // New packets or application send/receive credit can interrupt an idle
    // retry. Resumption remains a timer-loop action, outside router dispatch.
    auto notify() noexcept -> void
    { check_owner(); work_pending_=true; if (idle_) idle_->wake(); }
    // Progress notifications run on the owning loop after receive, send, or
    // recovery state changes; the endpoint resumes public-API waiters.
    auto set_progress(void* argument, void (*callback)(void*) noexcept) noexcept
    { check_owner(); progress_argument_=argument; progress_=callback; }
    // The hook runs from the pump, outside router dispatch, in receive order.
    // Returning true asks the owner to restart after run() has retired.
    auto set_retry_handler(void* argument,
        bool (*callback)(void*, std::span<const std::uint8_t>) noexcept) noexcept -> void
    { check_owner(); retry_argument_=argument; retry_=callback; }
    auto set_initial_token(std::span<const std::uint8_t> token) noexcept -> void
    { check_owner(); initial_token_=token; }
    [[nodiscard]] auto retired() const noexcept -> bool { return started_ && !running_; }
    [[nodiscard]] auto run_active() const noexcept -> bool { return running_; }
    [[nodiscard]] auto failure() const noexcept -> std::optional<connection_error> { return failure_; }
    [[nodiscard]] auto initiate_key_update() -> std::expected<void, key_update_error>
    {
        check_owner();
        if (scheduler_.pending()) return std::unexpected(key_update_error::invalid_input);
        const auto pto = connection_.application_pto();
        if (!pto) return std::unexpected(key_update_error::handshake_not_confirmed);
        const auto result=connection_.core().initiate_key_update(lifecycle_time_point::clock::now(), *pto);
        notify();
        return result;
    }
    [[nodiscard]] auto run() -> task<std::expected<void,connection_error>> { return pump(loop_,*this); }
    [[nodiscard]] auto dropped_packets() const noexcept -> std::size_t { return dropped_; }
    // Internal frame-local wait until a deadline (1 ms by default); notify()
    // advances it without inline resume.
    class idle_wait {
    public:
        explicit idle_wait(connection_driver& driver,
            event_loop::clock::time_point deadline=eventloop::detail::deadline_after(std::chrono::milliseconds(1))) noexcept
            : driver_(driver)
        {
            timer_.deadline=deadline;
            timer_.cancellation.operation=this;
            timer_.cancellation.cancel=&cancel;
        }
        idle_wait(const idle_wait&)=delete;
        auto operator=(const idle_wait&) -> idle_wait& = delete;
        [[nodiscard]] static auto await_ready() noexcept -> bool { return false; }
        template<typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> handle) -> bool
        {
            if (handle.promise().owner_loop()!=&driver_.loop_) std::terminate();
            auto& cancellation=*handle.promise().cancellation_state();
            if (cancellation.requested) { cancelled_=true; return false; }
            if (driver_.work_pending_) { driver_.work_pending_=false; return false; }
            timer_.handle=handle;
            timer_.owner=&driver_.loop_;
            if (!eventloop::detail::coroutine_frame_access::attach_cancellation(cancellation,timer_.cancellation)) {
                timer_.owner=nullptr; cancelled_=true; return false;
            }
            try { eventloop::detail::coroutine_frame_access::register_timer(driver_.loop_,timer_); }
            catch (...) {
                eventloop::detail::coroutine_frame_access::detach_cancellation(timer_.cancellation);
                timer_.owner=nullptr; throw;
            }
            if (driver_.idle_) std::terminate();
            driver_.idle_=this;
            return true;
        }
        [[nodiscard]] auto await_resume() noexcept -> bool
        { driver_.idle_=nullptr; driver_.work_pending_=false; return !cancelled_; }
        // Resume from the loop's FIFO wakeup queue: the endpoint's receive
        // loop queues itself there between bursts, behind woken drivers.
        auto wake() noexcept -> void
        {
            if (signalled_) return;
            signalled_=true;
            eventloop::detail::coroutine_frame_access::cancel_timer(timer_);
            node_.handle=timer_.handle;
            eventloop::detail::coroutine_frame_access::schedule_wakeup(driver_.loop_,node_);
        }
    private:
        static auto cancel(eventloop::detail::coroutine_cancellation_node& node) noexcept -> void
        {
            auto& self=*static_cast<idle_wait*>(node.operation);
            eventloop::detail::coroutine_frame_access::cancel_timer(self.timer_);
            self.cancelled_=true;
            self.timer_.handle.resume();
        }
        connection_driver& driver_;
        eventloop::detail::coroutine_timer_node timer_;
        eventloop::detail::wakeup_node node_;
        bool cancelled_ {},signalled_ {};
    };
private:
    struct queued_packet { std::array<std::uint8_t,packet_capacity> bytes{}; std::size_t size{}; ip_endpoint peer {}; };
    struct path_response_job { path_challenge token {}; ip_endpoint peer {}; bool occupied {}; };
    static auto stateless_reset(void* argument) noexcept -> void
    {
        auto& self=*static_cast<connection_driver*>(argument);
        self.reset_detected_=true; self.notify();
    }
    // A verified stateless reset drains without sending (RFC 9000 10.3.1).
    auto drain_after_reset(lifecycle_time_point now) noexcept -> bool
    {
        reset_detected_=false;
        if (!connection_.core().stateless_reset(now,
                connection_.application_pto().value_or(std::chrono::seconds(1)))) return false;
        stopped_=true;
        return true;
    }
    // A short-header packet the connection cannot decrypt ends its datagram,
    // so its tail is where a stateless reset carries the token.
    [[nodiscard]] auto matches_reset_token(std::span<const std::byte> packet) const noexcept -> bool
    {
        const auto* selected=connection_.peer_ids().selected();
        if (!selected || !selected->has_reset_token) return false;
        const auto matched=detect_stateless_reset(packet,std::span(&selected->reset_token,1));
        return matched && *matched;
    }
    static auto authenticate_changed_peer(void* argument, std::span<const std::byte> datagram,
        const packet_header& header, ip_endpoint) noexcept -> bool
    {
        auto& self=*static_cast<connection_driver*>(argument);
        if (self.stopped_ || header.kind!=packet_kind::short_header) return false;
        const auto bytes=std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(datagram.data()),datagram.size());
        return self.connection_.core().authenticate_application_packet(bytes,header.packet_offset,
            self.local_size_,self.packet_scratch_,self.plaintext_,self.auth_scratch_).has_value();
    }
    static auto enqueue(void* argument,std::span<const std::byte>,const packet_header& header,ip_endpoint peer) noexcept -> bool
    {
        auto& self=*static_cast<connection_driver*>(argument);
        if (self.stopped_) {
            // Closing does not decrypt/dispatch new frames. Credit limits
            // cached responses even when the routed peer address is validated.
            if (self.connection_.core().state()==connection_state::closing && self.close_size_) {
                const bool ready=self.close_credit_>=self.close_size_;
                self.close_credit_=std::min(self.close_size_,self.close_credit_+
                    3*std::min(self.close_size_,header.packet.size()));
                if (!ready && self.close_credit_>=self.close_size_) self.notify();
            }
            ++self.dropped_; return true;
        }
        if (self.count_==queue_capacity || header.packet.size()>packet_capacity) {
            ++self.dropped_; return true;
        }
        auto& slot=self.queue_[(self.head_+self.count_)%queue_capacity];
        slot.size=header.packet.size();
        slot.peer=peer;
        std::memcpy(slot.bytes.data(),header.packet.data(),slot.size); ++self.count_;
        self.notify(); return true;
    }
    auto check_owner() const noexcept -> void
    { if (owner_!=std::this_thread::get_id()) std::terminate(); }
#if defined(_MSC_VER)
    __declspec(noinline)
#else
    __attribute__((noinline))
#endif
    auto tick(lifecycle_time_point now) -> std::expected<void,connection_error>
    {
            if (reset_detected_ && drain_after_reset(now)) return {};
            while (count_) {
                const auto& packet=queue_[head_];
                const auto source=packet.peer;
                const auto header=parse_packet_header(
                    std::as_bytes(std::span(packet.bytes).first(packet.size)),0,local_size_,true);
                if (header && header->kind==packet_kind::retry) {
                    head_=(head_+1)%queue_capacity; --count_;
                    if (!authenticated_packet_seen_ && retry_ &&
                        retry_(retry_argument_,std::span(packet.bytes).first(packet.size))) {
                        stopped_=true;
                        return {};
                    }
                    continue;
                }
                const auto received=connection_.receive(std::span(packet.bytes).first(packet.size),0,
                    local_size_,packet_scratch_,plaintext_,auth_scratch_,
                    now,connection_.application_pto().value_or(std::chrono::seconds(1)));
                head_=(head_+1)%queue_capacity; --count_;
                if (!received) {
                    if (received.error()==connection_error::authentication_failed &&
                        header && header->kind==packet_kind::short_header &&
                        matches_reset_token(std::as_bytes(std::span(packet.bytes).first(packet.size))) &&
                        drain_after_reset(now)) return {};
                    if (received.error()==connection_error::authentication_failed ||
                        received.error()==connection_error::unavailable_keys ||
                        received.error()==connection_error::malformed_packet) continue;
                    return std::unexpected(received.error());
                }
                // A peer close enters draining during receive(). Stop data
                // processing now; pump() retains the route without sending.
                const auto state=connection_.core().state();
                if (state==connection_state::closing || state==connection_state::draining ||
                    state==connection_state::closed) {
                    stopped_=true;
                    return {};
                }
                authenticated_packet_seen_=true;
                // Learn the peer's source connection ID from an authenticated
                // long header. A client uses this to address the server's
                // chosen connection ID after the first response.
                const auto learned=parse_packet_header(
                    std::as_bytes(std::span(packet.bytes).first(packet.size)),0,local_size_,true);
                if (learned && (learned->kind==packet_kind::initial||learned->kind==packet_kind::handshake) &&
                    learned->source_cid.size()<=peer_.size()) {
                    if (!connection_.peer_ids().selected() &&
                        !connection_.peer_ids().set_initial(learned->source_cid))
                        return std::unexpected(connection_error::invalid_state);
                    if (!learned->source_cid.empty()) {
                        peer_size_=learned->source_cid.size();
                        std::memcpy(peer_.data(),learned->source_cid.data(),peer_size_);
                    }
                }
                // NEW_CONNECTION_ID with Retire Prior To may retire the ID in
                // use; address the peer's next active one (RFC 9000 5.1.2).
                if (const auto* selected=connection_.peer_ids().selected()) {
                    if (selected->length!=0) {
                        peer_size_=selected->length;
                        std::memcpy(peer_.data(),selected->bytes.data(),peer_size_);
                    }
                    // Unroutable datagrams from the peer are checked against
                    // the token of the ID in use.
                    if (selected->has_reset_token && router_reset_token_!=selected->reset_token) {
                        router_reset_token_=selected->reset_token;
                        (void)endpoint_.router().set_reset_token(route_,selected->reset_token);
                    }
                }
                if (!connection_.synchronize_discarded_spaces())
                    return std::unexpected(connection_error::invalid_state);
                const auto level=received->kind==packet_kind::initial ? tls_level::initial :
                    received->kind==packet_kind::handshake ? tls_level::handshake : tls_level::application;
                bool eliciting=false;
                const auto payload=std::as_bytes(std::span(plaintext_).first(received->plaintext_size));
                for (std::size_t cursor=0;cursor<payload.size();) {
                    const auto frame=decode_frame(payload.subspan(cursor));
                    if (!frame) return std::unexpected(connection_error::protocol_violation);
                    if (frame->type==0x1a) {
                        if (frame->data.size()!=8 || !queue_path_response(frame->data,source))
                            return std::unexpected(connection_error::capacity_exceeded);
                    } else if (frame->type==0x1b) {
                        path_challenge token;
                        std::copy(frame->data.begin(),frame->data.end(),token.begin());
                        const auto previous=endpoint_.router().peer(route_);
                        if (endpoint_.router().accept_path_response(route_,token)) {
                            candidate_challenge_active_=false;
                            candidate_attempts_=0;
                            connection_.recovery().set_peer_address_validated(true);
                            // A new address, not only a new port, is a new path
                            // with its own RTT and congestion (RFC 9000 9.4).
                            const auto current=endpoint_.router().peer(route_);
                            if (previous && current && !same_address(*previous,*current) &&
                                !connection_.recovery().reset_path_recovery(connection_.send_datagram_size()))
                                return std::unexpected(connection_error::invalid_state);
                        }
                    }
                    cursor+=frame->encoded_size;
                    eliciting|=frame->type!=0 && frame->type!=2 && frame->type!=3 && frame->type!=0x1c && frame->type!=0x1d;
                }
                if (eliciting) scheduler_.request_ack(level);
                reply_due_|=eliciting && level==tls_level::application;
                if (received->kind==packet_kind::handshake) (void)endpoint_.router().validate_peer(route_);
            }
            if (!connection_.core().poll(now,std::chrono::seconds(1))) return std::unexpected(connection_error::invalid_state);
            // RFC 9002 6.2.2.1: a server that cannot send a full datagram must
            // not arm PTO until client datagrams restore credit. A client keeps
            // an anti-deadlock PTO before address validation, at the highest
            // handshake level keyed, even with nothing in flight.
            if (connection_.role()==endpoint_role::server) {
                connection_.recovery().set_pto_blocked(
                    endpoint_.send_credit(route_)<scheduler_.datagram_limit(tls_level::initial));
            } else {
                const auto& core=connection_.core();
                const std::uint8_t keyed=core.keys_available(tls_level::handshake,tls_direction::write) ? 2 :
                    core.keys_available(tls_level::initial,tls_direction::write) ? 1 : 0;
                if (keyed>client_probe_keyed_) {
                    (void)connection_.recovery().configure_client_handshake_probe(keyed==2 ?
                        packet_number_space::handshake : packet_number_space::initial,now);
                    client_probe_keyed_=keyed;
                }
            }
            const auto timeout=connection_.on_timeout(now);
            if (!timeout) return std::unexpected(timeout.error());
            if (timeout->probe_space) {
                probe_level_=static_cast<tls_level>(*timeout->probe_space); probes_=timeout->probe_count;
                scheduler_.begin_probes();
                // Initial wins a PTO tie with Handshake; probe Handshake too
                // rather than wait for its own backed-off PTO (RFC 9002 6.2.4).
                handshake_probe_=probe_level_==tls_level::initial &&
                    !connection_.core().level_discarded(tls_level::handshake) &&
                    connection_.core().keys_available(tls_level::handshake,tls_direction::write);
            }
            if (!synchronize_candidate(now))
                return std::unexpected(connection_error::provider_failure);
            if (endpoint_.router().role()==path_endpoint_role::server && connection_.core().handshake_confirmed() && !handshake_done_) {
                decoded_frame done; done.type=0x1e;
                if (const auto queued=scheduler_.queue_control(tls_level::application,done); !queued)
                    return std::unexpected(queued.error());
                handshake_done_=true;
            }
        return {};
    }
#if defined(_MSC_VER)
    __declspec(noinline)
#else
    __attribute__((noinline))
#endif
    auto prepare(tls_level level, bool probe, std::span<std::uint8_t> output,
                 lifecycle_time_point now)
        -> std::expected<std::size_t,connection_error>
    {
        protected_packet_fields fields;
        fields.destination_cid={peer_.data(),peer_size_};
        if (level==tls_level::initial) fields.token=initial_token_;
        if (level != tls_level::application) fields.source_cid={local_.data(),local_size_};
        return scheduler_.prepare(level,fields,now,output,build_scratch_,probe);
    }
    [[nodiscard]] static auto same_address(const ip_endpoint& a,const ip_endpoint& b) noexcept -> bool
    {
        const auto length=a.address_family==ip_endpoint::family::ipv4?4:16;
        return a.address_family==b.address_family&&a.scope_id==b.scope_id&&
            std::equal(a.address.begin(),a.address.begin()+length,b.address.begin());
    }
    [[nodiscard]] static auto same_peer(const ip_endpoint& a,const ip_endpoint& b) noexcept -> bool
    { return same_address(a,b)&&a.port==b.port; }
    auto queue_path_response(std::span<const std::byte> bytes,ip_endpoint peer) noexcept -> bool
    {
        for (auto& job:path_responses_) if (!job.occupied) {
            std::copy(bytes.begin(),bytes.end(),job.token.begin());
            job.peer=peer; job.occupied=true; return true;
        }
        return false;
    }
    template<typename T>
    [[nodiscard]] static auto unwrap_task(
        std::expected<std::expected<T,connection_error>,task_result> result)
        -> std::expected<T,connection_error>
    {
        if (!result) return std::unexpected(
            result.error()==task_result::frame_allocation_failure
                ? connection_error::capacity_exceeded : connection_error::invalid_state);
        return std::move(*result);
    }
    static auto send_path_frame(event_loop& loop,connection_driver& self,
                                std::uint64_t type,path_challenge token,bool candidate,
                                lifecycle_time_point now)
        -> task<std::expected<bool,connection_error>>
    {
        if (&loop!=&self.loop_) co_return std::unexpected(connection_error::invalid_state);
        if (!self.connection_.core().keys_available(tls_level::application,tls_direction::write) ||
            self.scheduler_.pending()) co_return false;
        decoded_frame frame; frame.type=type; frame.data=token;
        const auto encoded=encode_frame(frame,self.path_payload_);
        if (!encoded) co_return std::unexpected(connection_error::output_too_small);
        protected_packet_fields fields; fields.kind=packet_kind::short_header;
        fields.destination_cid={self.peer_.data(),self.peer_size_};
        const auto number=self.connection_.core().next_packet_number(tls_level::application);
        if (!number) co_return std::unexpected(connection_error::unavailable_keys);
        // PADDING expands the datagram to 1200 bytes when the path's
        // anti-amplification credit allows it (RFC 9000 8.2.1, 8.2.2).
        constexpr std::size_t expanded=1200;
        const auto overhead=1+self.peer_size_+
            self.connection_.core().packet_number_length(tls_level::application)+16;
        const auto payload=std::span(self.packet_scratch_).first(
            self.endpoint_.send_credit(self.route_,candidate)>=expanded ? expanded-overhead : *encoded);
        std::fill(payload.begin(),payload.end(),std::uint8_t{0});
        std::memcpy(payload.data(),self.path_payload_.data(),*encoded);
        const auto built=self.connection_.core().build(fields,payload,self.output_,self.build_scratch_);
        if (!built) co_return std::unexpected(built.error());
        const auto bytes=std::as_bytes(std::span(self.output_).first(*built));
        const auto sent=candidate ? co_await self.endpoint_.async_send_candidate(self.route_,bytes)
                                  : co_await self.endpoint_.async_send(self.route_,bytes);
        if (!sent) co_return std::unexpected(connection_error::provider_failure);
        if (!*sent) {
            const auto value=sent->error().value();
            if (value==EAGAIN || value==EBUSY || value==EWOULDBLOCK) co_return false;
            co_return std::unexpected(connection_error::provider_failure);
        }
        if (**sent!=*built) co_return std::unexpected(connection_error::provider_failure);
        const sent_packet packet{*number,now,true,true,*built};
        if (!self.connection_.record_sent(tls_level::application,packet,{}))
            co_return std::unexpected(connection_error::invalid_state);
        co_return true;
    }
    // Sleep until the earliest timer the connection owns: loss or PTO alarm,
    // idle or key-retirement deadline (tick polls lifecycle with a 1 s PTO),
    // path probe, or a short retry. Datagrams, application operations and
    // close requests wake the pump through notify().
    auto next_wake(lifecycle_time_point now,bool retry) noexcept -> event_loop::clock::time_point
    {
        auto deadline=connection_.core().next_deadline(std::chrono::seconds(1))
            .value_or(lifecycle_time_point::max());
        if (const auto alarm=connection_.recovery().next_alarm()) deadline=std::min(deadline,alarm->deadline);
        if (candidate_challenge_active_) deadline=std::min(deadline,candidate_probe_due_);
        if (mtu_search_&&connection_.core().handshake_confirmed()) deadline=std::min(deadline,mtu_probe_due_);
        const auto soon=now+std::chrono::milliseconds(1);
        if (retry) deadline=std::min(deadline,soon);
        // A deadline that passed yet stays armed degrades to polling, not spinning.
        return deadline<=now ? soon : deadline;
    }
    auto synchronize_candidate(lifecycle_time_point now) noexcept -> bool
    {
        const auto candidate=endpoint_.router().candidate_peer(route_);
        if (!candidate) { candidate_challenge_active_=false; candidate_attempts_=0; return true; }
        if (candidate_challenge_active_&&same_peer(*candidate,candidate_peer_)) return true;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(candidate_challenge_.data()),
                       static_cast<int>(candidate_challenge_.size()))!=1) return false;
        if (!endpoint_.router().issue_candidate_challenge(route_,candidate_challenge_)) return false;
        candidate_peer_=*candidate; candidate_challenge_active_=true;
        candidate_attempts_=0; candidate_probe_due_=now;
        return true;
    }
    static auto send_pending_path_responses(event_loop& loop,connection_driver& self,
                                           lifecycle_time_point now)
        -> task<std::expected<void,connection_error>>
    {
        if (&loop!=&self.loop_) co_return std::unexpected(connection_error::invalid_state);
        for (auto& job:self.path_responses_) {
            if (!job.occupied) continue;
            bool candidate=false;
            const auto candidate_address=self.endpoint_.router().candidate_peer(self.route_);
            const auto current_address=self.endpoint_.router().peer(self.route_);
            if (candidate_address&&same_peer(job.peer,*candidate_address)) candidate=true;
            else if (!current_address||!same_peer(job.peer,*current_address)) { job.occupied=false; continue; }
            const auto sent=unwrap_task(co_await send_path_frame(loop,self,0x1b,job.token,candidate,now));
            if (!sent) co_return std::unexpected(sent.error());
            if (*sent) job.occupied=false;
            else break;
        }
        co_return std::expected<void,connection_error>{};
    }
    static auto send_candidate_probe(event_loop& loop,connection_driver& self,
                                     lifecycle_time_point now)
        -> task<std::expected<void,connection_error>>
    {
        if (&loop!=&self.loop_) co_return std::unexpected(connection_error::invalid_state);
        if (!self.candidate_challenge_active_||now<self.candidate_probe_due_)
            co_return std::expected<void,connection_error>{};
        const auto candidate=self.endpoint_.router().candidate_peer(self.route_);
        if (!candidate||!same_peer(*candidate,self.candidate_peer_)) {
            self.candidate_challenge_active_=false; self.candidate_attempts_=0;
            co_return std::expected<void,connection_error>{};
        }
        if (self.candidate_attempts_>=3) {
            if (!self.endpoint_.router().cancel_candidate(self.route_))
                co_return std::unexpected(connection_error::invalid_state);
            self.candidate_challenge_active_=false; self.candidate_attempts_=0;
            co_return std::expected<void,connection_error>{};
        }
        const auto sent=unwrap_task(co_await send_path_frame(loop,self,0x1a,self.candidate_challenge_,true,now));
        if (!sent) co_return std::unexpected(sent.error());
        const auto retry=self.connection_.application_pto().value_or(std::chrono::seconds(1));
        self.candidate_probe_due_=now+(*sent?retry:std::chrono::milliseconds(25));
        if (*sent) ++self.candidate_attempts_;
        co_return std::expected<void,connection_error>{};
    }
    // The path MTU fell below the datagram size (the kernel learned it from
    // ICMP): the batch is lost and recovered as usual at the QUIC minimum.
    // A path that refuses datagrams of the minimum size cannot carry QUIC, so
    // the connection stops sending (RFC 9000 14.3).
    auto path_shrank(int error,std::size_t datagram_size) noexcept -> bool
    {
        if (error!=EMSGSIZE||!dont_fragment_||datagram_size<=1200) return false;
        connection_.lower_datagram_size();
        mtu_search_=false;
        return true;
    }
    // Path MTU search: one PING padded to the probed size, outside congestion
    // control (RFC 9000 14.4), sent up to three times a PTO apart. The
    // negotiated ceiling goes first; after a failure the search halves the
    // gap to the current size until it is under 64 bytes. An ACK raises the
    // datagram size; EMSGSIZE or three losses lower the upper bound.
    static auto send_mtu_probe(event_loop& loop,connection_driver& self,
                               lifecycle_time_point now)
        -> task<std::expected<void,connection_error>>
    {
        if (&loop!=&self.loop_) co_return std::unexpected(connection_error::invalid_state);
        auto& connection=self.connection_;
        if (!self.mtu_search_||now<self.mtu_probe_due_||self.scheduler_.pending()||
            !connection.core().handshake_confirmed())
            co_return std::expected<void,connection_error>{};
        const auto low=connection.send_datagram_size();
        if (self.mtu_target_!=0&&(low>=self.mtu_target_||self.mtu_attempts_>=3)) {
            if (low<self.mtu_target_) self.mtu_high_=self.mtu_target_-1;
            self.mtu_target_=0; self.mtu_attempts_=0;
        }
        if (self.mtu_target_==0) {
            const bool first=self.mtu_high_==0;
            if (first) self.mtu_high_=connection.datagram_ceiling();
            if (self.mtu_high_<low+64) {
                self.mtu_search_=false;
                co_return std::expected<void,connection_error>{};
            }
            self.mtu_target_=first ? self.mtu_high_ : low+(self.mtu_high_-low+1)/2;
        }
        const auto size=self.mtu_target_;
        protected_packet_fields fields; fields.kind=packet_kind::short_header;
        fields.destination_cid={self.peer_.data(),self.peer_size_};
        fields.packet_number_length=connection.core().packet_number_length(tls_level::application);
        // Short header, then the AEAD tag.
        const auto overhead=1+self.peer_size_+fields.packet_number_length+16;
        const auto payload=std::span(self.packet_scratch_).first(size-overhead);
        std::fill(payload.begin(),payload.end(),std::uint8_t{0});
        payload[0]=0x01; // PING; the rest is PADDING
        const auto number=connection.core().next_packet_number(tls_level::application);
        if (!number) co_return std::unexpected(connection_error::unavailable_keys);
        const auto built=connection.core().build(fields,payload,self.output_,self.build_scratch_);
        if (!built) co_return std::unexpected(built.error());
        if (*built!=size) {
            connection.core().unbuild(tls_level::application);
            self.mtu_search_=false;
            co_return std::expected<void,connection_error>{};
        }
        const auto sent=co_await self.endpoint_.async_send(self.route_,
            std::as_bytes(std::span(self.output_).first(*built)));
        if (!sent) co_return std::unexpected(connection_error::provider_failure);
        if (!*sent) {
            const auto value=sent->error().value();
            if (value==EMSGSIZE) { self.mtu_high_=size-1; self.mtu_target_=0; self.mtu_attempts_=0; }
            else if (value==EAGAIN||value==EBUSY||value==EWOULDBLOCK)
                self.mtu_probe_due_=now+std::chrono::milliseconds(25);
            else co_return std::unexpected(connection_error::provider_failure);
            co_return std::expected<void,connection_error>{};
        }
        const sent_packet packet{*number,now,true,false,*built};
        if (!connection.record_sent(tls_level::application,packet,{}))
            co_return std::unexpected(connection_error::invalid_state);
        connection.mtu_probe_sent(*number,size);
        ++self.mtu_attempts_;
        self.mtu_probe_due_=now+connection.application_pto().value_or(std::chrono::seconds(1));
        co_return std::expected<void,connection_error>{};
    }
    // Application work ends before the route's closing/draining retention.
    static auto pump(event_loop& loop,connection_driver& self) -> task<std::expected<void,connection_error>>
    {
        self.check_owner();
        if (self.running_) co_return std::unexpected(connection_error::invalid_state);
        self.running_=true;
        self.started_=true;
        struct reset { bool& flag; bool& retaining; ~reset(){flag=false; retaining=false;} } guard{self.running_,self.retaining_};
        auto outcome=co_await pump_loop(loop,self);
        // Event-loop shutdown cancels this task too, so its sends would fail.
        const bool cancelled=!outcome && outcome.error()==task_result::cancelled;
        const auto result=unwrap_task(std::move(outcome));
        self.stopped_=true;
        if (!result) self.failure_=result.error();
        if (cancelled) {
        } else if (!result) {
            if (const auto code=transport_close_code(self,result.error()))
                (void)co_await send_close(loop,self,0x1c,*code);
        } else if (self.close_frame_) {
            (void)co_await send_close(loop,self,self.close_frame_->first,self.close_frame_->second);
        }
        // The owner sees retaining() in the progress callback and may end the
        // period at once to free this or an older route.
        self.retaining_=!cancelled && self.retain_close_ &&
            (self.connection_.core().state()==connection_state::closing ||
             self.connection_.core().state()==connection_state::draining);
        if (self.progress_) self.progress_(self.progress_argument_);
        if (self.retaining_ && self.retain_close_)
            (void)co_await retain_close(loop,self);
        co_return result;
    }

    static auto retain_close(event_loop& loop,connection_driver& self) -> task<void>
    {
        (void)loop;
        const auto pto=self.connection_.application_pto().value_or(std::chrono::seconds(1));
        auto& core=self.connection_.core();
        while (self.retain_close_) {
            const auto now=lifecycle_time_point::clock::now();
            if (!core.poll(now,pto) || core.state()==connection_state::closed) break;
            if (core.state()==connection_state::closing && self.close_size_ &&
                self.close_credit_>=self.close_size_ && now>=self.close_reply_due_) {
                const auto sent=flatten_result(co_await self.endpoint_.async_send(self.route_,
                    std::as_bytes(std::span(self.output_).first(self.close_size_))));
                if (!sent && sent.error().value()!=EAGAIN &&
                    sent.error().value()!=EWOULDBLOCK && sent.error().value()!=EBUSY) break;
                if (sent) self.close_credit_=0;
                self.close_reply_due_=lifecycle_deadline(now,pto);
            }
            auto deadline=core.next_deadline(pto).value_or(lifecycle_time_point::max());
            if (self.close_size_ && self.close_credit_>=self.close_size_)
                deadline=std::min(deadline,self.close_reply_due_);
            if (!co_await idle_wait(self,deadline)) break;
        }
    }
    // RFC 9000 20.1 codes for local failures. Stream and flow violations in
    // peer frames are reported as PROTOCOL_VIOLATION, which 20.1 permits when
    // no more specific code is tracked. A UDP failure sends nothing.
    [[nodiscard]] static auto transport_close_code(connection_driver& self,
        connection_error error) noexcept -> std::optional<std::uint64_t>
    {
        switch (error) {
        case connection_error::provider_failure: return std::nullopt;
        case connection_error::protocol_violation:
        case connection_error::malformed_packet:
        case connection_error::authentication_failed: return 0x0a;
        case connection_error::unsupported_frame: return 0x07;
        case connection_error::key_update_violation: return 0x0e;
        case connection_error::aead_limit_reached: return 0x0f;
        case connection_error::tls_failure:
            if (const auto alert=self.connection_.core().tls_alert()) return 0x100+*alert;
            return 0x01;
        default: return 0x01;
        }
    }
    static auto pump_loop(event_loop& loop,connection_driver& self) -> task<std::expected<void,connection_error>>
    {
        if (const auto start=self.connection_.core().advance(lifecycle_time_point::clock::now()); !start)
            co_return std::unexpected(start.error());
        if (const auto synchronized=self.connection_.synchronize_discarded_spaces(); !synchronized)
            co_return std::unexpected(synchronized.error());
        bool replied=false;
        while (!self.stopped_) {
            const auto now=lifecycle_time_point::clock::now();
            self.work_pending_=false;
            if (const auto result=self.tick(now); !result) co_return std::unexpected(result.error());
            if (self.stopped_) break;
            // Packets that want an ACK usually wake the application. Give it
            // one turn to queue replies first, so the ACK rides on them
            // instead of going in a packet of its own.
            if (std::exchange(self.reply_due_,false) && !std::exchange(replied,true) &&
                self.progress_ && self.connection_.core().state()==connection_state::active) {
                self.progress_(self.progress_argument_);
                if (co_await yield(loop)) continue;
            }
            replied=false;
            if (const auto result=unwrap_task(co_await send_pending_path_responses(loop,self,now)); !result)
                co_return std::unexpected(result.error());
            if (const auto result=unwrap_task(co_await send_candidate_probe(loop,self,now)); !result)
                co_return std::unexpected(result.error());
            if (const auto result=unwrap_task(co_await send_mtu_probe(loop,self,now)); !result)
                co_return std::unexpected(result.error());
            // Drain a bounded burst rather than charging every packet a
            // timer tick. Per-packet preflight still enforces congestion,
            // flow credit and sent-record capacity. Leave two slots of
            // receive-queue headroom and yield before sending more.
            constexpr std::size_t burst_capacity=queue_capacity-2;
            std::size_t transmitted=0;
            // A refused socket send or a waiting PATH_RESPONSE retries soon;
            // nothing else notifies the pump about them.
            bool stop_sending=false,retry=false;
            const auto datagram_size=self.connection_.send_datagram_size();
            for (const auto level : {tls_level::initial,tls_level::handshake,tls_level::application}) {
                if (stop_sending) break;
                if (!self.connection_.core().keys_available(level,tls_direction::write)) continue;
                while (transmitted<burst_capacity) {
                    // Build only what the flush may send (RFC 9000 8.1); a
                    // packet refused there would be recorded but never sent.
                    if (self.endpoint_.send_credit(self.route_)<self.scheduler_.datagram_limit(level)) {
                        stop_sending=true;
                        break;
                    }
                    const bool probe=(self.probes_ && self.probe_level_==level) ||
                        (level==tls_level::handshake && self.handshake_probe_);
                    // Build the packet directly into the offload batch; a
                    // later loss recovers any datagram the provider drops.
                    const auto reserved_error=self.endpoint_.reserve_send(
                        self.route_,bounded_connection::datagram_buffer_size,false);
                    if (reserved_error &&
                        reserved_error.value()!=EAGAIN &&
                        reserved_error.value()!=EWOULDBLOCK &&
                        reserved_error.value()!=EBUSY)
                        co_return std::unexpected(connection_error::provider_failure);
                    const auto prepared=self.prepare(level,probe,self.endpoint_.reserved(),now);
                    if (!prepared) {
                        if (prepared.error()==connection_error::invalid_state || prepared.error()==connection_error::capacity_exceeded) break;
                        co_return std::unexpected(prepared.error());
                    }
                    const auto committed_error=self.endpoint_.commit_send(*prepared);
                    const auto completed=self.scheduler_.complete(true,now);
                    if (!completed) co_return std::unexpected(completed.error());
                    if (probe && self.probe_level_==level) --self.probes_;
                    else if (probe) self.handshake_probe_=false;
                    ++transmitted;
                    const auto error=reserved_error?reserved_error:committed_error;
                    if (error) {
                        const auto value=error.value();
                        if (value!=EAGAIN && value!=EWOULDBLOCK && value!=EBUSY &&
                            !self.path_shrank(value,datagram_size))
                            co_return std::unexpected(connection_error::provider_failure);
                        stop_sending=retry=true;
                        break;
                    }
                }
            }
            if (const auto flushed=self.endpoint_.flush_send(); flushed) {
                const auto value=flushed.value();
                if (value!=EAGAIN && value!=EWOULDBLOCK && value!=EBUSY && !self.path_shrank(value,datagram_size))
                    co_return std::unexpected(connection_error::provider_failure);
                retry=true;
            }
            for (const auto& job:self.path_responses_) retry|=job.occupied;
            if (self.progress_) self.progress_(self.progress_argument_);
            // A progress callback can make more application data ready, and
            // yielded socket receivers can supply ACKs/credit. Give them a
            // turn before deciding that this connection needs a timed retry.
            if (transmitted && co_await yield(loop)) continue;
            if (!co_await idle_wait(self,self.next_wake(now,retry))) break;
        }
        co_return std::expected<void,connection_error>{};
    }
    // One CONNECTION_CLOSE at the highest level with write keys. An
    // application close below 1-RTT becomes APPLICATION_ERROR (0x0c).
    static auto send_close(event_loop& loop,connection_driver& self,
                           std::uint64_t type,std::uint64_t code) -> task<void>
    {
        (void)loop;
        auto& core=self.connection_.core();
        const auto state=core.state();
        if ((state!=connection_state::active && state!=connection_state::handshake) ||
            self.scheduler_.pending())
            co_return;
        // build() needs both 1-RTT directions; a server has the 1-RTT write
        // key before the client's Finished supplies the read key.
        std::optional<tls_level> level;
        for (const auto candidate : {tls_level::application,tls_level::handshake,tls_level::initial})
            if (!core.level_discarded(candidate) &&
                core.keys_available(candidate,tls_direction::write) &&
                (candidate!=tls_level::application ||
                 core.keys_available(candidate,tls_direction::read))) { level=candidate; break; }
        if (!level) co_return;
        decoded_frame frame; frame.type=type; frame.error_code=code;
        if (*level!=tls_level::application && type==0x1d) {
            frame.type=0x1c; frame.error_code=0x0c;
        }
        protected_packet_fields fields;
        fields.kind=*level==tls_level::initial ? packet_kind::initial :
            *level==tls_level::handshake ? packet_kind::handshake : packet_kind::short_header;
        fields.destination_cid={self.peer_.data(),self.peer_size_};
        if (*level!=tls_level::application) fields.source_cid={self.local_.data(),self.local_size_};
        if (*level==tls_level::initial) fields.token=self.initial_token_;
        fields.packet_number_length=core.packet_number_length(*level);
        // The receive scratch is idle once the pump has stopped.
        const auto payload=std::as_writable_bytes(std::span(self.packet_scratch_));
        const auto encoded=encode_frame(frame,payload);
        if (!encoded) co_return;
        std::size_t size=*encoded;
        if (*level==tls_level::initial) {
            // Datagrams carrying Initial packets are at least 1200 bytes
            // (RFC 9000 14.1); pad with PADDING frames as the scheduler does.
            const auto overhead=7+fields.destination_cid.size()+fields.source_cid.size()+
                varint_size(fields.token.size())+fields.token.size()+2+
                fields.packet_number_length+16;
            if (overhead<1200 && size<1200-overhead) {
                std::fill(payload.begin()+static_cast<std::ptrdiff_t>(size),
                          payload.begin()+static_cast<std::ptrdiff_t>(1200-overhead),std::byte{});
                size=1200-overhead;
            }
        }
        const auto built=core.build(fields,
            {self.packet_scratch_.data(),size},self.output_,self.build_scratch_);
        if (!built) co_return;
        const auto sent=flatten_result(co_await self.endpoint_.async_send(self.route_,
            std::as_bytes(std::span(self.output_).first(*built))));
        if (!sent) co_return;
        const auto now=lifecycle_time_point::clock::now();
        if (core.close_sent(now,self.connection_.application_pto().value_or(std::chrono::seconds(1))))
            self.close_size_=*built;
    }
    event_loop& loop_;
    udp_endpoint& endpoint_;
    bounded_connection& connection_;
    packet_scheduler scheduler_;
    std::thread::id owner_{std::this_thread::get_id()};
    endpoint_connection route_{};
    std::array<std::uint8_t,20> local_{},peer_{};
    std::size_t local_size_{},peer_size_{},head_{},count_{},dropped_{};
    std::array<queued_packet,queue_capacity> queue_{};
    std::array<std::uint8_t,packet_capacity> packet_scratch_{},plaintext_{},auth_scratch_{},output_{},build_scratch_{};
    std::array<std::byte,32> path_payload_{};
    std::array<path_response_job,4> path_responses_{};
    path_challenge candidate_challenge_{};
    ip_endpoint candidate_peer_{};
    lifecycle_time_point candidate_probe_due_{};
    std::uint8_t candidate_attempts_{};
    lifecycle_time_point mtu_probe_due_{};
    std::uint8_t mtu_attempts_{};
    std::size_t mtu_target_{},mtu_high_{};
    bool mtu_search_{},dont_fragment_{};
    tls_level probe_level_{};
    std::uint8_t probes_{};
    std::uint8_t client_probe_keyed_{};
    bool handshake_probe_{};
    // Requested CONNECTION_CLOSE frame type and error code.
    std::optional<std::pair<std::uint64_t,std::uint64_t>> close_frame_{};
    std::optional<connection_error> failure_{};
    std::size_t close_size_{},close_credit_{};
    lifecycle_time_point close_reply_due_{};
    bool retain_close_{true};
    bool retaining_{};
    void* progress_argument_{};
    idle_wait* idle_ {};
    void (*progress_)(void*) noexcept {};
    void* retry_argument_{};
    bool (*retry_)(void*,std::span<const std::uint8_t>) noexcept {};
    std::span<const std::uint8_t> initial_token_{};
    bool authenticated_packet_seen_{};
    bool reset_detected_{};
    std::optional<stateless_reset_token> router_reset_token_{};
    bool work_pending_ {};
    bool reply_due_ {}; // a received 1-RTT packet asked for an ACK
    bool running_{},stopped_{},started_{},handshake_done_{},candidate_challenge_active_{};
};
} // namespace eventloop::quic::detail
