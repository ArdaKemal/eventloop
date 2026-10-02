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
    static constexpr std::size_t packet_capacity = bounded_connection::datagram_buffer_size;
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
            {this,enqueue,authenticate_changed_peer},validated);
        if (!route) throw std::runtime_error("QUIC driver route capacity");
        route_=*route;
    }
    ~connection_driver()
    {
        check_owner();
        if (running_ || idle_) std::terminate();
        if (!endpoint_.router().remove(route_)) std::terminate();
    }
    connection_driver(const connection_driver&)=delete;
    auto operator=(const connection_driver&)-> connection_driver& = delete;
    auto stop() noexcept -> void { check_owner(); stopped_=true; notify(); }
    // New packets or application send/receive credit can interrupt an idle
    // retry. Resumption remains a timer-loop action, outside router dispatch.
    auto notify() noexcept -> void
    { check_owner(); work_pending_=true; if (idle_) idle_->wake(); }
    // Progress notifications run on the owning loop after each pump iteration;
    // the endpoint uses them to resume ready public-API waiters.
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
    [[nodiscard]] auto initiate_key_update() -> std::expected<void, key_update_error>
    {
        check_owner();
        if (scheduler_.pending()) return std::unexpected(key_update_error::invalid_input);
        const auto pto = connection_.application_pto();
        if (!pto) return std::unexpected(key_update_error::handshake_not_confirmed);
        return connection_.core().initiate_key_update(lifecycle_time_point::clock::now(), *pto);
    }
    [[nodiscard]] auto run() -> task<std::expected<void,connection_error>> { return pump(loop_,*this); }
    [[nodiscard]] auto dropped_packets() const noexcept -> std::size_t { return dropped_; }
    // Internal frame-local wait; the deadline remains bounded polling for
    // idle/recovery work, but notify() can advance it without inline resume.
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
        auto wake() noexcept -> void
        {
            if (signalled_) return;
            signalled_=true;
            auto* cancellation=timer_.cancellation.state;
            eventloop::detail::coroutine_frame_access::cancel_timer(timer_);
            timer_.deadline=event_loop::clock::now();
            timer_.owner=&driver_.loop_;
            if (!eventloop::detail::coroutine_frame_access::attach_cancellation(*cancellation,timer_.cancellation))
                cancelled_=true;
            try { eventloop::detail::coroutine_frame_access::register_timer(driver_.loop_,timer_); }
            catch (...) { std::terminate(); }
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
        bool cancelled_ {},signalled_ {};
    };
private:
    struct queued_packet { std::array<std::uint8_t,packet_capacity> bytes{}; std::size_t size{}; ip_endpoint peer {}; };
    struct path_response_job { path_challenge token {}; ip_endpoint peer {}; bool occupied {}; };
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
        if (self.stopped_ || self.count_==queue_capacity || header.packet.size()>packet_capacity) {
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
    auto tick() -> std::expected<void,connection_error>
    {            while (count_) {
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
                    lifecycle_time_point::clock::now(),std::chrono::seconds(1));
                head_=(head_+1)%queue_capacity; --count_;
                if (!received) {
                    if (received.error()==connection_error::authentication_failed ||
                        received.error()==connection_error::unavailable_keys ||
                        received.error()==connection_error::malformed_packet) continue;
                    return std::unexpected(received.error());
                }
                // A peer close enters draining during receive(). Retire before
                // processing queued/coalesced packets or preparing another send.
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
                        if (endpoint_.router().accept_path_response(route_,token)) {
                            candidate_challenge_active_=false;
                            candidate_attempts_=0;
                            connection_.recovery().set_peer_address_validated(true);
                        }
                    }
                    cursor+=frame->encoded_size;
                    eliciting|=frame->type!=0 && frame->type!=2 && frame->type!=3 && frame->type!=0x1c && frame->type!=0x1d;
                }
                if (eliciting) scheduler_.request_ack(level);
                if (received->kind==packet_kind::handshake) (void)endpoint_.router().validate_peer(route_);
            }
            const auto now=lifecycle_time_point::clock::now();
            if (!connection_.core().poll(now,std::chrono::seconds(1))) return std::unexpected(connection_error::invalid_state);
            const auto timeout=connection_.on_timeout(now);
            if (!timeout) return std::unexpected(timeout.error());
            if (timeout->probe_space) { probe_level_=static_cast<tls_level>(*timeout->probe_space); probes_=timeout->probe_count; }
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
    auto prepare(tls_level level, bool probe) -> std::expected<std::size_t,connection_error>
    {
        protected_packet_fields fields;
        fields.destination_cid={peer_.data(),peer_size_};
        if (level==tls_level::initial) fields.token=initial_token_;
        if (level != tls_level::application) fields.source_cid={local_.data(),local_size_};
        return scheduler_.prepare(level,fields,lifecycle_time_point::clock::now(),output_,build_scratch_,probe);
    }
    [[nodiscard]] static auto same_peer(const ip_endpoint& a,const ip_endpoint& b) noexcept -> bool
    {
        const auto length=a.address_family==ip_endpoint::family::ipv4?4:16;
        return a.address_family==b.address_family&&a.port==b.port&&a.scope_id==b.scope_id&&
            std::equal(a.address.begin(),a.address.begin()+length,b.address.begin());
    }
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
                                std::uint64_t type,path_challenge token,bool candidate)
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
        const auto built=self.connection_.core().build(fields,
            {reinterpret_cast<const std::uint8_t*>(self.path_payload_.data()),*encoded},self.output_,self.build_scratch_);
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
        const auto now=lifecycle_time_point::clock::now();
        const sent_packet packet{*number,now,true,true,*built};
        if (!self.connection_.record_sent(tls_level::application,packet,{}))
            co_return std::unexpected(connection_error::invalid_state);
        co_return true;
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
    static auto send_pending_path_responses(event_loop& loop,connection_driver& self)
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
            const auto sent=unwrap_task(co_await send_path_frame(loop,self,0x1b,job.token,candidate));
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
        const auto sent=unwrap_task(co_await send_path_frame(loop,self,0x1a,self.candidate_challenge_,true));
        if (!sent) co_return std::unexpected(sent.error());
        const auto retry=self.connection_.application_pto().value_or(std::chrono::seconds(1));
        self.candidate_probe_due_=now+(*sent?retry:std::chrono::milliseconds(25));
        if (*sent) ++self.candidate_attempts_;
        co_return std::expected<void,connection_error>{};
    }
    static auto pump(event_loop& loop,connection_driver& self) -> task<std::expected<void,connection_error>>
    {
        self.check_owner();
        if (self.running_) co_return std::unexpected(connection_error::invalid_state);
        self.running_=true;
        self.started_=true;
        struct reset { bool& flag; ~reset(){flag=false;} } guard{self.running_};
        if (const auto start=self.connection_.core().advance(lifecycle_time_point::clock::now()); !start)
            co_return std::unexpected(start.error());
        if (const auto synchronized=self.connection_.synchronize_discarded_spaces(); !synchronized)
            co_return std::unexpected(synchronized.error());
        while (!self.stopped_) {
            self.work_pending_=false;
            if (const auto result=self.tick(); !result) co_return std::unexpected(result.error());
            if (self.stopped_) break;
            if (const auto result=unwrap_task(co_await send_pending_path_responses(loop,self)); !result)
                co_return std::unexpected(result.error());
            if (const auto result=unwrap_task(co_await send_candidate_probe(loop,self,lifecycle_time_point::clock::now())); !result)
                co_return std::unexpected(result.error());
            // Drain a bounded burst rather than charging every packet a
            // timer tick. Per-packet preflight still enforces congestion,
            // flow credit and sent-record capacity. Keep the total below
            // the receive queue capacity and yield before sending more.
            constexpr std::size_t burst_capacity=queue_capacity/2;
            std::size_t transmitted=0;
            for (const auto level : {tls_level::initial,tls_level::handshake,tls_level::application}) {
                if (!self.connection_.core().keys_available(level,tls_direction::write)) continue;
                while (transmitted<burst_capacity) {
                    const bool probe=self.probes_ && self.probe_level_==level;
                    const auto prepared=self.prepare(level,probe);
                    if (!prepared) {
                        if (prepared.error()==connection_error::invalid_state || prepared.error()==connection_error::capacity_exceeded) break;
                        co_return std::unexpected(prepared.error());
                    }
                    const auto sent=co_await self.endpoint_.async_send(self.route_,std::as_bytes(std::span(self.output_).first(*prepared)));
                    const bool success=sent && *sent && **sent==*prepared;
                    const auto completed=self.scheduler_.complete(success,lifecycle_time_point::clock::now());
                    if (!completed) co_return std::unexpected(completed.error());
                    if (success && probe) --self.probes_;
                    if (!success && (!sent || (sent && !*sent && sent->error().value()!=EAGAIN)))
                        co_return std::unexpected(connection_error::provider_failure);
                    if (!success) break;
                    ++transmitted;
                }
            }
            if (self.progress_) self.progress_(self.progress_argument_);
            // A progress callback can make more application data ready, and
            // yielded socket receivers can supply ACKs/credit. Give them a
            // turn before deciding that this connection needs a timed retry.
            if (transmitted && co_await yield(loop)) continue;
            if (!co_await idle_wait(self)) break;
        }
        co_return std::expected<void,connection_error>{};
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
    tls_level probe_level_{};
    std::uint8_t probes_{};
    void* progress_argument_{};
    idle_wait* idle_ {};
    void (*progress_)(void*) noexcept {};
    void* retry_argument_{};
    bool (*retry_)(void*,std::span<const std::uint8_t>) noexcept {};
    std::span<const std::uint8_t> initial_token_{};
    bool authenticated_packet_seen_{};
    bool work_pending_ {};
    bool running_{},stopped_{},started_{},handshake_done_{},candidate_challenge_active_{};
};
} // namespace eventloop::quic::detail
