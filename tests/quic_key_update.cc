#include "quic/key_update.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <string_view>

using namespace eventloop::quic::detail;
using namespace std::chrono_literals;

#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "QUIC key update check failed at %d: %s\n", \
                 __LINE__, #condition); std::abort(); } } while (false)

namespace {

constexpr auto secret(std::string_view hex) -> std::array<std::uint8_t, 32>
{
    const auto nibble = [](char c) {
        return c <= '9' ? c - '0' : c - 'a' + 10;
    };
    std::array<std::uint8_t, 32> bytes {};
    for (std::size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<std::uint8_t>(
            nibble(hex[i * 2]) * 16 + nibble(hex[i * 2 + 1]));
    return bytes;
}

constexpr auto client_secret = secret(
    "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
constexpr std::array<std::uint8_t, 32> server_secret {};

auto same(const aes_128_gcm_keys& a, const aes_128_gcm_keys& b) -> bool
{ return a.key == b.key && a.iv == b.iv && a.hp == b.hp; }

auto derivation() -> void
{
    // RFC 9001 A.5 / RFC 9369 A.5 use SHA-256 independently of the AEAD.
    CHECK(derive_next_traffic_secret(version_1, client_secret) == secret(
        "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"));
    CHECK(derive_next_traffic_secret(version_2, client_secret) == secret(
        "c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88"));
    CHECK(derive_next_traffic_secret(0, client_secret).error() ==
          protection_error::unsupported_version);
    CHECK(derive_next_traffic_secret(version_1,
              std::span(client_secret).first(31)).error() ==
          protection_error::invalid_input);
}

auto local_gates_and_retention(std::uint32_t version) -> void
{
    key_update_state state;
    CHECK(!state.send_keys() && !state.receive_keys(receive_key_slot::next));
    CHECK(state.initiate_update().error() == key_update_error::not_initialized);
    CHECK(state.initialize(version, client_secret, server_secret));
    const auto original_send = *state.send_keys();
    const auto original_receive = *state.receive_keys(receive_key_slot::current);
    CHECK(state.initialize(version, client_secret, server_secret).error() ==
          key_update_error::already_initialized);
    CHECK(state.on_sent(10));
    CHECK(state.on_acknowledged(10));
    CHECK(state.initiate_update().error() ==
          key_update_error::handshake_not_confirmed);
    CHECK(!state.send_phase() && same(*state.send_keys(), original_send));
    state.confirm_handshake();
    CHECK(state.on_received(receive_key_slot::current, false, 20, true, 0us, 1us));
    CHECK(state.initiate_update());
    CHECK(state.send_phase() && !state.receive_phase());
    CHECK(state.receive_keys_for_send_phase() ==
          state.receive_keys(receive_key_slot::next));
    CHECK(state.receive_keys_for_send_phase()->key != original_receive.key);
    CHECK(state.send_keys()->hp == original_send.hp &&
          state.send_keys()->key != original_send.key);
    CHECK(same(*state.receive_keys(receive_key_slot::current), original_receive));
    CHECK(!state.retirement_deadline());
    CHECK(state.retire_previous(1000000us).error() ==
          key_update_error::previous_keys_unavailable);
    CHECK(state.on_received(receive_key_slot::next, true, 21, false,
              100us, 10us).error() == key_update_error::authentication_failed);
    CHECK(!state.receive_phase() &&
          same(*state.receive_keys(receive_key_slot::current), original_receive));
    CHECK(state.on_sent(11));
    CHECK(state.on_acknowledged(11));
    CHECK(state.initiate_update().error() == key_update_error::peer_update_pending);
    CHECK(state.on_received(receive_key_slot::next, true, 21, true, 100us, 10us));
    CHECK(state.send_phase() && state.receive_phase());
    CHECK(state.receive_keys_for_send_phase() ==
          state.receive_keys(receive_key_slot::current));
    CHECK(same(*state.receive_keys(receive_key_slot::previous), original_receive));
    CHECK(state.retirement_deadline() == 130us);
    CHECK(state.on_received(receive_key_slot::previous, false, 19, true,
                           110us, 10us));
    CHECK(state.on_received(receive_key_slot::previous, false, 22, true,
              110us, 10us).error() == key_update_error::invalid_packet_number);
    CHECK(state.retire_previous(129us).error() == key_update_error::retirement_not_due);
    CHECK(state.receive_keys(receive_key_slot::previous));
    CHECK(state.retire_previous(130us));
    CHECK(!state.receive_keys(receive_key_slot::previous));
    CHECK(state.on_received(receive_key_slot::previous, false, 19, true,
              131us, 10us).error() == key_update_error::previous_keys_unavailable);
    CHECK(state.initiate_update().error() ==
          key_update_error::peer_update_unacknowledged);
    CHECK(state.on_ack_sent(11, 21));
    CHECK(state.initiate_update());
    CHECK(!state.send_phase() && state.receive_phase());
    CHECK(state.send_keys()->hp == original_send.hp);
    CHECK(state.on_acknowledged(11)); // delayed prior-phase ACK
    CHECK(state.on_sent(12));
    CHECK(state.on_received(receive_key_slot::next, false, 30, true, 200us, 10us));
    CHECK(state.on_ack_sent(12, 30));
    CHECK(state.initiate_update().error() ==
          key_update_error::current_phase_not_acknowledged);
    CHECK(state.on_acknowledged(12));
    CHECK(state.initiate_update());
    CHECK(state.send_phase() && !state.receive_phase());
}

auto peer_updates_and_atomic_failures() -> void
{
    key_update_state state;
    CHECK(state.initialize(version_1, client_secret, server_secret));
    auto original = *state.send_keys();
    CHECK(state.on_received(receive_key_slot::next, true, 10, true, 0us, 1us).error() ==
          key_update_error::handshake_not_confirmed);
    CHECK(same(original, *state.send_keys()) && !state.receive_phase());
    state.confirm_handshake();
    CHECK(state.initiate_update().error() ==
          key_update_error::current_phase_not_acknowledged);
    CHECK(state.on_received(receive_key_slot::current, false, 10, true, 0us, 1us));
    CHECK(state.on_received(receive_key_slot::next, true, 9, true, 0us, 1us).error() ==
          key_update_error::invalid_packet_number);
    CHECK(state.on_received(receive_key_slot::next, true, 11, true, 0us, 0us).error() ==
          key_update_error::invalid_input);
    CHECK(state.on_received(receive_key_slot::next, false, 11, true, 0us, 1us).error() ==
          key_update_error::wrong_key_phase);
    CHECK(same(original, *state.send_keys()) && !state.receive_phase());
    CHECK(state.on_sent(1));
    CHECK(state.on_received(receive_key_slot::next, true, 11, true, 100us, 10us));
    CHECK(state.send_phase() && state.receive_phase());
    CHECK(state.send_keys()->hp == original.hp);
    original = *state.send_keys();
    const auto receive = *state.receive_keys(receive_key_slot::current);
    CHECK(state.on_received(receive_key_slot::next, false, 12, true,
              101us, 10us).error() == key_update_error::peer_update_unacknowledged);
    CHECK(state.send_phase() && state.receive_phase() &&
          same(original, *state.send_keys()) &&
          same(receive, *state.receive_keys(receive_key_slot::current)));
    CHECK(state.on_ack_sent(1, 11).error() == key_update_error::invalid_input);
    CHECK(state.on_sent(2));
    CHECK(state.on_ack_sent(2, 12).error() == key_update_error::invalid_input);
    CHECK(state.on_ack_sent(2, 11));
    CHECK(state.on_received(receive_key_slot::next, false, 12, true,
                           110us, 10us));
    CHECK(!state.send_phase() && !state.receive_phase());
    CHECK(state.on_received(receive_key_slot::current, false, 11, true,
              111us, 10us).error() == key_update_error::invalid_packet_number);
    CHECK(state.on_sent(2).error() == key_update_error::invalid_packet_number);
    CHECK(state.on_sent(max_packet_number + 1).error() ==
          key_update_error::invalid_packet_number);
    CHECK(state.on_acknowledged(100).error() == key_update_error::invalid_packet_number);
}

auto authenticated_exchange(std::uint32_t version) -> void
{
    key_update_state client, server;
    CHECK(client.initialize(version, client_secret, server_secret));
    CHECK(server.initialize(version, server_secret, client_secret));
    client.confirm_handshake();
    server.confirm_handshake();
    CHECK(client.on_sent(0));
    CHECK(client.on_acknowledged(0));
    CHECK(client.initiate_update());
    const std::array<std::uint8_t, 2> header {0x44, 1};
    const std::array<std::uint8_t, 1> ping {1};
    std::array<std::uint8_t, 17> encrypted {};
    std::array<std::uint8_t, 1> plaintext {};
    CHECK(seal_payload(*client.send_keys(), 1, header, ping, encrypted) == 17);
    CHECK(client.on_sent(1));
    CHECK(open_payload(*server.receive_keys(receive_key_slot::current),
              1, header, encrypted, plaintext).error() ==
          protection_error::authentication_failed);
    auto result = open_payload(*server.receive_keys(receive_key_slot::next),
                               1, header, encrypted, plaintext);
    CHECK(result == 1 && plaintext == ping);
    CHECK(server.on_received(receive_key_slot::next, true, 1,
                             result.has_value(), 1us, 10us));
    CHECK(server.send_phase());
    CHECK(seal_payload(*server.send_keys(), 0, header, ping, encrypted) == 17);
    CHECK(server.on_sent(0));
    CHECK(server.on_ack_sent(0, 1));
    result = open_payload(*client.receive_keys(receive_key_slot::next),
                          0, header, encrypted, plaintext);
    CHECK(result == 1);
    CHECK(client.on_received(receive_key_slot::next, true, 0,
                             result.has_value(), 2us, 10us));
    CHECK(client.on_acknowledged(1));
    CHECK(client.on_sent(2));
    CHECK(client.on_ack_sent(2, 0));
    CHECK(client.initiate_update());
    CHECK(!client.send_phase());
}

auto retirement_saturation() -> void
{
    key_update_state state;
    CHECK(state.initialize(version_2, client_secret, server_secret));
    state.confirm_handshake();
    CHECK(state.on_received(receive_key_slot::next, true, 0, true,
                           key_update_time::max() - 1us, key_update_time::max()));
    CHECK(state.retirement_deadline() == key_update_time::max());
    CHECK(state.retire_previous(key_update_time::max()));
}

} // namespace

auto main() -> int
{
    derivation();
    local_gates_and_retention(version_1);
    local_gates_and_retention(version_2);
    peer_updates_and_atomic_failures();
    authenticated_exchange(version_1);
    authenticated_exchange(version_2);
    retirement_saturation();
}
