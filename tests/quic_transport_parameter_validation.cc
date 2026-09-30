#include "quic/transport_parameter_validation.h"
#include <array>
#include <cstdio>
#include <cstdlib>

using namespace eventloop::quic::detail;
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); std::abort(); } } while (false)

int main()
{
    using error = parameter_validation_error;
    // Both connection versions advertise version information. The client
    // cannot invite a version switch; the server reports all accepted versions.
    for (const auto chosen : {version_1, version_2}) {
        for (const auto client : {false, true}) {
            std::array<std::byte, 12> encoded {};
            const auto size = encode_fixed_version_information(chosen, client, encoded);
            CHECK(size && *size == (client ? 8 : 12));
            CHECK(version_at(encoded, 0) == chosen);
            CHECK(version_at(encoded, 1) == (client ? chosen : version_1));
            if (!client) CHECK(version_at(encoded, 2) == version_2);
        }
    }
    std::array<std::byte, 7> short_output {};
    CHECK(encode_fixed_version_information(version_1, true, short_output).error() ==
          version_negotiation_error::output_too_small);
    const std::array a {std::byte{1}}, b {std::byte{2}}, c {std::byte{3}};
    const std::array<std::uint32_t, 2> preference {version_2, version_1};
    const std::array<std::byte, 12> vi1 {
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{0x6b}, std::byte{0x33}, std::byte{0x43}, std::byte{0xcf}};
    const std::array<std::byte, 12> vi2 {
        std::byte{0x6b}, std::byte{0x33}, std::byte{0x43}, std::byte{0xcf},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{0x6b}, std::byte{0x33}, std::byte{0x43}, std::byte{0xcf}};
    transport_parameters p;
    auto put = [&](parameter_id id, std::span<const std::byte> value) {
        p.entries[p.count++] = {static_cast<std::uint64_t>(id), value};
    };
    parameter_handshake_observations seen;
    seen.peer_role = parameter_sender::server;
    seen.peer_first_initial_scid = a;
    seen.original_initial_dcid = b;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::missing_initial_source_cid);
    put(parameter_id::initial_source_connection_id, a);
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::missing_original_destination_cid);
    put(parameter_id::original_destination_connection_id, b);
    CHECK(validate_peer_transport_parameters(p, seen));
    seen.client_chosen_version = seen.negotiated_version = version_2;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::missing_version_information);
    seen.client_chosen_version = seen.negotiated_version = version_1;
    p.entries[0].value = b;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::initial_source_cid_mismatch);
    p.entries[0].value = a;
    p.entries[1].value = a;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::original_destination_cid_mismatch);
    p.entries[1].value = b;
    seen.retry_used = true;
    seen.retry_scid = c;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::missing_retry_source_cid);
    put(parameter_id::retry_source_connection_id, c);
    CHECK(validate_peer_transport_parameters(p, seen));
    p.entries[2].value = a;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::retry_source_cid_mismatch);
    p.entries[2].value = c;
    seen.retry_used = false;
    seen.retry_scid = {};
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::unexpected_retry_source_cid);
    --p.count;
    seen.acted_on_version_negotiation = true;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::missing_version_information);
    put(parameter_id::version_information, vi1);
    seen.client_available_versions = preference;
    seen.client_version_preference = preference;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::version_downgrade);
    seen.client_version_preference = std::span(preference).subspan(1);
    CHECK(validate_peer_transport_parameters(p, seen));
    p.entries[2].value = vi2;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::chosen_version_mismatch);
    seen.negotiated_version = version_2;
    seen.client_chosen_version = version_2;
    seen.client_version_preference = preference;
    CHECK(validate_peer_transport_parameters(p, seen));
    p.entries[2].value = std::span(vi2).first(4);
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::version_downgrade);
    seen.acted_on_version_negotiation = false;
    CHECK(validate_peer_transport_parameters(p, seen));
    seen.client_available_versions = std::span(preference).subspan(1);
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::negotiated_version_not_advertised);
    seen.client_available_versions = {};
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::invalid_observation);

    p.count = 1;
    seen = {};
    seen.peer_role = parameter_sender::client;
    seen.peer_first_initial_scid = a;
    CHECK(validate_peer_transport_parameters(p, seen));
    put(parameter_id::retry_source_connection_id, c);
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::forbidden_parameter);
    --p.count;
    put(parameter_id::version_information, vi1);
    CHECK(validate_peer_transport_parameters(p, seen));
    seen.negotiated_version = version_2;
    CHECK(validate_peer_transport_parameters(p, seen));
    p.entries[1].value = std::span(vi1).first(8);
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::negotiated_version_not_advertised);
    p.entries[1].value = vi2;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::chosen_version_mismatch);
    p.entries[1].value = std::span(vi1).first(4);
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::invalid_parameters);
    p.count = 1;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::missing_version_information);
    seen.negotiated_version = version_1;
    seen.client_chosen_version = seen.negotiated_version = version_2;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::missing_version_information);
    const std::array<std::uint32_t, 1> only_v2 {version_2};
    const std::array<std::byte, 8> only_v2_information {
        std::byte{0x6b}, std::byte{0x33}, std::byte{0x43}, std::byte{0xcf},
        std::byte{0x6b}, std::byte{0x33}, std::byte{0x43}, std::byte{0xcf}};
    put(parameter_id::version_information, only_v2_information);
    CHECK(validate_peer_transport_parameters(p, seen));
    seen.peer_role = parameter_sender::server;
    seen.original_initial_dcid = b;
    seen.client_available_versions = only_v2;
    put(parameter_id::original_destination_connection_id, b);
    CHECK(validate_peer_transport_parameters(p, seen));
    p.entries[1].value = vi1;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::chosen_version_mismatch);
    p.entries[1].value = only_v2_information;
    p.entries[0].value = b;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::initial_source_cid_mismatch);
    p.entries[0].value = a;
    p.count = 1;
    seen = {};
    seen.peer_role = parameter_sender::client;
    p.entries[0].value = {};
    seen.peer_first_initial_scid = {};
    CHECK(validate_peer_transport_parameters(p, seen)); // empty CID is present, not missing
    p.count = transport_parameters::max_entries + 1;
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::invalid_parameters);
    p.count = 2;
    p.entries[1] = p.entries[0];
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::invalid_parameters);
    seen.peer_role = static_cast<parameter_sender>(9);
    CHECK(validate_peer_transport_parameters(p, seen).error() == error::invalid_observation);
}
