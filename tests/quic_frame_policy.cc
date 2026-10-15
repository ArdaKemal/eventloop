#include "quic/frame_policy.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <iostream>

namespace {

using namespace eventloop::quic::detail;

struct frame_case {
    std::uint64_t type;
    unsigned allowed_packets;
    bool server_may_receive;
};

constexpr unsigned initial = 1;
constexpr unsigned zero_rtt = 2;
constexpr unsigned handshake = 4;
constexpr unsigned one_rtt = 8;

// RFC 9000 Table 3, Section 12.5, and RFC 9221 Section 4.
// RFC 9000 erratum 7365 excludes RETIRE_CONNECTION_ID from 0-RTT.
constexpr std::array cases {
    frame_case {0x00, 15, true}, frame_case {0x01, 15, true},
    frame_case {0x02, 13, true}, frame_case {0x03, 13, true},
    frame_case {0x04, 10, true}, frame_case {0x05, 10, true},
    frame_case {0x06, 13, true}, frame_case {0x07, 8, false},
    frame_case {0x08, 10, true}, frame_case {0x09, 10, true},
    frame_case {0x0a, 10, true}, frame_case {0x0b, 10, true},
    frame_case {0x0c, 10, true}, frame_case {0x0d, 10, true},
    frame_case {0x0e, 10, true}, frame_case {0x0f, 10, true},
    frame_case {0x10, 10, true}, frame_case {0x11, 10, true},
    frame_case {0x12, 10, true}, frame_case {0x13, 10, true},
    frame_case {0x14, 10, true}, frame_case {0x15, 10, true},
    frame_case {0x16, 10, true}, frame_case {0x17, 10, true},
    frame_case {0x18, 10, true}, frame_case {0x19, 8, true},
    frame_case {0x1a, 10, true}, frame_case {0x1b, 8, true},
    frame_case {0x1c, 15, true}, frame_case {0x1d, 10, true},
    frame_case {0x1e, 8, false}, frame_case {0x24, 10, true},
    frame_case {0x30, 10, true}, frame_case {0x31, 10, true},
};

constexpr std::array packets {
    packet_kind::initial, packet_kind::zero_rtt,
    packet_kind::handshake, packet_kind::short_header,
};

constexpr std::array packet_bits {initial, zero_rtt, handshake, one_rtt};

auto check(bool condition, std::uint64_t type, packet_kind packet,
           endpoint_role receiver) -> void
{
    if (condition) return;
    std::cerr << "QUIC frame policy mismatch: type=" << type
              << " packet=" << static_cast<int>(packet)
              << " receiver=" << static_cast<int>(receiver) << '\n';
    std::exit(1);
}

auto test_matrix() -> void
{
    for (const auto& entry : cases) {
        for (const auto receiver : {endpoint_role::client,
                                    endpoint_role::server}) {
            for (std::size_t i = 0; i < packets.size(); ++i) {
                const auto packet = packets[i];
                const auto result = validate_frame_policy(packet, entry.type,
                                                          receiver);
                frame_policy_error expected_error {};
                if (packet == packet_kind::zero_rtt &&
                    receiver == endpoint_role::client)
                    expected_error = frame_policy_error::prohibited_sender_role;
                else if (!entry.server_may_receive &&
                         receiver == endpoint_role::server)
                    expected_error = frame_policy_error::prohibited_sender_role;
                else if ((entry.allowed_packets & packet_bits[i]) == 0)
                    expected_error = frame_policy_error::prohibited_packet_kind;
                else {
                    check(result.has_value(), entry.type, packet, receiver);
                    continue;
                }
                check(!result && result.error() == expected_error,
                      entry.type, packet, receiver);
            }
        }
    }
}

auto test_other_inputs() -> void
{
    for (const auto packet : {packet_kind::retry,
                              packet_kind::version_negotiation}) {
        for (const auto& entry : cases) {
            const auto result = validate_frame_policy(
                packet, entry.type, endpoint_role::client);
            check(!result && result.error() ==
                  frame_policy_error::packet_has_no_frames,
                  entry.type, packet, endpoint_role::client);
        }
    }

    for (const auto type : {0x1fULL, 0x20ULL, 0x2fULL, 0x32ULL,
                            0x4000ULL}) {
        const auto result = validate_frame_policy(
            packet_kind::short_header, type, endpoint_role::client);
        check(!result && result.error() ==
              frame_policy_error::unknown_frame_type,
              type, packet_kind::short_header, endpoint_role::client);
    }

    decoded_frame frame;
    frame.type = 0x1e;
    const auto result = validate_frame_policy(
        packet_kind::short_header, frame, endpoint_role::client);
    check(result.has_value(), frame.type, packet_kind::short_header,
          endpoint_role::client);
}

} // namespace

auto main() -> int
{
    test_matrix();
    test_other_inputs();
}
