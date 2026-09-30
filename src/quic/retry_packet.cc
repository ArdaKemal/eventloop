#include "quic/retry_packet.h"

#include <algorithm>
#include <cstring>

namespace eventloop::quic::detail {
namespace {
auto overlaps(std::span<const std::uint8_t> a,
              std::span<const std::uint8_t> b) noexcept -> bool
{
    if (a.empty() || b.empty()) return false;
    const auto x = reinterpret_cast<std::uintptr_t>(a.data());
    const auto y = reinterpret_cast<std::uintptr_t>(b.data());
    return x <= y ? y - x < a.size() : x - y < b.size();
}
} // namespace

auto build_retry_packet(
    std::uint32_t version, std::span<const std::uint8_t> original_dcid,
    std::span<const std::uint8_t> client_scid,
    std::span<const std::uint8_t> retry_scid,
    std::span<const std::uint8_t> token,
    std::span<std::uint8_t> scratch, std::span<std::uint8_t> output)
    -> std::expected<std::size_t, protection_error>
{
    if (!is_supported_version(version))
        return std::unexpected(protection_error::unsupported_version);
    if (original_dcid.size() > 20 || client_scid.size() > 20 ||
        retry_scid.size() > 20 || token.empty() || token.size() > 65527 ||
        std::ranges::equal(original_dcid, retry_scid))
        return std::unexpected(protection_error::invalid_input);
    const auto overhead = 23 + client_scid.size() + retry_scid.size();
    if (token.size() > 65527 - overhead)
        return std::unexpected(protection_error::invalid_input);
    const auto size = overhead + token.size();
    if (scratch.size() < size || output.size() < size)
        return std::unexpected(protection_error::output_too_small);
    const auto work = scratch.first(size);
    const auto dest = output.first(size);
    if (overlaps(work, dest))
        return std::unexpected(protection_error::invalid_input);
    for (const auto input : {original_dcid, client_scid, retry_scid, token}) {
        if (overlaps(work, input) || overlaps(dest, input))
            return std::unexpected(protection_error::invalid_input);
    }
    work[0] = static_cast<std::uint8_t>(0xc0 |
        (long_header_type_bits(version, long_packet_type::retry) << 4));
    for (std::size_t i = 0; i < 4; ++i)
        work[1 + i] = static_cast<std::uint8_t>(version >> (24 - 8 * i));
    std::size_t cursor = 5;
    work[cursor++] = static_cast<std::uint8_t>(client_scid.size());
    std::ranges::copy(client_scid, work.begin() + cursor);
    cursor += client_scid.size();
    work[cursor++] = static_cast<std::uint8_t>(retry_scid.size());
    std::ranges::copy(retry_scid, work.begin() + cursor);
    cursor += retry_scid.size();
    std::ranges::copy(token, work.begin() + cursor);
    const auto tag = generate_retry_integrity_tag(version, original_dcid,
                                                work.first(size - 16));
    if (!tag) return std::unexpected(tag.error());
    std::ranges::copy(*tag, work.end() - 16);
    std::memcpy(dest.data(), work.data(), size);
    return size;
}

auto parse_and_validate_retry_packet(
    std::span<const std::uint8_t> datagram, std::uint32_t expected_version,
    std::span<const std::uint8_t> original_dcid)
    -> std::expected<packet_header, protection_error>
{
    if (!is_supported_version(expected_version))
        return std::unexpected(protection_error::unsupported_version);
    if (datagram.size() > 65527 || original_dcid.size() > 20)
        return std::unexpected(protection_error::invalid_input);
    const auto header = parse_packet_header(std::as_bytes(datagram));
    if (!header || header->kind != packet_kind::retry ||
        header->version != expected_version || header->token.empty() ||
        header->packet_offset != 0 || header->packet_end_offset != datagram.size() ||
        std::ranges::equal(header->source_cid, std::as_bytes(original_dcid)))
        return std::unexpected(protection_error::invalid_input);
    const auto valid = validate_retry_integrity_tag(expected_version,
                                                   original_dcid, datagram);
    if (!valid) return std::unexpected(valid.error());
    return *header;
}
} // namespace eventloop::quic::detail
