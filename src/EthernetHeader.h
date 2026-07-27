//
// Created by tomaszp on 27.07.2026.
//

#pragma once
#include <bit>
#include "PacketBuffer.h"
#include <optional>
#include <fmt/format.h>
#include "Parsers.h"
namespace net
{
enum class EthernetType: uint16_t
{
    IPv4 = 0x0800,
    ARP = 0x0806,
    VLAN = 0x8100,
};
inline auto format_as(EthernetType c) {
    return static_cast<std::underlying_type_t<EthernetType>>(c);
}
#pragma pack(push, 1)
struct TCI
{
    uint16_t VID :12;
    uint16_t DEI : 1;
    uint16_t PCP : 3;
};
#pragma pack(pop)

struct VLAN_TAG
{
    TCI tci;
    const uint16_t TPID = 0x8100;

};

struct EthernetHeader
{
    std::array<uint8_t,6> dst_mac;
    std::array<uint8_t,6> src_mac;
    std::optional<VLAN_TAG> vlan_tag;
    EthernetType type;

    void serialize(PacketBuffer& buf) const
    {
        buf.mac(dst_mac);
        buf.mac(src_mac);
        if (vlan_tag.has_value())
        {
            buf.be32(std::bit_cast<uint32_t>(vlan_tag.value()));
        }
        buf.be16(static_cast<uint16_t>(type));

    }
};
}
template<>
struct fmt::formatter<net::TCI> : fmt::formatter<std::string_view> {
    auto format(const net::TCI& tci, fmt::format_context& ctx) const
    {
        return fmt::format_to(ctx.out(), "VID: {} PCP: {} DEI: {}",
            tci.VID, tci.PCP, tci.DEI);
    }
};
template<>
struct fmt::formatter<net::VLAN_TAG> : fmt::formatter<std::string_view> {
    auto format(const net::VLAN_TAG& tag, fmt::format_context& ctx) const
    {
        return fmt::format_to(ctx.out(), "{}", tag.tci);
    }
};
template<>
struct fmt::formatter<net::EthernetHeader> : fmt::formatter<std::string_view> {
    auto format(const net::EthernetHeader& eh, fmt::format_context& ctx) const
    {
        if (eh.vlan_tag.has_value())
        {
            return fmt::format_to(ctx.out(), "dst: {} src: {} tag: [{}] type: {}",
            parsers::parse_mac(eh.dst_mac),parsers::parse_mac(eh.src_mac), eh.vlan_tag.value(),eh.type);
        }
        return fmt::format_to(ctx.out(), "dst: {} src: {} type: {}",
            parsers::parse_mac(eh.dst_mac),parsers::parse_mac(eh.src_mac), eh.type);
    }
};

