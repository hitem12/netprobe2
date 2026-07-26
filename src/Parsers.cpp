//
// Created by dev on 6/8/26.
//

#include "Parsers.h"
std::string parsers::parse_mac(const std::span<const uint8_t> mac)
{
    return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3],
                       mac[4], mac[5]);
}
std::string_view parsers::DEI_to_string(uint8_t dei)
{
    switch (dei)
    {
        case 0:
            return "drop not eligible (default)";
        case 1:
            return "drop eligible";
        default:
            return "unknown";
    }
}
std::string parsers::parse_mac(unsigned char* mac)
{
    return std::format("{:02X}:{:02x}:{:02x}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3],
                       mac[4], mac[5]);
}
std::string_view parsers::PCP_to_string(uint8_t pcp)
{
    switch (pcp)
    {
        case 0:
            return "Best Effort (default)";
        case 1:
            return "Background";
        case 2:
            return "Excellent Effort";
        case 3:
            return "Critical Applications";
        case 4:
            return "Video (<100ms latency)";
        case 5:
            return "Voice (<10ms latency)";
        case 6:
            return "Internetwork Control";
        case 7:
            return "Network Control";
        default:
            return "unknown";
    }
}
std::string parsers::parse_vlan(const struct vlan_hdr* vlan)
{
    const uint16_t tci = ntohs(vlan->h_vlan_TCI);
    const uint8_t pcp = (tci >> 13) & 0x07;  // bity 15-13
    const uint8_t dei = (tci >> 12) & 0x01;  // bit  12
    const uint16_t vid = (tci) & 0x0FFF;     // bity 11-0
    return std::format("PCP:{}, dei: {}, vid: {}", PCP_to_string(pcp), DEI_to_string(dei), vid);
}