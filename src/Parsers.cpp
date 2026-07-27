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
std::optional<std::array<uint8_t, 6>> parsers::serialize_mac(
    const std::string_view mac)
{
    std::array<uint8_t, 6> mac_bytes;
    auto mac_bytes_it = mac_bytes.begin();
    uint8_t group {0};
    uint8_t nip {0};
    for (const auto& c : mac)
    {
        if (c == ':')
        {
            if (nip != 2) return std::nullopt;
            *mac_bytes_it = group;
            mac_bytes_it++;
            group = 0; nip =0;
            if (mac_bytes_it == mac_bytes.end()) return std::nullopt;
            continue;
        }
        uint8_t d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return std::nullopt;
        if (nip > 1) return std::nullopt;
        group += d << 4*(1 - nip);
        nip++;
    }
    if (nip != 2) return std::nullopt;
    *mac_bytes_it = group;
    mac_bytes_it++;
    if (mac_bytes_it != mac_bytes.end()) return std::nullopt;
    return mac_bytes;
}