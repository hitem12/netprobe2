//
// Created by dev on 6/8/26.
//

#ifndef NETLEARN_PARSERS_H
#define NETLEARN_PARSERS_H
#include <string>
#include <span>
#include <format>
#include <netinet/in.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;                  // PCP + DEI + VID
    __be16 h_vlan_encapsulated_proto;   // inner EtherType
};
namespace parsers
{
std::string print_mac(std::span<const uint8_t> mac);
std::string_view DEI_to_string(uint8_t dei);
std::string parse_mac(const unsigned char* mac);
std::string_view PCP_to_string(uint8_t pcp);
std::string parse_vlan(const struct vlan_hdr* vlan);
}  // namespace parsers

#endif  // NETLEARN_PARSERS_H
