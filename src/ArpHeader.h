//
// Created by tomaszp on 15.08.2026.
//

#pragma once
#include "PacketBuffer.h"
namespace net
{

enum class arp_oper : uint16_t
{
    request = 1,
    replay = 2,
};
enum class arp_htype : uint16_t
{
    ethernet = 1,
};
enum class arp_ptype : uint16_t
{
    ipv4 = 0x0800,
};
struct ArpHeader
{
        arp_htype htype;  //hardware type
        arp_ptype ptype;  //protocol type
        uint8_t hlen; //hardware len
        uint8_t plen; //protocol length
        arp_oper oper; //operation
        std::array<uint8_t,8> sha; //sender hardware address
        std::array<uint8_t,6> spa; //sender protocol address
        std::array<uint8_t,8> tha; //target hardware address
        std::array<uint8_t,6> tpa; //target protocol address
        void serialize(PacketBuffer& buf) const
        {
            buf.be16(static_cast<uint16_t>(htype));
            buf.be16(static_cast<uint16_t>(ptype));
            buf.u8(hlen);
            buf.u8(plen);
            buf.be16(static_cast<uint16_t>(oper));
            buf.bytes(sha);
            buf.bytes(spa);
            buf.bytes(tpa);
            buf.bytes(tha);
            buf.bytes(tpa);
        }
        void deseriaze(PacketBuffer& buf)

};

}  // namespace net
