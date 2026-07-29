//
// Created by tomaszp on 29.07.2026.
//
#pragma once
#include <cstdint>
#include <inplace_vector>
#include "PacketBuffer.h"
namespace net
{
#pragma pack(push, 1)

#pragma pack(push, 1)
struct flagsFragment
{
    uint16_t fragmentOffset: 13;
    uint16_t mf: 1;
    uint16_t df: 1;
    uint16_t res: 1;
};
#pragma pack(pop)

struct IPv4Header
{
    const uint8_t version : 4 = 4;
    uint8_t hlen : 4 ; //value between 5 - 15
    uint8_t typeOfService : 8;
    uint16_t totalLength : 16;
    uint16_t packetId: 16;
    flagsFragment flags;
    uint8_t ttl: 8; //time to life
    uint8_t protocol: 8;
    uint16_t headerChecksum: 16;
    uint32_t sourceIP: 32;
    uint32_t destinationIP: 32;
    std::inplace_vector<uint8_t,40> options; //optional have t o be aligned to 4 bits

    void serialize(PacketBuffer& buf);
};
#pragma pack(pop)

}  // namespace net
