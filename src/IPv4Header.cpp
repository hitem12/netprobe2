//
// Created by tomaszp on 29.07.2026.
//

#pragma once
#include "IPv4Header.h"
void net::IPv4Header::serialize(PacketBuffer& buf)
{
    buf.u8(version << 4 | hlen);
    buf.u8(typeOfService);
    buf.be16(totalLength);
    buf.be16(packetId);
    buf.be16(std::bit_cast<uint16_t>(flags));
    buf.u8(ttl);
    buf.u8(protocol);
    buf.be16(headerChecksum);
    buf.be32(sourceIP);
    buf.be32(destinationIP);
    buf.bytes(options);
}