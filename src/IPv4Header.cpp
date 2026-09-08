//
// Created by tomaszp on 29.07.2026.
//

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
std::error_code net::IPv4Header::deserialize(PacketReader& buf)
{
    if (const auto o = buf.u8();o.has_value())
    {
        version = o.value() >> 4;
        hlen = o.value();
    }
    else return std::make_error_code(std::errc::invalid_argument);

    if (const auto o = buf.u8();o.has_value())
    {
        typeOfService=o.value();
    }
    else return std::make_error_code(std::errc::invalid_argument);

    if (const auto o = buf.be16();o.has_value())
    {
        totalLength = o.value();
    }
    else return std::make_error_code(std::errc::invalid_argument);

    if (const auto o = buf.be16();o.has_value())
    {
        packetId = o.value();
    }
    else return std::make_error_code(std::errc::invalid_argument);

    if (const auto o = buf.be16();o.has_value())
    {
        flags=static_cast<flagsFragment>(flags);
    }
    else return std::make_error_code(std::errc::invalid_argument);

    if (const auto o = buf.u8();o.has_value())
    {
        ttl = o.value();
    }
    else return std::make_error_code(std::errc::invalid_argument);

    if (const auto o = buf.u8();o.has_value())
    {
        protocol = o.value();
    }
    else return std::make_error_code(std::errc::invalid_argument);

    if (const auto o = buf.be16();o.has_value())
    {
        headerChecksum = o.value();
    }
    else return std::make_error_code(std::errc::invalid_argument);

    if (const auto o = buf.be32();o.has_value())
    {
        sourceIP = o.value();
    }
    else return std::make_error_code(std::errc::invalid_argument);

    if (const auto o = buf.be32();o.has_value())
    {
        destinationIP = o.value();
    }
    else return std::make_error_code(std::errc::invalid_argument);

    if (const auto o = buf.bytes(hlen*4 - 20);o.has_value())
    {
        options.assign(o.value().begin(), o.value().end());
    }
    else return std::make_error_code(std::errc::invalid_argument);
    return {};
}