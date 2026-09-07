//
// Created by tomaszp on 29.07.2026.
//

#pragma once
#include "IPv4Header.h"
namespace net
{

class IPv4HeaderBuilder
{
    IPv4Header ipv4_header_;

    public:
    // IPv4HeaderBuilder& typeOfService();
    // IPv4HeaderBuilder& packetId();
    // IPv4HeaderBuilder& flags();
    IPv4HeaderBuilder& timeToLive(uint8_t t) { ipv4_header_.ttl = t; return *this; }
    IPv4HeaderBuilder& protocol(uint8_t p) {ipv4_header_.protocol = p; return *this; }
    IPv4HeaderBuilder& sourceIP(uint32_t a) {ipv4_header_.sourceIP = a; return *this; }
    IPv4HeaderBuilder& destinationIP(uint32_t a) {ipv4_header_.destinationIP = a; return *this; }
    IPv4HeaderBuilder& add_option(std::span<uint8_t> o) { ipv4_header_.options.insert(ipv4_header_.options.end(), o.begin(), o.end()); return *this; }
    IPv4Header build(size_t payload_len)
    {
        ipv4_header_.version = 0x04;

        while (ipv4_header_.options.size()%4 != 0)
        {
            if (!ipv4_header_.options.try_push_back(0x00).has_value())
            {
                return ipv4_header_; //error
            }
        }
        uint8_t options_words = ipv4_header_.options.size()%4;
        ipv4_header_.hlen = 5 + options_words;
        ipv4_header_.totalLength = ipv4_header_.hlen + payload_len;
        //walidacja ihl >5 <15
        return ipv4_header_;
    }


};

}  // namespace net
