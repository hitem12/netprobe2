//
// Created by tomaszp on 9.05.2026.
//
#pragma once
#ifndef NETLEARN_PCAP_STRUCT_HPP
#define NETLEARN_PCAP_STRUCT_HPP
#include <cstdint>
#include <fstream>
struct PcapGlobalHeader {
    uint32_t magic_number  = 0xa1b2c3d4;
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    int32_t  thiszone      = 0;
    uint32_t sigfigs       = 0;
    uint32_t snaplen       = 65535;
    uint32_t network       = 1; // LINKTYPE_ETHERNET
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;  // zapisana długość
    uint32_t orig_len;  // oryginalna długość
};

class Ppcap
{
    public:
        void save_to_file()
        {

        }
private:
    PcapGlobalHeader header;

};



#endif  // NETLEARN_PCAP_STRUCT_HPP
