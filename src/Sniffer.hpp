//
// Created by tomaszp on 8.05.2026.
//
#pragma once
#ifndef NETLEARN_DUMMY_AF_HPP
#define NETLEARN_DUMMY_AF_HPP

#include <net/if_arp.h>
#include <string>

#include <linux/ipv6.h>
#include <chrono>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "control_massage_header.h"
#include <print>
#include "SocketCtl.h"
struct vlan_hdr {
    __be16 h_vlan_TCI;                  // PCP + DEI + VID
    __be16 h_vlan_encapsulated_proto;   // inner EtherType
};



using steady_clock = std::chrono::steady_clock;
struct EPB {
    uint32_t block_type        = 0x00000006;
    uint32_t block_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t original_len;
    // uint8_t packet_data[captured_len]  (padded to 32-bit boundary)
    // [opcje]
    uint32_t block_length_end;
};

class Sniffer
{
    static std::string_view PCP_to_string(uint8_t pcp)
    {
        switch (pcp)
        {
            case 0: return "Best Effort (default)";
            case 1: return "Background";
            case 2: return "Excellent Effort";
            case 3: return "Critical Applications";
            case 4: return "Video (<100ms latency)";
            case 5: return "Voice (<10ms latency)";
            case 6: return "Internetwork Control";
            case 7: return "Network Control";
            default:
                return "unknown";
        }
    }
    static std::string_view DEI_to_string(uint8_t dei)
    {
        switch (dei)
        {
            case 0: return "drop not eligible (default)";
            case 1: return "drop eligible";
                default: return "unknown";
        }
    }
    static std::string print_mac(std::span<uint8_t> mac)
    {
        return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
public:

    std::expected<bool, std::error_code> sniff(const SocketCtl &socket_ctl, const size_t packet_count)
    {
        const auto log = Logger::get();
        const int* fd = socket_ctl.get();
        if (fd == nullptr || *fd==0)
        {
            return std::unexpected{std::error_code{ std::make_error_code(std::errc::bad_address)}};
        }
#define BATCH_SIZE 32
        // pre-allocate everything — no malloc in the hot path
        struct sockaddr_in name_buf[BATCH_SIZE];
        uint8_t      bufs[BATCH_SIZE][2048];
        char         cmsg_bufs[BATCH_SIZE][256];
        struct iovec iovecs[BATCH_SIZE];
        struct mmsghdr msgvec[BATCH_SIZE];

        // one-time setup
        for (int i = 0; i < BATCH_SIZE; i++) {
            iovecs[i].iov_base = bufs[i];
            iovecs[i].iov_len  = sizeof(bufs[i]);

            memset(&msgvec[i], 0, sizeof(msgvec[i]));
            msgvec[i].msg_hdr.msg_name = &name_buf[i]; // sockaddr_in
            msgvec[i].msg_hdr.msg_namelen = sizeof(name_buf[i]);
            msgvec[i].msg_hdr.msg_iov        = &iovecs[i]; //buffer_array (raw frame)
            msgvec[i].msg_hdr.msg_iovlen     = 1; //number of iov entries
            msgvec[i].msg_hdr.msg_control    = cmsg_bufs[i]; //cmsghdr (timstamp, TTL)
            msgvec[i].msg_hdr.msg_controllen = sizeof(cmsg_bufs[i]);
        }

        int received = recvmmsg(*socket_ctl.get(), msgvec, packet_count, 0, NULL);
            if (received < 0) { return std::unexpected{std::error_code{errno, std::generic_category()}};}
        log->debug("received {}", received);
        for (int i = 0; i < received; ++i)
        {
            // metadata
            frame::control_massage_header::parse(&msgvec[i].msg_hdr);
            // header
            const struct ethhdr *eth = reinterpret_cast<struct ethhdr*>(bufs[i]);
            log->info("Header: \ndst: {}, src: {}", parse_mac(eth->h_source), parse_mac(eth->h_source));

            switch (uint16_t ethertype = ntohs(eth->h_proto))
            {
                case ETH_P_8021Q:
                {
                    const struct vlan_hdr *vlan = reinterpret_cast<struct vlan_hdr *>(bufs[i] + sizeof(struct ethhdr));
                    log->info(parse_vlan(vlan));
                    break;
                }
                case ETH_P_IP:
                {
                    const struct iphdr *ip4_hdr = reinterpret_cast<struct iphdr *>(bufs[i] + sizeof(struct ethhdr));
                    frame::ipv4_parser::log_frame(ip4_hdr);
                    break;
                }
                case (ETH_P_IPV6):
                {
                    const struct ipv6hdr *ip6_hdr = reinterpret_cast<struct ipv6hdr *>(bufs[i] + sizeof(struct ethhdr));
                    char src_str[INET_ADDRSTRLEN];
                    char dst_str[INET_ADDRSTRLEN];

                    inet_ntop(AF_INET, &ip6_hdr->saddr, src_str, sizeof(src_str));
                    inet_ntop(AF_INET, &ip6_hdr->daddr, dst_str, sizeof(dst_str));
                    std::print("ipv6 src: {}, dst: {}", src_str, dst_str);
                    std::println();
                    break;
                }
                case ETH_P_ARP:
                {
                    const static ether_arp * arp = reinterpret_cast<ether_arp *>(bufs[i] + sizeof(struct ethhdr));
                    uint16_t op = ntohs(arp->ea_hdr.ar_op);

                    // sender
                    char spa[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, arp->arp_spa, spa, sizeof(spa));

                    // target
                    char tpa[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, arp->arp_tpa, tpa, sizeof(tpa));

                    switch(op)
                    {
                        case ARPOP_REQUEST: {
                            printf("ARP request: who has %s? tell %s\n", tpa, spa);
                            printf("  sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                   arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                                   arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
                            break;
                        }
                        case ARPOP_REPLY:
                        {
                            printf("ARP reply: %s is at %02x:%02x:%02x:%02x:%02x:%02x\n",
                                   spa,
                                   arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                                   arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);

                            break;
                        }
                        default:
                        {
                            std::println("ARP reply: unknown opcode: {}", op);
                        }
                    }
                    break;
                }
                default:
                    std::println("Unknown ethernet type: {}", ethertype);
            }
        }
        return true;
    }
private:
    inline static std::string parse_mac(const unsigned char *mac)
    {
        return std::format("{:02X}:{:02x}:{:02x}:{:02X}:{:02X}:{:02X}",
                   mac[0], mac[1], mac[2],
                   mac[3], mac[4], mac[5]);
    }
    inline static std::string parse_vlan(const struct vlan_hdr* vlan)
    {
        const uint16_t tci = ntohs(vlan->h_vlan_TCI);
        const uint8_t  pcp = (tci >> 13) & 0x07;   // bity 15-13
        const uint8_t  dei = (tci >> 12) & 0x01;   // bit  12
        const uint16_t vid = (tci       ) & 0x0FFF; // bity 11-0
        return std::format("PCP:{}, dei: {}, vid: {}", PCP_to_string(pcp), DEI_to_string(dei), vid);
    }

};
#endif  // NETLEARN_DUMMY_AF_HPP
