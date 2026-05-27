//
// Created by tomaszp on 8.05.2026.
//
#pragma once
#ifndef NETLEARN_DUMMY_AF_HPP
#define NETLEARN_DUMMY_AF_HPP
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <expected>
#include <system_error>
#include <print>
#include <string>
#include <chrono>
#include "logger.hpp"
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/net_tstamp.h>

#include "ipv4_parser.h"
#include "control_massage_header.h"
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

class dummy_af
{
    static constexpr std::string_view PCP_to_string(uint8_t pcp)
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
    static constexpr  std::string_view DEI_to_string(uint8_t dei)
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
    static std::expected<bool, std::error_code> ala(const std::string_view interface, const size_t packet_count)
    {
        const auto log = Logger::get();
        const int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (!fd){ return std::unexpected{std::error_code{errno, std::generic_category()}};}

        struct ifreq ifr{};
        strncpy(ifr.ifr_name, interface.data(), IFNAMSIZ - 1);
        ioctl(fd, SIOCGIFINDEX, &ifr);

        // ── promiscuous mode ───────────────────────────────────
        struct packet_mreq mr{};
        mr.mr_ifindex = ifr.ifr_ifindex;
        mr.mr_type    = PACKET_MR_PROMISC;
        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                       &mr, sizeof(mr)) < 0) {
            perror("PACKET_ADD_MEMBERSHIP");
                       }

        // ── receive buffer ─────────────────────────────────────
        int size = 4 * 1024 * 1024;  // 4MB
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

        int flags = SOF_TIMESTAMPING_RX_HARDWARE
          | SOF_TIMESTAMPING_RX_SOFTWARE
          | SOF_TIMESTAMPING_SOFTWARE
          | SOF_TIMESTAMPING_RAW_HARDWARE;
        if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) != 0)
        {return  std::unexpected{std::error_code{errno, std::generic_category()}};}


        struct sockaddr_ll addr{};
        addr.sll_family   = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_ALL);
        addr.sll_ifindex  = ifr.ifr_ifindex;

        if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)))
        { return std::unexpected{std::error_code{errno, std::generic_category()}};}
        // uint8_t buf[2048];

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

        int received = recvmmsg(fd, msgvec, packet_count, 0, NULL);
        if (received < 0) { return std::unexpected{std::error_code{errno, std::generic_category()}};}
        log->debug("received {}", received);
        for (int i = 0; i < received; ++i)
        {
            // metadata
            frame::control_massage_header::parse(&msgvec[i].msg_hdr);
            // header
            const struct ethhdr *eth = reinterpret_cast<struct ethhdr*>(bufs[i]);
            std::print("Header: ");
            // użycie
            printf("dst: %02x:%02x:%02x:%02x:%02x:%02x, ",
                   eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                   eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

            printf("src: %02x:%02x:%02x:%02x:%02x:%02x, ",
                   eth->h_source[0], eth->h_source[1], eth->h_source[2],
                   eth->h_source[3], eth->h_source[4], eth->h_source[5]);

            uint16_t ethertype = ntohs(eth->h_proto);
            printf("ethertype: 0x%04x\n", ethertype);
            switch (ethertype)
            {
                case ETH_P_8021Q:
                {
                    const struct vlan_hdr *vlan = reinterpret_cast<struct vlan_hdr *>(bufs[i] + sizeof(struct ethhdr));
                    parse_vlan(vlan);
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

        const struct packet_mreq mr_end = {
            .mr_ifindex = ifr.ifr_ifindex,
            .mr_type    = PACKET_MR_PROMISC,
        };
        setsockopt(fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mr_end, sizeof(mr_end));
        close(fd);
        return true;
    }
private:
    static void parse_vlan(const struct vlan_hdr* vlan)
    {
        const uint16_t tci = ntohs(vlan->h_vlan_TCI);
        const uint8_t  pcp = (tci >> 13) & 0x07;   // bity 15-13
        const uint8_t  dei = (tci >> 12) & 0x01;   // bit  12
        const uint16_t vid = (tci       ) & 0x0FFF; // bity 11-0
        std::print("PCP:{}, dei: {}, vid: {}", PCP_to_string(pcp), DEI_to_string(dei), vid);
    }
};
#endif  // NETLEARN_DUMMY_AF_HPP
